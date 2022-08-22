// SPDX-License-Identifier: GPL-2.0-or-later
//
// core.c  --  Voltage/Current Regulator framework.
//
// Copyright 2007, 2008 Wolfson Microelectronics PLC.
// Copyright 2008 SlimLogic Ltd.
//
// Author: Liam Girdwood <lrg@slimlogic.co.uk>

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/async.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/suspend.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/of.h>
#include <linux/regmap.h>
#include <linux/regulator/of_regulator.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/coupler.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/module.h>

#define CREATE_TRACE_POINTS
#include <trace/events/regulator.h>

#include "dummy.h"
#include "internal.h"

#define rdev_crit(rdev, fmt, ...)					\
	pr_crit("%s: " fmt, rdev_get_name(rdev), ##__VA_ARGS__)
#define rdev_err(rdev, fmt, ...)					\
	pr_err("%s: " fmt, rdev_get_name(rdev), ##__VA_ARGS__)
#define rdev_warn(rdev, fmt, ...)					\
	pr_warn("%s: " fmt, rdev_get_name(rdev), ##__VA_ARGS__)
#define rdev_info(rdev, fmt, ...)					\
	pr_info("%s: " fmt, rdev_get_name(rdev), ##__VA_ARGS__)
#define rdev_dbg(rdev, fmt, ...)					\
	pr_debug("%s: " fmt, rdev_get_name(rdev), ##__VA_ARGS__)

static DEFINE_WW_CLASS(regulator_ww_class);
static DEFINE_MUTEX(regulator_nesting_mutex);
static DEFINE_MUTEX(regulator_list_mutex);
static LIST_HEAD(regulator_map_list);
static LIST_HEAD(regulator_ena_gpio_list);
static LIST_HEAD(regulator_supply_alias_list);
static LIST_HEAD(regulator_coupler_list);
static LIST_HEAD(regulator_debug_list);
static bool has_full_constraints;

static struct dentry *debugfs_root;

/*
 * struct regulator_map
 *
 * Used to provide symbolic supply names to devices.
 */
struct regulator_map {
	struct list_head list;
	const char *dev_name;   /* The dev_name() for the consumer */
	const char *supply;
	struct regulator_dev *regulator;
};

/*
 * struct regulator_enable_gpio
 *
 * Management for shared enable GPIO pin
 */
struct regulator_enable_gpio {
	struct list_head list;
	struct gpio_desc *gpiod;
	u32 enable_count;	/* a number of enabled shared GPIO */
	u32 request_count;	/* a number of requested shared GPIO */
};

/*
 * struct regulator_supply_alias
 *
 * Used to map lookups for a supply onto an alternative device.
 */
struct regulator_supply_alias {
	struct list_head list;
	struct device *src_dev;
	const char *src_supply;
	struct device *alias_dev;
	const char *alias_supply;
};

struct regulator_limit_volt {
	struct list_head list;
	struct regulator *reg;
};

static int _regulator_is_enabled(struct regulator_dev *rdev);
static int _regulator_disable(struct regulator *regulator);
static int _regulator_get_current_limit(struct regulator_dev *rdev);
static unsigned int _regulator_get_mode(struct regulator_dev *rdev);
static int _notifier_call_chain(struct regulator_dev *rdev,
				  unsigned long event, void *data);
static int _regulator_do_set_voltage(struct regulator_dev *rdev,
				     int min_uV, int max_uV);
static int regulator_balance_voltage(struct regulator_dev *rdev,
				     suspend_state_t state);
static struct regulator *create_regulator(struct regulator_dev *rdev,
					  struct device *dev,
					  const char *supply_name);
static void destroy_regulator(struct regulator *regulator);
static void _regulator_put(struct regulator *regulator);

const char *rdev_get_name(struct regulator_dev *rdev)
{
	if (rdev->constraints && rdev->constraints->name)
		return rdev->constraints->name;
	else if (rdev->desc->name)
		return rdev->desc->name;
	else
		return "";
}

static bool have_full_constraints(void)
{
	return has_full_constraints || of_have_populated_dt();
}

static bool regulator_ops_is_valid(struct regulator_dev *rdev, int ops)
{
	if (!rdev->constraints) {
		rdev_err(rdev, "no constraints\n");
		return false;
	}

	if (rdev->constraints->valid_ops_mask & ops)
		return true;

	return false;
}

/**
 * regulator_lock_nested - lock a single regulator
 * @rdev:		regulator source
 * @ww_ctx:		w/w mutex acquire context
 *
 * This function can be called many times by one task on
 * a single regulator and its mutex will be locked only
 * once. If a task, which is calling this function is other
 * than the one, which initially locked the mutex, it will
 * wait on mutex.
 */
static inline int regulator_lock_nested(struct regulator_dev *rdev,
					struct ww_acquire_ctx *ww_ctx)
{
	bool lock = false;
	int ret = 0;

	mutex_lock(&regulator_nesting_mutex);

	if (ww_ctx || !ww_mutex_trylock(&rdev->mutex)) {
		if (rdev->mutex_owner == current)
			rdev->ref_cnt++;
		else
			lock = true;

		if (lock) {
			mutex_unlock(&regulator_nesting_mutex);
			ret = ww_mutex_lock(&rdev->mutex, ww_ctx);
			mutex_lock(&regulator_nesting_mutex);
		}
	} else {
		lock = true;
	}

	if (lock && ret != -EDEADLK) {
		rdev->ref_cnt++;
		rdev->mutex_owner = current;
	}

	mutex_unlock(&regulator_nesting_mutex);

	return ret;
}

/**
 * regulator_lock - lock a single regulator
 * @rdev:		regulator source
 *
 * This function can be called many times by one task on
 * a single regulator and its mutex will be locked only
 * once. If a task, which is calling this function is other
 * than the one, which initially locked the mutex, it will
 * wait on mutex.
 */
static void regulator_lock(struct regulator_dev *rdev)
{
	regulator_lock_nested(rdev, NULL);
}

/**
 * regulator_unlock - unlock a single regulator
 * @rdev:		regulator_source
 *
 * This function unlocks the mutex when the
 * reference counter reaches 0.
 */
static void regulator_unlock(struct regulator_dev *rdev)
{
	mutex_lock(&regulator_nesting_mutex);

	if (--rdev->ref_cnt == 0) {
		rdev->mutex_owner = NULL;
		ww_mutex_unlock(&rdev->mutex);
	}

	WARN_ON_ONCE(rdev->ref_cnt < 0);

	mutex_unlock(&regulator_nesting_mutex);
}

static bool regulator_supply_is_couple(struct regulator_dev *rdev)
{
	struct regulator_dev *c_rdev;
	int i;

	for (i = 1; i < rdev->coupling_desc.n_coupled; i++) {
		c_rdev = rdev->coupling_desc.coupled_rdevs[i];

		if (rdev->supply->rdev == c_rdev)
			return true;
	}

	return false;
}

static void regulator_unlock_recursive(struct regulator_dev *rdev,
				       unsigned int n_coupled)
{
	struct regulator_dev *c_rdev, *supply_rdev;
	int i, supply_n_coupled;

	for (i = n_coupled; i > 0; i--) {
		c_rdev = rdev->coupling_desc.coupled_rdevs[i - 1];

		if (!c_rdev)
			continue;

		if (c_rdev->supply && !regulator_supply_is_couple(c_rdev)) {
			supply_rdev = c_rdev->supply->rdev;
			supply_n_coupled = supply_rdev->coupling_desc.n_coupled;

			regulator_unlock_recursive(supply_rdev,
						   supply_n_coupled);
		}

		regulator_unlock(c_rdev);
	}
}

static int regulator_lock_recursive(struct regulator_dev *rdev,
				    struct regulator_dev **new_contended_rdev,
				    struct regulator_dev **old_contended_rdev,
				    struct ww_acquire_ctx *ww_ctx)
{
	struct regulator_dev *c_rdev;
	int i, err;

	for (i = 0; i < rdev->coupling_desc.n_coupled; i++) {
		c_rdev = rdev->coupling_desc.coupled_rdevs[i];

		if (!c_rdev)
			continue;

		if (c_rdev != *old_contended_rdev) {
			err = regulator_lock_nested(c_rdev, ww_ctx);
			if (err) {
				if (err == -EDEADLK) {
					*new_contended_rdev = c_rdev;
					goto err_unlock;
				}

				/* shouldn't happen */
				WARN_ON_ONCE(err != -EALREADY);
			}
		} else {
			*old_contended_rdev = NULL;
		}

		if (c_rdev->supply && !regulator_supply_is_couple(c_rdev)) {
			err = regulator_lock_recursive(c_rdev->supply->rdev,
						       new_contended_rdev,
						       old_contended_rdev,
						       ww_ctx);
			if (err) {
				regulator_unlock(c_rdev);
				goto err_unlock;
			}
		}
	}

	return 0;

err_unlock:
	regulator_unlock_recursive(rdev, i);

	return err;
}

/**
 * regulator_unlock_dependent - unlock regulator's suppliers and coupled
 *				regulators
 * @rdev:			regulator source
 * @ww_ctx:			w/w mutex acquire context
 *
 * Unlock all regulators related with rdev by coupling or supplying.
 */
static void regulator_unlock_dependent(struct regulator_dev *rdev,
				       struct ww_acquire_ctx *ww_ctx)
{
	regulator_unlock_recursive(rdev, rdev->coupling_desc.n_coupled);
	ww_acquire_fini(ww_ctx);
}

/**
 * regulator_lock_dependent - lock regulator's suppliers and coupled regulators
 * @rdev:			regulator source
 * @ww_ctx:			w/w mutex acquire context
 *
 * This function as a wrapper on regulator_lock_recursive(), which locks
 * all regulators related with rdev by coupling or supplying.
 */
static void regulator_lock_dependent(struct regulator_dev *rdev,
				     struct ww_acquire_ctx *ww_ctx)
{
	struct regulator_dev *new_contended_rdev = NULL;
	struct regulator_dev *old_contended_rdev = NULL;
	int err;

	mutex_lock(&regulator_list_mutex);

	ww_acquire_init(ww_ctx, &regulator_ww_class);

	do {
		if (new_contended_rdev) {
			ww_mutex_lock_slow(&new_contended_rdev->mutex, ww_ctx);
			old_contended_rdev = new_contended_rdev;
			old_contended_rdev->ref_cnt++;
		}

		err = regulator_lock_recursive(rdev,
					       &new_contended_rdev,
					       &old_contended_rdev,
					       ww_ctx);

		if (old_contended_rdev)
			regulator_unlock(old_contended_rdev);

	} while (err == -EDEADLK);

	ww_acquire_done(ww_ctx);

	mutex_unlock(&regulator_list_mutex);
}

/**
 * of_get_child_regulator - get a child regulator device node
 * based on supply name
 * @parent: Parent device node
 * @prop_name: Combination regulator supply name and "-supply"
 *
 * Traverse all child nodes.
 * Extract the child regulator device node corresponding to the supply name.
 * returns the device node corresponding to the regulator if found, else
 * returns NULL.
 */
static struct device_node *of_get_child_regulator(struct device_node *parent,
						  const char *prop_name)
{
	struct device_node *regnode = NULL;
	struct device_node *child = NULL;

	for_each_child_of_node(parent, child) {
		regnode = of_parse_phandle(child, prop_name, 0);

		if (!regnode) {
			regnode = of_get_child_regulator(child, prop_name);
			if (regnode)
				goto err_node_put;
		} else {
			goto err_node_put;
		}
	}
	return NULL;

err_node_put:
	of_node_put(child);
	return regnode;
}

/**
 * of_get_regulator - get a regulator device node based on supply name
 * @dev: Device pointer for the consumer (of regulator) device
 * @supply: regulator supply name
 *
 * Extract the regulator device node corresponding to the supply name.
 * returns the device node corresponding to the regulator if found, else
 * returns NULL.
 */
static struct device_node *of_get_regulator(struct device *dev, const char *supply)
{
	struct device_node *regnode = NULL;
	char prop_name[64]; /* 64 is max size of property name */

	dev_dbg(dev, "Looking up %s-supply from device tree\n", supply);

	snprintf(prop_name, 64, "%s-supply", supply);
	regnode = of_parse_phandle(dev->of_node, prop_name, 0);

	if (!regnode) {
		regnode = of_get_child_regulator(dev->of_node, prop_name);
		if (regnode)
			return regnode;

		dev_dbg(dev, "Looking up %s property in node %pOF failed\n",
				prop_name, dev->of_node);
		return NULL;
	}
	return regnode;
}

/* Platform voltage constraint check */
int regulator_check_voltage(struct regulator_dev *rdev,
			    int *min_uV, int *max_uV)
{
	BUG_ON(*min_uV > *max_uV);

	if (!regulator_ops_is_valid(rdev, REGULATOR_CHANGE_VOLTAGE)) {
		rdev_err(rdev, "voltage operation not allowed\n");
		return -EPERM;
	}

	if (*max_uV > rdev->constraints->max_uV)
		*max_uV = rdev->constraints->max_uV;
	if (*min_uV < rdev->constraints->min_uV)
		*min_uV = rdev->constraints->min_uV;

	if (*min_uV > *max_uV) {
		rdev_err(rdev, "unsupportable voltage range: %d-%duV\n",
			 *min_uV, *max_uV);
		return -EINVAL;
	}

	return 0;
}

/* return 0 if the state is valid */
static int regulator_check_states(suspend_state_t state)
{
	return (state > PM_SUSPEND_MAX || state == PM_SUSPEND_TO_IDLE);
}

/* Make sure we select a voltage that suits the needs of all
 * regulator consumers
 */
int regulator_check_consumers(struct regulator_dev *rdev,
			      int *min_uV, int *max_uV,
			      suspend_state_t state)
{
	struct regulator *regulator;
	struct regulator_voltage *voltage;

	list_for_each_entry(regulator, &rdev->consumer_list, list) {
		voltage = &regulator->voltage[state];
		/*
		 * Assume consumers that didn't say anything are OK
		 * with anything in the constraint range.
		 */
		if (!voltage->min_uV && !voltage->max_uV)
			continue;

		if (*max_uV > voltage->max_uV)
			*max_uV = voltage->max_uV;
		if (*min_uV < voltage->min_uV)
			*min_uV = voltage->min_uV;
	}

	if (*min_uV > *max_uV) {
		rdev_err(rdev, "Restricting voltage, %u-%uuV\n",
			*min_uV, *max_uV);
		return -EINVAL;
	}

	return 0;
}

/* current constraint check */
static int regulator_check_current_limit(struct regulator_dev *rdev,
					int *min_uA, int *max_uA)
{
	BUG_ON(*min_uA > *max_uA);

	if (!regulator_ops_is_valid(rdev, REGULATOR_CHANGE_CURRENT)) {
		rdev_err(rdev, "current operation not allowed\n");
		return -EPERM;
	}

	if (*max_uA > rdev->constraints->max_uA)
		*max_uA = rdev->constraints->max_uA;
	if (*min_uA < rdev->constraints->min_uA)
		*min_uA = rdev->constraints->min_uA;

	if (*min_uA > *max_uA) {
		rdev_err(rdev, "unsupportable current range: %d-%duA\n",
			 *min_uA, *max_uA);
		return -EINVAL;
	}

	return 0;
}

/* operating mode constraint check */
static int regulator_mode_constrain(struct regulator_dev *rdev,
				    unsigned int *mode)
{
	switch (*mode) {
	case REGULATOR_MODE_FAST:
	case REGULATOR_MODE_NORMAL:
	case REGULATOR_MODE_IDLE:
	case REGULATOR_MODE_STANDBY:
		break;
	default:
		rdev_err(rdev, "invalid mode %x specified\n", *mode);
		return -EINVAL;
	}

	if (!regulator_ops_is_valid(rdev, REGULATOR_CHANGE_MODE)) {
		rdev_err(rdev, "mode operation not allowed\n");
		return -EPERM;
	}

	/* The modes are bitmasks, the most power hungry modes having
	 * the lowest values. If the requested mode isn't supported
	 * try higher modes. */
	while (*mode) {
		if (rdev->constraints->valid_modes_mask & *mode)
			return 0;
		*mode /= 2;
	}

	return -EINVAL;
}

static inline struct regulator_state *
regulator_get_suspend_state(struct regulator_dev *rdev, suspend_state_t state)
{
	if (rdev->constraints == NULL)
		return NULL;

	switch (state) {
	case PM_SUSPEND_STANDBY:
		return &rdev->constraints->state_standby;
	case PM_SUSPEND_MEM:
		return &rdev->constraints->state_mem;
	case PM_SUSPEND_MAX:
		return &rdev->constraints->state_disk;
	default:
		return NULL;
	}
}

static const struct regulator_state *
regulator_get_suspend_state_check(struct regulator_dev *rdev, suspend_state_t state)
{
	const struct regulator_state *rstate;

	rstate = regulator_get_suspend_state(rdev, state);
	if (rstate == NULL)
		return NULL;

	/* If we have no suspend mode configuration don't set anything;
	 * only warn if the driver implements set_suspend_voltage or
	 * set_suspend_mode callback.
	 */
	if (rstate->enabled != ENABLE_IN_SUSPEND &&
	    rstate->enabled != DISABLE_IN_SUSPEND) {
		if (rdev->desc->ops->set_suspend_voltage ||
		    rdev->desc->ops->set_suspend_mode)
			rdev_warn(rdev, "No configuration\n");
		return NULL;
	}

	return rstate;
}

static ssize_t regulator_uV_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);
	int uV;

	regulator_lock(rdev);
	uV = regulator_get_voltage_rdev(rdev);
	regulator_unlock(rdev);

	if (uV < 0)
		return uV;
	return sprintf(buf, "%d\n", uV);
}
static DEVICE_ATTR(microvolts, 0444, regulator_uV_show, NULL);

static ssize_t regulator_uA_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", _regulator_get_current_limit(rdev));
}
static DEVICE_ATTR(microamps, 0444, regulator_uA_show, NULL);

static ssize_t name_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", rdev_get_name(rdev));
}
static DEVICE_ATTR_RO(name);

static const char *regulator_opmode_to_str(int mode)
{
	switch (mode) {
	case REGULATOR_MODE_FAST:
		return "fast";
	case REGULATOR_MODE_NORMAL:
		return "normal";
	case REGULATOR_MODE_IDLE:
		return "idle";
	case REGULATOR_MODE_STANDBY:
		return "standby";
	}
	return "unknown";
}

static ssize_t regulator_print_opmode(char *buf, int mode)
{
	return sprintf(buf, "%s\n", regulator_opmode_to_str(mode));
}

static ssize_t regulator_opmode_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return regulator_print_opmode(buf, _regulator_get_mode(rdev));
}
static DEVICE_ATTR(opmode, 0444, regulator_opmode_show, NULL);

static ssize_t regulator_print_state(char *buf, int state)
{
	if (state > 0)
		return sprintf(buf, "enabled\n");
	else if (state == 0)
		return sprintf(buf, "disabled\n");
	else
		return sprintf(buf, "unknown\n");
}

static ssize_t regulator_state_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);
	ssize_t ret;

	regulator_lock(rdev);
	ret = regulator_print_state(buf, _regulator_is_enabled(rdev));
	regulator_unlock(rdev);

	return ret;
}
static DEVICE_ATTR(state, 0444, regulator_state_show, NULL);

static ssize_t regulator_status_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);
	int status;
	char *label;

	status = rdev->desc->ops->get_status(rdev);
	if (status < 0)
		return status;

	switch (status) {
	case REGULATOR_STATUS_OFF:
		label = "off";
		break;
	case REGULATOR_STATUS_ON:
		label = "on";
		break;
	case REGULATOR_STATUS_ERROR:
		label = "error";
		break;
	case REGULATOR_STATUS_FAST:
		label = "fast";
		break;
	case REGULATOR_STATUS_NORMAL:
		label = "normal";
		break;
	case REGULATOR_STATUS_IDLE:
		label = "idle";
		break;
	case REGULATOR_STATUS_STANDBY:
		label = "standby";
		break;
	case REGULATOR_STATUS_BYPASS:
		label = "bypass";
		break;
	case REGULATOR_STATUS_UNDEFINED:
		label = "undefined";
		break;
	default:
		return -ERANGE;
	}

	return sprintf(buf, "%s\n", label);
}
static DEVICE_ATTR(status, 0444, regulator_status_show, NULL);

static ssize_t regulator_min_uA_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	if (!rdev->constraints)
		return sprintf(buf, "constraint not defined\n");

	return sprintf(buf, "%d\n", rdev->constraints->min_uA);
}
static DEVICE_ATTR(min_microamps, 0444, regulator_min_uA_show, NULL);

static ssize_t regulator_max_uA_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	if (!rdev->constraints)
		return sprintf(buf, "constraint not defined\n");

	return sprintf(buf, "%d\n", rdev->constraints->max_uA);
}
static DEVICE_ATTR(max_microamps, 0444, regulator_max_uA_show, NULL);

static ssize_t regulator_min_uV_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	if (!rdev->constraints)
		return sprintf(buf, "constraint not defined\n");

	return sprintf(buf, "%d\n", rdev->constraints->min_uV);
}
static DEVICE_ATTR(min_microvolts, 0444, regulator_min_uV_show, NULL);

static ssize_t regulator_max_uV_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	if (!rdev->constraints)
		return sprintf(buf, "constraint not defined\n");

	return sprintf(buf, "%d\n", rdev->constraints->max_uV);
}
static DEVICE_ATTR(max_microvolts, 0444, regulator_max_uV_show, NULL);

static ssize_t regulator_total_uA_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);
	struct regulator *regulator;
	int uA = 0;

	regulator_lock(rdev);
	list_for_each_entry(regulator, &rdev->consumer_list, list) {
		if (regulator->enable_count)
			uA += regulator->uA_load;
	}
	regulator_unlock(rdev);
	return sprintf(buf, "%d\n", uA);
}
static DEVICE_ATTR(requested_microamps, 0444, regulator_total_uA_show, NULL);

static ssize_t num_users_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", rdev->use_count);
}
static DEVICE_ATTR_RO(num_users);

static ssize_t type_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	switch (rdev->desc->type) {
	case REGULATOR_VOLTAGE:
		return sprintf(buf, "voltage\n");
	case REGULATOR_CURRENT:
		return sprintf(buf, "current\n");
	}
	return sprintf(buf, "unknown\n");
}
static DEVICE_ATTR_RO(type);

static ssize_t regulator_suspend_mem_uV_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", rdev->constraints->state_mem.uV);
}
static DEVICE_ATTR(suspend_mem_microvolts, 0444,
		regulator_suspend_mem_uV_show, NULL);

static ssize_t regulator_suspend_disk_uV_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", rdev->constraints->state_disk.uV);
}
static DEVICE_ATTR(suspend_disk_microvolts, 0444,
		regulator_suspend_disk_uV_show, NULL);

static ssize_t regulator_suspend_standby_uV_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", rdev->constraints->state_standby.uV);
}
static DEVICE_ATTR(suspend_standby_microvolts, 0444,
		regulator_suspend_standby_uV_show, NULL);

static ssize_t regulator_suspend_mem_mode_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return regulator_print_opmode(buf,
		rdev->constraints->state_mem.mode);
}
static DEVICE_ATTR(suspend_mem_mode, 0444,
		regulator_suspend_mem_mode_show, NULL);

static ssize_t regulator_suspend_disk_mode_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return regulator_print_opmode(buf,
		rdev->constraints->state_disk.mode);
}
static DEVICE_ATTR(suspend_disk_mode, 0444,
		regulator_suspend_disk_mode_show, NULL);

static ssize_t regulator_suspend_standby_mode_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return regulator_print_opmode(buf,
		rdev->constraints->state_standby.mode);
}
static DEVICE_ATTR(suspend_standby_mode, 0444,
		regulator_suspend_standby_mode_show, NULL);

static ssize_t regulator_suspend_mem_state_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return regulator_print_state(buf,
			rdev->constraints->state_mem.enabled);
}
static DEVICE_ATTR(suspend_mem_state, 0444,
		regulator_suspend_mem_state_show, NULL);

static ssize_t regulator_suspend_disk_state_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return regulator_print_state(buf,
			rdev->constraints->state_disk.enabled);
}
static DEVICE_ATTR(suspend_disk_state, 0444,
		regulator_suspend_disk_state_show, NULL);

static ssize_t regulator_suspend_standby_state_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);

	return regulator_print_state(buf,
			rdev->constraints->state_standby.enabled);
}
static DEVICE_ATTR(suspend_standby_state, 0444,
		regulator_suspend_standby_state_show, NULL);

static ssize_t regulator_bypass_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct regulator_dev *rdev = dev_get_drvdata(dev);
	const char *report;
	bool bypass;
	int ret;

	ret = rdev->desc->ops->get_bypass(rdev, &bypass);

	if (ret != 0)
		report = "unknown";
	else if (bypass)
		report = "enabled";
	else
		report = "disabled";

	return sprintf(buf, "%s\n", report);
}
static DEVICE_ATTR(bypass, 0444,
		   regulator_bypass_show, NULL);

/* Calculate the new optimum regulator operating mode based on the new total
 * consumer load. All locks held by caller */
static int drms_uA_update(struct regulator_dev *rdev)
{
	struct regulator *sibling;
	int current_uA = 0, output_uV, input_uV, err;
	unsigned int mode;

	/*
	 * first check to see if we can set modes at all, otherwise just
	 * tell the consumer everything is OK.
	 */
	if (!regulator_ops_is_valid(rdev, REGULATOR_CHANGE_DRMS)) {
		rdev_dbg(rdev, "DRMS operation not allowed\n");
		return 0;
	}

	if (!rdev->desc->ops->get_optimum_mode &&
	    !rdev->desc->ops->set_load)
		return 0;

	if (!rdev->desc->ops->set_mode &&
	    !rdev->desc->ops->set_load)
		return -EINVAL;

	/* calc total requested load */
	list_for_each_entry(sibling, &rdev->consumer_list, list) {
		if (sibling->enable_count)
			current_uA += sibling->uA_load;
	}

	current_uA += rdev->constraints->system_load;

	if (rdev->desc->ops->set_load) {
		/* set the optimum mode for our new total regulator load */
		err = rdev->desc->ops->set_load(rdev, current_uA);
		if (err < 0)
			rdev_err(rdev, "failed to set load %d: %pe\n",
				 current_uA, ERR_PTR(err));
	} else {
		/* get output voltage */
		output_uV = regulator_get_voltage_rdev(rdev);
		if (output_uV <= 0) {
			rdev_err(rdev, "invalid output voltage found\n");
			return -EINVAL;
		}

		/* get input voltage */
		input_uV = 0;
		if (rdev->supply)
			input_uV = regulator_get_voltage(rdev->supply);
		if (input_uV <= 0)
			input_uV = rdev->constraints->input_uV;
		if (input_uV <= 0) {
			rdev_err(rdev, "invalid input voltage found\n");
			return -EINVAL;
		}

		/* now get the optimum mode for our new total regulator load */
		mode = rdev->desc->ops->get_optimum_mode(rdev, input_uV,
							 output_uV, current_uA);

		/* check the new mode is allowed */
		err = regulator_mode_constrain(rdev, &mode);
		if (err < 0) {
			rdev_err(rdev, "failed to get optimum mode @ %d uA %d -> %d uV: %pe\n",
				 current_uA, input_uV, output_uV, ERR_PTR(err));
			return err;
		}

		err = rdev->desc->ops->set_mode(rdev, mode);
		if (err < 0)
			rdev_err(rdev, "failed to set optimum mode %x: %pe\n",
				 mode, ERR_PTR(err));
	}

	return err;
}

static int __suspend_set_state(struct regulator_dev *rdev,
			       const struct regulator_state *rstate)
{
	int ret = 0;

	if (rstate->enabled == ENABLE_IN_SUSPEND &&
		rdev->desc->ops->set_suspend_enable)
		ret = rdev->desc->ops->set_suspend_enable(rdev);
	else if (rstate->enabled == DISABLE_IN_SUSPEND &&
		rdev->desc->ops->set_suspend_disable)
		ret = rdev->desc->ops->set_suspend_disable(rdev);
	else /* OK if set_suspend_enable or set_suspend_disable is NULL */
		ret = 0;

	if (ret < 0) {
		rdev_err(rdev, "failed to enabled/disable: %pe\n", ERR_PTR(ret));
		return ret;
	}

	if (rdev->desc->ops->set_suspend_voltage && rstate->uV > 0) {
		ret = rdev->desc->ops->set_suspend_voltage(rdev, rstate->uV);
		if (ret < 0) {
			rdev_err(rdev, "failed to set voltage: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	if (rdev->desc->ops->set_suspend_mode && rstate->mode > 0) {
		ret = rdev->desc->ops->set_suspend_mode(rdev, rstate->mode);
		if (ret < 0) {
			rdev_err(rdev, "failed to set mode: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	return ret;
}

static int suspend_set_initial_state(struct regulator_dev *rdev)
{
	const struct regulator_state *rstate;

	rstate = regulator_get_suspend_state_check(rdev,
			rdev->constraints->initial_state);
	if (!rstate)
		return 0;

	return __suspend_set_state(rdev, rstate);
}

#if defined(DEBUG) || defined(CONFIG_DYNAMIC_DEBUG)
static void print_constraints_debug(struct regulator_dev *rdev)
{
	struct regulation_constraints *constraints = rdev->constraints;
	char buf[160] = "";
	size_t len = sizeof(buf) - 1;
	int count = 0;
	int ret;

	if (constraints->min_uV && constraints->max_uV) {
		if (constraints->min_uV == constraints->max_uV)
			count += scnprintf(buf + count, len - count, "%d mV ",
					   constraints->min_uV / 1000);
		else
			count += scnprintf(buf + count, len - count,
					   "%d <--> %d mV ",
					   constraints->min_uV / 1000,
					   constraints->max_uV / 1000);
	}

	if (!constraints->min_uV ||
	    constraints->min_uV != constraints->max_uV) {
		ret = regulator_get_voltage_rdev(rdev);
		if (ret > 0)
			count += scnprintf(buf + count, len - count,
					   "at %d mV ", ret / 1000);
	}

	if (constraints->uV_offset)
		count += scnprintf(buf + count, len - count, "%dmV offset ",
				   constraints->uV_offset / 1000);

	if (constraints->min_uA && constraints->max_uA) {
		if (constraints->min_uA == constraints->max_uA)
			count += scnprintf(buf + count, len - count, "%d mA ",
					   constraints->min_uA / 1000);
		else
			count += scnprintf(buf + count, len - count,
					   "%d <--> %d mA ",
					   constraints->min_uA / 1000,
					   constraints->max_uA / 1000);
	}

	if (!constraints->min_uA ||
	    constraints->min_uA != constraints->max_uA) {
		ret = _regulator_get_current_limit(rdev);
		if (ret > 0)
			count += scnprintf(buf + count, len - count,
					   "at %d mA ", ret / 1000);
	}

	if (constraints->valid_modes_mask & REGULATOR_MODE_FAST)
		count += scnprintf(buf + count, len - count, "fast ");
	if (constraints->valid_modes_mask & REGULATOR_MODE_NORMAL)
		count += scnprintf(buf + count, len - count, "normal ");
	if (constraints->valid_modes_mask & REGULATOR_MODE_IDLE)
		count += scnprintf(buf + count, len - count, "idle ");
	if (constraints->valid_modes_mask & REGULATOR_MODE_STANDBY)
		count += scnprintf(buf + count, len - count, "standby ");

	if (!count)
		count = scnprintf(buf, len, "no parameters");
	else
		--count;

	count += scnprintf(buf + count, len - count, ", %s",
		_regulator_is_enabled(rdev) ? "enabled" : "disabled");

	rdev_dbg(rdev, "%s\n", buf);
}
#else /* !DEBUG && !CONFIG_DYNAMIC_DEBUG */
static inline void print_constraints_debug(struct regulator_dev *rdev) {}
#endif /* !DEBUG && !CONFIG_DYNAMIC_DEBUG */

static void print_constraints(struct regulator_dev *rdev)
{
	struct regulation_constraints *constraints = rdev->constraints;

	print_constraints_debug(rdev);

	if ((constraints->min_uV != constraints->max_uV) &&
	    !regulator_ops_is_valid(rdev, REGULATOR_CHANGE_VOLTAGE))
		rdev_warn(rdev,
			  "Voltage range but no REGULATOR_CHANGE_VOLTAGE\n");
}

static int machine_constraints_voltage(struct regulator_dev *rdev,
	struct regulation_constraints *constraints)
{
	const struct regulator_ops *ops = rdev->desc->ops;
	int ret;

	/* do we need to apply the constraint voltage */
	if (rdev->constraints->apply_uV &&
	    rdev->constraints->min_uV && rdev->constraints->max_uV) {
		int target_min, target_max;
		int current_uV = regulator_get_voltage_rdev(rdev);

		if (current_uV == -ENOTRECOVERABLE) {
			/* This regulator can't be read and must be initialized */
			rdev_info(rdev, "Setting %d-%duV\n",
				  rdev->constraints->min_uV,
				  rdev->constraints->max_uV);
			_regulator_do_set_voltage(rdev,
						  rdev->constraints->min_uV,
						  rdev->constraints->max_uV);
			current_uV = regulator_get_voltage_rdev(rdev);
		}

		if (current_uV < 0) {
			rdev_err(rdev,
				 "failed to get the current voltage: %pe\n",
				 ERR_PTR(current_uV));
			return current_uV;
		}

		/*
		 * If we're below the minimum voltage move up to the
		 * minimum voltage, if we're above the maximum voltage
		 * then move down to the maximum.
		 */
		target_min = current_uV;
		target_max = current_uV;

		if (current_uV < rdev->constraints->min_uV) {
			target_min = rdev->constraints->min_uV;
			target_max = rdev->constraints->min_uV;
		}

		if (current_uV > rdev->constraints->max_uV) {
			target_min = rdev->constraints->max_uV;
			target_max = rdev->constraints->max_uV;
		}

		if (target_min != current_uV || target_max != current_uV) {
			rdev_info(rdev, "Bringing %duV into %d-%duV\n",
				  current_uV, target_min, target_max);
			ret = _regulator_do_set_voltage(
				rdev, target_min, target_max);
			if (ret < 0) {
				rdev_err(rdev,
					"failed to apply %d-%duV constraint: %pe\n",
					target_min, target_max, ERR_PTR(ret));
				return ret;
			}
		}
	}

	/* constrain machine-level voltage specs to fit
	 * the actual range supported by this regulator.
	 */
	if (ops->list_voltage && rdev->desc->n_voltages) {
		int	count = rdev->desc->n_voltages;
		int	i;
		int	min_uV = INT_MAX;
		int	max_uV = INT_MIN;
		int	cmin = constraints->min_uV;
		int	cmax = constraints->max_uV;

		/* it's safe to autoconfigure fixed-voltage supplies
		   and the constraints are used by list_voltage. */
		if (count == 1 && !cmin) {
			cmin = 1;
			cmax = INT_MAX;
			constraints->min_uV = cmin;
			constraints->max_uV = cmax;
		}

		/* voltage constraints are optional */
		if ((cmin == 0) && (cmax == 0))
			return 0;

		/* else require explicit machine-level constraints */
		if (cmin <= 0 || cmax <= 0 || cmax < cmin) {
			rdev_err(rdev, "invalid voltage constraints\n");
			return -EINVAL;
		}

		/* no need to loop voltages if range is continuous */
		if (rdev->desc->continuous_voltage_range)
			return 0;

		/* initial: [cmin..cmax] valid, [min_uV..max_uV] not */
		for (i = 0; i < count; i++) {
			int	value;

			value = ops->list_voltage(rdev, i);
			if (value <= 0)
				continue;

			/* maybe adjust [min_uV..max_uV] */
			if (value >= cmin && value < min_uV)
				min_uV = value;
			if (value <= cmax && value > max_uV)
				max_uV = value;
		}

		/* final: [min_uV..max_uV] valid iff constraints valid */
		if (max_uV < min_uV) {
			rdev_err(rdev,
				 "unsupportable voltage constraints %u-%uuV\n",
				 min_uV, max_uV);
			return -EINVAL;
		}

		/* use regulator's subset of machine constraints */
		if (constraints->min_uV < min_uV) {
			rdev_dbg(rdev, "override min_uV, %d -> %d\n",
				 constraints->min_uV, min_uV);
			constraints->min_uV = min_uV;
		}
		if (constraints->max_uV > max_uV) {
			rdev_dbg(rdev, "override max_uV, %d -> %d\n",
				 constraints->max_uV, max_uV);
			constraints->max_uV = max_uV;
		}
	}

	return 0;
}

static int machine_constraints_current(struct regulator_dev *rdev,
	struct regulation_constraints *constraints)
{
	const struct regulator_ops *ops = rdev->desc->ops;
	int ret;

	if (!constraints->min_uA && !constraints->max_uA)
		return 0;

	if (constraints->min_uA > constraints->max_uA) {
		rdev_err(rdev, "Invalid current constraints\n");
		return -EINVAL;
	}

	if (!ops->set_current_limit || !ops->get_current_limit) {
		rdev_warn(rdev, "Operation of current configuration missing\n");
		return 0;
	}

	/* Set regulator current in constraints range */
	ret = ops->set_current_limit(rdev, constraints->min_uA,
			constraints->max_uA);
	if (ret < 0) {
		rdev_err(rdev, "Failed to set current constraint, %d\n", ret);
		return ret;
	}

	return 0;
}

static int _regulator_do_enable(struct regulator_dev *rdev);

/**
 * set_machine_constraints - sets regulator constraints
 * @rdev: regulator source
 *
 * Allows platform initialisation code to define and constrain
 * regulator circuits e.g. valid voltage/current ranges, etc.  NOTE:
 * Constraints *must* be set by platform code in order for some
 * regulator operations to proceed i.e. set_voltage, set_current_limit,
 * set_mode.
 */
static int set_machine_constraints(struct regulator_dev *rdev)
{
	int ret = 0;
	const struct regulator_ops *ops = rdev->desc->ops;

	ret = machine_constraints_voltage(rdev, rdev->constraints);
	if (ret != 0)
		return ret;

	ret = machine_constraints_current(rdev, rdev->constraints);
	if (ret != 0)
		return ret;

	if (rdev->constraints->ilim_uA && ops->set_input_current_limit) {
		ret = ops->set_input_current_limit(rdev,
						   rdev->constraints->ilim_uA);
		if (ret < 0) {
			rdev_err(rdev, "failed to set input limit: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	/* do we need to setup our suspend state */
	if (rdev->constraints->initial_state) {
		ret = suspend_set_initial_state(rdev);
		if (ret < 0) {
			rdev_err(rdev, "failed to set suspend state: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	if (rdev->constraints->initial_mode) {
		if (!ops->set_mode) {
			rdev_err(rdev, "no set_mode operation\n");
			return -EINVAL;
		}

		ret = ops->set_mode(rdev, rdev->constraints->initial_mode);
		if (ret < 0) {
			rdev_err(rdev, "failed to set initial mode: %pe\n", ERR_PTR(ret));
			return ret;
		}
	} else if (rdev->constraints->system_load) {
		/*
		 * We'll only apply the initial system load if an
		 * initial mode wasn't specified.
		 */
		drms_uA_update(rdev);
	}

	if ((rdev->constraints->ramp_delay || rdev->constraints->ramp_disable)
		&& ops->set_ramp_delay) {
		ret = ops->set_ramp_delay(rdev, rdev->constraints->ramp_delay);
		if (ret < 0) {
			rdev_err(rdev, "failed to set ramp_delay: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	if (rdev->constraints->pull_down && ops->set_pull_down) {
		ret = ops->set_pull_down(rdev);
		if (ret < 0) {
			rdev_err(rdev, "failed to set pull down: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	if (rdev->constraints->soft_start && ops->set_soft_start) {
		ret = ops->set_soft_start(rdev);
		if (ret < 0) {
			rdev_err(rdev, "failed to set soft start: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	if (rdev->constraints->over_current_protection
		&& ops->set_over_current_protection) {
		ret = ops->set_over_current_protection(rdev);
		if (ret < 0) {
			rdev_err(rdev, "failed to set over current protection: %pe\n",
				 ERR_PTR(ret));
			return ret;
		}
	}

	if (rdev->constraints->active_discharge && ops->set_active_discharge) {
		bool ad_state = (rdev->constraints->active_discharge ==
			      REGULATOR_ACTIVE_DISCHARGE_ENABLE) ? true : false;

		ret = ops->set_active_discharge(rdev, ad_state);
		if (ret < 0) {
			rdev_err(rdev, "failed to set active discharge: %pe\n", ERR_PTR(ret));
			return ret;
		}
	}

	/* If the constraints say the regulator should be on at this point
	 * and we have control then make sure it is enabled.
	 */
	if (rdev->constraints->always_on || rdev->constraints->boot_on) {
		/* If we want to enable this regulator, make sure that we know
		 * the supplying regulator.
		 */
		if (rdev->supply_name && !rdev->supply)
			return -EPROBE_DEFER;

		if (rdev->supply) {
			ret = regulator_enable(rdev->supply);
			if (ret < 0) {
				_regulator_put(rdev->supply);
				rdev->supply = NULL;
				return ret;
			}
		}

		ret = _regulator_do_enable(rdev);
		if (ret < 0 && ret != -EINVAL) {
			rdev_err(rdev, "failed to enable: %pe\n", ERR_PTR(ret));
			return ret;
		}

		if (rdev->constraints->always_on)
			rdev->use_count++;
	} else if (rdev->desc->off_on_delay) {
		rdev->last_off_jiffy = jiffies;
	}

	print_constraints(rdev);
	return 0;
}

/**
 * set_supply - set regulator supply regulator
 * @rdev: regulator name
 * @supply_rdev: supply regulator name
 *
 * Called by platform initialisation code to set the supply regulator for this
 * regulator. This ensures that a regulators supply will also be enabled by the
 * core if it's child is enabled.
 */
static int set_supply(struct regulator_dev *rdev,
		      struct regulator_dev *supply_rdev)
{
	int err;

	rdev_info(rdev, "supplied by %s\n", rdev_get_name(supply_rdev));

	if (!try_module_get(supply_rdev->owner))
		return -ENODEV;

	rdev->supply = create_regulator(supply_rdev, &rdev->dev, "SUPPLY");
	if (rdev->supply == NULL) {
		err = -ENOMEM;
		return err;
	}
	supply_rdev->open_count++;

	return 0;
}

/**
 * set_consumer_device_supply - Bind a regulator to a symbolic supply
 * @rdev:         regulator source
 * @consumer_dev_name: dev_name() string for device supply applies to
 * @supply:       symbolic name for supply
 *
 * Allows platform initialisation code to map physical regulator
 * sources to symbolic names for supplies for use by devices.  Devices
 * should use these symbolic names to request regulators, avoiding the
 * need to provide board-specific regulator names as platform data.
 */
static int set_consumer_device_supply(struct regulator_dev *rdev,
				      const char *consumer_dev_name,
				      const char *supply)
{
	struct regulator_map *node, *new_node;
	int has_dev;

	if (supply == NULL)
		return -EINVAL;

	if (consumer_dev_name != NULL)
		has_dev = 1;
	else
		has_dev = 0;

	new_node = kzalloc(sizeof(struct regulator_map), GFP_KERNEL);
	if (new_node == NULL)
		return -ENOMEM;

	new_node->regulator = rdev;
	new_node->supply = supply;

	if (has_dev) {
		new_node->dev_name = kstrdup(consumer_dev_name, GFP_KERNEL);
		if (new_node->dev_name == NULL) {
			kfree(new_node);
			return -ENOMEM;
		}
	}

	mutex_lock(&regulator_list_mutex);
	list_for_each_entry(node, &regulator_map_list, list) {
		if (node->dev_name && consumer_dev_name) {
			if (strcmp(node->dev_name, consumer_dev_name) != 0)
				continue;
		} else if (node->dev_name || consumer_dev_name) {
			continue;
		}

		if (strcmp(node->supply, supply) != 0)
			continue;

		pr_debug("%s: %s/%s is '%s' supply; fail %s/%s\n",
			 consumer_dev_name,
			 dev_name(&node->regulator->dev),
			 node->regulator->desc->name,
			 supply,
			 dev_name(&rdev->dev), rdev_get_name(rdev));
		goto fail;
	}

	list_add(&new_node->list, &regulator_map_list);
	mutex_unlock(&regulator_list_mutex);

	return 0;

fail:
	mutex_unlock(&regulator_list_mutex);
	kfree(new_node->dev_name);
	kfree(new_node);
	return -EBUSY;
}

static void unset_regulator_supplies(struct regulator_dev *rdev)
{
	struct regulator_map *node, *n;

	list_for_each_entry_safe(node, n, &regulator_map_list, list) {
		if (rdev == node->regulator) {
			list_del(&node->list);
			kfree(node->dev_name);
			kfree(node);
		}
	}
}

#ifdef CONFIG_DEBUG_FS
static ssize_t constraint_flags_read_file(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	const struct regulator *regulator = file->private_data;
	const struct regulation_constraints *c = regulator->rdev->constraints;
	char *buf;
	ssize_t ret;

	if (!c)
		return 0;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = snprintf(buf, PAGE_SIZE,
			"always_on: %u\n"
			"boot_on: %u\n"
			"apply_uV: %u\n"
			"ramp_disable: %u\n"
			"soft_start: %u\n"
			"pull_down: %u\n"
			"over_current_protection: %u\n",
			c->always_on,
			c->boot_on,
			c->apply_uV,
			c->ramp_disable,
			c->soft_start,
			c->pull_down,
			c->over_current_protection);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, ret);
	kfree(buf);

	return ret;
}

#endif

static const struct file_operations constraint_flags_fops = {
#ifdef CONFIG_DEBUG_FS
	.open = simple_open,
	.read = constraint_flags_read_file,
	.llseek = default_llseek,
#endif
};

#define REG_STR_SIZE	64

static struct regulator *create_regulator(struct regulator_dev *rdev,
					  struct device *dev,
					  const char *supply_name)
{
	struct regulator *regulator;
	int err = 0;

	if (dev) {
		char buf[REG_STR_SIZE];
		int size;

		size = snprintf(buf, REG_STR_SIZE, "%s-%s",
				dev->kobj.name, supply_name);
		if (size >= REG_STR_SIZE)
			return NULL;

		supply_name = kstrdup(buf, GFP_KERNEL);
		if (supply_name == NULL)
			return NULL;
	} else {
		supply_name = kstrdup_const(supply_name, GFP_KERNEL);
		if (supply_name == NULL)
			return NULL;
	}

	regulator = kzalloc(sizeof(*regulator), GFP_KERNEL);
	if (regulator == NULL) {
		kfree(supply_name);
		return NULL;
	}

	regulator->rdev = rdev;
	regulator->supply_name = supply_name;

	regulator_lock(rdev);
	list_add(&regulator->list, &rdev->consumer_list);
	regulator_unlock(rdev);

	if (dev) {
		regulator->dev = dev;

		/* Add a link to the device sysfs entry */
		err = sysfs_create_link_nowarn(&rdev->dev.kobj, &dev->kobj,
					       supply_name);
		if (err) {
			rdev_dbg(rdev, "could not add device link %s: %pe\n",
				  dev->kobj.name, ERR_PTR(err));
			/* non-fatal */
		}
	}

	if (err != -EEXIST)
		regulator->debugfs = debugfs_create_dir(supply_name, rdev->debugfs);
	if (!regulator->debugfs) {
		rdev_dbg(rdev, "Failed to create debugfs directory\n");
	} else {
		debugfs_create_u32("uA_load", 0444, regulator->debugfs,
				   &regulator->uA_load);
		debugfs_create_u32("min_uV", 0444, regulator->debugfs,
				   &regulator->voltage[PM_SUSPEND_ON].min_uV);
		debugfs_create_u32("max_uV", 0444, regulator->debugfs,
				   &regulator->voltage[PM_SUSPEND_ON].max_uV);
		debugfs_create_file("constraint_flags", 0444,
				    regulator->debugfs, regulator,
				    &constraint_flags_fops);
	}

	/*
	 * Check now if the regulator is an always on regulator - if
	 * it is then we don't need to do nearly so much work for
	 * enable/disable calls.
	 */
	if (!regulator_ops_is_valid(rdev, REGULATOR_CHANGE_STATUS) &&
	    _regulator_is_enabled(rdev))
		regulator->always_on = true;

	return regulator;
}

static int _regulator_get_enable_time(struct regulator_dev *rdev)
{
	if (rdev->constraints && rdev->constraints->enable_time)
		return rdev->constraints->enable_time;
	if (rdev->desc->ops->enable_time)
		return rdev->desc->ops->enable_time(rdev);
	return rdev->desc->enable_time;
}

static struct regulator_supply_alias *regulator_find_supply_alias(
		struct device *dev, const char *supply)
{
	struct regulator_supply_alias *map;

	list_for_each_entry(map, &regulator_supply_alias_list, list)
		if (map->src_dev == dev && strcmp(map->src_supply, supply) == 0)
			return map;

	return NULL;
}

static void regulator_supply_alias(struct device **dev, const char **supply)
{
	struct regulator_supply_alias *map;

	map = regulator_find_supply_alias(*dev, *supply);
	if (map) {
		dev_dbg(*dev, "Mapping supply %s to %s,%s\n",
				*supply, map->alias_supply,
				dev_name(map->alias_dev));
		*dev = map->alias_dev;
		*supply = map->alias_supply;
	}
}

static int regulator_match(struct device *dev, const void *data)
{
	struct regulator_dev *r = dev_to_rdev(dev);

	return strcmp(rdev_get_name(r), data) == 0;
}

static struct regulator_dev *regulator_lookup_by_name(const char *name)
{
	struct device *dev;

	dev = class_find_device(&regulator_class, NULL, name, regulator_match);

	return dev ? dev_to_rdev(dev) : NULL;
}

/**
 * regulator_dev_lookup - lookup a regulator device.
 * @dev: device for regulator "consumer".
 * @supply: Supply name or regulator ID.
 *
 * If successful, returns a struct regulator_dev that corresponds to the name
 * @supply and with the embedded struct device refcount incremented by one.
 * The refcount must be dropped by calling put_device().
 * On failure one of the following ERR-PTR-encoded values is returned:
 * -ENODEV if lookup fails permanently, -EPROBE_DEFER if lookup could succeed
 * in the future.
 */
static struct regulator_dev *regulator_dev_lookup(struct device *dev,
						  const char *supply)
{
	struct regulator_dev *r = NULL;
	struct device_node *node;
	struct regulator_map *map;
	const char *devname = NULL;

	regulator_supply_alias(&dev, &supply);

	/* first do a dt based lookup */
	if (dev && dev->of_node) {
		node = of_get_regulator(dev, supply);
		if (node) {
			r = of_find_regulator_by_node(node);
			if (r)
				return r;

			/*
			 * We have a node, but there is no device.
			 * assume it has not registered yet.
			 */
			return ERR_PTR(-EPROBE_DEFER);
		}
	}

	/* if not found, try doing it non-dt way */
	if (dev)
		devname = dev_name(dev);

	mutex_lock(&regulator_list_mutex);
	list_for_each_entry(map, &regulator_map_list, list) {
		/* If the mapping has a device set up it must match */
		if (map->dev_name &&
		    (!devname || strcmp(map->dev_name, devname)))
			continue;

		if (strcmp(map->supply, supply) == 0 &&
		    get_device(&map->regulator->dev)) {
			r = map->regulator;
			break;
		}
	}
	mutex_unlock(&regulator_list_mutex);

	if (r)
		return r;

	r = regulator_lookup_by_name(supply);
	if (r)
		return r;

	return ERR_PTR(-ENODEV);
}

static int regulator_resolve_supply(struct regulator_dev *rdev)
{
	struct regulator_dev *r;
	struct device *dev = rdev->dev.parent;
	int ret = 0;

	/* No supply to resolve? */
	if (!rdev->supply_name)
		return 0;

	/* Supply already resolved? (fast-path without locking contention) */
	if (rdev->supply)
		return 0;

	r = regulator_dev_lookup(dev, rdev->supply_name);
	if (IS_ERR(r)) {
		ret = PTR_ERR(r);

		/* Did the lookup explicitly defer for us? */
		if (ret == -EPROBE_DEFER)
			goto out;

		if (have_full_constraints()) {
			r = dummy_regulator_rdev;
			get_device(&r->dev);
		} else {
			dev_err(dev, "Failed to resolve %s-supply for %s\n",
				rdev->supply_name, rdev->desc->name);
			ret = -EPROBE_DEFER;
			goto out;
		}
	}

	if (r == rdev) {
		dev_err(dev, "Supply for %s (%s) resolved to itself\n",
			rdev->desc->name, rdev->supply_name);
		if (!have_full_constraints()) {
			ret = -EINVAL;
			goto out;
		}
		r = dummy_regulator_rdev;
		get_device(&r->dev);
	}

	/*
	 * If the supply's parent device is not the same as the
	 * regulator's parent device, then ensure the parent device
	 * is bound before we resolve the supply, in case the parent
	 * device get probe deferred and unregisters the supply.
	 */
	if (r->dev.parent && r->dev.parent != rdev->dev.parent) {
		if (!device_is_bound(r->dev.parent)) {
			put_device(&r->dev);
			ret = -EPROBE_DEFER;
			goto out;
		}
	}

	/* Recursively resolve the supply of the supply */
	ret = regulator_resolve_supply(r);
	if (ret < 0) {
		put_device(&r->dev);
		goto out;
	}

	/*
	 * Recheck rdev->supply with rdev->mutex lock held to avoid a race
	 * between rdev->supply null check and setting rdev->supply in
	 * set_supply() from concurrent tasks.
	 */
	regulator_lock(rdev);

	/* Supply just resolved by a concurrent task? */
	if (rdev->supply) {
		regulator_unlock(rdev);
		put_device(&r->dev);
		goto out;
	}

	ret = set_supply(rdev, r);
	if (ret < 0) {
		regulator_unlock(rdev);
		put_device(&r->dev);
		goto out;
	}

	regulator_unlock(rdev);

	/*
	 * In set_machine_constraints() we may have turned this regulator on
	 * but we couldn't propagate to the supply if it hadn't been resolved
	 * yet.  Do it now.
	 */
	if (rdev->use_count) {
		ret = regulator_enable(rdev->supply);
		if (ret < 0) {
			_regulator_put(rdev->supply);
			rdev->supply = NULL;
			goto out;
		}
	}

out:
	return ret;
}

/* Internal regulator request function */
struct regulator *_regulator_get(struct device *dev, const char *id,
				 enum regulator_get_type get_type)
{
	struct regulator_dev *rdev;
	struct regulator *regulator;
	struct device_link *link;
	int ret;

	if (get_type >= MAX_GET_TYPE) {
		dev_err(dev, "invalid type %d in %s\n", get_type, __func__);
		return ERR_PTR(-EINVAL);
	}

	if (id == NULL) {
		pr_err("get() with no identifier\n");
		return ERR_PTR(-EINVAL);
	}

	rdev = regulator_dev_lookup(dev, id);
	if (IS_ERR(rdev)) {
		ret = PTR_ERR(rdev);

		/*
		 * If regulator_dev_lookup() fails with error other
		 * than -ENODEV our job here is done, we simply return it.
		 */
		if (ret != -ENODEV)
			return ERR_PTR(ret);

		if (!have_full_constraints()) {
			dev_warn(dev,
				 "incomplete constraints, dummy supplies not allowed\n");
			return ERR_PTR(-ENODEV);
		}

		switch (get_type) {
		case NORMAL_GET:
			/*
			 * Assume that a regulator is physically present and
			 * enabled, even if it isn't hooked up, and just
			 * provide a dummy.
			 */
			dev_warn(dev, "supply %s not found, using dummy regulator\n", id);
			rdev = dummy_regulator_rdev;
			get_device(&rdev->dev);
			break;

		case EXCLUSIVE_GET:
			dev_warn(dev,
				 "dummy supplies not allowed for exclusive requests\n");
			fallthrough;

		default:
			return ERR_PTR(-ENODEV);
		}

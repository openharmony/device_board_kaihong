// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux I2C core
 *
 * Copyright (C) 1995-99 Simon G. Vogl
 *   With some changes from Kyösti Mälkki <kmalkki@cc.hut.fi>
 *   Mux support by Rodolfo Giometti <giometti@enneenne.com> and
 *   Michael Lawnick <michael.lawnick.ext@nsn.com>
 *
 * Copyright (C) 2013-2017 Wolfram Sang <wsa@kernel.org>
 */

#define pr_fmt(fmt) "i2c-core: " fmt

#include <dt-bindings/i2c/i2c.h>
#include <linux/acpi.h>
#include <linux/clk/clk-conf.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/i2c-smbus.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqflags.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/pm_wakeirq.h>
#include <linux/property.h>
#include <linux/rwsem.h>
#include <linux/slab.h>

#include "i2c-core.h"

#define CREATE_TRACE_POINTS
#include <trace/events/i2c.h>

#define I2C_ADDR_OFFSET_TEN_BIT	0xa000
#define I2C_ADDR_OFFSET_SLAVE	0x1000

#define I2C_ADDR_7BITS_MAX	0x77
#define I2C_ADDR_7BITS_COUNT	(I2C_ADDR_7BITS_MAX + 1)

#define I2C_ADDR_DEVICE_ID	0x7c

/*
 * core_lock protects i2c_adapter_idr, and guarantees that device detection,
 * deletion of detected devices are serialized
 */
static DEFINE_MUTEX(core_lock);
static DEFINE_IDR(i2c_adapter_idr);

static int i2c_check_addr_ex(struct i2c_adapter *adapter, int addr);
static int i2c_detect(struct i2c_adapter *adapter, struct i2c_driver *driver);

static DEFINE_STATIC_KEY_FALSE(i2c_trace_msg_key);
static bool is_registered;

int i2c_transfer_trace_reg(void)
{
	static_branch_inc(&i2c_trace_msg_key);
	return 0;
}

void i2c_transfer_trace_unreg(void)
{
	static_branch_dec(&i2c_trace_msg_key);
}

const struct i2c_device_id *i2c_match_id(const struct i2c_device_id *id,
						const struct i2c_client *client)
{
	if (!(id && client))
		return NULL;

	while (id->name[0]) {
		if (strcmp(client->name, id->name) == 0)
			return id;
		id++;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(i2c_match_id);

static int i2c_device_match(struct device *dev, struct device_driver *drv)
{
	struct i2c_client	*client = i2c_verify_client(dev);
	struct i2c_driver	*driver;


	/* Attempt an OF style match */
	if (i2c_of_match_device(drv->of_match_table, client))
		return 1;

	/* Then ACPI style match */
	if (acpi_driver_match_device(dev, drv))
		return 1;

	driver = to_i2c_driver(drv);

	/* Finally an I2C match */
	if (i2c_match_id(driver->id_table, client))
		return 1;

	return 0;
}

static int i2c_device_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct i2c_client *client = to_i2c_client(dev);
	int rc;

	rc = of_device_uevent_modalias(dev, env);
	if (rc != -ENODEV)
		return rc;

	rc = acpi_device_uevent_modalias(dev, env);
	if (rc != -ENODEV)
		return rc;

	return add_uevent_var(env, "MODALIAS=%s%s", I2C_MODULE_PREFIX, client->name);
}

/* i2c bus recovery routines */
static int get_scl_gpio_value(struct i2c_adapter *adap)
{
	return gpiod_get_value_cansleep(adap->bus_recovery_info->scl_gpiod);
}

static void set_scl_gpio_value(struct i2c_adapter *adap, int val)
{
	gpiod_set_value_cansleep(adap->bus_recovery_info->scl_gpiod, val);
}

static int get_sda_gpio_value(struct i2c_adapter *adap)
{
	return gpiod_get_value_cansleep(adap->bus_recovery_info->sda_gpiod);
}

static void set_sda_gpio_value(struct i2c_adapter *adap, int val)
{
	gpiod_set_value_cansleep(adap->bus_recovery_info->sda_gpiod, val);
}

static int i2c_generic_bus_free(struct i2c_adapter *adap)
{
	struct i2c_bus_recovery_info *bri = adap->bus_recovery_info;
	int ret = -EOPNOTSUPP;

	if (bri->get_bus_free)
		ret = bri->get_bus_free(adap);
	else if (bri->get_sda)
		ret = bri->get_sda(adap);

	if (ret < 0)
		return ret;

	return ret ? 0 : -EBUSY;
}

/*
 * We are generating clock pulses. ndelay() determines durating of clk pulses.
 * We will generate clock with rate 100 KHz and so duration of both clock levels
 * is: delay in ns = (10^6 / 100) / 2
 */
#define RECOVERY_NDELAY		5000
#define RECOVERY_CLK_CNT	9

int i2c_generic_scl_recovery(struct i2c_adapter *adap)
{
	struct i2c_bus_recovery_info *bri = adap->bus_recovery_info;
	int i = 0, scl = 1, ret = 0;

	if (bri->prepare_recovery)
		bri->prepare_recovery(adap);
	if (bri->pinctrl)
		pinctrl_select_state(bri->pinctrl, bri->pins_gpio);

	/*
	 * If we can set SDA, we will always create a STOP to ensure additional
	 * pulses will do no harm. This is achieved by letting SDA follow SCL
	 * half a cycle later. Check the 'incomplete_write_byte' fault injector
	 * for details. Note that we must honour tsu:sto, 4us, but lets use 5us
	 * here for simplicity.
	 */
	bri->set_scl(adap, scl);
	ndelay(RECOVERY_NDELAY);
	if (bri->set_sda)
		bri->set_sda(adap, scl);
	ndelay(RECOVERY_NDELAY / 2);

	/*
	 * By this time SCL is high, as we need to give 9 falling-rising edges
	 */
	while (i++ < RECOVERY_CLK_CNT * 2) {
		if (scl) {
			/* SCL shouldn't be low here */
			if (!bri->get_scl(adap)) {
				dev_err(&adap->dev,
					"SCL is stuck low, exit recovery\n");
				ret = -EBUSY;
				break;
			}
		}

		scl = !scl;
		bri->set_scl(adap, scl);
		/* Creating STOP again, see above */
		if (scl)  {
			/* Honour minimum tsu:sto */
			ndelay(RECOVERY_NDELAY);
		} else {
			/* Honour minimum tf and thd:dat */
			ndelay(RECOVERY_NDELAY / 2);
		}
		if (bri->set_sda)
			bri->set_sda(adap, scl);
		ndelay(RECOVERY_NDELAY / 2);

		if (scl) {
			ret = i2c_generic_bus_free(adap);
			if (ret == 0)
				break;
		}
	}

	/* If we can't check bus status, assume recovery worked */
	if (ret == -EOPNOTSUPP)
		ret = 0;

	if (bri->unprepare_recovery)
		bri->unprepare_recovery(adap);
	if (bri->pinctrl)
		pinctrl_select_state(bri->pinctrl, bri->pins_default);

	return ret;
}
EXPORT_SYMBOL_GPL(i2c_generic_scl_recovery);

int i2c_recover_bus(struct i2c_adapter *adap)
{
	if (!adap->bus_recovery_info)
		return -EOPNOTSUPP;

	dev_dbg(&adap->dev, "Trying i2c bus recovery\n");
	return adap->bus_recovery_info->recover_bus(adap);
}
EXPORT_SYMBOL_GPL(i2c_recover_bus);

static void i2c_gpio_init_pinctrl_recovery(struct i2c_adapter *adap)
{
	struct i2c_bus_recovery_info *bri = adap->bus_recovery_info;
	struct device *dev = &adap->dev;
	struct pinctrl *p = bri->pinctrl;

	/*
	 * we can't change states without pinctrl, so remove the states if
	 * populated
	 */
	if (!p) {
		bri->pins_default = NULL;
		bri->pins_gpio = NULL;
		return;
	}

	if (!bri->pins_default) {
		bri->pins_default = pinctrl_lookup_state(p,
							 PINCTRL_STATE_DEFAULT);
		if (IS_ERR(bri->pins_default)) {
			dev_dbg(dev, PINCTRL_STATE_DEFAULT " state not found for GPIO recovery\n");
			bri->pins_default = NULL;
		}
	}
	if (!bri->pins_gpio) {
		bri->pins_gpio = pinctrl_lookup_state(p, "gpio");
		if (IS_ERR(bri->pins_gpio))
			bri->pins_gpio = pinctrl_lookup_state(p, "recovery");

		if (IS_ERR(bri->pins_gpio)) {
			dev_dbg(dev, "no gpio or recovery state found for GPIO recovery\n");
			bri->pins_gpio = NULL;
		}
	}

	/* for pinctrl state changes, we need all the information */
	if (bri->pins_default && bri->pins_gpio) {
		dev_info(dev, "using pinctrl states for GPIO recovery");
	} else {
		bri->pinctrl = NULL;
		bri->pins_default = NULL;
		bri->pins_gpio = NULL;
	}
}

static int i2c_gpio_init_generic_recovery(struct i2c_adapter *adap)
{
	struct i2c_bus_recovery_info *bri = adap->bus_recovery_info;
	struct device *dev = &adap->dev;
	struct gpio_desc *gpiod;
	int ret = 0;

	/*
	 * don't touch the recovery information if the driver is not using
	 * generic SCL recovery
	 */
	if (bri->recover_bus && bri->recover_bus != i2c_generic_scl_recovery)
		return 0;

	/*
	 * pins might be taken as GPIO, so we should inform pinctrl about
	 * this and move the state to GPIO
	 */
	if (bri->pinctrl)
		pinctrl_select_state(bri->pinctrl, bri->pins_gpio);

	/*
	 * if there is incomplete or no recovery information, see if generic
	 * GPIO recovery is available
	 */
	if (!bri->scl_gpiod) {
		gpiod = devm_gpiod_get(dev, "scl", GPIOD_OUT_HIGH_OPEN_DRAIN);
		if (PTR_ERR(gpiod) == -EPROBE_DEFER) {
			ret  = -EPROBE_DEFER;
			goto cleanup_pinctrl_state;
		}
		if (!IS_ERR(gpiod)) {
			bri->scl_gpiod = gpiod;
			bri->recover_bus = i2c_generic_scl_recovery;
			dev_info(dev, "using generic GPIOs for recovery\n");
		}
	}

	/* SDA GPIOD line is optional, so we care about DEFER only */
	if (!bri->sda_gpiod) {
		/*
		 * We have SCL. Pull SCL low and wait a bit so that SDA glitches
		 * have no effect.
		 */
		gpiod_direction_output(bri->scl_gpiod, 0);
		udelay(10);
		gpiod = devm_gpiod_get(dev, "sda", GPIOD_IN);

		/* Wait a bit in case of a SDA glitch, and then release SCL. */
		udelay(10);
		gpiod_direction_output(bri->scl_gpiod, 1);

		if (PTR_ERR(gpiod) == -EPROBE_DEFER) {
			ret = -EPROBE_DEFER;
			goto cleanup_pinctrl_state;
		}
		if (!IS_ERR(gpiod))
			bri->sda_gpiod = gpiod;
	}

cleanup_pinctrl_state:
	/* change the state of the pins back to their default state */
	if (bri->pinctrl)
		pinctrl_select_state(bri->pinctrl, bri->pins_default);

	return ret;
}

static int i2c_gpio_init_recovery(struct i2c_adapter *adap)
{
	i2c_gpio_init_pinctrl_recovery(adap);
	return i2c_gpio_init_generic_recovery(adap);
}

static int i2c_init_recovery(struct i2c_adapter *adap)
{
	struct i2c_bus_recovery_info *bri = adap->bus_recovery_info;
	char *err_str, *err_level = KERN_ERR;

	if (!bri)
		return 0;

	if (i2c_gpio_init_recovery(adap) == -EPROBE_DEFER)
		return -EPROBE_DEFER;

	if (!bri->recover_bus) {
		err_str = "no suitable method provided";
		err_level = KERN_DEBUG;
		goto err;
	}

	if (bri->scl_gpiod && bri->recover_bus == i2c_generic_scl_recovery) {
		bri->get_scl = get_scl_gpio_value;
		bri->set_scl = set_scl_gpio_value;
		if (bri->sda_gpiod) {
			bri->get_sda = get_sda_gpio_value;
			/* FIXME: add proper flag instead of '0' once available */
			if (gpiod_get_direction(bri->sda_gpiod) == 0)
				bri->set_sda = set_sda_gpio_value;
		}
	} else if (bri->recover_bus == i2c_generic_scl_recovery) {
		/* Generic SCL recovery */
		if (!bri->set_scl || !bri->get_scl) {
			err_str = "no {get|set}_scl() found";
			goto err;

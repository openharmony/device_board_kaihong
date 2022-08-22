// SPDX-License-Identifier: GPL-2.0-only
/*
 * Rockchip Generic power domain support.
 *
 * Copyright (c) 2015 ROCKCHIP, Co. Ltd.
 */

#include <linux/module.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/err.h>
#include <linux/pm_clock.h>
#include <linux/pm_domain.h>
#include <linux/of_address.h>
#include <linux/of_clk.h>
#include <linux/of_platform.h>
#include <linux/clk.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/mfd/syscon.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <soc/rockchip/pm_domains.h>
#include <soc/rockchip/rockchip_dmc.h>
#include <dt-bindings/power/px30-power.h>
#include <dt-bindings/power/rv1126-power.h>
#include <dt-bindings/power/rk1808-power.h>
#include <dt-bindings/power/rk3036-power.h>
#include <dt-bindings/power/rk3066-power.h>
#include <dt-bindings/power/rk3128-power.h>
#include <dt-bindings/power/rk3188-power.h>
#include <dt-bindings/power/rk3228-power.h>
#include <dt-bindings/power/rk3288-power.h>
#include <dt-bindings/power/rk3328-power.h>
#include <dt-bindings/power/rk3366-power.h>
#include <dt-bindings/power/rk3368-power.h>
#include <dt-bindings/power/rk3399-power.h>
#include <dt-bindings/power/rk3568-power.h>
#include <dt-bindings/power/rk3588-power.h>

struct rockchip_domain_info {
	const char *name;
	int pwr_mask;
	int status_mask;
	int req_mask;
	int idle_mask;
	int ack_mask;
	bool active_wakeup;
	int pwr_w_mask;
	int req_w_mask;
	int repair_status_mask;
	bool keepon_startup;
	u32 pwr_offset;
	u32 req_offset;
};

struct rockchip_pmu_info {
	u32 pwr_offset;
	u32 status_offset;
	u32 req_offset;
	u32 idle_offset;
	u32 ack_offset;
	u32 repair_status_offset;

	u32 core_pwrcnt_offset;
	u32 gpu_pwrcnt_offset;

	unsigned int core_power_transition_time;
	unsigned int gpu_power_transition_time;

	int num_domains;
	const struct rockchip_domain_info *domain_info;
};

#define MAX_QOS_REGS_NUM	5
#define QOS_PRIORITY		0x08
#define QOS_MODE		0x0c
#define QOS_BANDWIDTH		0x10
#define QOS_SATURATION		0x14
#define QOS_EXTCONTROL		0x18

struct rockchip_pm_domain {
	struct generic_pm_domain genpd;
	const struct rockchip_domain_info *info;
	struct rockchip_pmu *pmu;
	int num_qos;
	struct regmap **qos_regmap;
	u32 *qos_save_regs[MAX_QOS_REGS_NUM];
	int num_clks;
	struct clk_bulk_data *clks;
	bool is_ignore_pwr;
	bool is_qos_saved;
	struct regulator *supply;
};

struct rockchip_pmu {
	struct device *dev;
	struct regmap *regmap;
	const struct rockchip_pmu_info *info;
	struct mutex mutex; /* mutex lock for pmu */
	struct genpd_onecell_data genpd_data;
	struct generic_pm_domain *domains[];
};

static struct rockchip_pmu *g_pmu;
static bool pm_domain_always_on;

module_param_named(always_on, pm_domain_always_on, bool, 0644);
MODULE_PARM_DESC(always_on,
		 "Always keep pm domains power on except for system suspend.");

static void rockchip_pmu_lock(struct rockchip_pm_domain *pd)
{
	mutex_lock(&pd->pmu->mutex);
	rockchip_dmcfreq_lock_nested();
}

static void rockchip_pmu_unlock(struct rockchip_pm_domain *pd)
{
	rockchip_dmcfreq_unlock();
	mutex_unlock(&pd->pmu->mutex);
}

#define to_rockchip_pd(gpd) container_of(gpd, struct rockchip_pm_domain, genpd)

#define DOMAIN(_name, pwr, status, req, idle, ack, wakeup, keepon)	\
{							\
	.name = _name,					\
	.pwr_mask = (pwr),				\
	.status_mask = (status),			\
	.req_mask = (req),				\
	.idle_mask = (idle),				\
	.ack_mask = (ack),				\
	.active_wakeup = (wakeup),			\
	.keepon_startup = (keepon),			\
}

#define DOMAIN_M(_name, pwr, status, req, idle, ack, wakeup, keepon)	\
{							\
	.name = _name,					\
	.pwr_w_mask = (pwr) << 16,			\
	.pwr_mask = (pwr),				\
	.status_mask = (status),			\
	.req_w_mask = (req) << 16,			\
	.req_mask = (req),				\
	.idle_mask = (idle),				\
	.ack_mask = (ack),				\
	.active_wakeup = wakeup,			\
	.keepon_startup = keepon,			\
}

#define DOMAIN_M_O(_name, pwr, status, p_offset, req, idle, ack, r_offset, wakeup, keepon)	\
{							\
	.name = _name,					\
	.pwr_w_mask = (pwr) << 16,			\
	.pwr_mask = (pwr),				\
	.status_mask = (status),			\
	.req_w_mask = (req) << 16,			\
	.req_mask = (req),				\
	.idle_mask = (idle),				\
	.ack_mask = (ack),				\
	.active_wakeup = wakeup,			\
	.keepon_startup = keepon,			\
	.pwr_offset = p_offset,				\
	.req_offset = r_offset,				\
}

#define DOMAIN_M_O_R(_name, p_offset, pwr, status, r_status, r_offset, req, idle, ack, wakeup, keepon)	\
{							\
	.name = _name,					\
	.pwr_offset = p_offset,				\
	.pwr_w_mask = (pwr) << 16,			\
	.pwr_mask = (pwr),				\
	.status_mask = (status),			\
	.repair_status_mask = (r_status),		\
	.req_offset = r_offset,				\
	.req_w_mask = (req) << 16,			\
	.req_mask = (req),				\
	.idle_mask = (idle),				\
	.ack_mask = (ack),				\
	.active_wakeup = wakeup,			\
	.keepon_startup = keepon,			\
}

#define DOMAIN_RK3036(_name, req, ack, idle, wakeup)	\
{							\
	.name = _name,					\
	.req_mask = (req),				\
	.req_w_mask = (req) << 16,			\
	.ack_mask = (ack),				\
	.idle_mask = (idle),				\
	.active_wakeup = wakeup,			\
}

#define DOMAIN_PX30(name, pwr, status, req, wakeup)		\
	DOMAIN_M(name, pwr, status, req, (req) << 16, req, wakeup, false)

#define DOMAIN_PX30_PROTECT(name, pwr, status, req, wakeup)	\
	DOMAIN_M(name, pwr, status, req, (req) << 16, req, wakeup, true)

#define DOMAIN_RV1126(name, pwr, req, idle, wakeup)		\
	DOMAIN_M(name, pwr, pwr, req, idle, idle, wakeup, false)

#define DOMAIN_RV1126_PROTECT(name, pwr, req, idle, wakeup)	\
	DOMAIN_M(name, pwr, pwr, req, idle, idle, wakeup, true)

#define DOMAIN_RV1126_O(name, pwr, req, idle, r_offset, wakeup)	\
	DOMAIN_M_O(name, pwr, pwr, 0, req, idle, idle, r_offset, wakeup, false)

#define DOMAIN_RK3288(name, pwr, status, req, wakeup)		\
	DOMAIN(name, pwr, status, req, req, (req) << 16, wakeup, false)

#define DOMAIN_RK3288_PROTECT(name, pwr, status, req, wakeup)	\
	DOMAIN(name, pwr, status, req, req, (req) << 16, wakeup, true)

#define DOMAIN_RK3328(name, pwr, status, req, wakeup)		\
	DOMAIN_M(name, pwr, pwr, req, (req) << 10, req, wakeup, false)

#define DOMAIN_RK3368(name, pwr, status, req, wakeup)		\
	DOMAIN(name, pwr, status, req, (req) << 16, req, wakeup, false)

#define DOMAIN_RK3368_PROTECT(name, pwr, status, req, wakeup)	\
	DOMAIN(name, pwr, status, req, (req) << 16, req, wakeup, true)

#define DOMAIN_RK3399(name, pwr, status, req, wakeup)		\
	DOMAIN(name, pwr, status, req, req, req, wakeup, false)

#define DOMAIN_RK3399_PROTECT(name, pwr, status, req, wakeup)	\
	DOMAIN(name, pwr, status, req, req, req, wakeup, true)

#define DOMAIN_RK3568(name, pwr, req, wakeup)			\
	DOMAIN_M(name, pwr, pwr, req, req, req, wakeup, false)

#define DOMAIN_RK3568_PROTECT(name, pwr, req, wakeup)		\
	DOMAIN_M(name, pwr, pwr, req, req, req, wakeup, true)

#define DOMAIN_RK3588(name, p_offset, pwr, status, r_status, r_offset, req, idle, wakeup)	\
	DOMAIN_M_O_R(name, p_offset, pwr, status, r_status, r_offset, req, idle, idle, wakeup, false)

#define DOMAIN_RK3588_P(name, p_offset, pwr, status, r_status, r_offset, req, idle, wakeup)	\
	DOMAIN_M_O_R(name, p_offset, pwr, status, r_status, r_offset, req, idle, idle, wakeup, true)

static bool rockchip_pmu_domain_is_idle(struct rockchip_pm_domain *pd)
{
	struct rockchip_pmu *pmu = pd->pmu;
	const struct rockchip_domain_info *pd_info = pd->info;
	unsigned int val;

	regmap_read(pmu->regmap, pmu->info->idle_offset, &val);
	return (val & pd_info->idle_mask) == pd_info->idle_mask;
}

static unsigned int rockchip_pmu_read_ack(struct rockchip_pmu *pmu)
{
	unsigned int val;

	regmap_read(pmu->regmap, pmu->info->ack_offset, &val);
	return val;
}

static int rockchip_pmu_set_idle_request(struct rockchip_pm_domain *pd,
					 bool idle)
{
	const struct rockchip_domain_info *pd_info = pd->info;
	struct generic_pm_domain *genpd = &pd->genpd;
	struct rockchip_pmu *pmu = pd->pmu;
	u32 pd_req_offset = 0;
	unsigned int target_ack;
	unsigned int val;
	bool is_idle;
	int ret = 0;

	if (pd_info->req_offset)
		pd_req_offset = pd_info->req_offset;

	if (pd_info->req_mask == 0)
		return 0;
	else if (pd_info->req_w_mask)
		regmap_write(pmu->regmap, pmu->info->req_offset + pd_req_offset,
			     idle ? (pd_info->req_mask | pd_info->req_w_mask) :
			     pd_info->req_w_mask);
	else
		regmap_update_bits(pmu->regmap, pmu->info->req_offset +
				   pd_req_offset, pd_info->req_mask,
				   idle ? -1U : 0);

	dsb(sy);

	/* Wait util idle_ack = 1 */
	target_ack = idle ? pd_info->ack_mask : 0;
	ret = readx_poll_timeout_atomic(rockchip_pmu_read_ack, pmu, val,
					(val & pd_info->ack_mask) == target_ack,
					0, 10000);
	if (ret) {
		dev_err(pmu->dev,
			"failed to get ack on domain '%s', target_idle = %d, target_ack = %d, val=0x%x\n",
			genpd->name, idle, target_ack, val);
		goto error;
	}

	ret = readx_poll_timeout_atomic(rockchip_pmu_domain_is_idle, pd,
					is_idle, is_idle == idle, 0, 10000);
	if (ret) {
		dev_err(pmu->dev,
			"failed to set idle on domain '%s',  target_idle = %d, val=%d\n",
			genpd->name, idle, is_idle);
		goto error;
	}

	return ret;
error:
	panic("panic_on_set_idle set ...\n");
	return ret;
}

int rockchip_pmu_idle_request(struct device *dev, bool idle)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;
	int ret;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;

	if (IS_ERR_OR_NULL(dev->pm_domain))
		return -EINVAL;

	genpd = pd_to_genpd(dev->pm_domain);
	pd = to_rockchip_pd(genpd);

	rockchip_pmu_lock(pd);
	ret = rockchip_pmu_set_idle_request(pd, idle);
	rockchip_pmu_unlock(pd);

	return ret;
}
EXPORT_SYMBOL(rockchip_pmu_idle_request);

static int rockchip_pmu_save_qos(struct rockchip_pm_domain *pd)
{
	int i;

	for (i = 0; i < pd->num_qos; i++) {
		regmap_read(pd->qos_regmap[i],
			    QOS_PRIORITY,
			    &pd->qos_save_regs[0][i]);
		regmap_read(pd->qos_regmap[i],
			    QOS_MODE,
			    &pd->qos_save_regs[1][i]);
		regmap_read(pd->qos_regmap[i],
			    QOS_BANDWIDTH,
			    &pd->qos_save_regs[2][i]);
		regmap_read(pd->qos_regmap[i],
			    QOS_SATURATION,
			    &pd->qos_save_regs[3][i]);
		regmap_read(pd->qos_regmap[i],
			    QOS_EXTCONTROL,
			    &pd->qos_save_regs[4][i]);
	}
	return 0;
}

static int rockchip_pmu_restore_qos(struct rockchip_pm_domain *pd)
{
	int i;

	for (i = 0; i < pd->num_qos; i++) {
		regmap_write(pd->qos_regmap[i],
			     QOS_PRIORITY,
			     pd->qos_save_regs[0][i]);
		regmap_write(pd->qos_regmap[i],
			     QOS_MODE,
			     pd->qos_save_regs[1][i]);
		regmap_write(pd->qos_regmap[i],
			     QOS_BANDWIDTH,
			     pd->qos_save_regs[2][i]);
		regmap_write(pd->qos_regmap[i],
			     QOS_SATURATION,
			     pd->qos_save_regs[3][i]);
		regmap_write(pd->qos_regmap[i],
			     QOS_EXTCONTROL,
			     pd->qos_save_regs[4][i]);
	}

	return 0;
}

int rockchip_save_qos(struct device *dev)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;
	int ret;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;

	if (IS_ERR_OR_NULL(dev->pm_domain))
		return -EINVAL;

	genpd = pd_to_genpd(dev->pm_domain);
	pd = to_rockchip_pd(genpd);

	rockchip_pmu_lock(pd);
	ret = rockchip_pmu_save_qos(pd);
	rockchip_pmu_unlock(pd);

	return ret;
}
EXPORT_SYMBOL(rockchip_save_qos);

int rockchip_restore_qos(struct device *dev)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;
	int ret;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;

	if (IS_ERR_OR_NULL(dev->pm_domain))
		return -EINVAL;

	genpd = pd_to_genpd(dev->pm_domain);
	pd = to_rockchip_pd(genpd);

	rockchip_pmu_lock(pd);
	ret = rockchip_pmu_restore_qos(pd);
	rockchip_pmu_unlock(pd);

	return ret;
}
EXPORT_SYMBOL(rockchip_restore_qos);

static bool rockchip_pmu_domain_is_on(struct rockchip_pm_domain *pd)
{
	struct rockchip_pmu *pmu = pd->pmu;
	unsigned int val;

	if (pd->info->repair_status_mask) {
		regmap_read(pmu->regmap, pmu->info->repair_status_offset, &val);
		/* 1'b1: power on, 1'b0: power off */
		return val & pd->info->repair_status_mask;
	}

	/* check idle status for idle-only domains */
	if (pd->info->status_mask == 0)
		return !rockchip_pmu_domain_is_idle(pd);

	regmap_read(pmu->regmap, pmu->info->status_offset, &val);

	/* 1'b0: power on, 1'b1: power off */
	return !(val & pd->info->status_mask);
}

static int rockchip_do_pmu_set_power_domain(struct rockchip_pm_domain *pd,
					    bool on)
{
	struct rockchip_pmu *pmu = pd->pmu;
	struct generic_pm_domain *genpd = &pd->genpd;
	u32 pd_pwr_offset = 0;
	bool is_on;
	int ret = 0;

	if (pd->info->pwr_offset)
		pd_pwr_offset = pd->info->pwr_offset;

	if (pd->info->pwr_mask == 0)
		return 0;
	else if (pd->info->pwr_w_mask)
		regmap_write(pmu->regmap, pmu->info->pwr_offset + pd_pwr_offset,
			     on ? pd->info->pwr_w_mask :
			     (pd->info->pwr_mask | pd->info->pwr_w_mask));
	else
		regmap_update_bits(pmu->regmap, pmu->info->pwr_offset +
				   pd_pwr_offset, pd->info->pwr_mask,
				   on ? 0 : -1U);

	dsb(sy);

	ret = readx_poll_timeout_atomic(rockchip_pmu_domain_is_on, pd, is_on,
					is_on == on, 0, 10000);
	if (ret) {
		dev_err(pmu->dev,
			"failed to set domain '%s', target_on= %d, val=%d\n",
			genpd->name, on, is_on);
			goto error;
	}
	return ret;

error:
	panic("panic_on_set_domain set ...\n");
	return ret;
}

static int rockchip_pd_power(struct rockchip_pm_domain *pd, bool power_on)
{
	struct rockchip_pmu *pmu = pd->pmu;
	int ret = 0;
	struct generic_pm_domain *genpd = &pd->genpd;

	if (pm_domain_always_on && !power_on)
		return 0;

	rockchip_pmu_lock(pd);

	if (rockchip_pmu_domain_is_on(pd) != power_on) {
		if (IS_ERR_OR_NULL(pd->supply) &&
		    PTR_ERR(pd->supply) != -ENODEV)
			pd->supply = devm_regulator_get_optional(pd->pmu->dev,
								 genpd->name);

		if (power_on && !IS_ERR(pd->supply)) {
			ret = regulator_enable(pd->supply);
			if (ret < 0) {
				dev_err(pd->pmu->dev, "failed to set vdd supply enable '%s',\n",
					genpd->name);
				rockchip_pmu_unlock(pd);
				return ret;
			}
		}

		ret = clk_bulk_enable(pd->num_clks, pd->clks);
		if (ret < 0) {
			dev_err(pmu->dev, "failed to enable clocks\n");
			rockchip_pmu_unlock(pd);
			return ret;
		}

		if (!power_on) {
			rockchip_pmu_save_qos(pd);
			pd->is_qos_saved = true;

			/* if powering down, idle request to NIU first */
			ret = rockchip_pmu_set_idle_request(pd, true);
			if (ret) {
				dev_err(pd->pmu->dev, "failed to set idle request '%s',\n",
					genpd->name);
				goto out;
			}
		}

		ret = rockchip_do_pmu_set_power_domain(pd, power_on);
		if (ret) {
			dev_err(pd->pmu->dev, "failed to set power '%s' = %d,\n",
				genpd->name, power_on);
			goto out;
		}

		if (power_on) {
			/* if powering up, leave idle mode */
			ret = rockchip_pmu_set_idle_request(pd, false);
			if (ret) {
				dev_err(pd->pmu->dev, "failed to set deidle request '%s',\n",
					genpd->name);
				goto out;
			}

			if (pd->is_qos_saved)
				rockchip_pmu_restore_qos(pd);
		}

out:
		clk_bulk_disable(pd->num_clks, pd->clks);

		if (!power_on && !IS_ERR(pd->supply))
			ret = regulator_disable(pd->supply);
	}

	rockchip_pmu_unlock(pd);
	return ret;
}

static int rockchip_pd_power_on(struct generic_pm_domain *domain)
{
	struct rockchip_pm_domain *pd = to_rockchip_pd(domain);

	if (pd->is_ignore_pwr)
		return 0;

	return rockchip_pd_power(pd, true);
}

static int rockchip_pd_power_off(struct generic_pm_domain *domain)
{
	struct rockchip_pm_domain *pd = to_rockchip_pd(domain);

	if (pd->is_ignore_pwr)
		return 0;

	return rockchip_pd_power(pd, false);
}

int rockchip_pmu_pd_on(struct device *dev)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;

	if (IS_ERR_OR_NULL(dev->pm_domain))
		return -EINVAL;

	genpd = pd_to_genpd(dev->pm_domain);
	pd = to_rockchip_pd(genpd);

	return rockchip_pd_power(pd, true);
}
EXPORT_SYMBOL(rockchip_pmu_pd_on);

int rockchip_pmu_pd_off(struct device *dev)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;

	if (IS_ERR_OR_NULL(dev))
		return -EINVAL;

	if (IS_ERR_OR_NULL(dev->pm_domain))
		return -EINVAL;

	genpd = pd_to_genpd(dev->pm_domain);
	pd = to_rockchip_pd(genpd);

	return rockchip_pd_power(pd, false);
}
EXPORT_SYMBOL(rockchip_pmu_pd_off);

bool rockchip_pmu_pd_is_on(struct device *dev)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;
	bool is_on;

	if (IS_ERR_OR_NULL(dev))
		return false;

	if (IS_ERR_OR_NULL(dev->pm_domain))
		return false;

	genpd = pd_to_genpd(dev->pm_domain);
	pd = to_rockchip_pd(genpd);

	rockchip_pmu_lock(pd);
	is_on = rockchip_pmu_domain_is_on(pd);
	rockchip_pmu_unlock(pd);

	return is_on;
}
EXPORT_SYMBOL(rockchip_pmu_pd_is_on);

static int rockchip_pd_attach_dev(struct generic_pm_domain *genpd,
				  struct device *dev)
{
	struct clk *clk;
	int i;
	int error;

	dev_dbg(dev, "attaching to power domain '%s'\n", genpd->name);

	error = pm_clk_create(dev);
	if (error) {
		dev_err(dev, "pm_clk_create failed %d\n", error);
		return error;
	}

	i = 0;
	while ((clk = of_clk_get(dev->of_node, i++)) && !IS_ERR(clk)) {
		dev_dbg(dev, "adding clock '%pC' to list of PM clocks\n", clk);
		error = pm_clk_add_clk(dev, clk);
		if (error) {
			dev_err(dev, "pm_clk_add_clk failed %d\n", error);
			clk_put(clk);
			pm_clk_destroy(dev);
			return error;
		}
	}

	return 0;
}

static void rockchip_pd_detach_dev(struct generic_pm_domain *genpd,
				   struct device *dev)
{
	dev_dbg(dev, "detaching from power domain '%s'\n", genpd->name);

	pm_clk_destroy(dev);
}

static void rockchip_pd_qos_init(struct rockchip_pm_domain *pd,
				 bool **qos_is_need_init)
{
	int i, is_pd_on;

	is_pd_on = rockchip_pmu_domain_is_on(pd);
	if (!is_pd_on)
		rockchip_pd_power(pd, true);

	for (i = 0; i < pd->num_qos; i++) {
		if (qos_is_need_init[0][i])
			regmap_write(pd->qos_regmap[i],
				     QOS_PRIORITY,
				     pd->qos_save_regs[0][i]);

		if (qos_is_need_init[1][i])
			regmap_write(pd->qos_regmap[i],
				     QOS_MODE,
				     pd->qos_save_regs[1][i]);

		if (qos_is_need_init[2][i])
			regmap_write(pd->qos_regmap[i],
				     QOS_BANDWIDTH,
				     pd->qos_save_regs[2][i]);

		if (qos_is_need_init[3][i])
			regmap_write(pd->qos_regmap[i],
				     QOS_SATURATION,
				     pd->qos_save_regs[3][i]);

		if (qos_is_need_init[4][i])
			regmap_write(pd->qos_regmap[i],
				     QOS_EXTCONTROL,
				     pd->qos_save_regs[4][i]);
	}

	if (!is_pd_on)
		rockchip_pd_power(pd, false);
}

static int rockchip_pm_add_one_domain(struct rockchip_pmu *pmu,
				      struct device_node *node)
{
	const struct rockchip_domain_info *pd_info;
	struct rockchip_pm_domain *pd;
	struct device_node *qos_node;
	int num_qos = 0, num_qos_reg = 0;
	int i, j;
	u32 id, val;
	int error;
	bool *qos_is_need_init[MAX_QOS_REGS_NUM] = { NULL };
	bool is_qos_need_init = false;

	error = of_property_read_u32(node, "reg", &id);
	if (error) {
		dev_err(pmu->dev,
			"%pOFn: failed to retrieve domain id (reg): %d\n",
			node, error);
		return -EINVAL;
	}

	if (id >= pmu->info->num_domains) {
		dev_err(pmu->dev, "%pOFn: invalid domain id %d\n",
			node, id);
		return -EINVAL;
	}
	if (pmu->genpd_data.domains[id])
		return 0;

	pd_info = &pmu->info->domain_info[id];
	if (!pd_info) {
		dev_err(pmu->dev, "%pOFn: undefined domain id %d\n",
			node, id);
		return -EINVAL;
	}

	pd = devm_kzalloc(pmu->dev, sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return -ENOMEM;

	pd->info = pd_info;
	pd->pmu = pmu;
	if (!pd_info->pwr_mask)
		pd->is_ignore_pwr = true;

	pd->num_clks = of_clk_get_parent_count(node);
	if (pd->num_clks > 0) {
		pd->clks = devm_kcalloc(pmu->dev, pd->num_clks,
					sizeof(*pd->clks), GFP_KERNEL);
		if (!pd->clks)
			return -ENOMEM;
	} else {
		dev_dbg(pmu->dev, "%pOFn: doesn't have clocks: %d\n",
			node, pd->num_clks);
		pd->num_clks = 0;
	}

	for (i = 0; i < pd->num_clks; i++) {
		pd->clks[i].clk = of_clk_get(node, i);
		if (IS_ERR(pd->clks[i].clk)) {
			error = PTR_ERR(pd->clks[i].clk);
			dev_err(pmu->dev,
				"%pOFn: failed to get clk at index %d: %d\n",
				node, i, error);
			return error;
		}
	}

	error = clk_bulk_prepare(pd->num_clks, pd->clks);
	if (error)
		goto err_put_clocks;

	num_qos = of_count_phandle_with_args(node, "pm_qos", NULL);

	for (j = 0; j < num_qos; j++) {
		qos_node = of_parse_phandle(node, "pm_qos", j);
		if (qos_node && of_device_is_available(qos_node))
			pd->num_qos++;
		of_node_put(qos_node);
	}

	if (pd->num_qos > 0) {
		pd->qos_regmap = devm_kcalloc(pmu->dev, pd->num_qos,
					      sizeof(*pd->qos_regmap),
					      GFP_KERNEL);
		if (!pd->qos_regmap) {
			error = -ENOMEM;
			goto err_unprepare_clocks;
		}

		pd->qos_save_regs[0] = (u32 *)devm_kmalloc(pmu->dev,
							   sizeof(u32) *
							   MAX_QOS_REGS_NUM *
							   pd->num_qos,
							   GFP_KERNEL);
		if (!pd->qos_save_regs[0]) {
			error = -ENOMEM;
			goto err_unprepare_clocks;
		}
		qos_is_need_init[0] = kzalloc(sizeof(bool) *
					      MAX_QOS_REGS_NUM *
					      pd->num_qos,
					      GFP_KERNEL);
		if (!qos_is_need_init[0]) {
			error = -ENOMEM;
			goto err_unprepare_clocks;
		}
		for (i = 1; i < MAX_QOS_REGS_NUM; i++) {
			pd->qos_save_regs[i] = pd->qos_save_regs[i - 1] +
					       num_qos;
			qos_is_need_init[i] = qos_is_need_init[i - 1] + num_qos;
		}

		for (j = 0; j < num_qos; j++) {
			qos_node = of_parse_phandle(node, "pm_qos", j);
			if (!qos_node) {
				error = -ENODEV;
				goto err_unprepare_clocks;
			}
			if (of_device_is_available(qos_node)) {
				pd->qos_regmap[num_qos_reg] =
					syscon_node_to_regmap(qos_node);
				if (IS_ERR(pd->qos_regmap[num_qos_reg])) {
					error = -ENODEV;
					of_node_put(qos_node);
					goto err_unprepare_clocks;
				}
				if (!of_property_read_u32(qos_node,
							  "priority-init",
							  &val)) {
					pd->qos_save_regs[0][j] = val;
					qos_is_need_init[0][j] = true;
					is_qos_need_init = true;
				}

				if (!of_property_read_u32(qos_node,
							  "mode-init",
							  &val)) {
					pd->qos_save_regs[1][j] = val;
					qos_is_need_init[1][j] = true;
					is_qos_need_init = true;
				}

				if (!of_property_read_u32(qos_node,
							  "bandwidth-init",
							  &val)) {
					pd->qos_save_regs[2][j] = val;
					qos_is_need_init[2][j] = true;
					is_qos_need_init = true;
				}

				if (!of_property_read_u32(qos_node,
							  "saturation-init",
							  &val)) {
					pd->qos_save_regs[3][j] = val;
					qos_is_need_init[3][j] = true;
					is_qos_need_init = true;
				}

				if (!of_property_read_u32(qos_node,
							  "extcontrol-init",
							  &val)) {
					pd->qos_save_regs[4][j] = val;
					qos_is_need_init[4][j] = true;
					is_qos_need_init = true;
				}

				num_qos_reg++;
			}
			of_node_put(qos_node);
			if (num_qos_reg > pd->num_qos)
				goto err_unprepare_clocks;
		}
	}

	if (pd->info->name)
		pd->genpd.name = pd->info->name;
	else
		pd->genpd.name = kbasename(node->full_name);
	pd->genpd.power_off = rockchip_pd_power_off;
	pd->genpd.power_on = rockchip_pd_power_on;
	pd->genpd.attach_dev = rockchip_pd_attach_dev;
	pd->genpd.detach_dev = rockchip_pd_detach_dev;
	if (pd_info->active_wakeup)
		pd->genpd.flags |= GENPD_FLAG_ACTIVE_WAKEUP;
#ifndef MODULE
	if (pd_info->keepon_startup) {
		pd->genpd.flags |= GENPD_FLAG_ALWAYS_ON;
		if (!rockchip_pmu_domain_is_on(pd)) {
			error = rockchip_pd_power(pd, true);
			if (error) {
				dev_err(pmu->dev,
					"failed to power on domain '%s': %d\n",
					node->name, error);
				goto err_unprepare_clocks;
			}
		}
	}
#endif
	if (is_qos_need_init)
		rockchip_pd_qos_init(pd, &qos_is_need_init[0]);

	kfree(qos_is_need_init[0]);

	pm_genpd_init(&pd->genpd, NULL, !rockchip_pmu_domain_is_on(pd));

	pmu->genpd_data.domains[id] = &pd->genpd;
	return 0;

err_unprepare_clocks:
	kfree(qos_is_need_init[0]);
	clk_bulk_unprepare(pd->num_clks, pd->clks);
err_put_clocks:
	clk_bulk_put(pd->num_clks, pd->clks);
	return error;
}

static void rockchip_pm_remove_one_domain(struct rockchip_pm_domain *pd)
{
	int ret;

	/*
	 * We're in the error cleanup already, so we only complain,
	 * but won't emit another error on top of the original one.
	 */
	ret = pm_genpd_remove(&pd->genpd);
	if (ret < 0)
		dev_err(pd->pmu->dev, "failed to remove domain '%s' : %d - state may be inconsistent\n",
			pd->genpd.name, ret);

	clk_bulk_unprepare(pd->num_clks, pd->clks);
	clk_bulk_put(pd->num_clks, pd->clks);

	/* protect the zeroing of pm->num_clks */
	rockchip_pmu_lock(pd);
	pd->num_clks = 0;
	rockchip_pmu_unlock(pd);

	/* devm will free our memory */
}

static void rockchip_pm_domain_cleanup(struct rockchip_pmu *pmu)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;
	int i;

	for (i = 0; i < pmu->genpd_data.num_domains; i++) {
		genpd = pmu->genpd_data.domains[i];
		if (genpd) {
			pd = to_rockchip_pd(genpd);
			rockchip_pm_remove_one_domain(pd);
		}
	}

	/* devm will free our memory */
}

static void rockchip_configure_pd_cnt(struct rockchip_pmu *pmu,
				      u32 domain_reg_offset,
				      unsigned int count)
{
	/* First configure domain power down transition count ... */
	regmap_write(pmu->regmap, domain_reg_offset, count);
	/* ... and then power up count. */
	regmap_write(pmu->regmap, domain_reg_offset + 4, count);
}


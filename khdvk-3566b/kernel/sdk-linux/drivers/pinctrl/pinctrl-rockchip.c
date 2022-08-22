// SPDX-License-Identifier: GPL-2.0-only
/*
 * Pinctrl driver for Rockchip SoCs
 *
 * Copyright (c) 2013 MundoReader S.L.
 * Author: Heiko Stuebner <heiko@sntech.de>
 *
 * With some ideas taken from pinctrl-samsung:
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 * Copyright (c) 2012 Linaro Ltd
 *		https://www.linaro.org
 *
 * and pinctrl-at91:
 * Copyright (C) 2011-2012 Jean-Christophe PLAGNIOL-VILLARD <plagnioj@jcrosoft.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/gpio.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_device.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/clk.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>
#include <linux/rockchip/cpu.h>
#include <dt-bindings/pinctrl/rockchip.h>

#include "core.h"
#include "pinconf.h"
#include "pinctrl-rockchip.h"

/**
 * Generate a bitmask for setting a value (v) with a write mask bit in hiword
 * register 31:16 area.
 */
#define WRITE_MASK_VAL(h, l, v) \
	(GENMASK(((h) + 16), ((l) + 16)) | (((v) << (l)) & GENMASK((h), (l))))

/*
 * Encode variants of iomux registers into a type variable
 */
#define IOMUX_GPIO_ONLY		BIT(0)
#define IOMUX_WIDTH_4BIT	BIT(1)
#define IOMUX_SOURCE_PMU	BIT(2)
#define IOMUX_UNROUTED		BIT(3)
#define IOMUX_WIDTH_3BIT	BIT(4)
#define IOMUX_WIDTH_2BIT	BIT(5)
#define IOMUX_WRITABLE_32BIT	BIT(6)
#define IOMUX_L_SOURCE_PMU	BIT(7)

#define PIN_BANK(id, pins, label)			\
	{						\
		.bank_num	= id,			\
		.nr_pins	= pins,			\
		.name		= label,		\
		.iomux		= {			\
			{ .offset = -1 },		\
			{ .offset = -1 },		\
			{ .offset = -1 },		\
			{ .offset = -1 },		\
		},					\
	}

#define PIN_BANK_IOMUX_FLAGS(id, pins, label, iom0, iom1, iom2, iom3)	\
	{								\
		.bank_num	= id,					\
		.nr_pins	= pins,					\
		.name		= label,				\
		.iomux		= {					\
			{ .type = iom0, .offset = -1 },			\
			{ .type = iom1, .offset = -1 },			\
			{ .type = iom2, .offset = -1 },			\
			{ .type = iom3, .offset = -1 },			\
		},							\
	}

#define PIN_BANK_IOMUX_FLAGS_OFFSET(id, pins, label, iom0, iom1, iom2,	\
				    iom3, offset0, offset1, offset2,	\
				    offset3)				\
	{								\
		.bank_num	= id,					\
		.nr_pins	= pins,					\
		.name		= label,				\
		.iomux		= {					\
			{ .type = iom0, .offset = offset0 },		\
			{ .type = iom1, .offset = offset1 },		\
			{ .type = iom2, .offset = offset2 },		\
			{ .type = iom3, .offset = offset3 },		\
		},							\
	}

#define PIN_BANK_DRV_FLAGS(id, pins, label, type0, type1, type2, type3) \
	{								\
		.bank_num	= id,					\
		.nr_pins	= pins,					\
		.name		= label,				\
		.iomux		= {					\
			{ .offset = -1 },				\
			{ .offset = -1 },				\
			{ .offset = -1 },				\
			{ .offset = -1 },				\
		},							\
		.drv		= {					\
			{ .drv_type = type0, .offset = -1 },		\
			{ .drv_type = type1, .offset = -1 },		\
			{ .drv_type = type2, .offset = -1 },		\
			{ .drv_type = type3, .offset = -1 },		\
		},							\
	}

#define PIN_BANK_DRV_FLAGS_PULL_FLAGS(id, pins, label, drv0, drv1,	\
				      drv2, drv3, pull0, pull1,		\
				      pull2, pull3)			\
	{								\
		.bank_num	= id,					\
		.nr_pins	= pins,					\
		.name		= label,				\
		.iomux		= {					\
			{ .offset = -1 },				\
			{ .offset = -1 },				\
			{ .offset = -1 },				\
			{ .offset = -1 },				\
		},							\
		.drv		= {					\
			{ .drv_type = drv0, .offset = -1 },		\
			{ .drv_type = drv1, .offset = -1 },		\
			{ .drv_type = drv2, .offset = -1 },		\
			{ .drv_type = drv3, .offset = -1 },		\
		},							\
		.pull_type[0] = pull0,					\
		.pull_type[1] = pull1,					\
		.pull_type[2] = pull2,					\
		.pull_type[3] = pull3,					\
	}

#define PIN_BANK_IOMUX_DRV_FLAGS_OFFSET(id, pins, label, iom0, iom1,	\
					iom2, iom3, drv0, drv1, drv2,	\
					drv3, offset0, offset1,		\
					offset2, offset3)		\
	{								\
		.bank_num	= id,					\
		.nr_pins	= pins,					\
		.name		= label,				\
		.iomux		= {					\
			{ .type = iom0, .offset = -1 },			\
			{ .type = iom1, .offset = -1 },			\
			{ .type = iom2, .offset = -1 },			\
			{ .type = iom3, .offset = -1 },			\
		},							\
		.drv		= {					\
			{ .drv_type = drv0, .offset = offset0 },	\
			{ .drv_type = drv1, .offset = offset1 },	\
			{ .drv_type = drv2, .offset = offset2 },	\
			{ .drv_type = drv3, .offset = offset3 },	\
		},							\
	}

#define PIN_BANK_IOMUX_FLAGS_DRV_FLAGS_OFFSET_PULL_FLAGS(id, pins,	\
					      label, iom0, iom1, iom2,  \
					      iom3, drv0, drv1, drv2,   \
					      drv3, offset0, offset1,   \
					      offset2, offset3, pull0,  \
					      pull1, pull2, pull3)	\
	{								\
		.bank_num	= id,					\
		.nr_pins	= pins,					\
		.name		= label,				\
		.iomux		= {					\
			{ .type = iom0, .offset = -1 },			\
			{ .type = iom1, .offset = -1 },			\
			{ .type = iom2, .offset = -1 },			\
			{ .type = iom3, .offset = -1 },			\
		},							\
		.drv		= {					\
			{ .drv_type = drv0, .offset = offset0 },	\
			{ .drv_type = drv1, .offset = offset1 },	\
			{ .drv_type = drv2, .offset = offset2 },	\
			{ .drv_type = drv3, .offset = offset3 },	\
		},							\
		.pull_type[0] = pull0,					\
		.pull_type[1] = pull1,					\
		.pull_type[2] = pull2,					\
		.pull_type[3] = pull3,					\
	}

#define PIN_BANK_MUX_ROUTE_FLAGS(ID, PIN, FUNC, REG, VAL, FLAG)		\
	{								\
		.bank_num	= ID,					\
		.pin		= PIN,					\
		.func		= FUNC,					\
		.route_offset	= REG,					\
		.route_val	= VAL,					\
		.route_location	= FLAG,					\
	}

#define RK_MUXROUTE_SAME(ID, PIN, FUNC, REG, VAL)	\
	PIN_BANK_MUX_ROUTE_FLAGS(ID, PIN, FUNC, REG, VAL, ROCKCHIP_ROUTE_SAME)

#define RK_MUXROUTE_GRF(ID, PIN, FUNC, REG, VAL)	\
	PIN_BANK_MUX_ROUTE_FLAGS(ID, PIN, FUNC, REG, VAL, ROCKCHIP_ROUTE_GRF)

#define RK_MUXROUTE_PMU(ID, PIN, FUNC, REG, VAL)	\
	PIN_BANK_MUX_ROUTE_FLAGS(ID, PIN, FUNC, REG, VAL, ROCKCHIP_ROUTE_PMU)

static struct regmap_config rockchip_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

static inline const struct rockchip_pin_group *pinctrl_name_to_group(
					const struct rockchip_pinctrl *info,
					const char *name)
{
	int i;

	for (i = 0; i < info->ngroups; i++) {
		if (!strcmp(info->groups[i].name, name))
			return &info->groups[i];
	}

	return NULL;
}

/*
 * given a pin number that is local to a pin controller, find out the pin bank
 * and the register base of the pin bank.
 */
static struct rockchip_pin_bank *pin_to_bank(struct rockchip_pinctrl *info,
								unsigned pin)
{
	struct rockchip_pin_bank *b = info->ctrl->pin_banks;

	while (pin >= (b->pin_base + b->nr_pins))
		b++;

	return b;
}

static struct rockchip_pin_bank *bank_num_to_bank(
					struct rockchip_pinctrl *info,
					unsigned num)
{
	struct rockchip_pin_bank *b = info->ctrl->pin_banks;
	int i;

	for (i = 0; i < info->ctrl->nr_banks; i++, b++) {
		if (b->bank_num == num)
			return b;
	}

	return ERR_PTR(-EINVAL);
}

/*
 * Pinctrl_ops handling
 */

static int rockchip_get_groups_count(struct pinctrl_dev *pctldev)
{
	struct rockchip_pinctrl *info = pinctrl_dev_get_drvdata(pctldev);

	return info->ngroups;
}

static const char *rockchip_get_group_name(struct pinctrl_dev *pctldev,
							unsigned selector)
{
	struct rockchip_pinctrl *info = pinctrl_dev_get_drvdata(pctldev);

	return info->groups[selector].name;
}

static int rockchip_get_group_pins(struct pinctrl_dev *pctldev,
				      unsigned selector, const unsigned **pins,
				      unsigned *npins)
{
	struct rockchip_pinctrl *info = pinctrl_dev_get_drvdata(pctldev);

	if (selector >= info->ngroups)
		return -EINVAL;

	*pins = info->groups[selector].pins;
	*npins = info->groups[selector].npins;

	return 0;
}

static int rockchip_dt_node_to_map(struct pinctrl_dev *pctldev,
				 struct device_node *np,
				 struct pinctrl_map **map, unsigned *num_maps)
{
	struct rockchip_pinctrl *info = pinctrl_dev_get_drvdata(pctldev);
	const struct rockchip_pin_group *grp;
	struct pinctrl_map *new_map;
	struct device_node *parent;
	int map_num = 1;
	int i;

	/*
	 * first find the group of this node and check if we need to create
	 * config maps for pins
	 */
	grp = pinctrl_name_to_group(info, np->name);
	if (!grp) {
		dev_err(info->dev, "unable to find group for node %pOFn\n",
			np);
		return -EINVAL;
	}

	map_num += grp->npins;

	new_map = kcalloc(map_num, sizeof(*new_map), GFP_KERNEL);
	if (!new_map)
		return -ENOMEM;

	*map = new_map;
	*num_maps = map_num;

	/* create mux map */
	parent = of_get_parent(np);
	if (!parent) {
		kfree(new_map);
		return -EINVAL;
	}
	new_map[0].type = PIN_MAP_TYPE_MUX_GROUP;
	new_map[0].data.mux.function = parent->name;
	new_map[0].data.mux.group = np->name;
	of_node_put(parent);

	/* create config map */
	new_map++;
	for (i = 0; i < grp->npins; i++) {
		new_map[i].type = PIN_MAP_TYPE_CONFIGS_PIN;
		new_map[i].data.configs.group_or_pin =
				pin_get_name(pctldev, grp->pins[i]);
		new_map[i].data.configs.configs = grp->data[i].configs;
		new_map[i].data.configs.num_configs = grp->data[i].nconfigs;
	}

	dev_dbg(pctldev->dev, "maps: function %s group %s num %d\n",
		(*map)->data.mux.function, (*map)->data.mux.group, map_num);

	return 0;
}

static void rockchip_dt_free_map(struct pinctrl_dev *pctldev,
				    struct pinctrl_map *map, unsigned num_maps)
{
	kfree(map);
}

static const struct pinctrl_ops rockchip_pctrl_ops = {
	.get_groups_count	= rockchip_get_groups_count,
	.get_group_name		= rockchip_get_group_name,
	.get_group_pins		= rockchip_get_group_pins,
	.dt_node_to_map		= rockchip_dt_node_to_map,
	.dt_free_map		= rockchip_dt_free_map,
};

/*
 * Hardware access
 */

static struct rockchip_mux_recalced_data rv1108_mux_recalced_data[] = {
	{
		.num = 1,
		.pin = 0,
		.reg = 0x418,
		.bit = 0,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 1,
		.reg = 0x418,
		.bit = 2,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 2,
		.reg = 0x418,
		.bit = 4,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 3,
		.reg = 0x418,
		.bit = 6,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 4,
		.reg = 0x418,
		.bit = 8,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 5,
		.reg = 0x418,
		.bit = 10,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 6,
		.reg = 0x418,
		.bit = 12,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 7,
		.reg = 0x418,
		.bit = 14,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 8,
		.reg = 0x41c,
		.bit = 0,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 9,
		.reg = 0x41c,
		.bit = 2,
		.mask = 0x3
	},
};

static struct rockchip_mux_recalced_data rv1126_mux_recalced_data[] = {
	{
		.num = 0,
		.pin = 20,
		.reg = 0x10000,
		.bit = 0,
		.mask = 0xf
	},
	{
		.num = 0,
		.pin = 21,
		.reg = 0x10000,
		.bit = 4,
		.mask = 0xf
	},
	{
		.num = 0,
		.pin = 22,
		.reg = 0x10000,
		.bit = 8,
		.mask = 0xf
	},
	{
		.num = 0,
		.pin = 23,
		.reg = 0x10000,
		.bit = 12,
		.mask = 0xf
	},
};

static  struct rockchip_mux_recalced_data rk3128_mux_recalced_data[] = {
	{
		.num = 2,
		.pin = 20,
		.reg = 0xe8,
		.bit = 0,
		.mask = 0x7
	}, {
		.num = 2,
		.pin = 21,
		.reg = 0xe8,
		.bit = 4,
		.mask = 0x7
	}, {
		.num = 2,
		.pin = 22,
		.reg = 0xe8,
		.bit = 8,
		.mask = 0x7
	}, {
		.num = 2,
		.pin = 23,
		.reg = 0xe8,
		.bit = 12,
		.mask = 0x7
	}, {
		.num = 2,
		.pin = 24,
		.reg = 0xd4,
		.bit = 12,
		.mask = 0x7
	},
};

static struct rockchip_mux_recalced_data rk3308_mux_recalced_data[] = {
	{
		.num = 1,
		.pin = 14,
		.reg = 0x28,
		.bit = 12,
		.mask = 0xf
	}, {
		.num = 1,
		.pin = 15,
		.reg = 0x2c,
		.bit = 0,
		.mask = 0x3
	}, {
		.num = 1,
		.pin = 18,
		.reg = 0x30,
		.bit = 4,
		.mask = 0xf
	}, {
		.num = 1,
		.pin = 19,
		.reg = 0x30,
		.bit = 8,
		.mask = 0xf
	}, {
		.num = 1,
		.pin = 20,
		.reg = 0x30,
		.bit = 12,
		.mask = 0xf
	}, {
		.num = 1,
		.pin = 21,
		.reg = 0x34,
		.bit = 0,
		.mask = 0xf
	}, {
		.num = 1,
		.pin = 22,
		.reg = 0x34,
		.bit = 4,
		.mask = 0xf
	}, {
		.num = 1,
		.pin = 23,
		.reg = 0x34,
		.bit = 8,
		.mask = 0xf
	}, {
		.num = 3,
		.pin = 12,
		.reg = 0x68,
		.bit = 8,
		.mask = 0xf
	}, {
		.num = 3,
		.pin = 13,
		.reg = 0x68,
		.bit = 12,
		.mask = 0xf
	}, {
		.num = 2,
		.pin = 2,
		.reg = 0x608,
		.bit = 0,
		.mask = 0x7
	}, {
		.num = 2,
		.pin = 3,
		.reg = 0x608,
		.bit = 4,
		.mask = 0x7
	}, {
		.num = 2,
		.pin = 16,
		.reg = 0x610,
		.bit = 8,
		.mask = 0x7
	}, {
		.num = 3,
		.pin = 10,
		.reg = 0x610,
		.bit = 0,
		.mask = 0x7
	}, {
		.num = 3,
		.pin = 11,
		.reg = 0x610,
		.bit = 4,
		.mask = 0x7
	},
};

static struct rockchip_mux_recalced_data rk3328_mux_recalced_data[] = {
	{
		.num = 2,
		.pin = 8,
		.reg = 0x24,
		.bit = 0,
		.mask = 0x3
	}, {
		.num = 2,
		.pin = 9,
		.reg = 0x24,
		.bit = 2,
		.mask = 0x3
	}, {
		.num = 2,
		.pin = 10,
		.reg = 0x24,
		.bit = 4,
		.mask = 0x3
	}, {
		.num = 2,
		.pin = 11,
		.reg = 0x24,
		.bit = 6,
		.mask = 0x3
	}, {
		.num = 2,
		.pin = 12,
		.reg = 0x24,
		.bit = 8,
		.mask = 0x3
	}, {
		.num = 2,
		.pin = 13,
		.reg = 0x24,
		.bit = 10,
		.mask = 0x3
	}, {
		.num = 2,
		.pin = 14,
		.reg = 0x24,
		.bit = 12,
		.mask = 0x3
	}, {
		.num = 2,
		.pin = 15,
		.reg = 0x28,
		.bit = 0,
		.mask = 0x7
	}, {
		.num = 2,
		.pin = 23,
		.reg = 0x30,
		.bit = 14,
		.mask = 0x3
	},
};

static struct rockchip_mux_route_data rv1126_mux_route_data[] = {
	RK_MUXROUTE_GRF(3, RK_PD2, 1, 0x10260, WRITE_MASK_VAL(0, 0, 0)), /* I2S0_MCLK_M0 */
	RK_MUXROUTE_GRF(3, RK_PB0, 3, 0x10260, WRITE_MASK_VAL(0, 0, 1)), /* I2S0_MCLK_M1 */

	RK_MUXROUTE_GRF(0, RK_PD4, 4, 0x10260, WRITE_MASK_VAL(3, 2, 0)), /* I2S1_MCLK_M0 */
	RK_MUXROUTE_GRF(1, RK_PD5, 2, 0x10260, WRITE_MASK_VAL(3, 2, 1)), /* I2S1_MCLK_M1 */
	RK_MUXROUTE_GRF(2, RK_PC7, 6, 0x10260, WRITE_MASK_VAL(3, 2, 2)), /* I2S1_MCLK_M2 */

	RK_MUXROUTE_GRF(1, RK_PD0, 1, 0x10260, WRITE_MASK_VAL(4, 4, 0)), /* I2S2_MCLK_M0 */
	RK_MUXROUTE_GRF(2, RK_PB3, 2, 0x10260, WRITE_MASK_VAL(4, 4, 1)), /* I2S2_MCLK_M1 */

	RK_MUXROUTE_GRF(3, RK_PD4, 2, 0x10260, WRITE_MASK_VAL(12, 12, 0)), /* PDM_CLK0_M0 */
	RK_MUXROUTE_GRF(3, RK_PC0, 3, 0x10260, WRITE_MASK_VAL(12, 12, 1)), /* PDM_CLK0_M1 */

	RK_MUXROUTE_GRF(3, RK_PC6, 1, 0x10264, WRITE_MASK_VAL(0, 0, 0)), /* CIF_CLKOUT_M0 */
	RK_MUXROUTE_GRF(2, RK_PD1, 3, 0x10264, WRITE_MASK_VAL(0, 0, 1)), /* CIF_CLKOUT_M1 */

	RK_MUXROUTE_GRF(3, RK_PA4, 5, 0x10264, WRITE_MASK_VAL(5, 4, 0)), /* I2C3_SCL_M0 */
	RK_MUXROUTE_GRF(2, RK_PD4, 7, 0x10264, WRITE_MASK_VAL(5, 4, 1)), /* I2C3_SCL_M1 */
	RK_MUXROUTE_GRF(1, RK_PD6, 3, 0x10264, WRITE_MASK_VAL(5, 4, 2)), /* I2C3_SCL_M2 */

	RK_MUXROUTE_GRF(3, RK_PA0, 7, 0x10264, WRITE_MASK_VAL(6, 6, 0)), /* I2C4_SCL_M0 */
	RK_MUXROUTE_GRF(4, RK_PA0, 4, 0x10264, WRITE_MASK_VAL(6, 6, 1)), /* I2C4_SCL_M1 */

	RK_MUXROUTE_GRF(2, RK_PA5, 7, 0x10264, WRITE_MASK_VAL(9, 8, 0)), /* I2C5_SCL_M0 */
	RK_MUXROUTE_GRF(3, RK_PB0, 5, 0x10264, WRITE_MASK_VAL(9, 8, 1)), /* I2C5_SCL_M1 */
	RK_MUXROUTE_GRF(1, RK_PD0, 4, 0x10264, WRITE_MASK_VAL(9, 8, 2)), /* I2C5_SCL_M2 */

	RK_MUXROUTE_GRF(3, RK_PC0, 5, 0x10264, WRITE_MASK_VAL(11, 10, 0)), /* SPI1_CLK_M0 */
	RK_MUXROUTE_GRF(1, RK_PC6, 3, 0x10264, WRITE_MASK_VAL(11, 10, 1)), /* SPI1_CLK_M1 */
	RK_MUXROUTE_GRF(2, RK_PD5, 6, 0x10264, WRITE_MASK_VAL(11, 10, 2)), /* SPI1_CLK_M2 */

	RK_MUXROUTE_GRF(3, RK_PC0, 2, 0x10264, WRITE_MASK_VAL(12, 12, 0)), /* RGMII_CLK_M0 */
	RK_MUXROUTE_GRF(2, RK_PB7, 2, 0x10264, WRITE_MASK_VAL(12, 12, 1)), /* RGMII_CLK_M1 */

	RK_MUXROUTE_GRF(3, RK_PA1, 3, 0x10264, WRITE_MASK_VAL(13, 13, 0)), /* CAN_TXD_M0 */
	RK_MUXROUTE_GRF(3, RK_PA7, 5, 0x10264, WRITE_MASK_VAL(13, 13, 1)), /* CAN_TXD_M1 */

	RK_MUXROUTE_GRF(3, RK_PA4, 6, 0x10268, WRITE_MASK_VAL(0, 0, 0)), /* PWM8_M0 */
	RK_MUXROUTE_GRF(2, RK_PD7, 5, 0x10268, WRITE_MASK_VAL(0, 0, 1)), /* PWM8_M1 */

	RK_MUXROUTE_GRF(3, RK_PA5, 6, 0x10268, WRITE_MASK_VAL(2, 2, 0)), /* PWM9_M0 */
	RK_MUXROUTE_GRF(2, RK_PD6, 5, 0x10268, WRITE_MASK_VAL(2, 2, 1)), /* PWM9_M1 */

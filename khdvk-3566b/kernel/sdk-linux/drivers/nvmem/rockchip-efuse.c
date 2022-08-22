// SPDX-License-Identifier: GPL-2.0-only
/*
 * Rockchip eFuse Driver
 *
 * Copyright (c) 2015 Rockchip Electronics Co. Ltd.
 * Author: Caesar Wang <wxt@rock-chips.com>
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/nvmem-provider.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/rockchip/rockchip_sip.h>

#define T_CSB_P_S		0
#define T_PGENB_P_S		0
#define T_LOAD_P_S		0
#define T_ADDR_P_S		0
#define T_STROBE_P_S		(0 + 110) /* 1.1us */
#define T_CSB_P_L		(0 + 110 + 1000 + 20) /* 200ns */
#define T_PGENB_P_L		(0 + 110 + 1000 + 20)
#define T_LOAD_P_L		(0 + 110 + 1000 + 20)
#define T_ADDR_P_L		(0 + 110 + 1000 + 20)
#define T_STROBE_P_L		(0 + 110 + 1000) /* 10us */
#define T_CSB_R_S		0
#define T_PGENB_R_S		0
#define T_LOAD_R_S		0
#define T_ADDR_R_S		2
#define T_STROBE_R_S		(2 + 3)
#define T_CSB_R_L		(2 + 3 + 3 + 3)
#define T_PGENB_R_L		(2 + 3 + 3 + 3)
#define T_LOAD_R_L		(2 + 3 + 3 + 3)
#define T_ADDR_R_L		(2 + 3 + 3 + 2)
#define T_STROBE_R_L		(2 + 3 + 3)

#define T_CSB_P			0x28
#define T_PGENB_P		0x2c
#define T_LOAD_P		0x30
#define T_ADDR_P		0x34
#define T_STROBE_P		0x38
#define T_CSB_R			0x3c
#define T_PGENB_R		0x40
#define T_LOAD_R		0x44
#define T_ADDR_R		0x48
#define T_STROBE_R		0x4c

#define RK1808_MOD		0x00
#define RK1808_INT_STATUS	RK3328_INT_STATUS
#define RK1808_DOUT		RK3328_DOUT
#define RK1808_AUTO_CTRL	RK3328_AUTO_CTRL
#define RK1808_USER_MODE	BIT(0)
#define RK1808_INT_FINISH	RK3328_INT_FINISH
#define RK1808_AUTO_ENB		RK3328_AUTO_ENB
#define RK1808_AUTO_RD		RK3328_AUTO_RD
#define RK1808_A_SHIFT		RK3399_A_SHIFT
#define RK1808_A_MASK		RK3399_A_MASK
#define RK1808_NBYTES		RK3399_NBYTES

#define RK3128_A_SHIFT		7
#define RK3288_A_SHIFT		6
#define RK3288_A_MASK		0x3ff
#define RK3288_PGENB		BIT(3)
#define RK3288_LOAD		BIT(2)
#define RK3288_STROBE		BIT(1)
#define RK3288_CSB		BIT(0)

#define RK3328_SECURE_SIZES	96
#define RK3328_INT_STATUS	0x0018
#define RK3328_DOUT		0x0020
#define RK3328_AUTO_CTRL	0x0024
#define RK3328_INT_FINISH	BIT(0)
#define RK3328_AUTO_ENB		BIT(0)
#define RK3328_AUTO_RD		BIT(1)

#define RK3399_A_SHIFT		16
#define RK3399_A_MASK		0x3ff
#define RK3399_NBYTES		4
#define RK3399_STROBSFTSEL	BIT(9)
#define RK3399_RSB		BIT(7)
#define RK3399_PD		BIT(5)
#define RK3399_PGENB		BIT(3)
#define RK3399_LOAD		BIT(2)
#define RK3399_STROBE		BIT(1)
#define RK3399_CSB		BIT(0)

#define REG_EFUSE_CTRL		0x0000
#define REG_EFUSE_DOUT		0x0004

struct rockchip_efuse_chip {
	struct device *dev;
	void __iomem *base;
	struct clk_bulk_data *clks;
	int num_clks;
	phys_addr_t phys;
	struct mutex mutex;
};

static void rk1808_efuse_timing_init(void __iomem *base)
{
	/* enable auto mode */
	writel(readl(base + RK1808_MOD) & (~RK1808_USER_MODE),
	       base + RK1808_MOD);

	/* setup efuse timing */
	writel((T_CSB_P_S << 16) | T_CSB_P_L, base + T_CSB_P);
	writel((T_PGENB_P_S << 16) | T_PGENB_P_L, base + T_PGENB_P);
	writel((T_LOAD_P_S << 16) | T_LOAD_P_L, base + T_LOAD_P);
	writel((T_ADDR_P_S << 16) | T_ADDR_P_L, base + T_ADDR_P);
	writel((T_STROBE_P_S << 16) | T_STROBE_P_L, base + T_STROBE_P);
	writel((T_CSB_R_S << 16) | T_CSB_R_L, base + T_CSB_R);
	writel((T_PGENB_R_S << 16) | T_PGENB_R_L, base + T_PGENB_R);
	writel((T_LOAD_R_S << 16) | T_LOAD_R_L, base + T_LOAD_R);
	writel((T_ADDR_R_S << 16) | T_ADDR_R_L, base + T_ADDR_R);
	writel((T_STROBE_R_S << 16) | T_STROBE_R_L, base + T_STROBE_R);
}

static void rk1808_efuse_timing_deinit(void __iomem *base)
{
	/* disable auto mode */
	writel(readl(base + RK1808_MOD) | RK1808_USER_MODE,
	       base + RK1808_MOD);

	/* clear efuse timing */
	writel(0, base + T_CSB_P);
	writel(0, base + T_PGENB_P);
	writel(0, base + T_LOAD_P);
	writel(0, base + T_ADDR_P);
	writel(0, base + T_STROBE_P);
	writel(0, base + T_CSB_R);
	writel(0, base + T_PGENB_R);
	writel(0, base + T_LOAD_R);
	writel(0, base + T_ADDR_R);
	writel(0, base + T_STROBE_R);
}

static int rockchip_rk1808_efuse_read(void *context, unsigned int offset,
				      void *val, size_t bytes)
{
	struct rockchip_efuse_chip *efuse = context;
	unsigned int addr_start, addr_end, addr_offset, addr_len;
	u32 out_value, status;
	u8 *buf;
	int ret, i = 0;

	mutex_lock(&efuse->mutex);

	ret = clk_bulk_prepare_enable(efuse->num_clks, efuse->clks);
	if (ret < 0) {
		dev_err(efuse->dev, "failed to prepare/enable efuse clk\n");
		goto out;
	}

	addr_start = rounddown(offset, RK1808_NBYTES) / RK1808_NBYTES;
	addr_end = roundup(offset + bytes, RK1808_NBYTES) / RK1808_NBYTES;
	addr_offset = offset % RK1808_NBYTES;
	addr_len = addr_end - addr_start;

	buf = kzalloc(sizeof(*buf) * addr_len * RK1808_NBYTES, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto nomem;
	}

	rk1808_efuse_timing_init(efuse->base);

	while (addr_len--) {
		writel(RK1808_AUTO_RD | RK1808_AUTO_ENB |
		       ((addr_start++ & RK1808_A_MASK) << RK1808_A_SHIFT),
		       efuse->base + RK1808_AUTO_CTRL);
		udelay(2);
		status = readl(efuse->base + RK1808_INT_STATUS);
		if (!(status & RK1808_INT_FINISH)) {
			ret = -EIO;
			goto err;
		}
		out_value = readl(efuse->base + RK1808_DOUT);
		writel(RK1808_INT_FINISH, efuse->base + RK1808_INT_STATUS);

		memcpy(&buf[i], &out_value, RK1808_NBYTES);
		i += RK1808_NBYTES;
	}
	memcpy(val, buf + addr_offset, bytes);
err:
	rk1808_efuse_timing_deinit(efuse->base);
	kfree(buf);
nomem:
	rk1808_efuse_timing_deinit(efuse->base);
	clk_bulk_disable_unprepare(efuse->num_clks, efuse->clks);
out:
	mutex_unlock(&efuse->mutex);

	return ret;
}

static int rockchip_rk3128_efuse_read(void *context, unsigned int offset,
				      void *val, size_t bytes)
{
	struct rockchip_efuse_chip *efuse = context;
	u8 *buf = val;
	int ret;

	ret = clk_bulk_prepare_enable(efuse->num_clks, efuse->clks);
	if (ret < 0) {
		dev_err(efuse->dev, "failed to prepare/enable efuse clk\n");
		return ret;
	}

	writel(RK3288_LOAD | RK3288_PGENB, efuse->base + REG_EFUSE_CTRL);
	udelay(1);
	while (bytes--) {
		writel(readl(efuse->base + REG_EFUSE_CTRL) &
			     (~(RK3288_A_MASK << RK3128_A_SHIFT)),
			     efuse->base + REG_EFUSE_CTRL);
		writel(readl(efuse->base + REG_EFUSE_CTRL) |
			     ((offset++ & RK3288_A_MASK) << RK3128_A_SHIFT),
			     efuse->base + REG_EFUSE_CTRL);
		udelay(1);
		writel(readl(efuse->base + REG_EFUSE_CTRL) |
			     RK3288_STROBE, efuse->base + REG_EFUSE_CTRL);
		udelay(1);
		*buf++ = readb(efuse->base + REG_EFUSE_DOUT);
		writel(readl(efuse->base + REG_EFUSE_CTRL) &
		       (~RK3288_STROBE), efuse->base + REG_EFUSE_CTRL);
		udelay(1);
	}

	/* Switch to standby mode */
	writel(RK3288_PGENB | RK3288_CSB, efuse->base + REG_EFUSE_CTRL);

	clk_bulk_disable_unprepare(efuse->num_clks, efuse->clks);

	return 0;
}

static int rockchip_rk3288_efuse_read(void *context, unsigned int offset,
				      void *val, size_t bytes)
{
	struct rockchip_efuse_chip *efuse = context;
	u8 *buf = val;
	int ret;

	ret = clk_bulk_prepare_enable(efuse->num_clks, efuse->clks);
	if (ret < 0) {
		dev_err(efuse->dev, "failed to prepare/enable efuse clk\n");
		return ret;
	}

	writel(RK3288_LOAD | RK3288_PGENB, efuse->base + REG_EFUSE_CTRL);
	udelay(1);
	while (bytes--) {
		writel(readl(efuse->base + REG_EFUSE_CTRL) &
			     (~(RK3288_A_MASK << RK3288_A_SHIFT)),
			     efuse->base + REG_EFUSE_CTRL);
		writel(readl(efuse->base + REG_EFUSE_CTRL) |
			     ((offset++ & RK3288_A_MASK) << RK3288_A_SHIFT),
			     efuse->base + REG_EFUSE_CTRL);
		udelay(1);
		writel(readl(efuse->base + REG_EFUSE_CTRL) |
			     RK3288_STROBE, efuse->base + REG_EFUSE_CTRL);
		udelay(1);
		*buf++ = readb(efuse->base + REG_EFUSE_DOUT);
		writel(readl(efuse->base + REG_EFUSE_CTRL) &
		       (~RK3288_STROBE), efuse->base + REG_EFUSE_CTRL);
		udelay(1);
	}

	/* Switch to standby mode */
	writel(RK3288_PGENB | RK3288_CSB, efuse->base + REG_EFUSE_CTRL);

	clk_bulk_disable_unprepare(efuse->num_clks, efuse->clks);

	return 0;
}

static int rockchip_rk3288_efuse_secure_read(void *context,
					     unsigned int offset,
					     void *val, size_t bytes)
{
	struct rockchip_efuse_chip *efuse = context;
	u8 *buf = val;
	u32 wr_val;
	int ret;

	ret = clk_bulk_prepare_enable(efuse->num_clks, efuse->clks);
	if (ret < 0) {
		dev_err(efuse->dev, "failed to prepare/enable efuse clk\n");
		return ret;
	}

	sip_smc_secure_reg_write(efuse->phys + REG_EFUSE_CTRL,
				 RK3288_LOAD | RK3288_PGENB);
	udelay(1);

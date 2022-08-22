// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * DOC: dwmac-rk.c - Rockchip RK3288 DWMAC specific glue layer
 *
 * Copyright (C) 2014 Chen-Zhi (Roger Chen)
 *
 * Chen-Zhi (Roger Chen)  <roger.chen@rock-chips.com>
 */

#include <linux/stmmac.h>
#include <linux/bitops.h>
#include <linux/clk.h>
#include <linux/phy.h>
#include <linux/phy/phy.h>
#include <linux/of_net.h>
#include <linux/gpio.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/delay.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/pm_runtime.h>
#include <linux/soc/rockchip/rk_vendor_storage.h>
#include "stmmac_platform.h"
#include "dwmac-rk-tool.h"

#define MAX_ETH		2

struct rk_priv_data;
struct rk_gmac_ops {
	void (*set_to_rgmii)(struct rk_priv_data *bsp_priv,
			     int tx_delay, int rx_delay);
	void (*set_to_rmii)(struct rk_priv_data *bsp_priv);
	void (*set_to_sgmii)(struct rk_priv_data *bsp_priv);
	void (*set_to_qsgmii)(struct rk_priv_data *bsp_priv);
	void (*set_rgmii_speed)(struct rk_priv_data *bsp_priv, int speed);
	void (*set_rmii_speed)(struct rk_priv_data *bsp_priv, int speed);
	void (*set_clock_selection)(struct rk_priv_data *bsp_priv, bool input,
				    bool enable);
	void (*integrated_phy_powerup)(struct rk_priv_data *bsp_priv);
};

struct rk_priv_data {
	struct platform_device *pdev;
	phy_interface_t phy_iface;
	int bus_id;
	struct regulator *regulator;
	bool suspended;
	const struct rk_gmac_ops *ops;

	bool clk_enabled;
	bool clock_input;
	bool integrated_phy;

	struct clk *clk_mac;
	struct clk *gmac_clkin;
	struct clk *mac_clk_rx;
	struct clk *mac_clk_tx;
	struct clk *clk_mac_ref;
	struct clk *clk_mac_refout;
	struct clk *clk_mac_speed;
	struct clk *aclk_mac;
	struct clk *pclk_mac;
	struct clk *clk_phy;
	struct clk *pclk_xpcs;

	struct reset_control *phy_reset;

	int tx_delay;
	int rx_delay;

	struct regmap *grf;
	struct regmap *php_grf;
	struct regmap *xpcs;
};

/* XPCS */
#define XPCS_APB_INCREMENT		(0x4)
#define XPCS_APB_MASK			GENMASK_ULL(20, 0)

#define SR_MII_BASE			(0x1F0000)
#define SR_MII1_BASE			(0x1A0000)

#define VR_MII_DIG_CTRL1		(0x8000)
#define VR_MII_AN_CTRL			(0x8001)
#define VR_MII_AN_INTR_STS		(0x8002)
#define VR_MII_LINK_TIMER_CTRL		(0x800A)

#define SR_MII_CTRL_AN_ENABLE		\
	(BMCR_ANENABLE | BMCR_ANRESTART | BMCR_FULLDPLX | BMCR_SPEED1000)
#define MII_MAC_AUTO_SW			(0x0200)
#define PCS_MODE_OFFSET			(0x1)
#define MII_AN_INTR_EN			(0x1)
#define PCS_SGMII_MODE			(0x2 << PCS_MODE_OFFSET)
#define PCS_QSGMII_MODE			(0X3 << PCS_MODE_OFFSET)
#define VR_MII_CTRL_SGMII_AN_EN		(PCS_SGMII_MODE | MII_AN_INTR_EN)
#define VR_MII_CTRL_QSGMII_AN_EN	(PCS_QSGMII_MODE | MII_AN_INTR_EN)

#define SR_MII_OFFSET(_x) ({		\
	typeof(_x) (x) = (_x); \
	(((x) == 0) ? SR_MII_BASE : (SR_MII1_BASE + ((x) - 1) * 0x10000)); \
}) \

static int xpcs_read(void *priv, int reg)
{
	struct rk_priv_data *bsp_priv = (struct rk_priv_data *)priv;
	int ret, val;

	ret = regmap_read(bsp_priv->xpcs,
			  (u32)(reg * XPCS_APB_INCREMENT) & XPCS_APB_MASK,
			  &val);
	if (ret)
		return ret;

	return val;
}

static int xpcs_write(void *priv, int reg, u16 value)
{
	struct rk_priv_data *bsp_priv = (struct rk_priv_data *)priv;

	return regmap_write(bsp_priv->xpcs,
			    (reg * XPCS_APB_INCREMENT) & XPCS_APB_MASK, value);
}

static int xpcs_poll_reset(struct rk_priv_data *bsp_priv, int dev)
{
	/* Poll until the reset bit clears (50ms per retry == 0.6 sec) */
	unsigned int retries = 12;
	int ret;

	do {
		msleep(50);
		ret = xpcs_read(bsp_priv, SR_MII_OFFSET(dev) + MDIO_CTRL1);
		if (ret < 0)
			return ret;
	} while (ret & MDIO_CTRL1_RESET && --retries);

	return (ret & MDIO_CTRL1_RESET) ? -ETIMEDOUT : 0;
}

static int xpcs_soft_reset(struct rk_priv_data *bsp_priv, int dev)
{
	int ret;

	ret = xpcs_write(bsp_priv, SR_MII_OFFSET(dev) + MDIO_CTRL1,
			 MDIO_CTRL1_RESET);
	if (ret < 0)
		return ret;

	return xpcs_poll_reset(bsp_priv, dev);
}

static int xpcs_setup(struct rk_priv_data *bsp_priv, int mode)
{
	int ret, i, id = bsp_priv->bus_id;
	u32 val;

	if (mode == PHY_INTERFACE_MODE_QSGMII && id > 0)
		return 0;

	ret = xpcs_soft_reset(bsp_priv, id);
	if (ret) {
		dev_err(&bsp_priv->pdev->dev, "xpcs_soft_reset fail %d\n", ret);
		return ret;
	}

	xpcs_write(bsp_priv, SR_MII_OFFSET(0) + VR_MII_AN_INTR_STS, 0x0);
	xpcs_write(bsp_priv, SR_MII_OFFSET(0) + VR_MII_LINK_TIMER_CTRL, 0x1);

	if (mode == PHY_INTERFACE_MODE_SGMII)
		xpcs_write(bsp_priv, SR_MII_OFFSET(0) + VR_MII_AN_CTRL,
			   VR_MII_CTRL_SGMII_AN_EN);
	else
		xpcs_write(bsp_priv, SR_MII_OFFSET(0) + VR_MII_AN_CTRL,
			   VR_MII_CTRL_QSGMII_AN_EN);

	if (mode == PHY_INTERFACE_MODE_QSGMII) {
		for (i = 0; i < 4; i++) {
			val = xpcs_read(bsp_priv,
					SR_MII_OFFSET(i) + VR_MII_DIG_CTRL1);
			xpcs_write(bsp_priv,
				   SR_MII_OFFSET(i) + VR_MII_DIG_CTRL1,
				   val | MII_MAC_AUTO_SW);
			xpcs_write(bsp_priv, SR_MII_OFFSET(i) + MII_BMCR,
				   SR_MII_CTRL_AN_ENABLE);
		}
	} else {
		val = xpcs_read(bsp_priv, SR_MII_OFFSET(id) + VR_MII_DIG_CTRL1);
		xpcs_write(bsp_priv, SR_MII_OFFSET(id) + VR_MII_DIG_CTRL1,
			   val | MII_MAC_AUTO_SW);
		xpcs_write(bsp_priv, SR_MII_OFFSET(id) + MII_BMCR,
			   SR_MII_CTRL_AN_ENABLE);
	}

	return ret;
}

#define HIWORD_UPDATE(val, mask, shift) \
		((val) << (shift) | (mask) << ((shift) + 16))

#define GRF_BIT(nr)	(BIT(nr) | BIT(nr+16))
#define GRF_CLR_BIT(nr)	(BIT(nr+16))

#define DELAY_ENABLE(soc, tx, rx) \
	((((tx) >= 0) ? soc##_GMAC_TXCLK_DLY_ENABLE : soc##_GMAC_TXCLK_DLY_DISABLE) | \
	 (((rx) >= 0) ? soc##_GMAC_RXCLK_DLY_ENABLE : soc##_GMAC_RXCLK_DLY_DISABLE))

#define DELAY_ENABLE_BY_ID(soc, tx, rx, id) \
	((((tx) >= 0) ? soc##_GMAC_TXCLK_DLY_ENABLE(id) : soc##_GMAC_TXCLK_DLY_DISABLE(id)) | \
	 (((rx) >= 0) ? soc##_GMAC_RXCLK_DLY_ENABLE(id) : soc##_GMAC_RXCLK_DLY_DISABLE(id)))

#define DELAY_VALUE(soc, tx, rx) \
	((((tx) >= 0) ? soc##_GMAC_CLK_TX_DL_CFG(tx) : 0) | \
	 (((rx) >= 0) ? soc##_GMAC_CLK_RX_DL_CFG(rx) : 0))

#define PX30_GRF_GMAC_CON1		0x0904

/* PX30_GRF_GMAC_CON1 */
#define PX30_GMAC_PHY_INTF_SEL_RMII	(GRF_CLR_BIT(4) | GRF_CLR_BIT(5) | \
					 GRF_BIT(6))
#define PX30_GMAC_SPEED_10M		GRF_CLR_BIT(2)
#define PX30_GMAC_SPEED_100M		GRF_BIT(2)

static void px30_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, PX30_GRF_GMAC_CON1,
		     PX30_GMAC_PHY_INTF_SEL_RMII);
}

static void px30_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	int ret;

	if (IS_ERR(bsp_priv->clk_mac_speed)) {
		dev_err(dev, "%s: Missing clk_mac_speed clock\n", __func__);
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, PX30_GRF_GMAC_CON1,
			     PX30_GMAC_SPEED_10M);

		ret = clk_set_rate(bsp_priv->clk_mac_speed, 2500000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 2500000 failed: %d\n",
				__func__, ret);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, PX30_GRF_GMAC_CON1,
			     PX30_GMAC_SPEED_100M);

		ret = clk_set_rate(bsp_priv->clk_mac_speed, 25000000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 25000000 failed: %d\n",
				__func__, ret);

	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops px30_ops = {
	.set_to_rmii = px30_set_to_rmii,
	.set_rmii_speed = px30_set_rmii_speed,
};

#define RK1808_GRF_GMAC_CON0		0X0900
#define RK1808_GRF_GMAC_CON1		0X0904

/* RK1808_GRF_GMAC_CON0 */
#define RK1808_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 8)
#define RK1808_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

/* RK1808_GRF_GMAC_CON1 */
#define RK1808_GMAC_PHY_INTF_SEL_RGMII	\
		(GRF_BIT(4) | GRF_CLR_BIT(5) | GRF_CLR_BIT(6))
#define RK1808_GMAC_PHY_INTF_SEL_RMII	\
		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5) | GRF_BIT(6))
#define RK1808_GMAC_FLOW_CTRL		GRF_BIT(3)
#define RK1808_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(3)
#define RK1808_GMAC_SPEED_10M		GRF_CLR_BIT(2)
#define RK1808_GMAC_SPEED_100M		GRF_BIT(2)
#define RK1808_GMAC_RXCLK_DLY_ENABLE	GRF_BIT(1)
#define RK1808_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(1)
#define RK1808_GMAC_TXCLK_DLY_ENABLE	GRF_BIT(0)
#define RK1808_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(0)

static void rk1808_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK1808_GRF_GMAC_CON1,
		     RK1808_GMAC_PHY_INTF_SEL_RGMII |
		     DELAY_ENABLE(RK1808, tx_delay, rx_delay));

	regmap_write(bsp_priv->grf, RK1808_GRF_GMAC_CON0,
		     DELAY_VALUE(RK1808, tx_delay, rx_delay));
}

static void rk1808_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK1808_GRF_GMAC_CON1,
		     RK1808_GMAC_PHY_INTF_SEL_RMII);
}

static void rk1808_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	int ret;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10) {
		ret = clk_set_rate(bsp_priv->clk_mac_speed, 2500000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 2500000 failed: %d\n",
				__func__, ret);
	} else if (speed == 100) {
		ret = clk_set_rate(bsp_priv->clk_mac_speed, 25000000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 25000000 failed: %d\n",
				__func__, ret);
	} else if (speed == 1000) {
		ret = clk_set_rate(bsp_priv->clk_mac_speed, 125000000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 125000000 failed: %d\n",
				__func__, ret);
	} else {
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
	}
}

static void rk1808_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	int ret;

	if (IS_ERR(bsp_priv->clk_mac_speed)) {
		dev_err(dev, "%s: Missing clk_mac_speed clock\n", __func__);
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RK1808_GRF_GMAC_CON1,
			     RK1808_GMAC_SPEED_10M);

		ret = clk_set_rate(bsp_priv->clk_mac_speed, 2500000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 2500000 failed: %d\n",
				__func__, ret);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RK1808_GRF_GMAC_CON1,
			     RK1808_GMAC_SPEED_100M);

		ret = clk_set_rate(bsp_priv->clk_mac_speed, 25000000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 25000000 failed: %d\n",
				__func__, ret);

	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rk1808_ops = {
	.set_to_rgmii = rk1808_set_to_rgmii,
	.set_to_rmii = rk1808_set_to_rmii,
	.set_rgmii_speed = rk1808_set_rgmii_speed,
	.set_rmii_speed = rk1808_set_rmii_speed,
};

#define RK3128_GRF_MAC_CON0	0x0168
#define RK3128_GRF_MAC_CON1	0x016c

/* RK3128_GRF_MAC_CON0 */
#define RK3128_GMAC_TXCLK_DLY_ENABLE   GRF_BIT(14)
#define RK3128_GMAC_TXCLK_DLY_DISABLE  GRF_CLR_BIT(14)
#define RK3128_GMAC_RXCLK_DLY_ENABLE   GRF_BIT(15)
#define RK3128_GMAC_RXCLK_DLY_DISABLE  GRF_CLR_BIT(15)
#define RK3128_GMAC_CLK_RX_DL_CFG(val) HIWORD_UPDATE(val, 0x7F, 7)
#define RK3128_GMAC_CLK_TX_DL_CFG(val) HIWORD_UPDATE(val, 0x7F, 0)

/* RK3128_GRF_MAC_CON1 */
#define RK3128_GMAC_PHY_INTF_SEL_RGMII	\
		(GRF_BIT(6) | GRF_CLR_BIT(7) | GRF_CLR_BIT(8))
#define RK3128_GMAC_PHY_INTF_SEL_RMII	\
		(GRF_CLR_BIT(6) | GRF_CLR_BIT(7) | GRF_BIT(8))
#define RK3128_GMAC_FLOW_CTRL          GRF_BIT(9)
#define RK3128_GMAC_FLOW_CTRL_CLR      GRF_CLR_BIT(9)
#define RK3128_GMAC_SPEED_10M          GRF_CLR_BIT(10)
#define RK3128_GMAC_SPEED_100M         GRF_BIT(10)
#define RK3128_GMAC_RMII_CLK_25M       GRF_BIT(11)
#define RK3128_GMAC_RMII_CLK_2_5M      GRF_CLR_BIT(11)
#define RK3128_GMAC_CLK_125M           (GRF_CLR_BIT(12) | GRF_CLR_BIT(13))
#define RK3128_GMAC_CLK_25M            (GRF_BIT(12) | GRF_BIT(13))
#define RK3128_GMAC_CLK_2_5M           (GRF_CLR_BIT(12) | GRF_BIT(13))
#define RK3128_GMAC_RMII_MODE          GRF_BIT(14)
#define RK3128_GMAC_RMII_MODE_CLR      GRF_CLR_BIT(14)

static void rk3128_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON1,
		     RK3128_GMAC_PHY_INTF_SEL_RGMII |
		     RK3128_GMAC_RMII_MODE_CLR);
	regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON0,
		     DELAY_ENABLE(RK3128, tx_delay, rx_delay) |
		     DELAY_VALUE(RK3128, tx_delay, rx_delay));
}

static void rk3128_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON1,
		     RK3128_GMAC_PHY_INTF_SEL_RMII | RK3128_GMAC_RMII_MODE);
}

static void rk3128_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON1,
			     RK3128_GMAC_CLK_2_5M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON1,
			     RK3128_GMAC_CLK_25M);
	else if (speed == 1000)
		regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON1,
			     RK3128_GMAC_CLK_125M);
	else
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
}

static void rk3128_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON1,
			     RK3128_GMAC_RMII_CLK_2_5M |
			     RK3128_GMAC_SPEED_10M);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RK3128_GRF_MAC_CON1,
			     RK3128_GMAC_RMII_CLK_25M |
			     RK3128_GMAC_SPEED_100M);
	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rk3128_ops = {
	.set_to_rgmii = rk3128_set_to_rgmii,
	.set_to_rmii = rk3128_set_to_rmii,
	.set_rgmii_speed = rk3128_set_rgmii_speed,
	.set_rmii_speed = rk3128_set_rmii_speed,
};

#define RK3228_GRF_MAC_CON0	0x0900
#define RK3228_GRF_MAC_CON1	0x0904

#define RK3228_GRF_CON_MUX	0x50

/* RK3228_GRF_MAC_CON0 */
#define RK3228_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 7)
#define RK3228_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

/* RK3228_GRF_MAC_CON1 */
#define RK3228_GMAC_PHY_INTF_SEL_RGMII	\
		(GRF_BIT(4) | GRF_CLR_BIT(5) | GRF_CLR_BIT(6))
#define RK3228_GMAC_PHY_INTF_SEL_RMII	\
		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5) | GRF_BIT(6))
#define RK3228_GMAC_FLOW_CTRL		GRF_BIT(3)
#define RK3228_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(3)
#define RK3228_GMAC_SPEED_10M		GRF_CLR_BIT(2)
#define RK3228_GMAC_SPEED_100M		GRF_BIT(2)
#define RK3228_GMAC_RMII_CLK_25M	GRF_BIT(7)
#define RK3228_GMAC_RMII_CLK_2_5M	GRF_CLR_BIT(7)
#define RK3228_GMAC_CLK_125M		(GRF_CLR_BIT(8) | GRF_CLR_BIT(9))
#define RK3228_GMAC_CLK_25M		(GRF_BIT(8) | GRF_BIT(9))
#define RK3228_GMAC_CLK_2_5M		(GRF_CLR_BIT(8) | GRF_BIT(9))
#define RK3228_GMAC_RMII_MODE		GRF_BIT(10)
#define RK3228_GMAC_RMII_MODE_CLR	GRF_CLR_BIT(10)
#define RK3228_GMAC_TXCLK_DLY_ENABLE	GRF_BIT(0)
#define RK3228_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(0)
#define RK3228_GMAC_RXCLK_DLY_ENABLE	GRF_BIT(1)
#define RK3228_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(1)

/* RK3228_GRF_COM_MUX */
#define RK3228_GRF_CON_MUX_GMAC_INTEGRATED_PHY	GRF_BIT(15)

static void rk3228_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1,
		     RK3228_GMAC_PHY_INTF_SEL_RGMII |
		     RK3228_GMAC_RMII_MODE_CLR |
		     DELAY_ENABLE(RK3228, tx_delay, rx_delay));

	regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON0,
		     DELAY_VALUE(RK3128, tx_delay, rx_delay));
}

static void rk3228_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1,
		     RK3228_GMAC_PHY_INTF_SEL_RMII |
		     RK3228_GMAC_RMII_MODE);

	/* set MAC to RMII mode */
	regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1, GRF_BIT(11));
}

static void rk3228_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1,
			     RK3228_GMAC_CLK_2_5M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1,
			     RK3228_GMAC_CLK_25M);
	else if (speed == 1000)
		regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1,
			     RK3228_GMAC_CLK_125M);
	else
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
}

static void rk3228_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1,
			     RK3228_GMAC_RMII_CLK_2_5M |
			     RK3228_GMAC_SPEED_10M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3228_GRF_MAC_CON1,
			     RK3228_GMAC_RMII_CLK_25M |
			     RK3228_GMAC_SPEED_100M);
	else
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
}

static void rk3228_integrated_phy_powerup(struct rk_priv_data *priv)
{
	regmap_write(priv->grf, RK3228_GRF_CON_MUX,
		     RK3228_GRF_CON_MUX_GMAC_INTEGRATED_PHY);
}

static const struct rk_gmac_ops rk3228_ops = {
	.set_to_rgmii = rk3228_set_to_rgmii,
	.set_to_rmii = rk3228_set_to_rmii,
	.set_rgmii_speed = rk3228_set_rgmii_speed,
	.set_rmii_speed = rk3228_set_rmii_speed,
	.integrated_phy_powerup =  rk3228_integrated_phy_powerup,
};

#define RK3288_GRF_SOC_CON1	0x0248
#define RK3288_GRF_SOC_CON3	0x0250

/*RK3288_GRF_SOC_CON1*/
#define RK3288_GMAC_PHY_INTF_SEL_RGMII	(GRF_BIT(6) | GRF_CLR_BIT(7) | \
					 GRF_CLR_BIT(8))
#define RK3288_GMAC_PHY_INTF_SEL_RMII	(GRF_CLR_BIT(6) | GRF_CLR_BIT(7) | \
					 GRF_BIT(8))
#define RK3288_GMAC_FLOW_CTRL		GRF_BIT(9)
#define RK3288_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(9)
#define RK3288_GMAC_SPEED_10M		GRF_CLR_BIT(10)
#define RK3288_GMAC_SPEED_100M		GRF_BIT(10)
#define RK3288_GMAC_RMII_CLK_25M	GRF_BIT(11)
#define RK3288_GMAC_RMII_CLK_2_5M	GRF_CLR_BIT(11)
#define RK3288_GMAC_CLK_125M		(GRF_CLR_BIT(12) | GRF_CLR_BIT(13))
#define RK3288_GMAC_CLK_25M		(GRF_BIT(12) | GRF_BIT(13))
#define RK3288_GMAC_CLK_2_5M		(GRF_CLR_BIT(12) | GRF_BIT(13))
#define RK3288_GMAC_RMII_MODE		GRF_BIT(14)
#define RK3288_GMAC_RMII_MODE_CLR	GRF_CLR_BIT(14)

/*RK3288_GRF_SOC_CON3*/
#define RK3288_GMAC_TXCLK_DLY_ENABLE	GRF_BIT(14)
#define RK3288_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(14)
#define RK3288_GMAC_RXCLK_DLY_ENABLE	GRF_BIT(15)
#define RK3288_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(15)
#define RK3288_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 7)
#define RK3288_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

static void rk3288_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON1,
		     RK3288_GMAC_PHY_INTF_SEL_RGMII |
		     RK3288_GMAC_RMII_MODE_CLR);
	regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON3,
		     DELAY_ENABLE(RK3288, tx_delay, rx_delay) |
		     DELAY_VALUE(RK3288, tx_delay, rx_delay));
}

static void rk3288_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON1,
		     RK3288_GMAC_PHY_INTF_SEL_RMII | RK3288_GMAC_RMII_MODE);
}

static void rk3288_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON1,
			     RK3288_GMAC_CLK_2_5M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON1,
			     RK3288_GMAC_CLK_25M);
	else if (speed == 1000)
		regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON1,
			     RK3288_GMAC_CLK_125M);
	else
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
}

static void rk3288_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON1,
			     RK3288_GMAC_RMII_CLK_2_5M |
			     RK3288_GMAC_SPEED_10M);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RK3288_GRF_SOC_CON1,
			     RK3288_GMAC_RMII_CLK_25M |
			     RK3288_GMAC_SPEED_100M);
	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rk3288_ops = {
	.set_to_rgmii = rk3288_set_to_rgmii,
	.set_to_rmii = rk3288_set_to_rmii,
	.set_rgmii_speed = rk3288_set_rgmii_speed,
	.set_rmii_speed = rk3288_set_rmii_speed,
};

#define RK3308_GRF_MAC_CON0		0x04a0

/* Rk3308_GRF_MAC_CON1 */
#define RK3308_MAC_PHY_INTF_SEL_RMII	(GRF_CLR_BIT(2) | GRF_CLR_BIT(3) | \
					GRF_BIT(4))
#define RK3308_MAC_SPEED_10M		GRF_CLR_BIT(0)
#define Rk3308_MAC_SPEED_100M		GRF_BIT(0)

static void rk3308_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK3308_GRF_MAC_CON0,
		     RK3308_MAC_PHY_INTF_SEL_RMII);
}

static void rk3308_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	int ret;

	if (IS_ERR(bsp_priv->clk_mac_speed)) {
		dev_err(dev, "%s: Missing clk_mac_speed clock\n", __func__);
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RK3308_GRF_MAC_CON0,
			     RK3308_MAC_SPEED_10M);

		ret = clk_set_rate(bsp_priv->clk_mac_speed, 2500000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 2500000 failed: %d\n",
				__func__, ret);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RK3308_GRF_MAC_CON0,
			     Rk3308_MAC_SPEED_100M);

		ret = clk_set_rate(bsp_priv->clk_mac_speed, 25000000);
		if (ret)
			dev_err(dev, "%s: set clk_mac_speed rate 25000000 failed: %d\n",
				__func__, ret);

	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rk3308_ops = {
	.set_to_rmii = rk3308_set_to_rmii,
	.set_rmii_speed = rk3308_set_rmii_speed,
};

#define RK3328_GRF_MAC_CON0	0x0900
#define RK3328_GRF_MAC_CON1	0x0904
#define RK3328_GRF_MAC_CON2	0x0908
#define RK3328_GRF_MACPHY_CON1	0xb04

/* RK3328_GRF_MAC_CON0 */
#define RK3328_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 7)
#define RK3328_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

/* RK3328_GRF_MAC_CON1 */
#define RK3328_GMAC_PHY_INTF_SEL_RGMII	\
		(GRF_BIT(4) | GRF_CLR_BIT(5) | GRF_CLR_BIT(6))
#define RK3328_GMAC_PHY_INTF_SEL_RMII	\
		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5) | GRF_BIT(6))
#define RK3328_GMAC_FLOW_CTRL		GRF_BIT(3)
#define RK3328_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(3)
#define RK3328_GMAC_SPEED_10M		GRF_CLR_BIT(2)
#define RK3328_GMAC_SPEED_100M		GRF_BIT(2)
#define RK3328_GMAC_RMII_CLK_25M	GRF_BIT(7)
#define RK3328_GMAC_RMII_CLK_2_5M	GRF_CLR_BIT(7)
#define RK3328_GMAC_CLK_125M		(GRF_CLR_BIT(11) | GRF_CLR_BIT(12))
#define RK3328_GMAC_CLK_25M		(GRF_BIT(11) | GRF_BIT(12))
#define RK3328_GMAC_CLK_2_5M		(GRF_CLR_BIT(11) | GRF_BIT(12))
#define RK3328_GMAC_RMII_MODE		GRF_BIT(9)
#define RK3328_GMAC_RMII_MODE_CLR	GRF_CLR_BIT(9)
#define RK3328_GMAC_TXCLK_DLY_ENABLE	GRF_BIT(0)
#define RK3328_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(0)
#define RK3328_GMAC_RXCLK_DLY_ENABLE	GRF_BIT(1)
#define RK3328_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(0)

/* RK3328_GRF_MACPHY_CON1 */
#define RK3328_MACPHY_RMII_MODE		GRF_BIT(9)

static void rk3328_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RK3328_GRF_MAC_CON1,
		     RK3328_GMAC_PHY_INTF_SEL_RGMII |
		     RK3328_GMAC_RMII_MODE_CLR |
		     DELAY_ENABLE(RK3328, tx_delay, rx_delay));

	regmap_write(bsp_priv->grf, RK3328_GRF_MAC_CON0,
		     DELAY_VALUE(RK3328, tx_delay, rx_delay));
}

static void rk3328_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;
	unsigned int reg;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	reg = bsp_priv->integrated_phy ? RK3328_GRF_MAC_CON2 :
		  RK3328_GRF_MAC_CON1;

	regmap_write(bsp_priv->grf, reg,
		     RK3328_GMAC_PHY_INTF_SEL_RMII |
		     RK3328_GMAC_RMII_MODE);
}

static void rk3328_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3328_GRF_MAC_CON1,
			     RK3328_GMAC_CLK_2_5M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3328_GRF_MAC_CON1,
			     RK3328_GMAC_CLK_25M);
	else if (speed == 1000)
		regmap_write(bsp_priv->grf, RK3328_GRF_MAC_CON1,
			     RK3328_GMAC_CLK_125M);
	else
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
}

static void rk3328_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	unsigned int reg;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	reg = bsp_priv->integrated_phy ? RK3328_GRF_MAC_CON2 :
		  RK3328_GRF_MAC_CON1;

	if (speed == 10)
		regmap_write(bsp_priv->grf, reg,
			     RK3328_GMAC_RMII_CLK_2_5M |
			     RK3328_GMAC_SPEED_10M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, reg,
			     RK3328_GMAC_RMII_CLK_25M |
			     RK3328_GMAC_SPEED_100M);
	else
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
}

static void rk3328_integrated_phy_powerup(struct rk_priv_data *priv)
{
	regmap_write(priv->grf, RK3328_GRF_MACPHY_CON1,
		     RK3328_MACPHY_RMII_MODE);
}

static const struct rk_gmac_ops rk3328_ops = {
	.set_to_rgmii = rk3328_set_to_rgmii,
	.set_to_rmii = rk3328_set_to_rmii,
	.set_rgmii_speed = rk3328_set_rgmii_speed,
	.set_rmii_speed = rk3328_set_rmii_speed,
	.integrated_phy_powerup =  rk3328_integrated_phy_powerup,
};

#define RK3366_GRF_SOC_CON6	0x0418
#define RK3366_GRF_SOC_CON7	0x041c

/* RK3366_GRF_SOC_CON6 */
#define RK3366_GMAC_PHY_INTF_SEL_RGMII	(GRF_BIT(9) | GRF_CLR_BIT(10) | \
					 GRF_CLR_BIT(11))
#define RK3366_GMAC_PHY_INTF_SEL_RMII	(GRF_CLR_BIT(9) | GRF_CLR_BIT(10) | \
					 GRF_BIT(11))
#define RK3366_GMAC_FLOW_CTRL		GRF_BIT(8)
#define RK3366_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(8)
#define RK3366_GMAC_SPEED_10M		GRF_CLR_BIT(7)
#define RK3366_GMAC_SPEED_100M		GRF_BIT(7)
#define RK3366_GMAC_RMII_CLK_25M	GRF_BIT(3)
#define RK3366_GMAC_RMII_CLK_2_5M	GRF_CLR_BIT(3)
#define RK3366_GMAC_CLK_125M		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5))
#define RK3366_GMAC_CLK_25M		(GRF_BIT(4) | GRF_BIT(5))
#define RK3366_GMAC_CLK_2_5M		(GRF_CLR_BIT(4) | GRF_BIT(5))
#define RK3366_GMAC_RMII_MODE		GRF_BIT(6)
#define RK3366_GMAC_RMII_MODE_CLR	GRF_CLR_BIT(6)

/* RK3366_GRF_SOC_CON7 */
#define RK3366_GMAC_TXCLK_DLY_ENABLE	GRF_BIT(7)
#define RK3366_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(7)
#define RK3366_GMAC_RXCLK_DLY_ENABLE	GRF_BIT(15)
#define RK3366_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(15)
#define RK3366_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 8)
#define RK3366_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

static void rk3366_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON6,
		     RK3366_GMAC_PHY_INTF_SEL_RGMII |
		     RK3366_GMAC_RMII_MODE_CLR);
	regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON7,
		     DELAY_ENABLE(RK3366, tx_delay, rx_delay) |
		     DELAY_VALUE(RK3366, tx_delay, rx_delay));
}

static void rk3366_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON6,
		     RK3366_GMAC_PHY_INTF_SEL_RMII | RK3366_GMAC_RMII_MODE);
}

static void rk3366_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON6,
			     RK3366_GMAC_CLK_2_5M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON6,
			     RK3366_GMAC_CLK_25M);
	else if (speed == 1000)
		regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON6,
			     RK3366_GMAC_CLK_125M);
	else
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
}

static void rk3366_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON6,
			     RK3366_GMAC_RMII_CLK_2_5M |
			     RK3366_GMAC_SPEED_10M);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RK3366_GRF_SOC_CON6,
			     RK3366_GMAC_RMII_CLK_25M |
			     RK3366_GMAC_SPEED_100M);
	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rk3366_ops = {
	.set_to_rgmii = rk3366_set_to_rgmii,
	.set_to_rmii = rk3366_set_to_rmii,
	.set_rgmii_speed = rk3366_set_rgmii_speed,
	.set_rmii_speed = rk3366_set_rmii_speed,
};

#define RK3368_GRF_SOC_CON15	0x043c
#define RK3368_GRF_SOC_CON16	0x0440

/* RK3368_GRF_SOC_CON15 */
#define RK3368_GMAC_PHY_INTF_SEL_RGMII	(GRF_BIT(9) | GRF_CLR_BIT(10) | \
					 GRF_CLR_BIT(11))
#define RK3368_GMAC_PHY_INTF_SEL_RMII	(GRF_CLR_BIT(9) | GRF_CLR_BIT(10) | \
					 GRF_BIT(11))
#define RK3368_GMAC_FLOW_CTRL		GRF_BIT(8)
#define RK3368_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(8)
#define RK3368_GMAC_SPEED_10M		GRF_CLR_BIT(7)
#define RK3368_GMAC_SPEED_100M		GRF_BIT(7)
#define RK3368_GMAC_RMII_CLK_25M	GRF_BIT(3)
#define RK3368_GMAC_RMII_CLK_2_5M	GRF_CLR_BIT(3)
#define RK3368_GMAC_CLK_125M		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5))
#define RK3368_GMAC_CLK_25M		(GRF_BIT(4) | GRF_BIT(5))
#define RK3368_GMAC_CLK_2_5M		(GRF_CLR_BIT(4) | GRF_BIT(5))
#define RK3368_GMAC_RMII_MODE		GRF_BIT(6)
#define RK3368_GMAC_RMII_MODE_CLR	GRF_CLR_BIT(6)

/* RK3368_GRF_SOC_CON16 */
#define RK3368_GMAC_TXCLK_DLY_ENABLE	GRF_BIT(7)
#define RK3368_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(7)
#define RK3368_GMAC_RXCLK_DLY_ENABLE	GRF_BIT(15)
#define RK3368_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(15)
#define RK3368_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 8)
#define RK3368_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

static void rk3368_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON15,
		     RK3368_GMAC_PHY_INTF_SEL_RGMII |
		     RK3368_GMAC_RMII_MODE_CLR);
	regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON16,
		     DELAY_ENABLE(RK3368, tx_delay, rx_delay) |
		     DELAY_VALUE(RK3368, tx_delay, rx_delay));
}

static void rk3368_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON15,
		     RK3368_GMAC_PHY_INTF_SEL_RMII | RK3368_GMAC_RMII_MODE);
}

static void rk3368_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON15,
			     RK3368_GMAC_CLK_2_5M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON15,
			     RK3368_GMAC_CLK_25M);
	else if (speed == 1000)
		regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON15,
			     RK3368_GMAC_CLK_125M);
	else
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
}

static void rk3368_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON15,
			     RK3368_GMAC_RMII_CLK_2_5M |
			     RK3368_GMAC_SPEED_10M);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RK3368_GRF_SOC_CON15,
			     RK3368_GMAC_RMII_CLK_25M |
			     RK3368_GMAC_SPEED_100M);
	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rk3368_ops = {
	.set_to_rgmii = rk3368_set_to_rgmii,
	.set_to_rmii = rk3368_set_to_rmii,
	.set_rgmii_speed = rk3368_set_rgmii_speed,
	.set_rmii_speed = rk3368_set_rmii_speed,
};

#define RK3399_GRF_SOC_CON5	0xc214
#define RK3399_GRF_SOC_CON6	0xc218

/* RK3399_GRF_SOC_CON5 */
#define RK3399_GMAC_PHY_INTF_SEL_RGMII	(GRF_BIT(9) | GRF_CLR_BIT(10) | \
					 GRF_CLR_BIT(11))
#define RK3399_GMAC_PHY_INTF_SEL_RMII	(GRF_CLR_BIT(9) | GRF_CLR_BIT(10) | \
					 GRF_BIT(11))
#define RK3399_GMAC_FLOW_CTRL		GRF_BIT(8)
#define RK3399_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(8)
#define RK3399_GMAC_SPEED_10M		GRF_CLR_BIT(7)
#define RK3399_GMAC_SPEED_100M		GRF_BIT(7)
#define RK3399_GMAC_RMII_CLK_25M	GRF_BIT(3)
#define RK3399_GMAC_RMII_CLK_2_5M	GRF_CLR_BIT(3)
#define RK3399_GMAC_CLK_125M		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5))
#define RK3399_GMAC_CLK_25M		(GRF_BIT(4) | GRF_BIT(5))
#define RK3399_GMAC_CLK_2_5M		(GRF_CLR_BIT(4) | GRF_BIT(5))
#define RK3399_GMAC_RMII_MODE		GRF_BIT(6)
#define RK3399_GMAC_RMII_MODE_CLR	GRF_CLR_BIT(6)

/* RK3399_GRF_SOC_CON6 */
#define RK3399_GMAC_TXCLK_DLY_ENABLE	GRF_BIT(7)
#define RK3399_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(7)
#define RK3399_GMAC_RXCLK_DLY_ENABLE	GRF_BIT(15)
#define RK3399_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(15)
#define RK3399_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 8)
#define RK3399_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

static void rk3399_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON5,
		     RK3399_GMAC_PHY_INTF_SEL_RGMII |
		     RK3399_GMAC_RMII_MODE_CLR);
	regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON6,
		     DELAY_ENABLE(RK3399, tx_delay, rx_delay) |
		     DELAY_VALUE(RK3399, tx_delay, rx_delay));
}

static void rk3399_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON5,
		     RK3399_GMAC_PHY_INTF_SEL_RMII | RK3399_GMAC_RMII_MODE);
}

static void rk3399_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	if (speed == 10)
		regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON5,
			     RK3399_GMAC_CLK_2_5M);
	else if (speed == 100)
		regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON5,
			     RK3399_GMAC_CLK_25M);
	else if (speed == 1000)
		regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON5,
			     RK3399_GMAC_CLK_125M);
	else
		dev_err(dev, "unknown speed value for RGMII! speed=%d", speed);
}

static void rk3399_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON5,
			     RK3399_GMAC_RMII_CLK_2_5M |
			     RK3399_GMAC_SPEED_10M);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RK3399_GRF_SOC_CON5,
			     RK3399_GMAC_RMII_CLK_25M |
			     RK3399_GMAC_SPEED_100M);
	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rk3399_ops = {
	.set_to_rgmii = rk3399_set_to_rgmii,
	.set_to_rmii = rk3399_set_to_rmii,
	.set_rgmii_speed = rk3399_set_rgmii_speed,
	.set_rmii_speed = rk3399_set_rmii_speed,
};

#define RK3568_GRF_GMAC0_CON0		0X0380
#define RK3568_GRF_GMAC0_CON1		0X0384
#define RK3568_GRF_GMAC1_CON0		0X0388
#define RK3568_GRF_GMAC1_CON1		0X038c

/* RK3568_GRF_GMAC0_CON1 && RK3568_GRF_GMAC1_CON1 */
#define RK3568_GMAC_GMII_MODE			GRF_BIT(7)
#define RK3568_GMAC_PHY_INTF_SEL_RGMII	\
		(GRF_BIT(4) | GRF_CLR_BIT(5) | GRF_CLR_BIT(6))
#define RK3568_GMAC_PHY_INTF_SEL_RMII	\
		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5) | GRF_BIT(6))
#define RK3568_GMAC_FLOW_CTRL			GRF_BIT(3)
#define RK3568_GMAC_FLOW_CTRL_CLR		GRF_CLR_BIT(3)
#define RK3568_GMAC_RXCLK_DLY_ENABLE		GRF_BIT(1)
#define RK3568_GMAC_RXCLK_DLY_DISABLE		GRF_CLR_BIT(1)
#define RK3568_GMAC_TXCLK_DLY_ENABLE		GRF_BIT(0)
#define RK3568_GMAC_TXCLK_DLY_DISABLE		GRF_CLR_BIT(0)

/* RK3568_GRF_GMAC0_CON0 && RK3568_GRF_GMAC1_CON0 */
#define RK3568_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 8)
#define RK3568_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

#define RK3568_PIPE_GRF_XPCS_CON0	0X0040

#define RK3568_PIPE_GRF_XPCS_QGMII_MAC_SEL	GRF_BIT(0)
#define RK3568_PIPE_GRF_XPCS_SGMII_MAC_SEL	GRF_BIT(1)
#define RK3568_PIPE_GRF_XPCS_PHY_READY		GRF_BIT(2)

static void rk3568_set_to_sgmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;
	u32 offset_con1;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grfs property\n", __func__);
		return;
	}

	offset_con1 = bsp_priv->bus_id == 1 ? RK3568_GRF_GMAC1_CON1 :
					      RK3568_GRF_GMAC0_CON1;
	regmap_write(bsp_priv->grf, offset_con1, RK3568_GMAC_GMII_MODE);

	xpcs_setup(bsp_priv, PHY_INTERFACE_MODE_SGMII);
}

static void rk3568_set_to_qsgmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;
	u32 offset_con1;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grfs property\n", __func__);
		return;
	}

	offset_con1 = bsp_priv->bus_id == 1 ? RK3568_GRF_GMAC1_CON1 :
					      RK3568_GRF_GMAC0_CON1;
	regmap_write(bsp_priv->grf, offset_con1, RK3568_GMAC_GMII_MODE);

	xpcs_setup(bsp_priv, PHY_INTERFACE_MODE_QSGMII);
}

static void rk3568_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;
	u32 offset_con0, offset_con1;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	offset_con0 = (bsp_priv->bus_id == 1) ? RK3568_GRF_GMAC1_CON0 :
						RK3568_GRF_GMAC0_CON0;
	offset_con1 = (bsp_priv->bus_id == 1) ? RK3568_GRF_GMAC1_CON1 :
						RK3568_GRF_GMAC0_CON1;

	regmap_write(bsp_priv->grf, offset_con1,
		     RK3568_GMAC_PHY_INTF_SEL_RGMII |
		     DELAY_ENABLE(RK3568, tx_delay, rx_delay));

	regmap_write(bsp_priv->grf, offset_con0,
		     DELAY_VALUE(RK3568, tx_delay, rx_delay));
}

static void rk3568_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;
	u32 offset_con1;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	offset_con1 = (bsp_priv->bus_id == 1) ? RK3568_GRF_GMAC1_CON1 :
						RK3568_GRF_GMAC0_CON1;

	regmap_write(bsp_priv->grf, offset_con1, RK3568_GMAC_PHY_INTF_SEL_RMII);
}

static void rk3568_set_gmac_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	unsigned long rate;
	int ret;

	switch (speed) {
	case 10:
		rate = 2500000;
		break;
	case 100:
		rate = 25000000;
		break;
	case 1000:
		rate = 125000000;
		break;
	default:
		dev_err(dev, "unknown speed value for GMAC speed=%d", speed);
		return;
	}

	ret = clk_set_rate(bsp_priv->clk_mac_speed, rate);
	if (ret)
		dev_err(dev, "%s: set clk_mac_speed rate %ld failed %d\n",
			__func__, rate, ret);
}

static const struct rk_gmac_ops rk3568_ops = {
	.set_to_rgmii = rk3568_set_to_rgmii,
	.set_to_rmii = rk3568_set_to_rmii,
	.set_to_sgmii = rk3568_set_to_sgmii,
	.set_to_qsgmii = rk3568_set_to_qsgmii,
	.set_rgmii_speed = rk3568_set_gmac_speed,
	.set_rmii_speed = rk3568_set_gmac_speed,
};

/* sys_grf */
#define RK3588_GRF_GMAC_CON7			0X031c
#define RK3588_GRF_GMAC_CON8			0X0320
#define RK3588_GRF_GMAC_CON9			0X0324

#define RK3588_GMAC_RXCLK_DLY_ENABLE(id)	GRF_BIT(2 * (id) + 3)
#define RK3588_GMAC_RXCLK_DLY_DISABLE(id)	GRF_CLR_BIT(2 * (id) + 3)
#define RK3588_GMAC_TXCLK_DLY_ENABLE(id)	GRF_BIT(2 * (id) + 2)
#define RK3588_GMAC_TXCLK_DLY_DISABLE(id)	GRF_CLR_BIT(2 * (id) + 2)

#define RK3588_GMAC_CLK_RX_DL_CFG(val)		HIWORD_UPDATE(val, 0xFF, 8)
#define RK3588_GMAC_CLK_TX_DL_CFG(val)		HIWORD_UPDATE(val, 0xFF, 0)

/* php_grf */
#define RK3588_GRF_GMAC_CON0			0X0008
#define RK3588_GRF_CLK_CON1			0X0070

#define RK3588_GMAC_PHY_INTF_SEL_RGMII(id)	\
	(GRF_BIT(3 + (id) * 6) | GRF_CLR_BIT(4 + (id) * 6) | GRF_CLR_BIT(5 + (id) * 6))
#define RK3588_GMAC_PHY_INTF_SEL_RMII(id)	\
	(GRF_CLR_BIT(3 + (id) * 6) | GRF_CLR_BIT(4 + (id) * 6) | GRF_BIT(5 + (id) * 6))

#define RK3588_GMAC_CLK_RMII_MODE(id)		GRF_BIT(5 * (id))
#define RK3588_GMAC_CLK_RGMII_MODE(id)		GRF_CLR_BIT(5 * (id))

#define RK3588_GMAC_CLK_SELET_CRU(id)		GRF_BIT(5 * (id) + 4)
#define RK3588_GMAC_CLK_SELET_IO(id)		GRF_CLR_BIT(5 * (id) + 4)

#define RK3588_GMA_CLK_RMII_DIV2(id)		GRF_BIT(5 * (id) + 2)
#define RK3588_GMA_CLK_RMII_DIV20(id)		GRF_CLR_BIT(5 * (id) + 2)

#define RK3588_GMAC_CLK_RGMII_DIV1(id)		\
			(GRF_CLR_BIT(5 * (id) + 2) | GRF_CLR_BIT(5 * (id) + 3))
#define RK3588_GMAC_CLK_RGMII_DIV5(id)		\
			(GRF_BIT(5 * (id) + 2) | GRF_BIT(5 * (id) + 3))
#define RK3588_GMAC_CLK_RGMII_DIV50(id)		\
			(GRF_CLR_BIT(5 * (id) + 2) | GRF_BIT(5 * (id) + 3))

#define RK3588_GMAC_CLK_RMII_GATE(id)		GRF_BIT(5 * (id) + 1)
#define RK3588_GMAC_CLK_RMII_NOGATE(id)		GRF_CLR_BIT(5 * (id) + 1)

static void rk3588_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;
	u32 offset_con, id = bsp_priv->bus_id;

	if (IS_ERR(bsp_priv->grf) || IS_ERR(bsp_priv->php_grf)) {
		dev_err(dev, "Missing rockchip,grf or rockchip,php_grf property\n");
		return;
	}

	offset_con = bsp_priv->bus_id == 1 ? RK3588_GRF_GMAC_CON9 :
					     RK3588_GRF_GMAC_CON8;

	regmap_write(bsp_priv->php_grf, RK3588_GRF_GMAC_CON0,
		     RK3588_GMAC_PHY_INTF_SEL_RGMII(id));

	regmap_write(bsp_priv->php_grf, RK3588_GRF_CLK_CON1,
		     RK3588_GMAC_CLK_RGMII_MODE(id));

	regmap_write(bsp_priv->grf, RK3588_GRF_GMAC_CON7,
		     DELAY_ENABLE_BY_ID(RK3588, tx_delay, rx_delay, id));

	regmap_write(bsp_priv->grf, offset_con,
		     DELAY_VALUE(RK3588, tx_delay, rx_delay));
}

static void rk3588_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->php_grf)) {
		dev_err(dev, "%s: Missing rockchip,php_grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->php_grf, RK3588_GRF_GMAC_CON0,
		     RK3588_GMAC_PHY_INTF_SEL_RMII(bsp_priv->bus_id));

	regmap_write(bsp_priv->php_grf, RK3588_GRF_CLK_CON1,
		     RK3588_GMAC_CLK_RMII_MODE(bsp_priv->bus_id));
}

static void rk3588_set_gmac_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	unsigned int val = 0, id = bsp_priv->bus_id;

	switch (speed) {
	case 10:
		if (bsp_priv->phy_iface == PHY_INTERFACE_MODE_RMII)
			val = RK3588_GMA_CLK_RMII_DIV20(id);
		else
			val = RK3588_GMAC_CLK_RGMII_DIV50(id);
		break;
	case 100:
		if (bsp_priv->phy_iface == PHY_INTERFACE_MODE_RMII)
			val = RK3588_GMA_CLK_RMII_DIV2(id);
		else
			val = RK3588_GMAC_CLK_RGMII_DIV5(id);
		break;
	case 1000:
		if (bsp_priv->phy_iface != PHY_INTERFACE_MODE_RMII)
			val = RK3588_GMAC_CLK_RGMII_DIV1(id);
		else
			goto err;
		break;
	default:
		goto err;
	}

	regmap_write(bsp_priv->php_grf, RK3588_GRF_CLK_CON1, val);

	return;
err:
	dev_err(dev, "unknown speed value for GMAC speed=%d", speed);
}

static void rk3588_set_clock_selection(struct rk_priv_data *bsp_priv, bool input,
				       bool enable)
{
	unsigned int val = input ? RK3588_GMAC_CLK_SELET_IO(bsp_priv->bus_id) :
				   RK3588_GMAC_CLK_SELET_CRU(bsp_priv->bus_id);

	val |= enable ? RK3588_GMAC_CLK_RMII_NOGATE(bsp_priv->bus_id) :
			RK3588_GMAC_CLK_RMII_GATE(bsp_priv->bus_id);

	regmap_write(bsp_priv->php_grf, RK3588_GRF_CLK_CON1, val);
}

static const struct rk_gmac_ops rk3588_ops = {
	.set_to_rgmii = rk3588_set_to_rgmii,
	.set_to_rmii = rk3588_set_to_rmii,
	.set_rgmii_speed = rk3588_set_gmac_speed,
	.set_rmii_speed = rk3588_set_gmac_speed,
	.set_clock_selection = rk3588_set_clock_selection,
};

#define RV1108_GRF_GMAC_CON0		0X0900

/* RV1108_GRF_GMAC_CON0 */
#define RV1108_GMAC_PHY_INTF_SEL_RMII	(GRF_CLR_BIT(4) | GRF_CLR_BIT(5) | \
					GRF_BIT(6))
#define RV1108_GMAC_FLOW_CTRL		GRF_BIT(3)
#define RV1108_GMAC_FLOW_CTRL_CLR	GRF_CLR_BIT(3)
#define RV1108_GMAC_SPEED_10M		GRF_CLR_BIT(2)
#define RV1108_GMAC_SPEED_100M		GRF_BIT(2)
#define RV1108_GMAC_RMII_CLK_25M	GRF_BIT(7)
#define RV1108_GMAC_RMII_CLK_2_5M	GRF_CLR_BIT(7)

static void rv1108_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RV1108_GRF_GMAC_CON0,
		     RV1108_GMAC_PHY_INTF_SEL_RMII);
}

static void rv1108_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	if (speed == 10) {
		regmap_write(bsp_priv->grf, RV1108_GRF_GMAC_CON0,
			     RV1108_GMAC_RMII_CLK_2_5M |
			     RV1108_GMAC_SPEED_10M);
	} else if (speed == 100) {
		regmap_write(bsp_priv->grf, RV1108_GRF_GMAC_CON0,
			     RV1108_GMAC_RMII_CLK_25M |
			     RV1108_GMAC_SPEED_100M);
	} else {
		dev_err(dev, "unknown speed value for RMII! speed=%d", speed);
	}
}

static const struct rk_gmac_ops rv1108_ops = {
	.set_to_rmii = rv1108_set_to_rmii,
	.set_rmii_speed = rv1108_set_rmii_speed,
};

#define RV1126_GRF_GMAC_CON0		0X0070
#define RV1126_GRF_GMAC_CON1		0X0074
#define RV1126_GRF_GMAC_CON2		0X0078

/* RV1126_GRF_GMAC_CON0 */
#define RV1126_GMAC_PHY_INTF_SEL_RGMII	\
		(GRF_BIT(4) | GRF_CLR_BIT(5) | GRF_CLR_BIT(6))
#define RV1126_GMAC_PHY_INTF_SEL_RMII	\
		(GRF_CLR_BIT(4) | GRF_CLR_BIT(5) | GRF_BIT(6))
#define RV1126_GMAC_FLOW_CTRL			GRF_BIT(7)
#define RV1126_GMAC_FLOW_CTRL_CLR		GRF_CLR_BIT(7)
#define RV1126_M0_GMAC_RXCLK_DLY_ENABLE		GRF_BIT(1)
#define RV1126_M0_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(1)
#define RV1126_M0_GMAC_TXCLK_DLY_ENABLE		GRF_BIT(0)
#define RV1126_M0_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(0)
#define RV1126_M1_GMAC_RXCLK_DLY_ENABLE		GRF_BIT(3)
#define RV1126_M1_GMAC_RXCLK_DLY_DISABLE	GRF_CLR_BIT(3)
#define RV1126_M1_GMAC_TXCLK_DLY_ENABLE		GRF_BIT(2)
#define RV1126_M1_GMAC_TXCLK_DLY_DISABLE	GRF_CLR_BIT(2)

/* RV1126_GRF_GMAC_CON1 && RV1126_GRF_GMAC_CON2 */
#define RV1126_GMAC_CLK_RX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 8)
#define RV1126_GMAC_CLK_TX_DL_CFG(val)	HIWORD_UPDATE(val, 0x7F, 0)

static void rv1126_set_to_rgmii(struct rk_priv_data *bsp_priv,
				int tx_delay, int rx_delay)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "Missing rockchip,grf property\n");
		return;
	}

	regmap_write(bsp_priv->grf, RV1126_GRF_GMAC_CON0,
		     RV1126_GMAC_PHY_INTF_SEL_RGMII |
		     DELAY_ENABLE(RV1126_M0, tx_delay, rx_delay) |
		     DELAY_ENABLE(RV1126_M1, tx_delay, rx_delay));

	regmap_write(bsp_priv->grf, RV1126_GRF_GMAC_CON1,
		     DELAY_VALUE(RV1126, tx_delay, rx_delay));

	regmap_write(bsp_priv->grf, RV1126_GRF_GMAC_CON2,
		     DELAY_VALUE(RV1126, tx_delay, rx_delay));
}

static void rv1126_set_to_rmii(struct rk_priv_data *bsp_priv)
{
	struct device *dev = &bsp_priv->pdev->dev;

	if (IS_ERR(bsp_priv->grf)) {
		dev_err(dev, "%s: Missing rockchip,grf property\n", __func__);
		return;
	}

	regmap_write(bsp_priv->grf, RV1126_GRF_GMAC_CON0,
		     RV1126_GMAC_PHY_INTF_SEL_RMII);
}

static void rv1126_set_rgmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	unsigned long rate;
	int ret;

	switch (speed) {
	case 10:
		rate = 2500000;
		break;
	case 100:
		rate = 25000000;
		break;
	case 1000:
		rate = 125000000;
		break;
	default:
		dev_err(dev, "unknown speed value for RGMII speed=%d", speed);
		return;
	}

	ret = clk_set_rate(bsp_priv->clk_mac_speed, rate);
	if (ret)
		dev_err(dev, "%s: set clk_mac_speed rate %ld failed %d\n",
			__func__, rate, ret);
}

static void rv1126_set_rmii_speed(struct rk_priv_data *bsp_priv, int speed)
{
	struct device *dev = &bsp_priv->pdev->dev;
	unsigned long rate;
	int ret;

	switch (speed) {
	case 10:
		rate = 2500000;
		break;
	case 100:
		rate = 25000000;
		break;
	default:
		dev_err(dev, "unknown speed value for RGMII speed=%d", speed);
		return;
	}

	ret = clk_set_rate(bsp_priv->clk_mac_speed, rate);
	if (ret)
		dev_err(dev, "%s: set clk_mac_speed rate %ld failed %d\n",
			__func__, rate, ret);
}

static const struct rk_gmac_ops rv1126_ops = {
	.set_to_rgmii = rv1126_set_to_rgmii,
	.set_to_rmii = rv1126_set_to_rmii,
	.set_rgmii_speed = rv1126_set_rgmii_speed,
	.set_rmii_speed = rv1126_set_rmii_speed,
};

#define RK_GRF_MACPHY_CON0		0xb00
#define RK_GRF_MACPHY_CON1		0xb04
#define RK_GRF_MACPHY_CON2		0xb08
#define RK_GRF_MACPHY_CON3		0xb0c

#define RK_MACPHY_ENABLE		GRF_BIT(0)
#define RK_MACPHY_DISABLE		GRF_CLR_BIT(0)
#define RK_MACPHY_CFG_CLK_50M		GRF_BIT(14)
#define RK_GMAC2PHY_RMII_MODE		(GRF_BIT(6) | GRF_CLR_BIT(7))
#define RK_GRF_CON2_MACPHY_ID		HIWORD_UPDATE(0x1234, 0xffff, 0)
#define RK_GRF_CON3_MACPHY_ID		HIWORD_UPDATE(0x35, 0x3f, 0)

static void rk_gmac_integrated_phy_powerup(struct rk_priv_data *priv)
{
	if (priv->ops->integrated_phy_powerup)
		priv->ops->integrated_phy_powerup(priv);

	regmap_write(priv->grf, RK_GRF_MACPHY_CON0, RK_MACPHY_CFG_CLK_50M);
	regmap_write(priv->grf, RK_GRF_MACPHY_CON0, RK_GMAC2PHY_RMII_MODE);

	regmap_write(priv->grf, RK_GRF_MACPHY_CON2, RK_GRF_CON2_MACPHY_ID);
	regmap_write(priv->grf, RK_GRF_MACPHY_CON3, RK_GRF_CON3_MACPHY_ID);

	if (priv->phy_reset) {
		/* PHY needs to be disabled before trying to reset it */
		regmap_write(priv->grf, RK_GRF_MACPHY_CON0, RK_MACPHY_DISABLE);
		if (priv->phy_reset)
			reset_control_assert(priv->phy_reset);
		usleep_range(10, 20);
		if (priv->phy_reset)
			reset_control_deassert(priv->phy_reset);
		usleep_range(10, 20);
		regmap_write(priv->grf, RK_GRF_MACPHY_CON0, RK_MACPHY_ENABLE);
		msleep(30);
	}
}

static void rk_gmac_integrated_phy_powerdown(struct rk_priv_data *priv)
{
	regmap_write(priv->grf, RK_GRF_MACPHY_CON0, RK_MACPHY_DISABLE);
	if (priv->phy_reset)
		reset_control_assert(priv->phy_reset);
}

static int rk_gmac_clk_init(struct plat_stmmacenet_data *plat)
{
	struct rk_priv_data *bsp_priv = plat->bsp_priv;
	struct device *dev = &bsp_priv->pdev->dev;
	int ret;

	bsp_priv->clk_enabled = false;

	bsp_priv->mac_clk_rx = devm_clk_get(dev, "mac_clk_rx");
	if (IS_ERR(bsp_priv->mac_clk_rx))
		dev_err(dev, "cannot get clock %s\n",
			"mac_clk_rx");

	bsp_priv->mac_clk_tx = devm_clk_get(dev, "mac_clk_tx");
	if (IS_ERR(bsp_priv->mac_clk_tx))
		dev_err(dev, "cannot get clock %s\n",
			"mac_clk_tx");

	bsp_priv->aclk_mac = devm_clk_get(dev, "aclk_mac");
	if (IS_ERR(bsp_priv->aclk_mac))
		dev_err(dev, "cannot get clock %s\n",
			"aclk_mac");

	bsp_priv->pclk_mac = devm_clk_get(dev, "pclk_mac");
	if (IS_ERR(bsp_priv->pclk_mac))
		dev_err(dev, "cannot get clock %s\n",
			"pclk_mac");

	bsp_priv->clk_mac = devm_clk_get(dev, "stmmaceth");
	if (IS_ERR(bsp_priv->clk_mac))
		dev_err(dev, "cannot get clock %s\n",
			"stmmaceth");

	if (bsp_priv->phy_iface == PHY_INTERFACE_MODE_RMII) {
		bsp_priv->clk_mac_ref = devm_clk_get(dev, "clk_mac_ref");
		if (IS_ERR(bsp_priv->clk_mac_ref))
			dev_err(dev, "cannot get clock %s\n",
				"clk_mac_ref");

		if (!bsp_priv->clock_input) {
			bsp_priv->clk_mac_refout =
				devm_clk_get(dev, "clk_mac_refout");
			if (IS_ERR(bsp_priv->clk_mac_refout))
				dev_err(dev, "cannot get clock %s\n",
					"clk_mac_refout");
		}
	} else if (bsp_priv->phy_iface == PHY_INTERFACE_MODE_SGMII ||
		   bsp_priv->phy_iface == PHY_INTERFACE_MODE_QSGMII) {
		bsp_priv->pclk_xpcs = devm_clk_get(dev, "pclk_xpcs");
		if (IS_ERR(bsp_priv->pclk_xpcs))
			dev_err(dev, "cannot get clock %s\n",
				"pclk_xpcs");
	}

	bsp_priv->clk_mac_speed = devm_clk_get(dev, "clk_mac_speed");
	if (IS_ERR(bsp_priv->clk_mac_speed))
		dev_err(dev, "cannot get clock %s\n", "clk_mac_speed");

	if (bsp_priv->clock_input) {
		dev_info(dev, "clock input from PHY\n");
	} else {
		if (bsp_priv->phy_iface == PHY_INTERFACE_MODE_RMII)
			clk_set_rate(bsp_priv->clk_mac, 50000000);
	}

	if (plat->phy_node) {
		bsp_priv->clk_phy = of_clk_get(plat->phy_node, 0);
		/* If it is not integrated_phy, clk_phy is optional */
		if (bsp_priv->integrated_phy) {
			if (IS_ERR(bsp_priv->clk_phy)) {
				ret = PTR_ERR(bsp_priv->clk_phy);
				dev_err(dev, "Cannot get PHY clock: %d\n", ret);
				return -EINVAL;
			}
			clk_set_rate(bsp_priv->clk_phy, 50000000);
		}
	}

	return 0;
}

static int gmac_clk_enable(struct rk_priv_data *bsp_priv, bool enable)
{
	int phy_iface = bsp_priv->phy_iface;

	if (enable) {
		if (!bsp_priv->clk_enabled) {
			if (phy_iface == PHY_INTERFACE_MODE_RMII) {
				if (!IS_ERR(bsp_priv->mac_clk_rx))
					clk_prepare_enable(
						bsp_priv->mac_clk_rx);

				if (!IS_ERR(bsp_priv->clk_mac_ref))
					clk_prepare_enable(
						bsp_priv->clk_mac_ref);

				if (!IS_ERR(bsp_priv->clk_mac_refout))
					clk_prepare_enable(
						bsp_priv->clk_mac_refout);
			}

			if (!IS_ERR(bsp_priv->clk_phy))
				clk_prepare_enable(bsp_priv->clk_phy);

			if (!IS_ERR(bsp_priv->aclk_mac))
				clk_prepare_enable(bsp_priv->aclk_mac);

			if (!IS_ERR(bsp_priv->pclk_mac))
				clk_prepare_enable(bsp_priv->pclk_mac);

			if (!IS_ERR(bsp_priv->mac_clk_tx))
				clk_prepare_enable(bsp_priv->mac_clk_tx);

			if (!IS_ERR(bsp_priv->clk_mac_speed))
				clk_prepare_enable(bsp_priv->clk_mac_speed);

			if (!IS_ERR(bsp_priv->pclk_xpcs))
				clk_prepare_enable(bsp_priv->pclk_xpcs);

			if (bsp_priv->ops && bsp_priv->ops->set_clock_selection)
				bsp_priv->ops->set_clock_selection(bsp_priv,
					       bsp_priv->clock_input, true);

			/**
			 * if (!IS_ERR(bsp_priv->clk_mac))
			 *	clk_prepare_enable(bsp_priv->clk_mac);
			 */
			usleep_range(100, 200);
			bsp_priv->clk_enabled = true;
		}
	} else {
		if (bsp_priv->clk_enabled) {
			if (phy_iface == PHY_INTERFACE_MODE_RMII) {
				clk_disable_unprepare(bsp_priv->mac_clk_rx);

				clk_disable_unprepare(bsp_priv->clk_mac_ref);

				clk_disable_unprepare(bsp_priv->clk_mac_refout);
			}

			clk_disable_unprepare(bsp_priv->clk_phy);

			clk_disable_unprepare(bsp_priv->aclk_mac);

			clk_disable_unprepare(bsp_priv->pclk_mac);

			clk_disable_unprepare(bsp_priv->mac_clk_tx);

			clk_disable_unprepare(bsp_priv->clk_mac_speed);

			clk_disable_unprepare(bsp_priv->pclk_xpcs);

			if (bsp_priv->ops && bsp_priv->ops->set_clock_selection)
				bsp_priv->ops->set_clock_selection(bsp_priv,
					      bsp_priv->clock_input, false);
			/**
			 * if (!IS_ERR(bsp_priv->clk_mac))
			 *	clk_disable_unprepare(bsp_priv->clk_mac);
			 */
			bsp_priv->clk_enabled = false;
		}
	}

	return 0;
}

static int rk_gmac_phy_power_on(struct rk_priv_data *bsp_priv, bool enable)
{
	struct regulator *ldo = bsp_priv->regulator;
	int ret;
	struct device *dev = &bsp_priv->pdev->dev;

	if (!ldo)
		return 0;

	if (enable) {
		ret = regulator_enable(ldo);
		if (ret)
			dev_err(dev, "fail to enable phy-supply\n");
	} else {
		ret = regulator_disable(ldo);
		if (ret)
			dev_err(dev, "fail to disable phy-supply\n");
	}

	return 0;
}

static struct rk_priv_data *rk_gmac_setup(struct platform_device *pdev,
					  struct plat_stmmacenet_data *plat,
					  const struct rk_gmac_ops *ops)
{
	struct rk_priv_data *bsp_priv;
	struct device *dev = &pdev->dev;
	int ret;
	const char *strings = NULL;
	int value;

	bsp_priv = devm_kzalloc(dev, sizeof(*bsp_priv), GFP_KERNEL);
	if (!bsp_priv)
		return ERR_PTR(-ENOMEM);

	of_get_phy_mode(dev->of_node, &bsp_priv->phy_iface);
	bsp_priv->ops = ops;
	bsp_priv->bus_id = plat->bus_id;

	bsp_priv->regulator = devm_regulator_get_optional(dev, "phy");
	if (IS_ERR(bsp_priv->regulator)) {
		if (PTR_ERR(bsp_priv->regulator) == -EPROBE_DEFER) {
			dev_err(dev, "phy regulator is not available yet, deferred probing\n");
			return ERR_PTR(-EPROBE_DEFER);
		}
		dev_err(dev, "no regulator found\n");
		bsp_priv->regulator = NULL;
	}

	ret = of_property_read_string(dev->of_node, "clock_in_out", &strings);
	if (ret) {
		dev_err(dev, "Can not read property: clock_in_out.\n");
		bsp_priv->clock_input = true;
	} else {
		dev_info(dev, "clock input or output? (%s).\n",
			 strings);
		if (!strcmp(strings, "input"))
			bsp_priv->clock_input = true;
		else
			bsp_priv->clock_input = false;
	}

	ret = of_property_read_u32(dev->of_node, "tx_delay", &value);
	if (ret) {
		bsp_priv->tx_delay = -1;
		dev_err(dev, "Can not read property: tx_delay.");
		dev_err(dev, "set tx_delay to 0x%x\n",
			bsp_priv->tx_delay);
	} else {
		dev_info(dev, "TX delay(0x%x).\n", value);
		bsp_priv->tx_delay = value;
	}

	ret = of_property_read_u32(dev->of_node, "rx_delay", &value);
	if (ret) {

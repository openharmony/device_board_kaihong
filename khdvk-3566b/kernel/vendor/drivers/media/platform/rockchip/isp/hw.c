// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Rockchip Electronics Co., Ltd */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_graph.h>
#include <linux/of_platform.h>
#include <linux/of_reserved_mem.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-dma-sg.h>
#include <soc/rockchip/rockchip_iommu.h>

#include "common.h"
#include "dev.h"
#include "hw.h"
#include "regs.h"

/*
 * rkisp_hw share hardware resource with rkisp virtual device
 * rkisp_device rkisp_device rkisp_device rkisp_device
 *      |            |            |            |
 *      \            |            |            /
 *       --------------------------------------
 *                         |
 *                     rkisp_hw
 */

struct isp_irqs_data {
	const char *name;
	irqreturn_t (*irq_hdl)(int irq, void *ctx);
};

/* using default value if reg no write for multi device */
static void default_sw_reg_flag(struct rkisp_device *dev)
{
	u32 v20_reg[] = {
		CTRL_VI_ISP_PATH, IMG_EFF_CTRL, ISP_CCM_CTRL,
		CPROC_CTRL, DUAL_CROP_CTRL, ISP_GAMMA_OUT_CTRL,
		ISP_LSC_CTRL, ISP_DEBAYER_CONTROL, ISP_WDR_CTRL,
		ISP_GIC_CONTROL, ISP_BLS_CTRL, ISP_DPCC0_MODE,
		ISP_DPCC1_MODE, ISP_DPCC2_MODE, ISP_HDRMGE_CTRL,
		ISP_HDRTMO_CTRL, ISP_RAWNR_CTRL, ISP_LDCH_STS,
		ISP_DHAZ_CTRL, ISP_3DLUT_CTRL, ISP_GAIN_CTRL,
		ISP_AFM_CTRL, ISP_HIST_HIST_CTRL, RAWAE_BIG1_BASE,
		RAWAE_BIG2_BASE, RAWAE_BIG3_BASE, ISP_RAWAE_LITE_CTRL,
		ISP_RAWHIST_LITE_CTRL, ISP_RAWHIST_BIG1_BASE,
		ISP_RAWHIST_BIG2_BASE, ISP_RAWHIST_BIG3_BASE,
		ISP_YUVAE_CTRL, ISP_RAWAF_CTRL, ISP_RAWAWB_CTRL,
	};
	u32 v21_reg[] = {
		CTRL_VI_ISP_PATH, IMG_EFF_CTRL, ISP_CCM_CTRL,
		CPROC_CTRL, DUAL_CROP_CTRL, ISP_GAMMA_OUT_CTRL,
		SELF_RESIZE_CTRL, MAIN_RESIZE_CTRL, ISP_LSC_CTRL,
		ISP_DEBAYER_CONTROL, ISP21_YNR_GLOBAL_CTRL,
		ISP21_CNR_CTRL, ISP21_SHARP_SHARP_EN, ISP_GIC_CONTROL,
		ISP_BLS_CTRL, ISP_DPCC0_MODE, ISP_DPCC1_MODE,
		ISP_HDRMGE_CTRL, ISP21_DRC_CTRL0, ISP21_BAYNR_CTRL,
		ISP21_BAY3D_CTRL, ISP_LDCH_STS, ISP21_DHAZ_CTRL,
		ISP_3DLUT_CTRL, ISP_AFM_CTRL, ISP_HIST_HIST_CTRL,
		RAWAE_BIG1_BASE, RAWAE_BIG2_BASE, RAWAE_BIG3_BASE,
		ISP_RAWAE_LITE_CTRL, ISP_RAWHIST_LITE_CTRL,
		ISP_RAWHIST_BIG1_BASE, ISP_RAWHIST_BIG2_BASE,
		ISP_RAWHIST_BIG3_BASE, ISP_YUVAE_CTRL, ISP_RAWAF_CTRL,
		ISP21_RAWAWB_CTRL,
	};
	u32 v30_reg[] = {
		ISP3X_VI_ISP_PATH, ISP3X_IMG_EFF_CTRL, ISP3X_CMSK_CTRL0,
		ISP3X_CCM_CTRL, ISP3X_CPROC_CTRL, ISP3X_DUAL_CROP_CTRL,
		ISP3X_GAMMA_OUT_CTRL, ISP3X_SELF_RESIZE_CTRL, ISP3X_MAIN_RESIZE_CTRL,
		ISP3X_LSC_CTRL, ISP3X_DEBAYER_CONTROL, ISP3X_CAC_CTRL,
		ISP3X_YNR_GLOBAL_CTRL, ISP3X_CNR_CTRL, ISP3X_SHARP_EN,
		ISP3X_BAY3D_CTRL, ISP3X_GIC_CONTROL, ISP3X_BLS_CTRL,
		ISP3X_DPCC0_MODE, ISP3X_DPCC1_MODE, ISP3X_DPCC2_MODE,
		ISP3X_HDRMGE_CTRL, ISP3X_DRC_CTRL0, ISP3X_BAYNR_CTRL,
		ISP3X_LDCH_STS, ISP3X_DHAZ_CTRL, ISP3X_3DLUT_CTRL,
		ISP3X_GAIN_CTRL, ISP3X_RAWAE_LITE_CTRL, ISP3X_RAWAE_BIG1_BASE,
		ISP3X_RAWAE_BIG2_BASE, ISP3X_RAWAE_BIG3_BASE, ISP3X_RAWHIST_LITE_CTRL,
		ISP3X_RAWHIST_BIG1_BASE, ISP3X_RAWHIST_BIG2_BASE, ISP3X_RAWHIST_BIG3_BASE,
		ISP3X_RAWAF_CTRL, ISP3X_RAWAWB_CTRL,
	};
	u32 i, *flag, *reg, size;

	switch (dev->isp_ver) {
	case ISP_V20:
		reg = v20_reg;
		size = ARRAY_SIZE(v20_reg);
		break;
	case ISP_V21:
		reg = v21_reg;
		size = ARRAY_SIZE(v21_reg);
		break;
	case ISP_V30:
		reg = v30_reg;
		size = ARRAY_SIZE(v30_reg);
		break;
	default:
		return;
	}

	for (i = 0; i < size; i++) {
		flag = dev->sw_base_addr + reg[i] + RKISP_ISP_SW_REG_SIZE;
		*flag = SW_REG_CACHE;
		if (dev->hw_dev->is_unite) {
			flag += RKISP_ISP_SW_MAX_SIZE / 4;
			*flag = SW_REG_CACHE;
		}
	}
}

static irqreturn_t mipi_irq_hdl(int irq, void *ctx)
{
	struct device *dev = ctx;
	struct rkisp_hw_dev *hw_dev = dev_get_drvdata(dev);
	struct rkisp_device *isp = hw_dev->isp[hw_dev->mipi_dev_id];
	void __iomem *base = !hw_dev->is_unite ?
		hw_dev->base_addr : hw_dev->base_next_addr;

	if (hw_dev->is_thunderboot)
		return IRQ_HANDLED;

	if (hw_dev->isp_ver == ISP_V13 || hw_dev->isp_ver == ISP_V12) {
		u32 err1, err2, err3;

		err1 = readl(base + CIF_ISP_CSI0_ERR1);
		err2 = readl(base + CIF_ISP_CSI0_ERR2);
		err3 = readl(base + CIF_ISP_CSI0_ERR3);

		if (err1 || err2 || err3)
			rkisp_mipi_v13_isr(err1, err2, err3, isp);
	} else if (hw_dev->isp_ver == ISP_V20 ||
		   hw_dev->isp_ver == ISP_V21 ||
		   hw_dev->isp_ver == ISP_V30) {
		u32 phy, packet, overflow, state;

		state = readl(base + CSI2RX_ERR_STAT);
		phy = readl(base + CSI2RX_ERR_PHY);
		packet = readl(base + CSI2RX_ERR_PACKET);
		overflow = readl(base + CSI2RX_ERR_OVERFLOW);
		if (phy | packet | overflow | state) {
			if (hw_dev->isp_ver == ISP_V20)
				rkisp_mipi_v20_isr(phy, packet, overflow, state, isp);
			else if (hw_dev->isp_ver == ISP_V21)
				rkisp_mipi_v21_isr(phy, packet, overflow, state, isp);
			else
				rkisp_mipi_v30_isr(phy, packet, overflow, state, isp);
		}
	} else {
		u32 mis_val = readl(base + CIF_MIPI_MIS);

		if (mis_val)
			rkisp_mipi_isr(mis_val, isp);
	}

	return IRQ_HANDLED;
}

static irqreturn_t mi_irq_hdl(int irq, void *ctx)
{
	struct device *dev = ctx;
	struct rkisp_hw_dev *hw_dev = dev_get_drvdata(dev);
	struct rkisp_device *isp = hw_dev->isp[hw_dev->cur_dev_id];
	void __iomem *base = !hw_dev->is_unite ?
		hw_dev->base_addr : hw_dev->base_next_addr;
	u32 mis_val, tx_isr = MI_RAW0_WR_FRAME | MI_RAW1_WR_FRAME |
		MI_RAW2_WR_FRAME | MI_RAW3_WR_FRAME;

	if (hw_dev->is_thunderboot)
		return IRQ_HANDLED;

	mis_val = readl(base + CIF_MI_MIS);
	if (mis_val) {
		if (mis_val & ~tx_isr)
			rkisp_mi_isr(mis_val & ~tx_isr, isp);
		if (mis_val & tx_isr) {
			isp = hw_dev->isp[hw_dev->mipi_dev_id];
			rkisp_mi_isr(mis_val & tx_isr, isp);
		}
	}
	return IRQ_HANDLED;
}

static irqreturn_t isp_irq_hdl(int irq, void *ctx)
{
	struct device *dev = ctx;
	struct rkisp_hw_dev *hw_dev = dev_get_drvdata(dev);
	struct rkisp_device *isp = hw_dev->isp[hw_dev->cur_dev_id];
	void __iomem *base = !hw_dev->is_unite ?
		hw_dev->base_addr : hw_dev->base_next_addr;
	unsigned int mis_val, mis_3a = 0;

	if (hw_dev->is_thunderboot)
		return IRQ_HANDLED;

	mis_val = readl(base + CIF_ISP_MIS);
	if (hw_dev->isp_ver == ISP_V20 ||
	    hw_dev->isp_ver == ISP_V21 ||
	    hw_dev->isp_ver == ISP_V30)
		mis_3a = readl(base + ISP_ISP3A_MIS);
	if (mis_val || mis_3a)
		rkisp_isp_isr(mis_val, mis_3a, isp);

	return IRQ_HANDLED;
}

static irqreturn_t irq_handler(int irq, void *ctx)
{
	struct device *dev = ctx;
	struct rkisp_hw_dev *hw_dev = dev_get_drvdata(dev);
	struct rkisp_device *isp = hw_dev->isp[hw_dev->cur_dev_id];
	unsigned int mis_val, mis_3a = 0;

	mis_val = readl(hw_dev->base_addr + CIF_ISP_MIS);
	if (hw_dev->isp_ver == ISP_V20 ||
	    hw_dev->isp_ver == ISP_V21 ||
	    hw_dev->isp_ver == ISP_V30)
		mis_3a = readl(hw_dev->base_addr + ISP_ISP3A_MIS);
	if (mis_val || mis_3a)
		rkisp_isp_isr(mis_val, mis_3a, isp);

	mis_val = readl(hw_dev->base_addr + CIF_MIPI_MIS);
	if (mis_val)
		rkisp_mipi_isr(mis_val, isp);

	mis_val = readl(hw_dev->base_addr + CIF_MI_MIS);
	if (mis_val)
		rkisp_mi_isr(mis_val, isp);

	return IRQ_HANDLED;
}

int rkisp_register_irq(struct rkisp_hw_dev *hw_dev)
{
	const struct isp_match_data *match_data = hw_dev->match_data;
	struct platform_device *pdev = hw_dev->pdev;
	struct device *dev = &pdev->dev;
	struct resource *res;
	int i, ret, irq;

	res = platform_get_resource_byname(pdev, IORESOURCE_IRQ,
					   match_data->irqs[0].name);
	if (res) {
		/* there are irq names in dts */
		for (i = 0; i < match_data->num_irqs; i++) {
			irq = platform_get_irq_byname(pdev, match_data->irqs[i].name);
			if (irq < 0) {
				dev_err(dev, "no irq %s in dts\n",
					match_data->irqs[i].name);
				return irq;
			}

			if (!strcmp(match_data->irqs[i].name, "mipi_irq"))
				hw_dev->mipi_irq = irq;

			ret = devm_request_irq(dev, irq,
					       match_data->irqs[i].irq_hdl,
					       IRQF_SHARED,
					       dev_driver_string(dev),
					       dev);
			if (ret < 0) {
				dev_err(dev, "request %s failed: %d\n",
					match_data->irqs[i].name, ret);
				return ret;
			}

			if (hw_dev->mipi_irq == irq &&
			    (hw_dev->isp_ver == ISP_V12 ||
			     hw_dev->isp_ver == ISP_V13))
				disable_irq(hw_dev->mipi_irq);
		}
	} else {
		/* no irq names in dts */
		irq = platform_get_irq(pdev, 0);
		if (irq < 0) {
			dev_err(dev, "no isp irq in dts\n");
			return irq;
		}

		ret = devm_request_irq(dev, irq,
				       irq_handler,
				       IRQF_SHARED,
				       dev_driver_string(dev),
				       dev);
		if (ret < 0) {
			dev_err(dev, "request irq failed: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static const char * const rk1808_isp_clks[] = {
	"clk_isp",
	"aclk_isp",
	"hclk_isp",
	"pclk_isp",
};

static const char * const rk3288_isp_clks[] = {
	"clk_isp",
	"aclk_isp",
	"hclk_isp",
	"pclk_isp_in",
	"sclk_isp_jpe",
};

static const char * const rk3326_isp_clks[] = {
	"clk_isp",
	"aclk_isp",
	"hclk_isp",
	"pclk_isp",
};

static const char * const rk3368_isp_clks[] = {
	"clk_isp",
	"aclk_isp",
	"hclk_isp",
	"pclk_isp",
};

static const char * const rk3399_isp_clks[] = {
	"clk_isp",
	"aclk_isp",
	"hclk_isp",
	"aclk_isp_wrap",
	"hclk_isp_wrap",
	"pclk_isp_wrap"
};

static const char * const rk3568_isp_clks[] = {
	"clk_isp",
	"aclk_isp",
	"hclk_isp",
};

static const char * const rk3588_isp_clks[] = {
	"clk_isp_core",
	"aclk_isp",
	"hclk_isp",
	"clk_isp_core_marvin",
	"clk_isp_core_vicap",
};

static const char * const rk3588_isp_unite_clks[] = {
	"clk_isp_core0",
	"aclk_isp0",
	"hclk_isp0",
	"clk_isp_core_marvin0",
	"clk_isp_core_vicap0",
	"clk_isp_core1",
	"aclk_isp1",
	"hclk_isp1",
	"clk_isp_core_marvin1",
	"clk_isp_core_vicap1",
};

static const char * const rv1126_isp_clks[] = {
	"clk_isp",
	"aclk_isp",
	"hclk_isp",
};

/* isp clock adjustment table (MHz) */
static const struct isp_clk_info rk1808_isp_clk_rate[] = {
	{300, }, {400, }, {500, }, {600, }
};

/* isp clock adjustment table (MHz) */
static const struct isp_clk_info rk3288_isp_clk_rate[] = {
	{150, }, {384, }, {500, }, {594, }
};

/* isp clock adjustment table (MHz) */
static const struct isp_clk_info rk3326_isp_clk_rate[] = {
	{300, }, {347, }, {400, }, {520, }, {600, }
};

/* isp clock adjustment table (MHz) */
static const struct isp_clk_info rk3368_isp_clk_rate[] = {
	{300, }, {400, }, {600, }
};

/* isp clock adjustment table (MHz) */
static const struct isp_clk_info rk3399_isp_clk_rate[] = {
	{300, }, {400, }, {600, }
};

static const struct isp_clk_info rk3568_isp_clk_rate[] = {
	{
		.clk_rate = 300,
		.refer_data = 1920, //width
	}, {
		.clk_rate = 400,
		.refer_data = 2688,
	}, {
		.clk_rate = 500,
		.refer_data = 3072,
	}, {
		.clk_rate = 600,
		.refer_data = 3840,
	}
};

static const struct isp_clk_info rk3588_isp_clk_rate[] = {
	{
		.clk_rate = 300,
		.refer_data = 1920, //width
	}, {
		.clk_rate = 400,
		.refer_data = 2688,
	}, {
		.clk_rate = 500,
		.refer_data = 3072,
	}, {
		.clk_rate = 600,
		.refer_data = 3840,
	}, {
		.clk_rate = 702,
		.refer_data = 4672,
	}
};

static const struct isp_clk_info rv1126_isp_clk_rate[] = {
	{
		.clk_rate = 20,
		.refer_data = 0,
	}, {
		.clk_rate = 300,
		.refer_data = 1920, //width
	}, {
		.clk_rate = 400,
		.refer_data = 2688,
	}, {
		.clk_rate = 500,
		.refer_data = 3072,
	}, {
		.clk_rate = 600,
		.refer_data = 3840,
	}
};

static struct isp_irqs_data rk1808_isp_irqs[] = {
	{"isp_irq", isp_irq_hdl},
	{"mi_irq", mi_irq_hdl},
	{"mipi_irq", mipi_irq_hdl}
};

static struct isp_irqs_data rk3288_isp_irqs[] = {
	{"isp_irq", irq_handler}
};

static struct isp_irqs_data rk3326_isp_irqs[] = {
	{"isp_irq", isp_irq_hdl},
	{"mi_irq", mi_irq_hdl},
	{"mipi_irq", mipi_irq_hdl}
};

static struct isp_irqs_data rk3368_isp_irqs[] = {
	{"isp_irq", irq_handler}
};

static struct isp_irqs_data rk3399_isp_irqs[] = {
	{"isp_irq", irq_handler}
};

static struct isp_irqs_data rk3568_isp_irqs[] = {
	{"isp_irq", isp_irq_hdl},
	{"mi_irq", mi_irq_hdl},
	{"mipi_irq", mipi_irq_hdl}
};

static struct isp_irqs_data rk3588_isp_irqs[] = {
	{"isp_irq", isp_irq_hdl},
	{"mi_irq", mi_irq_hdl},
	{"mipi_irq", mipi_irq_hdl}
};

static struct isp_irqs_data rv1126_isp_irqs[] = {
	{"isp_irq", isp_irq_hdl},
	{"mi_irq", mi_irq_hdl},
	{"mipi_irq", mipi_irq_hdl}
};

static const struct isp_match_data rv1126_isp_match_data = {
	.clks = rv1126_isp_clks,
	.num_clks = ARRAY_SIZE(rv1126_isp_clks),
	.isp_ver = ISP_V20,
	.clk_rate_tbl = rv1126_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rv1126_isp_clk_rate),
	.irqs = rv1126_isp_irqs,
	.num_irqs = ARRAY_SIZE(rv1126_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk1808_isp_match_data = {
	.clks = rk1808_isp_clks,
	.num_clks = ARRAY_SIZE(rk1808_isp_clks),
	.isp_ver = ISP_V13,
	.clk_rate_tbl = rk1808_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk1808_isp_clk_rate),
	.irqs = rk1808_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk1808_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk3288_isp_match_data = {
	.clks = rk3288_isp_clks,
	.num_clks = ARRAY_SIZE(rk3288_isp_clks),
	.isp_ver = ISP_V10,
	.clk_rate_tbl = rk3288_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk3288_isp_clk_rate),
	.irqs = rk3288_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk3288_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk3326_isp_match_data = {
	.clks = rk3326_isp_clks,
	.num_clks = ARRAY_SIZE(rk3326_isp_clks),
	.isp_ver = ISP_V12,
	.clk_rate_tbl = rk3326_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk3326_isp_clk_rate),
	.irqs = rk3326_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk3326_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk3368_isp_match_data = {
	.clks = rk3368_isp_clks,
	.num_clks = ARRAY_SIZE(rk3368_isp_clks),
	.isp_ver = ISP_V10_1,
	.clk_rate_tbl = rk3368_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk3368_isp_clk_rate),
	.irqs = rk3368_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk3368_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk3399_isp_match_data = {
	.clks = rk3399_isp_clks,
	.num_clks = ARRAY_SIZE(rk3399_isp_clks),
	.isp_ver = ISP_V10,
	.clk_rate_tbl = rk3399_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk3399_isp_clk_rate),
	.irqs = rk3399_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk3399_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk3568_isp_match_data = {
	.clks = rk3568_isp_clks,
	.num_clks = ARRAY_SIZE(rk3568_isp_clks),
	.isp_ver = ISP_V21,
	.clk_rate_tbl = rk3568_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk3568_isp_clk_rate),
	.irqs = rk3568_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk3568_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk3588_isp_match_data = {
	.clks = rk3588_isp_clks,
	.num_clks = ARRAY_SIZE(rk3588_isp_clks),
	.isp_ver = ISP_V30,
	.clk_rate_tbl = rk3588_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk3588_isp_clk_rate),
	.irqs = rk3588_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk3588_isp_irqs),
	.unite = false,
};

static const struct isp_match_data rk3588_isp_unite_match_data = {
	.clks = rk3588_isp_unite_clks,
	.num_clks = ARRAY_SIZE(rk3588_isp_unite_clks),
	.isp_ver = ISP_V30,
	.clk_rate_tbl = rk3588_isp_clk_rate,
	.num_clk_rate_tbl = ARRAY_SIZE(rk3588_isp_clk_rate),
	.irqs = rk3588_isp_irqs,
	.num_irqs = ARRAY_SIZE(rk3588_isp_irqs),
	.unite = true,
};

static const struct of_device_id rkisp_hw_of_match[] = {
	{
		.compatible = "rockchip,rk1808-rkisp1",
		.data = &rk1808_isp_match_data,
	}, {
		.compatible = "rockchip,rk3288-rkisp1",
		.data = &rk3288_isp_match_data,
	}, {
		.compatible = "rockchip,rk3326-rkisp1",
		.data = &rk3326_isp_match_data,
	}, {
		.compatible = "rockchip,rk3368-rkisp1",
		.data = &rk3368_isp_match_data,
	}, {
		.compatible = "rockchip,rk3399-rkisp1",
		.data = &rk3399_isp_match_data,
	}, {
		.compatible = "rockchip,rk3568-rkisp",
		.data = &rk3568_isp_match_data,
	}, {
		.compatible = "rockchip,rk3588-rkisp",
		.data = &rk3588_isp_match_data,
	}, {
		.compatible = "rockchip,rk3588-rkisp-unite",
		.data = &rk3588_isp_unite_match_data,
	}, {
		.compatible = "rockchip,rv1126-rkisp",
		.data = &rv1126_isp_match_data,
	},
	{},
};

static inline bool is_iommu_enable(struct device *dev)
{
	struct device_node *iommu;

	iommu = of_parse_phandle(dev->of_node, "iommus", 0);
	if (!iommu) {
		dev_info(dev, "no iommu attached, using non-iommu buffers\n");
		return false;
	} else if (!of_device_is_available(iommu)) {
		dev_info(dev, "iommu is disabled, using non-iommu buffers\n");
		of_node_put(iommu);
		return false;
	}
	of_node_put(iommu);

	return true;
}

void rkisp_soft_reset(struct rkisp_hw_dev *dev, bool is_secure)
{
	void __iomem *base = dev->base_addr;

	if (is_secure) {
		/* if isp working, cru reset isn't secure.
		 * isp soft reset first to protect isp reset.
		 */
		writel(0xffff, base + CIF_IRCL);
		if (dev->is_unite)
			writel(0xffff, dev->base_next_addr + CIF_IRCL);
		udelay(10);
	}

	if (dev->reset) {
		reset_control_assert(dev->reset);
		udelay(10);
		reset_control_deassert(dev->reset);
		udelay(10);
	}

	/* reset for Dehaze */
	if (dev->isp_ver == ISP_V20)
		writel(CIF_ISP_CTRL_ISP_MODE_BAYER_ITU601, base + CIF_ISP_CTRL);
	writel(0xffff, base + CIF_IRCL);
	if (dev->is_unite)
		writel(0xffff, dev->base_next_addr + CIF_IRCL);
	udelay(10);

	/* refresh iommu after reset */
	if (dev->is_mmu) {
		rockchip_iommu_disable(dev->dev);
		rockchip_iommu_enable(dev->dev);
	}
}


// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2014, Fuzhou Rockchip Electronics Co., Ltd
 */

#include <linux/clk.h>
#include <linux/gpio/consumer.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/phy/phy.h>
#include <linux/regmap.h>
#include <linux/pm_runtime.h>

#include <drm/drm_of.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_dsc.h>
#include <drm/drm_edid.h>
#include <drm/bridge/dw_hdmi.h>
#include <drm/drm_edid.h>
#include <drm/drm_of.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_simple_kms_helper.h>

#include <uapi/linux/videodev2.h>

#include "rockchip_drm_drv.h"
#include "rockchip_drm_vop.h"

#define HIWORD_UPDATE(val, mask)	(val | (mask) << 16)

#define RK3228_GRF_SOC_CON2		0x0408
#define RK3228_HDMI_SDAIN_MSK		BIT(14)
#define RK3228_HDMI_SCLIN_MSK		BIT(13)
#define RK3228_GRF_SOC_CON6		0x0418
#define RK3228_HDMI_HPD_VSEL		BIT(6)
#define RK3228_HDMI_SDA_VSEL		BIT(5)
#define RK3228_HDMI_SCL_VSEL		BIT(4)

#define RK3288_GRF_SOC_CON6		0x025C
#define RK3288_HDMI_LCDC_SEL		BIT(4)
#define RK3288_GRF_SOC_CON16		0x03a8
#define RK3288_HDMI_LCDC0_YUV420	BIT(2)
#define RK3288_HDMI_LCDC1_YUV420	BIT(3)

#define RK3328_GRF_SOC_CON2		0x0408
#define RK3328_HDMI_SDAIN_MSK		BIT(11)
#define RK3328_HDMI_SCLIN_MSK		BIT(10)
#define RK3328_HDMI_HPD_IOE		BIT(2)
#define RK3328_GRF_SOC_CON3		0x040c
/* need to be unset if hdmi or i2c should control voltage */
#define RK3328_HDMI_SDA5V_GRF		BIT(15)
#define RK3328_HDMI_SCL5V_GRF		BIT(14)
#define RK3328_HDMI_HPD5V_GRF		BIT(13)
#define RK3328_HDMI_CEC5V_GRF		BIT(12)
#define RK3328_GRF_SOC_CON4		0x0410
#define RK3328_HDMI_HPD_SARADC		BIT(13)
#define RK3328_HDMI_CEC_5V		BIT(11)
#define RK3328_HDMI_SDA_5V		BIT(10)
#define RK3328_HDMI_SCL_5V		BIT(9)
#define RK3328_HDMI_HPD_5V		BIT(8)

#define RK3399_GRF_SOC_CON20		0x6250
#define RK3399_HDMI_LCDC_SEL		BIT(6)

#define RK3568_GRF_VO_CON1		0x0364
#define RK3568_HDMI_SDAIN_MSK		BIT(15)
#define RK3568_HDMI_SCLIN_MSK		BIT(14)

#define RK3588_GRF_SOC_CON2		0x0308
#define RK3588_HDMI1_HPD_INT_MSK	BIT(15)
#define RK3588_HDMI1_HPD_INT_CLR	BIT(14)
#define RK3588_HDMI0_HPD_INT_MSK	BIT(13)
#define RK3588_HDMI0_HPD_INT_CLR	BIT(12)
#define RK3588_GRF_SOC_CON7		0x031c
#define RK3588_SET_HPD_PATH_MASK	(0x3 << 12)
#define RK3588_GRF_SOC_STATUS1		0x0384
#define RK3588_HDMI0_LOW_MORETHAN100MS	BIT(20)
#define RK3588_HDMI0_HPD_PORT_LEVEL	BIT(19)
#define RK3588_HDMI0_IHPD_PORT		BIT(18)
#define RK3588_HDMI0_OHPD_INT		BIT(17)
#define RK3588_HDMI0_LEVEL_INT		BIT(16)
#define RK3588_HDMI0_INTR_CHANGE_CNT	(0x7 << 13)
#define RK3588_HDMI1_LOW_MORETHAN100MS	BIT(28)
#define RK3588_HDMI1_HPD_PORT_LEVEL	BIT(27)
#define RK3588_HDMI1_IHPD_PORT		BIT(26)
#define RK3588_HDMI1_OHPD_INT		BIT(25)
#define RK3588_HDMI1_LEVEL_INT		BIT(24)
#define RK3588_HDMI1_INTR_CHANGE_CNT	(0x7 << 21)

#define RK3588_GRF_VO1_CON3		0x000c
#define RK3588_COLOR_FORMAT_MASK	0xf
#define RK3588_YUV444			0x2
#define RK3588_YUV420			0x3
#define RK3588_COMPRESSED_DATA		0xb
#define RK3588_COLOR_DEPTH_MASK		(0xf << 4)
#define RK3588_8BPC			(0x5 << 4)
#define RK3588_10BPC			(0x6 << 4)
#define RK3588_CECIN_MASK		BIT(8)
#define RK3588_SCLIN_MASK		BIT(9)
#define RK3588_SDAIN_MASK		BIT(10)
#define RK3588_MODE_MASK		BIT(11)
#define RK3588_COMPRESS_MODE_MASK	BIT(12)
#define RK3588_I2S_SEL_MASK		BIT(13)
#define RK3588_SPDIF_SEL_MASK		BIT(14)
#define RK3588_GRF_VO1_CON4		0x0010
#define RK3588_HDMI21_MASK		BIT(0)
#define RK3588_GRF_VO1_CON9		0x0024
#define RK3588_HDMI0_GRANT_SEL		BIT(10)
#define RK3588_HDMI0_GRANT_SW		BIT(11)
#define RK3588_HDMI1_GRANT_SEL		BIT(12)
#define RK3588_HDMI1_GRANT_SW		BIT(13)
#define RK3588_GRF_VO1_CON6		0x0018
#define RK3588_GRF_VO1_CON7		0x001c

#define RK_HDMI_COLORIMETRY_BT2020	(HDMI_COLORIMETRY_EXTENDED + \
					 HDMI_EXTENDED_COLORIMETRY_BT2020)

#define COLOR_DEPTH_10BIT		BIT(31)
#define HDMI_FRL_MODE			BIT(30)
#define HDMI_EARC_MODE			BIT(29)

#define HDMI20_MAX_RATE			600000
#define HDMI_8K60_RATE			2376000

/**
 * struct rockchip_hdmi_chip_data - splite the grf setting of kind of chips
 * @lcdsel_grf_reg: grf register offset of lcdc select
 * @ddc_en_reg: grf register offset of hdmi ddc enable
 * @lcdsel_big: reg value of selecting vop big for HDMI
 * @lcdsel_lit: reg value of selecting vop little for HDMI
 */
struct rockchip_hdmi_chip_data {
	int	lcdsel_grf_reg;
	int	ddc_en_reg;
	u32	lcdsel_big;
	u32	lcdsel_lit;
};

/* HDMI output pixel format */
enum drm_hdmi_output_type {
	DRM_HDMI_OUTPUT_DEFAULT_RGB, /* default RGB */
	DRM_HDMI_OUTPUT_YCBCR444, /* YCBCR 444 */
	DRM_HDMI_OUTPUT_YCBCR422, /* YCBCR 422 */
	DRM_HDMI_OUTPUT_YCBCR420, /* YCBCR 420 */
	DRM_HDMI_OUTPUT_YCBCR_HQ, /* Highest subsampled YUV */
	DRM_HDMI_OUTPUT_YCBCR_LQ, /* Lowest subsampled YUV */
	DRM_HDMI_OUTPUT_INVALID, /* Guess what ? */
};

enum dw_hdmi_rockchip_color_depth {
	ROCKCHIP_HDMI_DEPTH_8,
	ROCKCHIP_HDMI_DEPTH_10,
	ROCKCHIP_HDMI_DEPTH_12,
	ROCKCHIP_HDMI_DEPTH_16,
	ROCKCHIP_HDMI_DEPTH_420_10,
	ROCKCHIP_HDMI_DEPTH_420_12,
	ROCKCHIP_HDMI_DEPTH_420_16
};

enum hdmi_frl_rate_per_lane {
	FRL_12G_PER_LANE = 12,
	FRL_10G_PER_LANE = 10,
	FRL_8G_PER_LANE = 8,
	FRL_6G_PER_LANE = 6,
	FRL_3G_PER_LANE = 3,
};

struct rockchip_hdmi {
	struct device *dev;
	struct regmap *regmap;
	struct regmap *vo1_regmap;
	struct drm_encoder encoder;
	const struct rockchip_hdmi_chip_data *chip_data;
	struct clk *aud_clk;
	struct clk *phyref_clk;
	struct clk *grf_clk;
	struct clk *hclk_vio;
	struct clk *hclk_vo1;
	struct clk *hclk_vop;
	struct clk *hpd_clk;
	struct clk *pclk;
	struct clk *earc_clk;
	struct clk *hdmitx_ref;
	struct dw_hdmi *hdmi;
	struct dw_hdmi_qp *hdmi_qp;

	struct phy *phy;

	u32 max_tmdsclk;
	bool unsupported_yuv_input;
	bool unsupported_deep_color;
	bool skip_check_420_mode;
	bool mode_changed;
	u8 force_output;
	u8 id;
	bool hpd_stat;
	bool is_hdmi_qp;

	unsigned long bus_format;
	unsigned long output_bus_format;
	unsigned long enc_out_encoding;
	int color_changed;
	int hpd_irq;

	struct drm_property *color_depth_property;
	struct drm_property *hdmi_output_property;
	struct drm_property *colordepth_capacity;
	struct drm_property *outputmode_capacity;
	struct drm_property *colorimetry_property;
	struct drm_property *quant_range;
	struct drm_property *hdr_panel_metadata_property;
	struct drm_property *next_hdr_sink_data_property;
	struct drm_property *output_hdmi_dvi;
	struct drm_property *output_type_capacity;

	struct drm_property_blob *hdr_panel_blob_ptr;
	struct drm_property_blob *next_hdr_data_ptr;

	unsigned int colordepth;
	unsigned int colorimetry;
	unsigned int hdmi_quant_range;
	unsigned int phy_bus_width;
	enum drm_hdmi_output_type hdmi_output;
	struct rockchip_drm_sub_dev sub_dev;

	u8 max_frl_rate_per_lane;
	u8 max_lanes;
	struct rockchip_drm_dsc_cap dsc_cap;
	struct next_hdr_sink_data next_hdr_data;
	struct dw_hdmi_link_config link_cfg;
	struct gpio_desc *enable_gpio;

	struct delayed_work work;
	struct workqueue_struct *workqueue;
};

#define to_rockchip_hdmi(x)	container_of(x, struct rockchip_hdmi, x)

/*
 * There are some rates that would be ranged for better clock jitter at
 * Chrome OS tree, like 25.175Mhz would range to 25.170732Mhz. But due
 * to the clock is aglined to KHz in struct drm_display_mode, this would
 * bring some inaccurate error if we still run the compute_n math, so
 * let's just code an const table for it until we can actually get the
 * right clock rate.
 */
static const struct dw_hdmi_audio_tmds_n rockchip_werid_tmds_n_table[] = {
	/* 25176471 for 25.175 MHz = 428000000 / 17. */
	{ .tmds = 25177000, .n_32k = 4352, .n_44k1 = 14994, .n_48k = 6528, },
	/* 57290323 for 57.284 MHz */
	{ .tmds = 57291000, .n_32k = 3968, .n_44k1 = 4557, .n_48k = 5952, },
	/* 74437500 for 74.44 MHz = 297750000 / 4 */
	{ .tmds = 74438000, .n_32k = 8192, .n_44k1 = 18816, .n_48k = 4096, },
	/* 118666667 for 118.68 MHz */
	{ .tmds = 118667000, .n_32k = 4224, .n_44k1 = 5292, .n_48k = 6336, },
	/* 121714286 for 121.75 MHz */
	{ .tmds = 121715000, .n_32k = 4480, .n_44k1 = 6174, .n_48k = 6272, },
	/* 136800000 for 136.75 MHz */
	{ .tmds = 136800000, .n_32k = 4096, .n_44k1 = 5684, .n_48k = 6144, },
	/* End of table */
	{ .tmds = 0,         .n_32k = 0,    .n_44k1 = 0,    .n_48k = 0, },
};

static const struct dw_hdmi_mpll_config rockchip_mpll_cfg[] = {
	{
		30666000, {
			{ 0x00b3, 0x0000 },
			{ 0x2153, 0x0000 },
			{ 0x40f3, 0x0000 },
		},
	},  {
		36800000, {
			{ 0x00b3, 0x0000 },
			{ 0x2153, 0x0000 },
			{ 0x40a2, 0x0001 },
		},
	},  {
		46000000, {
			{ 0x00b3, 0x0000 },
			{ 0x2142, 0x0001 },
			{ 0x40a2, 0x0001 },
		},
	},  {
		61333000, {
			{ 0x0072, 0x0001 },
			{ 0x2142, 0x0001 },
			{ 0x40a2, 0x0001 },
		},
	},  {
		73600000, {
			{ 0x0072, 0x0001 },
			{ 0x2142, 0x0001 },
			{ 0x4061, 0x0002 },
		},
	},  {
		92000000, {
			{ 0x0072, 0x0001 },
			{ 0x2145, 0x0002 },
			{ 0x4061, 0x0002 },
		},
	},  {
		122666000, {
			{ 0x0051, 0x0002 },
			{ 0x2145, 0x0002 },
			{ 0x4061, 0x0002 },
		},
	},  {
		147200000, {
			{ 0x0051, 0x0002 },
			{ 0x2145, 0x0002 },
			{ 0x4064, 0x0003 },
		},
	},  {
		184000000, {
			{ 0x0051, 0x0002 },
			{ 0x214c, 0x0003 },
			{ 0x4064, 0x0003 },
		},
	},  {
		226666000, {
			{ 0x0040, 0x0003 },
			{ 0x214c, 0x0003 },
			{ 0x4064, 0x0003 },
		},
	},  {
		272000000, {
			{ 0x0040, 0x0003 },
			{ 0x214c, 0x0003 },
			{ 0x5a64, 0x0003 },
		},
	},  {
		340000000, {
			{ 0x0040, 0x0003 },
			{ 0x3b4c, 0x0003 },
			{ 0x5a64, 0x0003 },
		},
	},  {
		600000000, {
			{ 0x1a40, 0x0003 },
			{ 0x3b4c, 0x0003 },
			{ 0x5a64, 0x0003 },
		},
	},  {
		~0UL, {
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
		},
	}
};

static const struct dw_hdmi_mpll_config rockchip_mpll_cfg_420[] = {
	{
		30666000, {
			{ 0x00b7, 0x0000 },
			{ 0x2157, 0x0000 },
			{ 0x40f7, 0x0000 },
		},
	},  {
		92000000, {
			{ 0x00b7, 0x0000 },
			{ 0x2143, 0x0001 },
			{ 0x40a3, 0x0001 },
		},
	},  {
		184000000, {
			{ 0x0073, 0x0001 },
			{ 0x2146, 0x0002 },
			{ 0x4062, 0x0002 },
		},
	},  {
		340000000, {
			{ 0x0052, 0x0003 },
			{ 0x214d, 0x0003 },
			{ 0x4065, 0x0003 },
		},
	},  {
		600000000, {
			{ 0x0041, 0x0003 },
			{ 0x3b4d, 0x0003 },
			{ 0x5a65, 0x0003 },
		},
	},  {
		~0UL, {
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
		},
	}
};

static const struct dw_hdmi_mpll_config rockchip_rk3288w_mpll_cfg_420[] = {
	{
		30666000, {
			{ 0x00b7, 0x0000 },
			{ 0x2157, 0x0000 },
			{ 0x40f7, 0x0000 },
		},
	},  {
		92000000, {
			{ 0x00b7, 0x0000 },
			{ 0x2143, 0x0001 },
			{ 0x40a3, 0x0001 },
		},
	},  {
		184000000, {
			{ 0x0073, 0x0001 },
			{ 0x2146, 0x0002 },
			{ 0x4062, 0x0002 },
		},
	},  {
		340000000, {
			{ 0x0052, 0x0003 },
			{ 0x214d, 0x0003 },
			{ 0x4065, 0x0003 },
		},
	},  {
		600000000, {
			{ 0x0040, 0x0003 },
			{ 0x3b4c, 0x0003 },
			{ 0x5a65, 0x0003 },
		},
	},  {
		~0UL, {
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
		},
	}
};

static const struct dw_hdmi_curr_ctrl rockchip_cur_ctr[] = {
	/*      pixelclk    bpp8    bpp10   bpp12 */
	{
		600000000, { 0x0000, 0x0000, 0x0000 },
	},  {
		~0UL,      { 0x0000, 0x0000, 0x0000},
	}
};

static struct dw_hdmi_phy_config rockchip_phy_config[] = {
	/*pixelclk   symbol   term   vlev*/
	{ 74250000,  0x8009, 0x0004, 0x0272},
	{ 165000000, 0x802b, 0x0004, 0x0209},
	{ 297000000, 0x8039, 0x0005, 0x028d},
	{ 594000000, 0x8039, 0x0000, 0x019d},
	{ ~0UL,	     0x0000, 0x0000, 0x0000},
	{ ~0UL,      0x0000, 0x0000, 0x0000},
};

enum ROW_INDEX_BPP {
	ROW_INDEX_6BPP = 0,
	ROW_INDEX_8BPP,
	ROW_INDEX_10BPP,
	ROW_INDEX_12BPP,
	ROW_INDEX_23BPP,
	MAX_ROW_INDEX
};

enum COLUMN_INDEX_BPC {
	COLUMN_INDEX_8BPC = 0,
	COLUMN_INDEX_10BPC,
	COLUMN_INDEX_12BPC,
	COLUMN_INDEX_14BPC,
	COLUMN_INDEX_16BPC,
	MAX_COLUMN_INDEX
};

#define PPS_TABLE_LEN 8
#define PPS_BPP_LEN 4
#define PPS_BPC_LEN 2

/* From DSC_v1.11 spec, rc_parameter_Set syntax element typically constant */
static const u16 rc_buf_thresh[] = {
	0x0e, 0x1c, 0x2a, 0x38, 0x46, 0x54, 0x62,
	0x69, 0x70, 0x77, 0x79, 0x7b, 0x7d, 0x7e,
};

struct rc_parameters {
	u16 initial_xmit_delay;
	u16 initial_dec_delay;
	u8 initial_scale_value;
	u16 scale_increment_interval;
	u16 scale_decrement_interval;
	u8 first_line_bpg_offset;
	u16 nfl_bpg_offset;
	u16 slice_bpg_offset;
	u16 initial_offset;
	u16 final_offset;
	u8 flatness_min_qp;
	u8 flatness_max_qp;
	u16 rc_model_size;
	u8 rc_edge_factor;
	u8 rc_quant_incr_limit0;
	u8 rc_quant_incr_limit1;
	u8 rc_tgt_offset_hi;
	u8 rc_tgt_offset_lo;
	struct drm_dsc_rc_range_parameters rc_range_params[DSC_NUM_BUF_RANGES];
};

struct pps_data {
	u32 pic_width;
	u32 pic_height;
	u32 slice_width;
	u32 slice_height;
	bool convert_rgb;
	u8 bpc;
	u8 bpp;
	u8 raw_pps[128];
};

/*
 * Selected Rate Control Related Parameter Recommended Values
 * from DSC_v1.11 spec & C Model release: DSC_model_20161212
 */
static struct pps_data pps_datas[PPS_TABLE_LEN] = {
	{
		/* 7680x4320/960X96 rgb 8bpc 12bpp */
		7680, 4320, 960, 96, 1, 8, 192,
		{
			0x12, 0x00, 0x00, 0x8d, 0x30, 0xc0, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x05, 0xa0,
			0x01, 0x55, 0x03, 0x90, 0x00, 0x0a, 0x05, 0xc9,
			0x00, 0xa0, 0x00, 0x0f, 0x01, 0x44, 0x01, 0xaa,
			0x08, 0x00, 0x10, 0xf4, 0x03, 0x0c, 0x20, 0x00,
			0x06, 0x0b, 0x0b, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x00, 0x82, 0x00, 0xc0, 0x09, 0x00,
			0x09, 0x7e, 0x19, 0xbc, 0x19, 0xba, 0x19, 0xf8,
			0x1a, 0x38, 0x1a, 0x38, 0x1a, 0x76, 0x2a, 0x76,
			0x2a, 0x76, 0x2a, 0x74, 0x3a, 0xb4, 0x52, 0xf4,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
	{
		/* 7680x4320/960X96 rgb 8bpc 11bpp */
		7680, 4320, 960, 96, 1, 8, 176,
		{
			0x12, 0x00, 0x00, 0x8d, 0x30, 0xb0, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x05, 0x28,
			0x01, 0x74, 0x03, 0x40, 0x00, 0x0f, 0x06, 0xe0,
			0x00, 0x2d, 0x00, 0x0f, 0x01, 0x44, 0x01, 0x33,
			0x0f, 0x00, 0x10, 0xf4, 0x03, 0x0c, 0x20, 0x00,
			0x06, 0x0b, 0x0b, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x00, 0x82, 0x01, 0x00, 0x09, 0x40,
			0x09, 0xbe, 0x19, 0xfc, 0x19, 0xfa, 0x19, 0xf8,
			0x1a, 0x38, 0x1a, 0x38, 0x1a, 0x76, 0x2a, 0x76,
			0x2a, 0x76, 0x2a, 0xb4, 0x3a, 0xb4, 0x52, 0xf4,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
	{
		/* 7680x4320/960X96 rgb 8bpc 10bpp */
		7680, 4320, 960, 96, 1, 8, 160,
		{
			0x12, 0x00, 0x00, 0x8d, 0x30, 0xa0, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x04, 0xb0,
			0x01, 0x9a, 0x02, 0xe0, 0x00, 0x19, 0x09, 0xb0,
			0x00, 0x12, 0x00, 0x0f, 0x01, 0x44, 0x00, 0xbb,
			0x16, 0x00, 0x10, 0xec, 0x03, 0x0c, 0x20, 0x00,
			0x06, 0x0b, 0x0b, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x00, 0xc2, 0x01, 0x00, 0x09, 0x40,
			0x09, 0xbe, 0x19, 0xfc, 0x19, 0xfa, 0x19, 0xf8,
			0x1a, 0x38, 0x1a, 0x78, 0x1a, 0x76, 0x2a, 0xb6,
			0x2a, 0xb6, 0x2a, 0xf4, 0x3a, 0xf4, 0x5b, 0x34,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
	{
		/* 7680x4320/960X96 rgb 8bpc 9bpp */
		7680, 4320, 960, 96, 1, 8, 144,
		{
			0x12, 0x00, 0x00, 0x8d, 0x30, 0x90, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x04, 0x38,
			0x01, 0xc7, 0x03, 0x16, 0x00, 0x1c, 0x08, 0xc7,
			0x00, 0x10, 0x00, 0x0f, 0x01, 0x44, 0x00, 0xaa,
			0x17, 0x00, 0x10, 0xf1, 0x03, 0x0c, 0x20, 0x00,
			0x06, 0x0b, 0x0b, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x00, 0xc2, 0x01, 0x00, 0x09, 0x40,
			0x09, 0xbe, 0x19, 0xfc, 0x19, 0xfa, 0x19, 0xf8,
			0x1a, 0x38, 0x1a, 0x78, 0x1a, 0x76, 0x2a, 0xb6,
			0x2a, 0xb6, 0x2a, 0xf4, 0x3a, 0xf4, 0x63, 0x74,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
	{
		/* 7680x4320/960X96 rgb 10bpc 12bpp */
		7680, 4320, 960, 96, 1, 10, 192,
		{
			0x12, 0x00, 0x00, 0xad, 0x30, 0xc0, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x05, 0xa0,
			0x01, 0x55, 0x03, 0x90, 0x00, 0x0a, 0x05, 0xc9,
			0x00, 0xa0, 0x00, 0x0f, 0x01, 0x44, 0x01, 0xaa,
			0x08, 0x00, 0x10, 0xf4, 0x07, 0x10, 0x20, 0x00,
			0x06, 0x0f, 0x0f, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x01, 0x02, 0x11, 0x80, 0x22, 0x00,
			0x22, 0x7e, 0x32, 0xbc, 0x32, 0xba, 0x3a, 0xf8,
			0x3b, 0x38, 0x3b, 0x38, 0x3b, 0x76, 0x4b, 0x76,
			0x4b, 0x76, 0x4b, 0x74, 0x5b, 0xb4, 0x73, 0xf4,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
	{
		/* 7680x4320/960X96 rgb 10bpc 11bpp */
		7680, 4320, 960, 96, 1, 10, 176,
		{
			0x12, 0x00, 0x00, 0xad, 0x30, 0xb0, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x05, 0x28,
			0x01, 0x74, 0x03, 0x40, 0x00, 0x0f, 0x06, 0xe0,
			0x00, 0x2d, 0x00, 0x0f, 0x01, 0x44, 0x01, 0x33,
			0x0f, 0x00, 0x10, 0xf4, 0x07, 0x10, 0x20, 0x00,
			0x06, 0x0f, 0x0f, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x01, 0x42, 0x19, 0xc0, 0x2a, 0x40,
			0x2a, 0xbe, 0x3a, 0xfc, 0x3a, 0xfa, 0x3a, 0xf8,
			0x3b, 0x38, 0x3b, 0x38, 0x3b, 0x76, 0x4b, 0x76,
			0x4b, 0x76, 0x4b, 0xb4, 0x5b, 0xb4, 0x73, 0xf4,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
	{
		/* 7680x4320/960X96 rgb 10bpc 10bpp */
		7680, 4320, 960, 96, 1, 10, 160,
		{
			0x12, 0x00, 0x00, 0xad, 0x30, 0xa0, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x04, 0xb0,
			0x01, 0x9a, 0x02, 0xe0, 0x00, 0x19, 0x09, 0xb0,
			0x00, 0x12, 0x00, 0x0f, 0x01, 0x44, 0x00, 0xbb,
			0x16, 0x00, 0x10, 0xec, 0x07, 0x10, 0x20, 0x00,
			0x06, 0x0f, 0x0f, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x01, 0xc2, 0x22, 0x00, 0x2a, 0x40,
			0x2a, 0xbe, 0x3a, 0xfc, 0x3a, 0xfa, 0x3a, 0xf8,
			0x3b, 0x38, 0x3b, 0x78, 0x3b, 0x76, 0x4b, 0xb6,
			0x4b, 0xb6, 0x4b, 0xf4, 0x63, 0xf4, 0x7c, 0x34,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
	{
		/* 7680x4320/960X96 rgb 10bpc 9bpp */
		7680, 4320, 960, 96, 1, 10, 144,
		{
			0x12, 0x00, 0x00, 0xad, 0x30, 0x90, 0x10, 0xe0,
			0x1e, 0x00, 0x00, 0x60, 0x03, 0xc0, 0x04, 0x38,
			0x01, 0xc7, 0x03, 0x16, 0x00, 0x1c, 0x08, 0xc7,
			0x00, 0x10, 0x00, 0x0f, 0x01, 0x44, 0x00, 0xaa,
			0x17, 0x00, 0x10, 0xf1, 0x07, 0x10, 0x20, 0x00,
			0x06, 0x0f, 0x0f, 0x33, 0x0e, 0x1c, 0x2a, 0x38,
			0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7b,
			0x7d, 0x7e, 0x01, 0xc2, 0x22, 0x00, 0x2a, 0x40,
			0x2a, 0xbe, 0x3a, 0xfc, 0x3a, 0xfa, 0x3a, 0xf8,
			0x3b, 0x38, 0x3b, 0x78, 0x3b, 0x76, 0x4b, 0xb6,
			0x4b, 0xb6, 0x4b, 0xf4, 0x63, 0xf4, 0x84, 0x74,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
	},
};

static bool hdmi_bus_fmt_is_rgb(unsigned int bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_RGB888_1X24:
	case MEDIA_BUS_FMT_RGB101010_1X30:
	case MEDIA_BUS_FMT_RGB121212_1X36:
	case MEDIA_BUS_FMT_RGB161616_1X48:
		return true;

	default:
		return false;
	}
}

static bool hdmi_bus_fmt_is_yuv444(unsigned int bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_YUV8_1X24:
	case MEDIA_BUS_FMT_YUV10_1X30:
	case MEDIA_BUS_FMT_YUV12_1X36:
	case MEDIA_BUS_FMT_YUV16_1X48:
		return true;

	default:
		return false;
	}
}

static bool hdmi_bus_fmt_is_yuv422(unsigned int bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_UYVY8_1X16:
	case MEDIA_BUS_FMT_UYVY10_1X20:
	case MEDIA_BUS_FMT_UYVY12_1X24:
		return true;

	default:
		return false;
	}
}

static bool hdmi_bus_fmt_is_yuv420(unsigned int bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_UYYVYY8_0_5X24:
	case MEDIA_BUS_FMT_UYYVYY10_0_5X30:
	case MEDIA_BUS_FMT_UYYVYY12_0_5X36:
	case MEDIA_BUS_FMT_UYYVYY16_0_5X48:
		return true;

	default:
	return false;
	}
}

static int hdmi_bus_fmt_color_depth(unsigned int bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_RGB888_1X24:
	case MEDIA_BUS_FMT_YUV8_1X24:
	case MEDIA_BUS_FMT_UYVY8_1X16:
	case MEDIA_BUS_FMT_UYYVYY8_0_5X24:
		return 8;

	case MEDIA_BUS_FMT_RGB101010_1X30:
	case MEDIA_BUS_FMT_YUV10_1X30:
	case MEDIA_BUS_FMT_UYVY10_1X20:
	case MEDIA_BUS_FMT_UYYVYY10_0_5X30:
		return 10;

	case MEDIA_BUS_FMT_RGB121212_1X36:
	case MEDIA_BUS_FMT_YUV12_1X36:
	case MEDIA_BUS_FMT_UYVY12_1X24:
	case MEDIA_BUS_FMT_UYYVYY12_0_5X36:
		return 12;

	case MEDIA_BUS_FMT_RGB161616_1X48:
	case MEDIA_BUS_FMT_YUV16_1X48:
	case MEDIA_BUS_FMT_UYYVYY16_0_5X48:
		return 16;

	default:
		return 0;
	}
}

static unsigned int
hdmi_get_tmdsclock(struct rockchip_hdmi *hdmi, unsigned long pixelclock)
{
	unsigned int tmdsclock = pixelclock;
	unsigned int depth =
		hdmi_bus_fmt_color_depth(hdmi->output_bus_format);

	if (!hdmi_bus_fmt_is_yuv422(hdmi->output_bus_format)) {
		switch (depth) {
		case 16:
			tmdsclock = pixelclock * 2;
			break;
		case 12:
			tmdsclock = pixelclock * 3 / 2;
			break;
		case 10:
			tmdsclock = pixelclock * 5 / 4;
			break;
		default:
			break;
		}
	}

	return tmdsclock;
}

static void hdmi_select_link_config(struct rockchip_hdmi *hdmi,
				    struct drm_crtc_state *crtc_state)
{
	struct drm_display_mode *mode = &crtc_state->mode;
	int max_lanes, max_rate_per_lane;
	int max_dsc_lanes, max_dsc_rate_per_lane;
	int val;
	unsigned long max_frl_rate;
	bool is_hdmi0;

	if (!hdmi->id)
		is_hdmi0 = true;
	else
		is_hdmi0 = false;

	max_lanes = hdmi->max_lanes;
	max_rate_per_lane = hdmi->max_frl_rate_per_lane;
	max_frl_rate = max_lanes * max_rate_per_lane * 1000000;

	hdmi->link_cfg.dsc_mode = false;
	hdmi->link_cfg.frl_lanes = max_lanes;
	hdmi->link_cfg.rate_per_lane = max_rate_per_lane;

	if (!max_frl_rate || mode->clock < HDMI20_MAX_RATE) {
		dev_info(hdmi->dev, "use tmds mode\n");
		hdmi->link_cfg.frl_mode = false;
		val = HIWORD_UPDATE(0, RK3588_HDMI21_MASK);
		if (is_hdmi0)
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON4, val);
		else
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON7, val);

		val = HIWORD_UPDATE(0, RK3588_COMPRESS_MODE_MASK | RK3588_COLOR_FORMAT_MASK);
		if (is_hdmi0)
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON3, val);
		else
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON6, val);
		return;
	}

	hdmi->link_cfg.frl_mode = true;
	val = HIWORD_UPDATE(RK3588_HDMI21_MASK, RK3588_HDMI21_MASK);
	if (is_hdmi0)
		regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON4, val);
	else
		regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON7, val);

	if (!hdmi->dsc_cap.v_1p2)
		return;

	max_dsc_lanes = hdmi->dsc_cap.max_lanes;
	max_dsc_rate_per_lane =
		hdmi->dsc_cap.max_frl_rate_per_lane;

	if (mode->clock >= HDMI_8K60_RATE &&
	    !hdmi_bus_fmt_is_yuv420(hdmi->bus_format) &&
	    !hdmi_bus_fmt_is_yuv422(hdmi->bus_format)) {
		hdmi->link_cfg.dsc_mode = true;
		hdmi->link_cfg.frl_lanes = max_dsc_lanes;
		hdmi->link_cfg.rate_per_lane = max_dsc_rate_per_lane;
		val = HIWORD_UPDATE(RK3588_COMPRESS_MODE_MASK | RK3588_COMPRESSED_DATA,
				    RK3588_COMPRESS_MODE_MASK | RK3588_COLOR_FORMAT_MASK);
		if (is_hdmi0)
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON3, val);
		else
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON6, val);
	} else {
		hdmi->link_cfg.dsc_mode = false;
		hdmi->link_cfg.frl_lanes = max_lanes;
		hdmi->link_cfg.rate_per_lane = max_rate_per_lane;
		val = HIWORD_UPDATE(0, RK3588_COMPRESS_MODE_MASK | RK3588_COLOR_FORMAT_MASK);
		if (is_hdmi0)
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON3, val);
		else
			regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON6, val);
	}
}

/////////////////////////////////////////////////////////////////////////////////////

static int hdmi_dsc_get_slice_height(int vactive)
{
	int slice_height;

	/*
	 * Slice Height determination : HDMI2.1 Section 7.7.5.2
	 * Select smallest slice height >=96, that results in a valid PPS and
	 * requires minimum padding lines required for final slice.
	 *
	 * Assumption : Vactive is even.
	 */
	for (slice_height = 96; slice_height <= vactive; slice_height += 2)
		if (vactive % slice_height == 0)
			return slice_height;

	return 0;
}

static int hdmi_dsc_get_num_slices(struct rockchip_hdmi *hdmi,
				   struct drm_crtc_state *crtc_state,
				   int src_max_slices, int src_max_slice_width,
				   int hdmi_max_slices, int hdmi_throughput)
{
/* Pixel rates in KPixels/sec */
#define HDMI_DSC_PEAK_PIXEL_RATE		2720000
/*
 * Rates at which the source and sink are required to process pixels in each
 * slice, can be two levels: either at least 340000KHz or at least 40000KHz.
 */
#define HDMI_DSC_MAX_ENC_THROUGHPUT_0		340000
#define HDMI_DSC_MAX_ENC_THROUGHPUT_1		400000

/* Spec limits the slice width to 2720 pixels */
#define MAX_HDMI_SLICE_WIDTH			2720
	int kslice_adjust;
	int adjusted_clk_khz;
	int min_slices;
	int target_slices;
	int max_throughput; /* max clock freq. in khz per slice */
	int max_slice_width;
	int slice_width;
	int pixel_clock = crtc_state->mode.clock;

	if (!hdmi_throughput)
		return 0;

	/*
	 * Slice Width determination : HDMI2.1 Section 7.7.5.1
	 * kslice_adjust factor for 4:2:0, and 4:2:2 formats is 0.5, where as
	 * for 4:4:4 is 1.0. Multiplying these factors by 10 and later
	 * dividing adjusted clock value by 10.
	 */
	if (hdmi_bus_fmt_is_yuv444(hdmi->output_bus_format) ||
	    hdmi_bus_fmt_is_rgb(hdmi->output_bus_format))
		kslice_adjust = 10;
	else
		kslice_adjust = 5;

	/*
	 * As per spec, the rate at which the source and the sink process
	 * the pixels per slice are at two levels: at least 340Mhz or 400Mhz.
	 * This depends upon the pixel clock rate and output formats
	 * (kslice adjust).
	 * If pixel clock * kslice adjust >= 2720MHz slices can be processed
	 * at max 340MHz, otherwise they can be processed at max 400MHz.
	 */

	adjusted_clk_khz = DIV_ROUND_UP(kslice_adjust * pixel_clock, 10);

	if (adjusted_clk_khz <= HDMI_DSC_PEAK_PIXEL_RATE)
		max_throughput = HDMI_DSC_MAX_ENC_THROUGHPUT_0;
	else
		max_throughput = HDMI_DSC_MAX_ENC_THROUGHPUT_1;

	/*
	 * Taking into account the sink's capability for maximum
	 * clock per slice (in MHz) as read from HF-VSDB.
	 */
	max_throughput = min(max_throughput, hdmi_throughput * 1000);

	min_slices = DIV_ROUND_UP(adjusted_clk_khz, max_throughput);
	max_slice_width = min(MAX_HDMI_SLICE_WIDTH, src_max_slice_width);

	/*
	 * Keep on increasing the num of slices/line, starting from min_slices
	 * per line till we get such a number, for which the slice_width is
	 * just less than max_slice_width. The slices/line selected should be
	 * less than or equal to the max horizontal slices that the combination
	 * of PCON encoder and HDMI decoder can support.
	 */
	do {
		if (min_slices <= 1 && src_max_slices >= 1 && hdmi_max_slices >= 1)
			target_slices = 1;
		else if (min_slices <= 2 && src_max_slices >= 2 && hdmi_max_slices >= 2)
			target_slices = 2;
		else if (min_slices <= 4 && src_max_slices >= 4 && hdmi_max_slices >= 4)
			target_slices = 4;
		else if (min_slices <= 8 && src_max_slices >= 8 && hdmi_max_slices >= 8)
			target_slices = 8;
		else if (min_slices <= 12 && src_max_slices >= 12 && hdmi_max_slices >= 12)
			target_slices = 12;
		else if (min_slices <= 16 && src_max_slices >= 16 && hdmi_max_slices >= 16)
			target_slices = 16;
		else
			return 0;

		slice_width = DIV_ROUND_UP(crtc_state->mode.hdisplay, target_slices);
		if (slice_width > max_slice_width)
			min_slices = target_slices + 1;
	} while (slice_width > max_slice_width);

	return target_slices;
}

static int hdmi_dsc_slices(struct rockchip_hdmi *hdmi,
			   struct drm_crtc_state *crtc_state)
{
	int hdmi_throughput = hdmi->dsc_cap.clk_per_slice;
	int hdmi_max_slices = hdmi->dsc_cap.max_slices;
	int rk_max_slices = 8;
	int rk_max_slice_width = 2048;

	return hdmi_dsc_get_num_slices(hdmi, crtc_state, rk_max_slices,
				       rk_max_slice_width,
				       hdmi_max_slices, hdmi_throughput);
}

static int
hdmi_dsc_get_bpp(struct rockchip_hdmi *hdmi, int src_fractional_bpp,
		 int slice_width, int num_slices, bool hdmi_all_bpp,
		 int hdmi_max_chunk_bytes)
{
	int max_dsc_bpp, min_dsc_bpp;
	int target_bytes;
	bool bpp_found = false;
	int bpp_decrement_x16;
	int bpp_target;
	int bpp_target_x16;

	/*
	 * Get min bpp and max bpp as per Table 7.23, in HDMI2.1 spec
	 * Start with the max bpp and keep on decrementing with
	 * fractional bpp, if supported by PCON DSC encoder
	 *
	 * for each bpp we check if no of bytes can be supported by HDMI sink
	 */

	/* only 9\10\12 bpp was tested */
	min_dsc_bpp = 9;
	max_dsc_bpp = 12;

	/*
	 * Taking into account if all dsc_all_bpp supported by HDMI2.1 sink
	 * Section 7.7.34 : Source shall not enable compressed Video
	 * Transport with bpp_target settings above 12 bpp unless
	 * DSC_all_bpp is set to 1.
	 */
	if (!hdmi_all_bpp)
		max_dsc_bpp = min(max_dsc_bpp, 12);

	/*
	 * The Sink has a limit of compressed data in bytes for a scanline,
	 * as described in max_chunk_bytes field in HFVSDB block of edid.
	 * The no. of bytes depend on the target bits per pixel that the
	 * source configures. So we start with the max_bpp and calculate
	 * the target_chunk_bytes. We keep on decrementing the target_bpp,
	 * till we get the target_chunk_bytes just less than what the sink's
	 * max_chunk_bytes, or else till we reach the min_dsc_bpp.
	 *
	 * The decrement is according to the fractional support from PCON DSC
	 * encoder. For fractional BPP we use bpp_target as a multiple of 16.
	 *
	 * bpp_target_x16 = bpp_target * 16
	 * So we need to decrement by {1, 2, 4, 8, 16} for fractional bpps
	 * {1/16, 1/8, 1/4, 1/2, 1} respectively.
	 */

	bpp_target = max_dsc_bpp;

	/* src does not support fractional bpp implies decrement by 16 for bppx16 */
	if (!src_fractional_bpp)
		src_fractional_bpp = 1;
	bpp_decrement_x16 = DIV_ROUND_UP(16, src_fractional_bpp);
	bpp_target_x16 = bpp_target * 16;

	while (bpp_target_x16 > (min_dsc_bpp * 16)) {
		int bpp;

		bpp = DIV_ROUND_UP(bpp_target_x16, 16);
		target_bytes = DIV_ROUND_UP((num_slices * slice_width * bpp), 8);
		if (target_bytes <= hdmi_max_chunk_bytes) {
			bpp_found = true;
			break;
		}
		bpp_target_x16 -= bpp_decrement_x16;
	}
	if (bpp_found)
		return bpp_target_x16;

	return 0;
}

static int
dw_hdmi_dsc_bpp(struct rockchip_hdmi *hdmi,
		int num_slices, int slice_width)
{
	bool hdmi_all_bpp = hdmi->dsc_cap.all_bpp;
	int fractional_bpp = 0;
	int hdmi_max_chunk_bytes = hdmi->dsc_cap.total_chunk_kbytes * 1024;

	return hdmi_dsc_get_bpp(hdmi, fractional_bpp, slice_width,
				num_slices, hdmi_all_bpp,
				hdmi_max_chunk_bytes);
}

static int dw_hdmi_qp_set_link_cfg(struct rockchip_hdmi *hdmi,
				   u16 pic_width, u16 pic_height,
				   u16 slice_width, u16 slice_height,
				   u16 bits_per_pixel, u8 bits_per_component)
{
	int i;

	for (i = 0; i < PPS_TABLE_LEN; i++)
		if (pic_width == pps_datas[i].pic_width &&
		    pic_height == pps_datas[i].pic_height &&
		    slice_width == pps_datas[i].slice_width &&
		    slice_height == pps_datas[i].slice_height &&
		    bits_per_component == pps_datas[i].bpc &&
		    bits_per_pixel == pps_datas[i].bpp &&
		    hdmi_bus_fmt_is_rgb(hdmi->output_bus_format) == pps_datas[i].convert_rgb)
			break;

	if (i == PPS_TABLE_LEN) {
		dev_err(hdmi->dev, "can't find pps cfg!\n");
		return -EINVAL;
	}

	memcpy(hdmi->link_cfg.pps_payload, pps_datas[i].raw_pps, 128);
	hdmi->link_cfg.hcactive = DIV_ROUND_UP(slice_width * (bits_per_pixel / 16), 8) *
		(pic_width / slice_width);

	return 0;
}

static void dw_hdmi_qp_dsc_configure(struct rockchip_hdmi *hdmi,
				     struct rockchip_crtc_state *s,
				     struct drm_crtc_state *crtc_state)
{
	int ret;
	int slice_height;
	int slice_width;
	int bits_per_pixel;
	int slice_count;
	bool hdmi_is_dsc_1_2;
	unsigned int depth = hdmi_bus_fmt_color_depth(hdmi->output_bus_format);

	if (!crtc_state)
		return;

	hdmi_is_dsc_1_2 = hdmi->dsc_cap.v_1p2;

	if (!hdmi_is_dsc_1_2)
		return;

	slice_height = hdmi_dsc_get_slice_height(crtc_state->mode.vdisplay);
	if (!slice_height)
		return;

	slice_count = hdmi_dsc_slices(hdmi, crtc_state);
	if (!slice_count)
		return;

	slice_width = DIV_ROUND_UP(crtc_state->mode.hdisplay, slice_count);

	bits_per_pixel = dw_hdmi_dsc_bpp(hdmi, slice_count, slice_width);
	if (!bits_per_pixel)
		return;

	ret = dw_hdmi_qp_set_link_cfg(hdmi, crtc_state->mode.hdisplay,
				      crtc_state->mode.vdisplay, slice_width,
				      slice_height, bits_per_pixel, depth);

	if (ret) {
		dev_err(hdmi->dev, "set vdsc cfg failed\n");
		return;
	}
	dev_info(hdmi->dev, "dsc_enable\n");
	s->dsc_enable = 1;
	s->dsc_sink_cap.version_major = 1;
	s->dsc_sink_cap.version_minor = 2;
	s->dsc_sink_cap.slice_width = slice_width;
	s->dsc_sink_cap.slice_height = slice_height;
	s->dsc_sink_cap.target_bits_per_pixel_x16 = bits_per_pixel;
	s->dsc_sink_cap.block_pred = 1;
	s->dsc_sink_cap.native_420 = 0;

	memcpy(&s->pps, hdmi->link_cfg.pps_payload, 128);
}
/////////////////////////////////////////////////////////////////////////////////////////

static int rockchip_hdmi_update_phy_table(struct rockchip_hdmi *hdmi,
					  u32 *config,
					  int phy_table_size)
{
	int i;

	if (phy_table_size > ARRAY_SIZE(rockchip_phy_config)) {
		dev_err(hdmi->dev, "phy table array number is out of range\n");
		return -E2BIG;
	}

	for (i = 0; i < phy_table_size; i++) {
		if (config[i * 4] != 0)
			rockchip_phy_config[i].mpixelclock = (u64)config[i * 4];
		else
			rockchip_phy_config[i].mpixelclock = ~0UL;
		rockchip_phy_config[i].sym_ctr = (u16)config[i * 4 + 1];
		rockchip_phy_config[i].term = (u16)config[i * 4 + 2];
		rockchip_phy_config[i].vlev_ctr = (u16)config[i * 4 + 3];
	}

	return 0;
}

static void repo_hpd_event(struct work_struct *p_work)
{
	struct rockchip_hdmi *hdmi = container_of(p_work, struct rockchip_hdmi, work.work);
	bool change;

	change = drm_helper_hpd_irq_event(hdmi->encoder.dev);
	if (change) {
		dev_dbg(hdmi->dev, "hpd stat changed:%d\n", hdmi->hpd_stat);
		dw_hdmi_qp_cec_set_hpd(hdmi->hdmi_qp, hdmi->hpd_stat, change);
	}
}

static irqreturn_t rockchip_hdmi_hardirq(int irq, void *dev_id)
{
	struct rockchip_hdmi *hdmi = dev_id;
	u32 intr_stat, val;

	regmap_read(hdmi->regmap, RK3588_GRF_SOC_STATUS1, &intr_stat);

	if (intr_stat) {
		dev_dbg(hdmi->dev, "hpd irq %#x\n", intr_stat);

		if (!hdmi->id)
			val = HIWORD_UPDATE(RK3588_HDMI0_HPD_INT_MSK,
					    RK3588_HDMI0_HPD_INT_MSK);
		else
			val = HIWORD_UPDATE(RK3588_HDMI1_HPD_INT_MSK,
					    RK3588_HDMI1_HPD_INT_MSK);
		regmap_write(hdmi->regmap, RK3588_GRF_SOC_CON2, val);
		return IRQ_WAKE_THREAD;
	}

	return IRQ_NONE;
}

static irqreturn_t rockchip_hdmi_irq(int irq, void *dev_id)
{
	struct rockchip_hdmi *hdmi = dev_id;
	u32 intr_stat, val;
	int msecs;
	bool stat;

	regmap_read(hdmi->regmap, RK3588_GRF_SOC_STATUS1, &intr_stat);

	if (!intr_stat)
		return IRQ_NONE;

	if (!hdmi->id) {
		val = HIWORD_UPDATE(RK3588_HDMI0_HPD_INT_CLR,
				    RK3588_HDMI0_HPD_INT_CLR);
		if (intr_stat & RK3588_HDMI0_LEVEL_INT)
			stat = true;
		else
			stat = false;
	} else {
		val = HIWORD_UPDATE(RK3588_HDMI1_HPD_INT_CLR,
				    RK3588_HDMI1_HPD_INT_CLR);
		if (intr_stat & RK3588_HDMI1_LEVEL_INT)
			stat = true;
		else
			stat = false;
	}

	regmap_write(hdmi->regmap, RK3588_GRF_SOC_CON2, val);

	if (stat) {
		hdmi->hpd_stat = true;
		msecs = 150;
	} else {
		hdmi->hpd_stat = false;
		msecs = 20;
	}
	mod_delayed_work(hdmi->workqueue, &hdmi->work, msecs_to_jiffies(msecs));

	if (!hdmi->id) {
		val = HIWORD_UPDATE(RK3588_HDMI0_HPD_INT_CLR,
				    RK3588_HDMI0_HPD_INT_CLR) |
		      HIWORD_UPDATE(0, RK3588_HDMI0_HPD_INT_MSK);
	} else {
		val = HIWORD_UPDATE(RK3588_HDMI1_HPD_INT_CLR,
				    RK3588_HDMI1_HPD_INT_CLR) |
		      HIWORD_UPDATE(0, RK3588_HDMI1_HPD_INT_MSK);
	}

	regmap_write(hdmi->regmap, RK3588_GRF_SOC_CON2, val);

	return IRQ_HANDLED;
}

static void init_hpd_work(struct rockchip_hdmi *hdmi)
{
	hdmi->workqueue = create_workqueue("hpd_queue");
	INIT_DELAYED_WORK(&hdmi->work, repo_hpd_event);
}

static int rockchip_hdmi_parse_dt(struct rockchip_hdmi *hdmi)
{
	int ret, val, phy_table_size;
	u32 *phy_config;
	struct device_node *np = hdmi->dev->of_node;

	hdmi->regmap = syscon_regmap_lookup_by_phandle(np, "rockchip,grf");
	if (IS_ERR(hdmi->regmap)) {
		DRM_DEV_ERROR(hdmi->dev, "Unable to get rockchip,grf\n");
		return PTR_ERR(hdmi->regmap);
	}

	if(hdmi->is_hdmi_qp) {
		hdmi->vo1_regmap = syscon_regmap_lookup_by_phandle(np, "rockchip,vo1_grf");
		if (IS_ERR(hdmi->vo1_regmap)) {
			DRM_DEV_ERROR(hdmi->dev, "Unable to get rockchip,vo1_grf\n");
			return PTR_ERR(hdmi->vo1_regmap);
		}
	}

	hdmi->phyref_clk = devm_clk_get(hdmi->dev, "vpll");
	if (PTR_ERR(hdmi->phyref_clk) == -ENOENT)
		hdmi->phyref_clk = devm_clk_get(hdmi->dev, "ref");

	if (PTR_ERR(hdmi->phyref_clk) == -ENOENT) {
		hdmi->phyref_clk = NULL;
	} else if (PTR_ERR(hdmi->phyref_clk) == -EPROBE_DEFER) {
		return -EPROBE_DEFER;
	} else if (IS_ERR(hdmi->phyref_clk)) {
		DRM_DEV_ERROR(hdmi->dev, "failed to get grf clock\n");
		return PTR_ERR(hdmi->phyref_clk);
	}

	hdmi->grf_clk = devm_clk_get(hdmi->dev, "grf");
	if (PTR_ERR(hdmi->grf_clk) == -ENOENT) {
		hdmi->grf_clk = NULL;
	} else if (PTR_ERR(hdmi->grf_clk) == -EPROBE_DEFER) {
		return -EPROBE_DEFER;
	} else if (IS_ERR(hdmi->grf_clk)) {
		DRM_DEV_ERROR(hdmi->dev, "failed to get grf clock\n");
		return PTR_ERR(hdmi->grf_clk);
	}

	hdmi->hclk_vio = devm_clk_get(hdmi->dev, "hclk_vio");
	if (PTR_ERR(hdmi->hclk_vio) == -ENOENT) {
		hdmi->hclk_vio = NULL;
	} else if (PTR_ERR(hdmi->hclk_vio) == -EPROBE_DEFER) {
		return -EPROBE_DEFER;
	} else if (IS_ERR(hdmi->hclk_vio)) {
		dev_err(hdmi->dev, "failed to get hclk_vio clock\n");
		return PTR_ERR(hdmi->hclk_vio);
	}

	hdmi->hclk_vop = devm_clk_get(hdmi->dev, "hclk");
	if (PTR_ERR(hdmi->hclk_vop) == -ENOENT) {
		hdmi->hclk_vop = NULL;
	} else if (PTR_ERR(hdmi->hclk_vop) == -EPROBE_DEFER) {
		return -EPROBE_DEFER;
	} else if (IS_ERR(hdmi->hclk_vop)) {
		dev_err(hdmi->dev, "failed to get hclk_vop clock\n");
		return PTR_ERR(hdmi->hclk_vop);
	}

	hdmi->aud_clk = devm_clk_get_optional(hdmi->dev, "aud");
	if (IS_ERR(hdmi->aud_clk)) {
		dev_err_probe(hdmi->dev, PTR_ERR(hdmi->aud_clk),
			      "failed to get aud_clk clock\n");
		return PTR_ERR(hdmi->aud_clk);
	}

	hdmi->hpd_clk = devm_clk_get_optional(hdmi->dev, "hpd");
	if (IS_ERR(hdmi->hpd_clk)) {
		dev_err_probe(hdmi->dev, PTR_ERR(hdmi->hpd_clk),
			      "failed to get hpd_clk clock\n");
		return PTR_ERR(hdmi->hpd_clk);
	}

	hdmi->hclk_vo1 = devm_clk_get_optional(hdmi->dev, "hclk_vo1");
	if (IS_ERR(hdmi->hclk_vo1)) {
		dev_err_probe(hdmi->dev, PTR_ERR(hdmi->hclk_vo1),
			      "failed to get hclk_vo1 clock\n");
		return PTR_ERR(hdmi->hclk_vo1);
	}

	hdmi->earc_clk = devm_clk_get_optional(hdmi->dev, "earc");
	if (IS_ERR(hdmi->earc_clk)) {
		dev_err_probe(hdmi->dev, PTR_ERR(hdmi->earc_clk),
			      "failed to get earc_clk clock\n");
		return PTR_ERR(hdmi->earc_clk);
	}

	hdmi->hdmitx_ref = devm_clk_get_optional(hdmi->dev, "hdmitx_ref");
	if (IS_ERR(hdmi->hdmitx_ref)) {
		dev_err_probe(hdmi->dev, PTR_ERR(hdmi->hdmitx_ref),
			      "failed to get hdmitx_ref clock\n");
		return PTR_ERR(hdmi->hdmitx_ref);
	}

	hdmi->pclk = devm_clk_get_optional(hdmi->dev, "pclk");
	if (IS_ERR(hdmi->pclk)) {
		dev_err_probe(hdmi->dev, PTR_ERR(hdmi->pclk),
			      "failed to get pclk clock\n");
		return PTR_ERR(hdmi->pclk);
	}

	hdmi->enable_gpio = devm_gpiod_get_optional(hdmi->dev, "enable",
						    GPIOD_OUT_HIGH);
	if (IS_ERR(hdmi->enable_gpio)) {
		ret = PTR_ERR(hdmi->enable_gpio);
		dev_err(hdmi->dev, "failed to request enable GPIO: %d\n", ret);
		return ret;
	}

	hdmi->skip_check_420_mode =
		of_property_read_bool(np, "skip-check-420-mode");

	if (of_get_property(np, "rockchip,phy-table", &val)) {
		phy_config = kmalloc(val, GFP_KERNEL);
		if (!phy_config) {
			/* use default table when kmalloc failed. */
			dev_err(hdmi->dev, "kmalloc phy table failed\n");

			return -ENOMEM;
		}
		phy_table_size = val / 16;
		of_property_read_u32_array(np, "rockchip,phy-table",
					   phy_config, val / sizeof(u32));
		ret = rockchip_hdmi_update_phy_table(hdmi, phy_config,
						     phy_table_size);
		if (ret) {
			kfree(phy_config);
			return ret;
		}
		kfree(phy_config);
	} else {
		dev_dbg(hdmi->dev, "use default hdmi phy table\n");
	}

	return 0;
}

static enum drm_mode_status
dw_hdmi_rockchip_mode_valid(struct drm_connector *connector, void *data,
			    const struct drm_display_info *info,
			    const struct drm_display_mode *mode)
{
	struct drm_encoder *encoder = connector->encoder;
	enum drm_mode_status status = MODE_OK;
	struct drm_device *dev = connector->dev;
	struct rockchip_drm_private *priv = dev->dev_private;
	struct drm_crtc *crtc;
	struct rockchip_hdmi *hdmi;

	/*
	 * Pixel clocks we support are always < 2GHz and so fit in an
	 * int.  We should make sure source rate does too so we don't get
	 * overflow when we multiply by 1000.
	 */
	if (mode->clock > INT_MAX / 1000)
		return MODE_BAD;

	if (!encoder) {
		const struct drm_connector_helper_funcs *funcs;

		funcs = connector->helper_private;
		if (funcs->atomic_best_encoder)
			encoder = funcs->atomic_best_encoder(connector,
							     connector->state);
		else
			encoder = funcs->best_encoder(connector);
	}

	if (!encoder || !encoder->possible_crtcs)
		return MODE_BAD;

	hdmi = to_rockchip_hdmi(encoder);

	/*
	 * If sink max TMDS clock < 340MHz, we should check the mode pixel
	 * clock > 340MHz is YCbCr420 or not and whether the platform supports
	 * YCbCr420.
	 */
	if (!hdmi->skip_check_420_mode) {
		if (mode->clock > 340000 &&
		    connector->display_info.max_tmds_clock < 340000 &&
		    (!drm_mode_is_420(&connector->display_info, mode) ||
		     !connector->ycbcr_420_allowed))
			return MODE_BAD;

		if (hdmi->max_tmdsclk <= 340000 && mode->clock > 340000 &&
		    !drm_mode_is_420(&connector->display_info, mode))
			return MODE_BAD;
	};

	if (hdmi->phy) {
		if (hdmi->is_hdmi_qp)
			phy_set_bus_width(hdmi->phy, mode->clock * 10);
		else
			phy_set_bus_width(hdmi->phy, 8);
	}

	/*
	 * ensure all drm display mode can work, if someone want support more
	 * resolutions, please limit the possible_crtc, only connect to
	 * needed crtc.
	 */
	drm_for_each_crtc(crtc, connector->dev) {
		int pipe = drm_crtc_index(crtc);
		const struct rockchip_crtc_funcs *funcs =
						priv->crtc_funcs[pipe];

		if (!(encoder->possible_crtcs & drm_crtc_mask(crtc)))
			continue;
		if (!funcs || !funcs->mode_valid)
			continue;

		status = funcs->mode_valid(crtc, mode,
					   DRM_MODE_CONNECTOR_HDMIA);
		if (status != MODE_OK)
			return status;
	}

	return status;
}

static void dw_hdmi_rockchip_encoder_disable(struct drm_encoder *encoder)
{
	struct rockchip_hdmi *hdmi = to_rockchip_hdmi(encoder);
	struct drm_crtc *crtc = encoder->crtc;
	struct rockchip_crtc_state *s = to_rockchip_crtc_state(crtc->state);

	if (!hdmi->mode_changed) {
		if (!hdmi->id)
			s->output_if &= ~VOP_OUTPUT_IF_HDMI1;
		else
			s->output_if &= ~VOP_OUTPUT_IF_HDMI0;
	}
	/*
	 * when plug out hdmi it will be switch cvbs and then phy bus width
	 * must be set as 8
	 */
	if (hdmi->phy)
		phy_set_bus_width(hdmi->phy, 8);
}

static void dw_hdmi_rockchip_encoder_enable(struct drm_encoder *encoder)
{
	struct rockchip_hdmi *hdmi = to_rockchip_hdmi(encoder);
	struct drm_crtc *crtc = encoder->crtc;
	u32 val;
	int mux;
	int ret;

	if (WARN_ON(!crtc || !crtc->state))
		return;

	if (hdmi->phy)
		phy_set_bus_width(hdmi->phy, hdmi->phy_bus_width);

	clk_set_rate(hdmi->phyref_clk,
		     crtc->state->adjusted_mode.crtc_clock * 1000);

	if (hdmi->chip_data->lcdsel_grf_reg < 0)
		return;

	mux = drm_of_encoder_active_endpoint_id(hdmi->dev->of_node, encoder);
	if (mux)
		val = hdmi->chip_data->lcdsel_lit;
	else
		val = hdmi->chip_data->lcdsel_big;

	ret = clk_prepare_enable(hdmi->grf_clk);
	if (ret < 0) {
		DRM_DEV_ERROR(hdmi->dev, "failed to enable grfclk %d\n", ret);
		return;
	}

	ret = regmap_write(hdmi->regmap, hdmi->chip_data->lcdsel_grf_reg, val);
	if (ret != 0)
		DRM_DEV_ERROR(hdmi->dev, "Could not write to GRF: %d\n", ret);

	if (hdmi->chip_data->lcdsel_grf_reg == RK3288_GRF_SOC_CON6) {
		struct rockchip_crtc_state *s =
				to_rockchip_crtc_state(crtc->state);
		u32 mode_mask = mux ? RK3288_HDMI_LCDC1_YUV420 :
					RK3288_HDMI_LCDC0_YUV420;

		if (s->output_mode == ROCKCHIP_OUT_MODE_YUV420)
			val = HIWORD_UPDATE(mode_mask, mode_mask);
		else
			val = HIWORD_UPDATE(0, mode_mask);

		regmap_write(hdmi->regmap, RK3288_GRF_SOC_CON16, val);
	}

	clk_disable_unprepare(hdmi->grf_clk);
	DRM_DEV_DEBUG(hdmi->dev, "vop %s output to hdmi\n",
		      ret ? "LIT" : "BIG");
}

static void rk3588_set_color_format(struct rockchip_hdmi *hdmi, u64 bus_format,
				    u32 depth)
{
	u32 val = 0;

	switch (bus_format) {
	case MEDIA_BUS_FMT_RGB888_1X24:
	case MEDIA_BUS_FMT_RGB101010_1X30:
		val = HIWORD_UPDATE(0, RK3588_COLOR_FORMAT_MASK);
		break;
	case MEDIA_BUS_FMT_UYYVYY8_0_5X24:
	case MEDIA_BUS_FMT_UYYVYY10_0_5X30:
		val = HIWORD_UPDATE(RK3588_YUV420, RK3588_COLOR_FORMAT_MASK);
		break;
	case MEDIA_BUS_FMT_YUV8_1X24:
	case MEDIA_BUS_FMT_YUV10_1X30:
		val = HIWORD_UPDATE(RK3588_YUV444, RK3588_COLOR_FORMAT_MASK);
		break;
	default:
		dev_err(hdmi->dev, "can't set correct color format\n");
		return;
	}

	if (hdmi->link_cfg.dsc_mode)
		val = HIWORD_UPDATE(RK3588_COMPRESSED_DATA, RK3588_COLOR_FORMAT_MASK);

	if (depth == 8)
		val |= HIWORD_UPDATE(RK3588_8BPC, RK3588_COLOR_DEPTH_MASK);
	else
		val |= HIWORD_UPDATE(RK3588_10BPC, RK3588_COLOR_DEPTH_MASK);

	if (!hdmi->id)
		regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON3, val);
	else
		regmap_write(hdmi->vo1_regmap, RK3588_GRF_VO1_CON6, val);
}

static void
dw_hdmi_rockchip_select_output(struct drm_connector_state *conn_state,
			       struct drm_crtc_state *crtc_state,
			       struct rockchip_hdmi *hdmi,
			       unsigned int *color_format,
			       unsigned int *output_mode,
			       unsigned long *bus_format,
			       unsigned int *bus_width,
			       unsigned long *enc_out_encoding,
			       unsigned int *eotf)
{
	struct drm_display_info *info = &conn_state->connector->display_info;
	struct drm_display_mode *mode = &crtc_state->mode;
	struct hdr_output_metadata *hdr_metadata;
	u32 vic = drm_match_cea_mode(mode);
	unsigned long tmdsclock, pixclock = mode->crtc_clock;
	unsigned int color_depth;
	bool support_dc = false;
	bool sink_is_hdmi = true;
	u32 max_tmds_clock = info->max_tmds_clock;
	int output_eotf;

	if (!hdmi->is_hdmi_qp)
		sink_is_hdmi = dw_hdmi_get_output_whether_hdmi(hdmi->hdmi);

	*color_format = DRM_HDMI_OUTPUT_DEFAULT_RGB;

	switch (hdmi->hdmi_output) {
	case DRM_HDMI_OUTPUT_YCBCR_HQ:
		if (info->color_formats & DRM_COLOR_FORMAT_YCRCB444)
			*color_format = DRM_HDMI_OUTPUT_YCBCR444;
		else if (info->color_formats & DRM_COLOR_FORMAT_YCRCB422)
			*color_format = DRM_HDMI_OUTPUT_YCBCR422;
		else if (conn_state->connector->ycbcr_420_allowed &&
			 drm_mode_is_420(info, mode) &&
			 (pixclock >= 594000 && !hdmi->is_hdmi_qp))
			*color_format = DRM_HDMI_OUTPUT_YCBCR420;
		break;
	case DRM_HDMI_OUTPUT_YCBCR_LQ:
		if (conn_state->connector->ycbcr_420_allowed &&
		    drm_mode_is_420(info, mode) && pixclock >= 594000)
			*color_format = DRM_HDMI_OUTPUT_YCBCR420;
		else if (info->color_formats & DRM_COLOR_FORMAT_YCRCB422)
			*color_format = DRM_HDMI_OUTPUT_YCBCR422;
		else if (info->color_formats & DRM_COLOR_FORMAT_YCRCB444)
			*color_format = DRM_HDMI_OUTPUT_YCBCR444;
		break;
	case DRM_HDMI_OUTPUT_YCBCR420:
		if (conn_state->connector->ycbcr_420_allowed &&
		    drm_mode_is_420(info, mode) && pixclock >= 594000)
			*color_format = DRM_HDMI_OUTPUT_YCBCR420;
		break;
	case DRM_HDMI_OUTPUT_YCBCR422:
		if (info->color_formats & DRM_COLOR_FORMAT_YCRCB422)
			*color_format = DRM_HDMI_OUTPUT_YCBCR422;
		break;
	case DRM_HDMI_OUTPUT_YCBCR444:
		if (info->color_formats & DRM_COLOR_FORMAT_YCRCB444)
			*color_format = DRM_HDMI_OUTPUT_YCBCR444;
		break;
	case DRM_HDMI_OUTPUT_DEFAULT_RGB:
	default:
		break;
	}

	if (*color_format == DRM_HDMI_OUTPUT_DEFAULT_RGB &&
	    info->edid_hdmi_dc_modes & DRM_EDID_HDMI_DC_30)
		support_dc = true;
	if (*color_format == DRM_HDMI_OUTPUT_YCBCR444 &&
	    info->edid_hdmi_dc_modes &
	    (DRM_EDID_HDMI_DC_Y444 | DRM_EDID_HDMI_DC_30))
		support_dc = true;
	if (*color_format == DRM_HDMI_OUTPUT_YCBCR422)
		support_dc = true;
	if (*color_format == DRM_HDMI_OUTPUT_YCBCR420 &&
	    info->hdmi.y420_dc_modes & DRM_EDID_YCBCR420_DC_30)
		support_dc = true;

	if (hdmi->colordepth > 8 && support_dc)
		color_depth = 10;
	else
		color_depth = 8;

	if (!sink_is_hdmi) {
		*color_format = DRM_HDMI_OUTPUT_DEFAULT_RGB;
		color_depth = 8;
	}

	*eotf = HDMI_EOTF_TRADITIONAL_GAMMA_SDR;
	if (conn_state->hdr_output_metadata) {
		hdr_metadata = (struct hdr_output_metadata *)
			conn_state->hdr_output_metadata->data;
		output_eotf = hdr_metadata->hdmi_metadata_type1.eotf;
		if (output_eotf > HDMI_EOTF_TRADITIONAL_GAMMA_SDR &&
		    output_eotf <= HDMI_EOTF_BT_2100_HLG)
			*eotf = output_eotf;
	}

	if ((*eotf > HDMI_EOTF_TRADITIONAL_GAMMA_SDR &&
	     conn_state->connector->hdr_sink_metadata.hdmi_type1.eotf &
	     BIT(*eotf)) || (hdmi->colorimetry ==
	     RK_HDMI_COLORIMETRY_BT2020))
		*enc_out_encoding = V4L2_YCBCR_ENC_BT2020;
	else if ((vic == 6) || (vic == 7) || (vic == 21) || (vic == 22) ||
		 (vic == 2) || (vic == 3) || (vic == 17) || (vic == 18))
		*enc_out_encoding = V4L2_YCBCR_ENC_601;
	else
		*enc_out_encoding = V4L2_YCBCR_ENC_709;

	if (*enc_out_encoding == V4L2_YCBCR_ENC_BT2020) {
		/* BT2020 require color depth at lest 10bit */
		color_depth = 10;
		/* We prefer use YCbCr422 to send 10bit */
		if (info->color_formats & DRM_COLOR_FORMAT_YCRCB422)
			*color_format = DRM_HDMI_OUTPUT_YCBCR422;
		if (hdmi->is_hdmi_qp) {
			if (info->color_formats & DRM_COLOR_FORMAT_YCRCB420)
				*color_format = DRM_HDMI_OUTPUT_YCBCR420;
			else
				*color_format = DRM_HDMI_OUTPUT_DEFAULT_RGB;
		}
	}

	if (mode->flags & DRM_MODE_FLAG_DBLCLK)
		pixclock *= 2;
	if ((mode->flags & DRM_MODE_FLAG_3D_MASK) ==
		DRM_MODE_FLAG_3D_FRAME_PACKING)
		pixclock *= 2;

	if (*color_format == DRM_HDMI_OUTPUT_YCBCR422 || color_depth == 8)
		tmdsclock = pixclock;
	else
		tmdsclock = pixclock * (color_depth) / 8;

	if (*color_format == DRM_HDMI_OUTPUT_YCBCR420)
		tmdsclock /= 2;

	/* XXX: max_tmds_clock of some sink is 0, we think it is 340MHz. */
	if (!max_tmds_clock)
		max_tmds_clock = 340000;

	max_tmds_clock = min(max_tmds_clock, hdmi->max_tmdsclk);

	if ((tmdsclock > max_tmds_clock) && !hdmi->is_hdmi_qp) {
		if (max_tmds_clock >= 594000) {
			color_depth = 8;
		} else if (max_tmds_clock > 340000) {
			if (drm_mode_is_420(info, mode) || tmdsclock >= 594000)
				*color_format = DRM_HDMI_OUTPUT_YCBCR420;
		} else {
			color_depth = 8;
			if (drm_mode_is_420(info, mode) || tmdsclock >= 594000)
				*color_format = DRM_HDMI_OUTPUT_YCBCR420;
		}
	}


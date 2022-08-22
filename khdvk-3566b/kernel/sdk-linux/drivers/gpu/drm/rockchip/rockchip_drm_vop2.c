// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2020 Rockchip Electronics Co., Ltd.
 * Author: Andy Yan <andy.yan@rock-chips.com>
 */
#include <drm/drm.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_uapi.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_debugfs.h>
#include <drm/drm_flip_work.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_writeback.h>
#ifdef CONFIG_DRM_ANALOGIX_DP
#include <drm/bridge/analogix_dp.h>
#endif
#include <dt-bindings/soc/rockchip-system-status.h>

#include <linux/debugfs.h>
#include <linux/fixp-arith.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/clk/clk-conf.h>
#include <linux/iopoll.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_graph.h>
#include <linux/pm_runtime.h>
#include <linux/component.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/mfd/syscon.h>
#include <linux/delay.h>
#include <linux/swab.h>
#include <linux/sort.h>
#include <linux/rockchip/cpu.h>
#include <soc/rockchip/rockchip_dmc.h>
#include <soc/rockchip/rockchip-system-status.h>
#include <uapi/linux/videodev2.h>

#include "../drm_crtc_internal.h"
#include "../drm_internal.h"

#include "rockchip_drm_drv.h"
#include "rockchip_drm_gem.h"
#include "rockchip_drm_fb.h"
#include "rockchip_drm_vop.h"
#include "rockchip_vop_reg.h"

#define _REG_SET(vop2, name, off, reg, mask, v, relaxed) \
		vop2_mask_write(vop2, off + reg.offset, mask, reg.shift, v, reg.write_mask, relaxed)

#define REG_SET(x, name, off, reg, v, relaxed) \
		_REG_SET(x, name, off, reg, reg.mask, v, relaxed)
#define REG_SET_MASK(x, name, off, reg, mask, v, relaxed) \
		_REG_SET(x, name, off, reg, reg.mask & mask, v, relaxed)

#define VOP_CLUSTER_SET(x, win, name, v) \
	do { \
		if (win->regs->cluster) \
			REG_SET(x, name, 0, win->regs->cluster->name, v, true); \
	} while (0)

#define VOP_AFBC_SET(x, win, name, v) \
	do { \
		if (win->regs->afbc) \
			REG_SET(x, name, win->offset, win->regs->afbc->name, v, true); \
	} while (0)

#define VOP_WIN_SET(x, win, name, v) \
		REG_SET(x, name, win->offset, VOP_WIN_NAME(win, name), v, true)

#define VOP_SCL_SET(x, win, name, v) \
		REG_SET(x, name, win->offset, win->regs->scl->name, v, true)

#define VOP_CTRL_SET(x, name, v) \
		REG_SET(x, name, 0, (x)->data->ctrl->name, v, false)

#define VOP_INTR_GET(vop2, name) \
		vop2_read_reg(vop2, 0, &vop2->data->ctrl->name)

#define VOP_INTR_SET(vop2, intr, name, v) \
		REG_SET(vop2, name, 0, intr->name, v, false)

#define VOP_MODULE_SET(vop2, module, name, v) \
		REG_SET(vop2, name, 0, module->regs->name, v, false)

#define VOP_INTR_SET_MASK(vop2, intr, name, mask, v) \
		REG_SET_MASK(vop2, name, 0, intr->name, mask, v, false)

#define VOP_INTR_SET_TYPE(vop2, intr, name, type, v) \
	do { \
		int i, reg = 0, mask = 0; \
		for (i = 0; i < intr->nintrs; i++) { \
			if (intr->intrs[i] & type) { \
				reg |= (v) << i; \
				mask |= 1 << i; \
			} \
		} \
		VOP_INTR_SET_MASK(vop2, intr, name, mask, reg); \
	} while (0)

#define VOP_INTR_GET_TYPE(vop2, intr, name, type) \
		vop2_get_intr_type(vop2, intr, &intr->name, type)

#define VOP_MODULE_GET(x, module, name) \
		vop2_read_reg(x, 0, &module->regs->name)

#define VOP_WIN_GET(vop2, win, name) \
		vop2_read_reg(vop2, win->offset, &VOP_WIN_NAME(win, name))

#define VOP_WIN_NAME(win, name) \
		(vop2_get_win_regs(win, &win->regs->name)->name)

#define VOP_WIN_TO_INDEX(vop2_win) \
	((vop2_win) - (vop2_win)->vop2->win)

#define VOP_GRF_SET(vop2, grf, reg, v) \
	do { \
		if (vop2->data->grf) { \
			vop2_grf_writel(vop2->grf, vop2->data->grf->reg, v); \
		} \
	} while (0)

#define to_vop2_win(x) container_of(x, struct vop2_win, base)
#define to_vop2_plane_state(x) container_of(x, struct vop2_plane_state, base)
#define to_wb_state(x) container_of(x, struct vop2_wb_connector_state, base)

/*
 * max two jobs a time, one is running(writing back),
 * another one will run in next frame.
 */
#define VOP2_WB_JOB_MAX      2
#define VOP2_SYS_AXI_BUS_NUM 2

#define VOP2_MAX_VP_OUTPUT_WIDTH	4096
/* KHZ */
#define VOP2_MAX_DCLK_RATE		600000

#define VOP2_COLOR_KEY_NONE		(0 << 31)
#define VOP2_COLOR_KEY_MASK		(1 << 31)

enum vop2_data_format {
	VOP2_FMT_ARGB8888 = 0,
	VOP2_FMT_RGB888,
	VOP2_FMT_RGB565,
	VOP2_FMT_XRGB101010,
	VOP2_FMT_YUV420SP,
	VOP2_FMT_YUV422SP,
	VOP2_FMT_YUV444SP,
	VOP2_FMT_YUYV422 = 8,
	VOP2_FMT_YUYV420,
	VOP2_FMT_VYUY422,
	VOP2_FMT_VYUY420,
	VOP2_FMT_YUV420SP_TILE_8x4 = 0x10,
	VOP2_FMT_YUV420SP_TILE_16x2,
	VOP2_FMT_YUV422SP_TILE_8x4,
	VOP2_FMT_YUV422SP_TILE_16x2,
	VOP2_FMT_YUV420SP_10,
	VOP2_FMT_YUV422SP_10,
	VOP2_FMT_YUV444SP_10,
};

enum vop2_afbc_format {
	VOP2_AFBC_FMT_RGB565,
	VOP2_AFBC_FMT_ARGB2101010 = 2,
	VOP2_AFBC_FMT_YUV420_10BIT,
	VOP2_AFBC_FMT_RGB888,
	VOP2_AFBC_FMT_ARGB8888,
	VOP2_AFBC_FMT_YUV420 = 9,
	VOP2_AFBC_FMT_YUV422 = 0xb,
	VOP2_AFBC_FMT_YUV422_10BIT = 0xe,
	VOP2_AFBC_FMT_INVALID = -1,
};

enum vop2_hdr_lut_mode {
	VOP2_HDR_LUT_MODE_AXI,
	VOP2_HDR_LUT_MODE_AHB,
};

enum vop2_pending {
	VOP_PENDING_FB_UNREF,
};

enum vop2_layer_phy_id {
	ROCKCHIP_VOP2_CLUSTER0 = 0,
	ROCKCHIP_VOP2_CLUSTER1,
	ROCKCHIP_VOP2_ESMART0,
	ROCKCHIP_VOP2_ESMART1,
	ROCKCHIP_VOP2_SMART0,
	ROCKCHIP_VOP2_SMART1,
	ROCKCHIP_VOP2_CLUSTER2,
	ROCKCHIP_VOP2_CLUSTER3,
	ROCKCHIP_VOP2_ESMART2,
	ROCKCHIP_VOP2_ESMART3,
	ROCKCHIP_VOP2_PHY_ID_INVALID = -1,
};

struct vop2_power_domain {
	struct vop2_power_domain *parent;
	struct vop2 *vop2;
	/*
	 * @lock: protect power up/down procedure.
	 * power on take effect immediately,
	 * power down take effect by vsync.
	 * we must check power_domain_status register
	 * to make sure the power domain is down before
	 * send a power on request.
	 *
	 */
	spinlock_t lock;
	unsigned int ref_count;
	bool on;
	/*
	 * If the module powered by this power domain was enabled.
	 */
	bool module_on;
	const struct vop2_power_domain_data *data;
	struct list_head list;
	struct delayed_work power_off_work;
};

struct vop2_zpos {
	struct drm_plane *plane;
	int win_phys_id;
	int zpos;
};

union vop2_alpha_ctrl {
	uint32_t val;
	struct {
		/* [0:1] */
		uint32_t color_mode:1;
		uint32_t alpha_mode:1;
		/* [2:3] */
		uint32_t blend_mode:2;
		uint32_t alpha_cal_mode:1;
		/* [5:7] */
		uint32_t factor_mode:3;
		/* [8:9] */
		uint32_t alpha_en:1;
		uint32_t src_dst_swap:1;
		uint32_t reserved:6;
		/* [16:23] */
		uint32_t glb_alpha:8;
	} bits;
};

struct vop2_alpha {
	union vop2_alpha_ctrl src_color_ctrl;
	union vop2_alpha_ctrl dst_color_ctrl;
	union vop2_alpha_ctrl src_alpha_ctrl;
	union vop2_alpha_ctrl dst_alpha_ctrl;
};

struct vop2_alpha_config {
	bool src_premulti_en;
	bool dst_premulti_en;
	bool src_pixel_alpha_en;
	bool dst_pixel_alpha_en;
	u16 src_glb_alpha_value;
	u16 dst_glb_alpha_value;
};

struct vop2_plane_state {
	struct drm_plane_state base;
	int format;
	int zpos;
	struct drm_rect src;
	struct drm_rect dest;
	dma_addr_t yrgb_mst;
	dma_addr_t uv_mst;
	bool afbc_en;
	bool hdr_in;
	bool hdr2sdr_en;
	bool r2y_en;
	bool y2r_en;
	uint32_t csc_mode;
	uint8_t xmirror_en;
	uint8_t ymirror_en;
	uint8_t rotate_90_en;
	uint8_t rotate_270_en;
	uint8_t afbc_half_block_en;
	int eotf;
	int color_space;
	int global_alpha;
	int blend_mode;
	int color_key;
	unsigned long offset;
	int pdaf_data_type;
	bool async_commit;
	struct vop_dump_list *planlist;
};

struct vop2_win {
	const char *name;
	struct vop2 *vop2;
	struct vop2_win *parent;
	struct drm_plane base;

	/*
	 * This is for cluster window
	 *
	 * A cluster window can split as two windows:
	 * a main window and a sub window.
	 */
	bool two_win_mode;

	/**
	 * ---------------------------
	 * |          |              |
	 * | Left     |  Right       |
	 * |          |              |
	 * | Cluster0 |  Cluster1    |
	 * ---------------------------
	 */

	/*
	 * @splice_mode_right: As right part of the screen in splice mode.
	 */
	bool splice_mode_right;

	/**
	 * @splice_win: splice win which used to splice for a plane
	 * hdisplay > 4096
	 */
	struct vop2_win *splice_win;
	struct vop2_win *left_win;

	uint8_t splice_win_id;

	struct vop2_power_domain *pd;

	bool enabled;

	/**
	 * @phys_id: physical id for cluster0/1, esmart0/1, smart0/1
	 * Will be used as a identification for some register
	 * configuration such as OVL_LAYER_SEL/OVL_PORT_SEL.
	 */
	uint8_t phys_id;

	/**
	 * @win_id: graphic window id, a cluster maybe split into two
	 * graphics windows.
	 */
	uint8_t win_id;
	/**
	 * @area_id: multi display region id in a graphic window, they
	 * share the same win_id.
	 */
	uint8_t area_id;
	/**
	 * @plane_id: unique plane id.
	 */
	uint8_t plane_id;
	/**
	 * @layer_id: id of the layer which the window attached to
	 */
	uint8_t layer_id;
	int layer_sel_id;
	/**
	 * @vp_mask: Bitmask of video_port0/1/2 this win attached to,
	 * one win can only attach to one vp at the one time.
	 */
	uint8_t vp_mask;
	/**
	 * @old_vp_mask: Bitmask of video_port0/1/2 this win attached of last commit,
	 * this is used for trackng the change of VOP2_PORT_SEL register.
	 */
	uint8_t old_vp_mask;
	uint8_t zpos;
	uint32_t offset;
	uint8_t axi_id;
	uint8_t axi_yrgb_id;
	uint8_t axi_uv_id;

	enum drm_plane_type type;
	unsigned int max_upscale_factor;
	unsigned int max_downscale_factor;
	unsigned int supported_rotations;
	const uint8_t *dly;
	/*
	 * vertical/horizontal scale up/down filter mode
	 */
	uint8_t hsu_filter_mode;
	uint8_t hsd_filter_mode;
	uint8_t vsu_filter_mode;
	uint8_t vsd_filter_mode;

	const struct vop2_win_regs *regs;
	const uint64_t *format_modifiers;
	const uint32_t *formats;
	uint32_t nformats;
	uint64_t feature;
	struct drm_property *feature_prop;
	struct drm_property *input_width_prop;
	struct drm_property *input_height_prop;
	struct drm_property *output_width_prop;
	struct drm_property *output_height_prop;
	struct drm_property *color_key_prop;
	struct drm_property *scale_prop;
	struct drm_property *name_prop;
};

struct vop2_cluster {
	struct vop2_win *main;
	struct vop2_win *sub;
};

struct vop2_layer {
	uint8_t id;
	/*
	 * @win_phys_id: window id of the layer selected.
	 * Every layer must make sure to select different
	 * windows of others.
	 */
	uint8_t win_phys_id;
	const struct vop2_layer_regs *regs;
};

struct vop2_wb_job {

	bool pending;
	/**
	 * @fs_vsync_cnt: frame start vysnc counter,
	 * used to get the write back complete event;
	 */
	uint32_t fs_vsync_cnt;
};

struct vop2_wb {
	uint8_t vp_id;
	struct drm_writeback_connector conn;
	const struct vop2_wb_regs *regs;
	struct vop2_wb_job jobs[VOP2_WB_JOB_MAX];
	uint8_t job_index;

	/**
	 * @job_lock:
	 *
	 * spinlock to protect the job between vop2_wb_commit and vop2_wb_handler in isr.
	 */
	spinlock_t job_lock;

};

struct vop2_dsc {
	uint8_t id;
	uint8_t max_slice_num;
	uint8_t max_linebuf_depth;	/* used to generate the bitstream */
	uint8_t min_bits_per_pixel;	/* bit num after encoder compress */
	bool enabled;
	char attach_vp_id;
	const struct vop2_dsc_regs *regs;
	struct vop2_power_domain *pd;
};

enum vop2_wb_format {
	VOP2_WB_ARGB8888,
	VOP2_WB_BGR888,
	VOP2_WB_RGB565,
	VOP2_WB_YUV420SP = 4,
	VOP2_WB_INVALID = -1,
};

struct vop2_wb_connector_state {
	struct drm_connector_state base;
	dma_addr_t yrgb_addr;
	dma_addr_t uv_addr;
	enum vop2_wb_format format;
	uint16_t scale_x_factor;
	uint8_t scale_x_en;
	uint8_t scale_y_en;
	uint8_t vp_id;
};

struct vop2_video_port {
	struct rockchip_crtc rockchip_crtc;
	struct vop2 *vop2;
	struct clk *dclk;
	struct reset_control *dclk_rst;
	uint8_t id;
	bool layer_sel_update;
	const struct vop2_video_port_regs *regs;

	struct completion dsp_hold_completion;
	struct completion line_flag_completion;

	/* protected by dev->event_lock */
	struct drm_pending_vblank_event *event;

	struct drm_flip_work fb_unref_work;
	unsigned long pending;

	/**
	 * @hdr_in: Indicate we have a hdr plane input.
	 *
	 */
	bool hdr_in;
	/**
	 * @hdr_out: Indicate the screen want a hdr output
	 * from video port.
	 *
	 */
	bool hdr_out;
	/*
	 * @sdr2hdr_en: All the ui plane need to do sdr2hdr for a hdr_out enabled vp.
	 *
	 */
	bool sdr2hdr_en;
	/**
	 * @skip_vsync: skip on vsync when port_mux changed on this vp.
	 * a win move from one VP to another need wait one vsync until
	 * port_mut take effect before this win can be enabled.
	 *
	 */
	bool skip_vsync;

	/**
	 * @bg_ovl_dly: The timing delay from background layer
	 * to overlay module.
	 */
	u8 bg_ovl_dly;

	/**
	 * @hdr_en: Set when has a hdr video input.
	 */
	int hdr_en;

	/**
	 * -----------------
	 * |      |       |
	 * | Left | Right |
	 * |      |       |
	 * | VP0  |  VP1  |
	 * -----------------
	 * @splice_mode_right: As right part of the screen in splice mode.
	 */
	bool splice_mode_right;
	/**
	 * @left_vp: VP as left part of the screen in splice mode.
	 */
	struct vop2_video_port *left_vp;

	/**
	 * @win_mask: Bitmask of wins attached to the video port;
	 */
	uint32_t win_mask;
	/**
	 * @nr_layers: active layers attached to the video port;
	 */
	uint8_t nr_layers;

	int cursor_win_id;
	/**
	 * @output_if: output connector attached to the video port,
	 * this flag is maintained in vop driver, updated in crtc_atomic_enable,
	 * cleared in crtc_atomic_disable;
	 */
	u32 output_if;

	/**
	 * @active_tv_state: TV connector related states
	 */
	struct drm_tv_connector_state active_tv_state;

	/**
	 * @lut: store legacy gamma look up table
	 */
	u32 *lut;

	/**
	 * @gamma_lut_len: gamma look up table size
	 */
	u32 gamma_lut_len;

	/**
	 * @gamma_lut_active: gamma states
	 */
	bool gamma_lut_active;

	/**
	 * @lut_dma_rid: lut dma id
	 */
	u16 lut_dma_rid;

	/**
	 * @gamma_lut: atomic gamma look up table
	 */
	struct drm_color_lut *gamma_lut;

	/**
	 * @cubic_lut_len: cubic look up table size
	 */
	u32 cubic_lut_len;

	/**
	 * @cubic_lut_gem_obj: gem obj to store cubic lut
	 */
	struct rockchip_gem_object *cubic_lut_gem_obj;

	/**
	 * @cubic_lut: cubic look up table
	 */
	struct drm_color_lut *cubic_lut;

	/**
	 * @loader_protect: loader logo protect state
	 */
	bool loader_protect;

	/**
	 * @plane_mask: show the plane attach to this vp,
	 * it maybe init at dts file or uboot driver
	 */
	uint32_t plane_mask;

	/**
	 * @plane_mask_prop: plane mask interaction with userspace
	 */
	struct drm_property *plane_mask_prop;
	/**
	 * @feature_prop: crtc feature interaction with userspace
	 */
	struct drm_property *feature_prop;

	/**
	 * @primary_plane_phy_id: vp primary plane phy id, the primary plane
	 * will be used to show uboot logo and kernel logo
	 */
	enum vop2_layer_phy_id primary_plane_phy_id;
};

struct vop2 {
	u32 version;
	struct device *dev;
	struct drm_device *drm_dev;
	struct vop2_dsc dscs[ROCKCHIP_MAX_CRTC];
	struct vop2_video_port vps[ROCKCHIP_MAX_CRTC];
	struct vop2_wb wb;
	struct dentry *debugfs;
	struct drm_info_list *debugfs_files;
	struct drm_prop_enum_list *plane_name_list;
	bool is_iommu_enabled;
	bool is_iommu_needed;
	bool is_enabled;
	bool support_multi_area;
	bool disable_afbc_win;

	/* no move win from one vp to another */
	bool disable_win_move;

	bool loader_protect;

	const struct vop2_data *data;
	/* Number of win that registered as plane,
	 * maybe less than the total number of hardware
	 * win.
	 */
	uint32_t registered_num_wins;
	uint8_t used_mixers;
	/**
	 * @active_vp_mask: Bitmask of active video ports;
	 */
	uint8_t active_vp_mask;
	uint16_t port_mux_cfg;

	uint32_t *regsbak;
	void __iomem *regs;
	struct regmap *grf;
	struct regmap *sys_grf;
	struct regmap *vo0_grf;
	struct regmap *vo1_grf;
	struct regmap *sys_pmu;

	/* physical map length of vop2 register */
	uint32_t len;

	void __iomem *lut_regs;
	/* one time only one process allowed to config the register */
	spinlock_t reg_lock;
	/* lock vop2 irq reg */
	spinlock_t irq_lock;
	/* protects crtc enable/disable */
	struct mutex vop2_lock;

	int irq;

	/*
	 * Some globle resource are shared between all
	 * the vidoe ports(crtcs), so we need a ref counter here.
	 */
	unsigned int enable_count;
	struct clk *hclk;
	struct clk *aclk;
	struct clk *pclk;
	struct reset_control *ahb_rst;
	struct reset_control *axi_rst;

	/* list_head of internal clk */
	struct list_head clk_list_head;
	struct list_head pd_list_head;

	struct vop2_layer layers[ROCKCHIP_MAX_LAYER];
	/* must put at the end of the struct */
	struct vop2_win win[];
};

struct vop2_clk {
	struct vop2 *vop2;
	struct list_head list;
	unsigned long rate;
	struct clk_hw hw;
	struct clk_divider div;
	int div_val;
	u8 parent_index;
};

#define to_vop2_clk(_hw) container_of(_hw, struct vop2_clk, hw)

/*
 * bus-format types.
 */
struct drm_bus_format_enum_list {
	int type;
	const char *name;
};

static const struct drm_bus_format_enum_list drm_bus_format_enum_list[] = {
	{ DRM_MODE_CONNECTOR_Unknown, "Unknown" },
	{ MEDIA_BUS_FMT_RGB565_1X16, "RGB565_1X16" },
	{ MEDIA_BUS_FMT_RGB666_1X18, "RGB666_1X18" },
	{ MEDIA_BUS_FMT_RGB666_1X24_CPADHI, "RGB666_1X24_CPADHI" },
	{ MEDIA_BUS_FMT_RGB666_1X7X3_SPWG, "RGB666_1X7X3_SPWG" },
	{ MEDIA_BUS_FMT_YUV8_1X24, "YUV8_1X24" },
	{ MEDIA_BUS_FMT_UYYVYY8_0_5X24, "UYYVYY8_0_5X24" },
	{ MEDIA_BUS_FMT_YUV10_1X30, "YUV10_1X30" },
	{ MEDIA_BUS_FMT_UYYVYY10_0_5X30, "UYYVYY10_0_5X30" },
	{ MEDIA_BUS_FMT_RGB888_3X8, "RGB888_3X8" },
	{ MEDIA_BUS_FMT_RGB888_DUMMY_4X8, "RGB888_DUMMY_4X8" },
	{ MEDIA_BUS_FMT_RGB888_1X24, "RGB888_1X24" },
	{ MEDIA_BUS_FMT_RGB888_1X7X4_SPWG, "RGB888_1X7X4_SPWG" },
	{ MEDIA_BUS_FMT_RGB888_1X7X4_JEIDA, "RGB888_1X7X4_JEIDA" },
	{ MEDIA_BUS_FMT_UYVY8_2X8, "UYVY8_2X8" },
	{ MEDIA_BUS_FMT_YUYV8_1X16, "YUYV8_1X16" },
	{ MEDIA_BUS_FMT_UYVY8_1X16, "UYVY8_1X16" },
	{ MEDIA_BUS_FMT_RGB101010_1X30, "RGB101010_1X30" },
	{ MEDIA_BUS_FMT_YUYV10_1X20, "YUYV10_1X20" },
};

static DRM_ENUM_NAME_FN(drm_get_bus_format_name, drm_bus_format_enum_list)

static inline struct vop2_video_port *to_vop2_video_port(struct drm_crtc *crtc)
{
	struct rockchip_crtc *rockchip_crtc;

	rockchip_crtc = container_of(crtc, struct rockchip_crtc, crtc);

	return container_of(rockchip_crtc, struct vop2_video_port, rockchip_crtc);
}

static void vop2_lock(struct vop2 *vop2)
{
	mutex_lock(&vop2->vop2_lock);
	rockchip_dmcfreq_lock();
}

static void vop2_unlock(struct vop2 *vop2)
{
	rockchip_dmcfreq_unlock();
	mutex_unlock(&vop2->vop2_lock);
}

static inline void vop2_grf_writel(struct regmap *regmap, struct vop_reg reg, u32 v)
{
	u32 val = 0;

	if (IS_ERR_OR_NULL(regmap))
		return;

	if (reg.mask) {
		val = (v << reg.shift) | (reg.mask << (reg.shift + 16));
		regmap_write(regmap, reg.offset, val);
	}
}

static inline uint32_t vop2_grf_readl(struct regmap *regmap, const struct vop_reg *reg)
{
	uint32_t v;

	regmap_read(regmap, reg->offset, &v);

	return v;
}

static inline void vop2_writel(struct vop2 *vop2, uint32_t offset, uint32_t v)
{
	writel(v, vop2->regs + offset);
	vop2->regsbak[offset >> 2] = v;
}

static inline uint32_t vop2_readl(struct vop2 *vop2, uint32_t offset)
{
	return readl(vop2->regs + offset);
}

static inline uint32_t vop2_read_reg(struct vop2 *vop2, uint32_t base,
				     const struct vop_reg *reg)
{
	return (vop2_readl(vop2, base + reg->offset) >> reg->shift) & reg->mask;
}

static inline uint32_t vop2_read_grf_reg(struct regmap *regmap, const struct vop_reg *reg)
{
	return (vop2_grf_readl(regmap, reg) >> reg->shift) & reg->mask;
}

static inline void vop2_mask_write(struct vop2 *vop2, uint32_t offset,
				   uint32_t mask, uint32_t shift, uint32_t v,
				   bool write_mask, bool relaxed)
{
	uint32_t cached_val;

	if (!mask)
		return;

	if (write_mask) {
		v = ((v & mask) << shift) | (mask << (shift + 16));
	} else {
		cached_val = vop2->regsbak[offset >> 2];

		v = (cached_val & ~(mask << shift)) | ((v & mask) << shift);
		vop2->regsbak[offset >> 2] = v;
	}

	if (relaxed)
		writel_relaxed(v, vop2->regs + offset);
	else
		writel(v, vop2->regs + offset);
}

static inline u32 vop2_line_to_time(struct drm_display_mode *mode, int line)
{
	u64 val = 1000000000ULL * mode->crtc_htotal * line;

	do_div(val, mode->crtc_clock);
	do_div(val, 1000000);

	return val; /* us */
}

static inline bool vop2_plane_active(struct drm_plane_state *pstate)
{
	if (!pstate || !pstate->fb)
		return false;
	else
		return true;
}

static bool vop2_soc_is_rk3566(void)
{
	return soc_is_rk3566();
}

static bool vop2_is_mirror_win(struct vop2_win *win)
{
	return soc_is_rk3566() && (win->feature & WIN_FEATURE_MIRROR);
}

static uint64_t vop2_soc_id_fixup(uint64_t soc_id)
{
	switch (soc_id) {
	case 0x3566:
		if (rockchip_get_cpu_version())
			return 0x3566A;
		else
			return 0x3566;
	case 0x3568:
		if (rockchip_get_cpu_version())
			return 0x3568A;
		else
			return 0x3568;
	default:
		return soc_id;
	}
}

void vop2_standby(struct drm_crtc *crtc, bool standby)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;

	if (standby) {
		VOP_MODULE_SET(vop2, vp, standby, 1);
		mdelay(20);
	} else {
		VOP_MODULE_SET(vop2, vp, standby, 0);
	}
}
EXPORT_SYMBOL(vop2_standby);

static inline const struct vop2_win_regs *vop2_get_win_regs(struct vop2_win *win,
							    const struct vop_reg *reg)
{
	if (!reg->mask && win->parent)
		return win->parent->regs;

	return win->regs;
}

static inline uint32_t vop2_get_intr_type(struct vop2 *vop2, const struct vop_intr *intr,
					  const struct vop_reg *reg, int type)
{
	uint32_t val, i;
	uint32_t ret = 0;

	val = vop2_read_reg(vop2, 0, reg);

	for (i = 0; i < intr->nintrs; i++) {
		if ((type & intr->intrs[i]) && (val & 1 << i))
			ret |= intr->intrs[i];
	}

	return ret;
}

/*
 * phys_id is used to identify a main window(Cluster Win/Smart Win, not
 * include the sub win of a cluster or the multi area) that can do
 * overlay in main overlay stage.
 */
static struct vop2_win *vop2_find_win_by_phys_id(struct vop2 *vop2, uint8_t phys_id)
{
	struct vop2_win *win;
	int i;

	for (i = 0; i < vop2->registered_num_wins; i++) {
		win = &vop2->win[i];
		if (win->phys_id == phys_id)
			return win;
	}

	return NULL;
}

static struct vop2_power_domain *vop2_find_pd_by_id(struct vop2 *vop2, uint8_t id)
{
	struct vop2_power_domain *pd, *n;

	list_for_each_entry_safe(pd, n, &vop2->pd_list_head, list) {
		if (pd->data->id == id)
			return pd;
	}

	return NULL;
}

static const struct vop2_connector_if_data *vop2_find_connector_if_data(struct vop2 *vop2, int id)
{
	const struct vop2_connector_if_data *if_data;
	int i;

	for (i = 0; i < vop2->data->nr_conns; i++) {
		if_data = &vop2->data->conn[i];
		if (if_data->id == id)
			return if_data;
	}

	return NULL;
}

static struct drm_crtc *vop2_find_crtc_by_plane_mask(struct vop2 *vop2, uint8_t phys_id)
{
	struct vop2_video_port *vp;
	int i;

	for (i = 0; i < vop2->data->nr_vps; i++) {
		vp = &vop2->vps[i];
		if (vp->plane_mask & BIT(phys_id))
			return &vp->rockchip_crtc.crtc;
	}

	return NULL;
}

static int vop2_clk_reset(struct reset_control *rstc)
{
	int ret;

	if (!rstc)
		return 0;

	ret = reset_control_assert(rstc);
	if (ret < 0)
		DRM_WARN("failed to assert reset\n");
	udelay(10);
	ret = reset_control_deassert(rstc);
	if (ret < 0)
		DRM_WARN("failed to deassert reset\n");

	return ret;
}

static void vop2_load_hdr2sdr_table(struct vop2_video_port *vp)
{
	struct vop2 *vop2 = vp->vop2;
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_video_port_data *vp_data = &vop2_data->vp[vp->id];
	const struct vop_hdr_table *table = vp_data->hdr_table;
	const struct vop2_video_port_regs *regs = vp->regs;
	uint32_t hdr2sdr_eetf_oetf_yn[33];
	int i;

	for (i = 0; i < 33; i++)
		hdr2sdr_eetf_oetf_yn[i] = table->hdr2sdr_eetf_yn[i] +
				(table->hdr2sdr_bt1886oetf_yn[i] << 16);

	for (i = 0; i < 33; i++)
		vop2_writel(vop2, regs->hdr2sdr_eetf_oetf_y0_offset + i * 4,
			    hdr2sdr_eetf_oetf_yn[i]);

	for (i = 0; i < 9; i++)
		vop2_writel(vop2, regs->hdr2sdr_sat_y0_offset + i * 4,
			    table->hdr2sdr_sat_yn[i]);
}

static void vop2_load_sdr2hdr_table(struct vop2_video_port *vp, int sdr2hdr_tf)
{
	struct vop2 *vop2 = vp->vop2;
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_video_port_data *vp_data = &vop2_data->vp[vp->id];
	const struct vop_hdr_table *table = vp_data->hdr_table;
	const struct vop2_video_port_regs *regs = vp->regs;
	uint32_t sdr2hdr_eotf_oetf_yn[65];
	uint32_t sdr2hdr_oetf_dx_dxpow[64];
	int i;

	for (i = 0; i < 65; i++) {
		if (sdr2hdr_tf == SDR2HDR_FOR_BT2020)
			sdr2hdr_eotf_oetf_yn[i] =
				table->sdr2hdr_bt1886eotf_yn_for_bt2020[i] +
				(table->sdr2hdr_st2084oetf_yn_for_bt2020[i] << 18);
		else if (sdr2hdr_tf == SDR2HDR_FOR_HDR)
			sdr2hdr_eotf_oetf_yn[i] =
				table->sdr2hdr_bt1886eotf_yn_for_hdr[i] +
				(table->sdr2hdr_st2084oetf_yn_for_hdr[i] << 18);
		else if (sdr2hdr_tf == SDR2HDR_FOR_HLG_HDR)
			sdr2hdr_eotf_oetf_yn[i] =
				table->sdr2hdr_bt1886eotf_yn_for_hlg_hdr[i] +
				(table->sdr2hdr_st2084oetf_yn_for_hlg_hdr[i] << 18);
	}

	for (i = 0; i < 65; i++)
		vop2_writel(vop2, regs->sdr2hdr_eotf_oetf_y0_offset + i * 4,
			    sdr2hdr_eotf_oetf_yn[i]);

	for (i = 0; i < 64; i++) {
		sdr2hdr_oetf_dx_dxpow[i] = table->sdr2hdr_st2084oetf_dxn[i] +
				(table->sdr2hdr_st2084oetf_dxn_pow2[i] << 16);
		vop2_writel(vop2, regs->sdr2hdr_oetf_dx_pow1_offset + i * 4,
			    sdr2hdr_oetf_dx_dxpow[i]);
	}

	for (i = 0; i < 63; i++)
		vop2_writel(vop2, regs->sdr2hdr_oetf_xn1_offset + i * 4,
			    table->sdr2hdr_st2084oetf_xn[i]);
}

static bool vop2_fs_irq_is_pending(struct vop2_video_port *vp)
{
	struct vop2 *vop2 = vp->vop2;
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_video_port_data *vp_data = &vop2_data->vp[vp->id];
	const struct vop_intr *intr = vp_data->intr;

	return VOP_INTR_GET_TYPE(vop2, intr, status, FS_FIELD_INTR);
}

static uint32_t vop2_read_vcnt(struct vop2_video_port *vp)
{
	uint32_t offset =  RK3568_SYS_STATUS0 + (vp->id << 2);

	return vop2_readl(vp->vop2, offset) >> 16;
}

static void vop2_wait_for_irq_handler(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	bool pending;
	int ret;

	/*
	 * Spin until frame start interrupt status bit goes low, which means
	 * that interrupt handler was invoked and cleared it. The timeout of
	 * 10 msecs is really too long, but it is just a safety measure if
	 * something goes really wrong. The wait will only happen in the very
	 * unlikely case of a vblank happening exactly at the same time and
	 * shouldn't exceed microseconds range.
	 */
	ret = readx_poll_timeout_atomic(vop2_fs_irq_is_pending, vp, pending,
					!pending, 0, 10 * 1000);
	if (ret)
		DRM_DEV_ERROR(vop2->dev, "VOP vblank IRQ stuck for 10 ms\n");

	synchronize_irq(vop2->irq);
}

static bool vop2_vp_done_bit_status(struct vop2_video_port *vp)
{
	struct vop2 *vop2 = vp->vop2;
	u32 done_bits = vop2_readl(vop2, RK3568_REG_CFG_DONE) & BIT(vp->id);

	/*
	 * When done bit is 0, indicate current frame is take effect.
	 */
	return done_bits == 0 ? true : false;
}

static void vop2_wait_for_fs_by_done_bit_status(struct vop2_video_port *vp)
{
	struct vop2 *vop2 = vp->vop2;
	bool done_bit;
	int ret;

	ret = readx_poll_timeout_atomic(vop2_vp_done_bit_status, vp, done_bit,
					done_bit, 0, 50 * 1000);
	if (ret)
		DRM_DEV_ERROR(vop2->dev, "wait vp%d done bit status timeout, vcnt: %d\n",
			      vp->id, vop2_read_vcnt(vp));
}

static uint16_t vop2_read_port_mux(struct vop2 *vop2)
{
	return vop2_readl(vop2, RK3568_OVL_PORT_SEL) & 0xffff;
}

static void vop2_wait_for_port_mux_done(struct vop2 *vop2)
{
	uint16_t port_mux_cfg;
	int ret;

	/*
	 * Spin until the previous port_mux figuration
	 * is done.
	 */
	ret = readx_poll_timeout_atomic(vop2_read_port_mux, vop2, port_mux_cfg,
					port_mux_cfg == vop2->port_mux_cfg, 0, 50 * 1000);
	if (ret)
		DRM_DEV_ERROR(vop2->dev, "wait port_mux done timeout: 0x%x--0x%x\n",
			      port_mux_cfg, vop2->port_mux_cfg);
}

static u32 vop2_read_layer_cfg(struct vop2 *vop2)
{
	return vop2_readl(vop2, RK3568_OVL_LAYER_SEL);
}

static void vop2_wait_for_layer_cfg_done(struct vop2 *vop2, u32 cfg)
{
	u32 atv_layer_cfg;
	int ret;

	/*
	 * Spin until the previous layer configuration is done.
	 */
	ret = readx_poll_timeout_atomic(vop2_read_layer_cfg, vop2, atv_layer_cfg,
					atv_layer_cfg == cfg, 0, 50 * 1000);
	if (ret)
		DRM_DEV_ERROR(vop2->dev, "wait layer cfg done timeout: 0x%x--0x%x\n",
			      atv_layer_cfg, cfg);
}

static int32_t vop2_pending_done_bits(struct vop2_video_port *vp)
{
	struct vop2 *vop2 = vp->vop2;
	struct drm_display_mode *adjusted_mode;
	struct vop2_video_port *done_vp;
	uint32_t done_bits, done_bits_bak;
	uint32_t vp_id;
	uint32_t vcnt;

	done_bits = vop2_readl(vop2, RK3568_REG_CFG_DONE) & 0x7;
	done_bits_bak = done_bits;

	/* no done bit, so no need to wait config done take effect */
	if (done_bits == 0)
		return 0;

	vp_id = ffs(done_bits) - 1;
	/* done bit is same with current vp config done, so no need to wait */
	if (hweight32(done_bits) == 1 && vp_id == vp->id)
		return 0;

	/* have the other one different vp, wait for config done take effect */
	if (hweight32(done_bits) == 1 ||
	    (hweight32(done_bits) == 2 && (done_bits & BIT(vp->id)))) {
		/* two done bit, clear current vp done bit and find the other done bit vp */
		if (done_bits & BIT(vp->id))
			done_bits &= ~BIT(vp->id);
		vp_id = ffs(done_bits) - 1;
		done_vp = &vop2->vps[vp_id];
		adjusted_mode = &done_vp->rockchip_crtc.crtc.state->adjusted_mode;
		vcnt = vop2_read_vcnt(done_vp);
		if (adjusted_mode->flags & DRM_MODE_FLAG_INTERLACE)
			vcnt >>= 1;
		/* if close to the last 1/8 frame, wait to next frame */
		if (vcnt > (adjusted_mode->crtc_vtotal * 7 >> 3)) {
			vop2_wait_for_fs_by_done_bit_status(done_vp);
			done_bits = 0;
		}
	} else { /* exist the other two vp done bit */
		struct drm_display_mode *first_mode, *second_mode;
		struct vop2_video_port *first_done_vp, *second_done_vp, *wait_vp;
		uint32_t first_vp_id, second_vp_id;
		uint32_t first_vp_vcnt, second_vp_vcnt;
		uint32_t first_vp_left_vcnt, second_vp_left_vcnt;
		uint32_t first_vp_left_time, second_vp_left_time;
		uint32_t first_vp_safe_time, second_vp_safe_time;

		first_vp_id = ffs(done_bits) - 1;
		first_done_vp = &vop2->vps[first_vp_id];
		first_mode = &first_done_vp->rockchip_crtc.crtc.state->adjusted_mode;
		/* set last 1/8 frame time as safe section */
		first_vp_safe_time = 1000000 / drm_mode_vrefresh(first_mode) >> 3;

		done_bits &= ~BIT(first_vp_id);
		second_vp_id = ffs(done_bits) - 1;
		second_done_vp = &vop2->vps[second_vp_id];
		second_mode = &second_done_vp->rockchip_crtc.crtc.state->adjusted_mode;
		/* set last 1/8 frame time as safe section */
		second_vp_safe_time = 1000000 / drm_mode_vrefresh(second_mode) >> 3;

		first_vp_vcnt = vop2_read_vcnt(first_done_vp);
		if (first_mode->flags & DRM_MODE_FLAG_INTERLACE)
			first_vp_vcnt >>= 1;
		second_vp_vcnt = vop2_read_vcnt(second_done_vp);
		if (second_mode->flags & DRM_MODE_FLAG_INTERLACE)
			second_vp_vcnt >>= 1;

		first_vp_left_vcnt = first_mode->crtc_vtotal - first_vp_vcnt;
		second_vp_left_vcnt = second_mode->crtc_vtotal - second_vp_vcnt;
		first_vp_left_time = vop2_line_to_time(first_mode, first_vp_left_vcnt);
		second_vp_left_time = vop2_line_to_time(second_mode, second_vp_left_vcnt);

		/* if the two vp both at safe section, no need to wait */
		if (first_vp_left_time > first_vp_safe_time &&
		    second_vp_left_time > second_vp_safe_time)
			return done_bits_bak;
		if (first_vp_left_time > second_vp_left_time)
			wait_vp = first_done_vp;
		else
			wait_vp = second_done_vp;

		vop2_wait_for_fs_by_done_bit_status(wait_vp);

		done_bits = vop2_readl(vop2, RK3568_REG_CFG_DONE) & 0x7;
		if (done_bits) {
			vp_id = ffs(done_bits) - 1;
			done_vp = &vop2->vps[vp_id];
			vop2_wait_for_fs_by_done_bit_status(done_vp);
		}
		done_bits = 0;
	}
	return done_bits;
}

static inline void rk3588_vop2_dsc_cfg_done(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(crtc->state);
	struct vop2_dsc *dsc = &vop2->dscs[vcstate->dsc_id];

	if (vcstate->output_flags & ROCKCHIP_OUTPUT_DUAL_CHANNEL_LEFT_RIGHT_MODE) {
		dsc = &vop2->dscs[0];
		if (vcstate->dsc_enable)
			VOP_MODULE_SET(vop2, dsc, dsc_cfg_done, 1);
		dsc = &vop2->dscs[1];
		if (vcstate->dsc_enable)
			VOP_MODULE_SET(vop2, dsc, dsc_cfg_done, 1);
	} else {
		if (vcstate->dsc_enable)
			VOP_MODULE_SET(vop2, dsc, dsc_cfg_done, 1);
	}
}

static inline void rk3568_vop2_cfg_done(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	uint32_t done_bits;
	uint32_t val;
	u32 old_layer_sel_val, cfg_layer_sel_val;
	struct vop2_layer *layer = &vop2->layers[0];
	u32 layer_sel_offset = layer->regs->layer_sel.offset;

	/*
	 * This is a workaround, the config done bits of VP0,
	 * VP1, VP2 on RK3568 stands on the first three bits
	 * on REG_CFG_DONE register without mask bit.
	 * If two or three config done events happens one after
	 * another in a very shot time, the flowing config done
	 * write may override the previous config done bit before
	 * it take effect:
	 * 1: config done 0x8001 for VP0
	 * 2: config done 0x8002 for VP1
	 *
	 * 0x8002 may override 0x8001 before it take effect.
	 *
	 * So we do a read | write here.
	 *
	 */
	done_bits = vop2_pending_done_bits(vp);
	val = RK3568_VOP2_GLB_CFG_DONE_EN | BIT(vp->id) | done_bits;
	old_layer_sel_val = vop2_readl(vop2, layer_sel_offset);
	cfg_layer_sel_val = vop2->regsbak[layer_sel_offset >> 2];
	/**
	 * This is rather low probability for miss some done bit.
	 */
	val |= vop2_readl(vop2, RK3568_REG_CFG_DONE) & 0x7;
	vop2_writel(vop2, 0, val);

	/**
	 * Make sure the layer sel is take effect when it's updated.
	 */
	if (old_layer_sel_val != cfg_layer_sel_val) {
		vp->layer_sel_update = true;
		vop2_wait_for_fs_by_done_bit_status(vp);
		DRM_DEV_DEBUG(vop2->dev, "vp%d need to wait fs as old layer_sel val[0x%x] != new val[0x%x]\n",
			      vp->id, old_layer_sel_val, cfg_layer_sel_val);
	}
}

static inline void rk3588_vop2_cfg_done(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(crtc->state);
	const struct vop2_video_port_data *vp_data = &vp->vop2->data->vp[vp->id];
	struct vop2 *vop2 = vp->vop2;
	uint32_t val;

	val = RK3568_VOP2_GLB_CFG_DONE_EN | BIT(vp->id) | (BIT(vp->id) << 16);
	if (vcstate->splice_mode)
		val |= BIT(vp_data->splice_vp_id) | (BIT(vp_data->splice_vp_id) << 16);

	vop2_writel(vop2, 0, val);
}

static inline void vop2_wb_cfg_done(struct vop2_video_port *vp)
{
	struct vop2 *vop2 = vp->vop2;
	uint32_t val = RK3568_VOP2_WB_CFG_DONE | (RK3568_VOP2_WB_CFG_DONE << 16);
	uint32_t done_bits;
	unsigned long flags;

	spin_lock_irqsave(&vop2->irq_lock, flags);
	done_bits = vop2_pending_done_bits(vp);

	val |=  RK3568_VOP2_GLB_CFG_DONE_EN | done_bits;

	vop2_writel(vop2, 0, val);
	spin_unlock_irqrestore(&vop2->irq_lock, flags);

}

static inline void vop2_cfg_done(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;

	if (vop2->version == VOP_VERSION_RK3568)
		return rk3568_vop2_cfg_done(crtc);
	else if (vop2->version == VOP_VERSION_RK3588)
		return rk3588_vop2_cfg_done(crtc);
}

/*
 * Read VOP internal power domain on/off status.
 * We should query BISR_STS register in PMU for
 * power up/down status when memory repair is enabled.
 * Return value: 1 for power on, 0 for power off;
 */
static uint32_t vop2_power_domain_status(struct vop2_power_domain *pd)
{
	struct vop2 *vop2 = pd->vop2;

	if (vop2_read_grf_reg(vop2->sys_pmu, &pd->data->regs->bisr_en_status))
		return vop2_read_grf_reg(vop2->sys_pmu, &pd->data->regs->pmu_status);
	else
		return vop2_read_reg(vop2, 0, &pd->data->regs->status) ? 0 : 1;
}

static void vop2_wait_power_domain_off(struct vop2_power_domain *pd)
{
	struct vop2 *vop2 = pd->vop2;
	int val;
	int ret;

	ret = readx_poll_timeout_atomic(vop2_power_domain_status, pd, val, !val, 0, 50 * 1000);

	if (ret)
		DRM_DEV_ERROR(vop2->dev, "wait pd%d off timeout\n", ffs(pd->data->id) - 1);
}

static void vop2_wait_power_domain_on(struct vop2_power_domain *pd)
{
	struct vop2 *vop2 = pd->vop2;
	int val;
	int ret;

	ret = readx_poll_timeout_atomic(vop2_power_domain_status, pd, val, val, 0, 50 * 1000);
	if (ret)
		DRM_DEV_ERROR(vop2->dev, "wait pd%d on timeout\n", ffs(pd->data->id) - 1);
}

/*
 * Power domain on take effect immediately
 */
static void vop2_power_domain_on(struct vop2_power_domain *pd)
{
	struct vop2 *vop2 = pd->vop2;

	if (!pd->on) {
		dev_dbg(vop2->dev, "pd%d on\n", ffs(pd->data->id) - 1);
		vop2_wait_power_domain_off(pd);
		VOP_MODULE_SET(vop2, pd->data, pd, 0);
		vop2_wait_power_domain_on(pd);
		pd->on = true;
	}
}

/*
 * Power domain off take effect by vsync.
 */
static void vop2_power_domain_off(struct vop2_power_domain *pd)
{
	struct vop2 *vop2 = pd->vop2;

	dev_dbg(vop2->dev, "pd%d off\n", ffs(pd->data->id) - 1);
	pd->on = false;
	VOP_MODULE_SET(vop2, pd->data, pd, 1);
}

static void vop2_power_domain_get(struct vop2_power_domain *pd)
{
	if (pd->parent)
		vop2_power_domain_get(pd->parent);

	spin_lock(&pd->lock);
	if (pd->ref_count == 0) {
		if (pd->vop2->data->delayed_pd)
			cancel_delayed_work(&pd->power_off_work);
		vop2_power_domain_on(pd);
	}
	pd->ref_count++;
	spin_unlock(&pd->lock);
}

static void vop2_power_domain_put(struct vop2_power_domain *pd)
{
	spin_lock(&pd->lock);

	/*
	 * For a nested power domain(PD_Cluster0 is the parent of PD_CLuster1/2/3)
	 * the parent powe domain must be enabled before child power domain
	 * is on.
	 *
	 * So we may met this condition: Cluster0 is not enabled, but PD_Cluster0
	 * must enabled as one of the child PD_CLUSTER1/2/3 is enabled.
	 * when all child PD is disabled, we want disable the parent
	 * PD(PD_CLUSTER0), but as module CLUSTER0 is not enabled,
	 * the turn down configuration will never take effect.
	 * so we will see a "wait pd0 off timeout" log when we
	 * turn on PD_CLUSTER0 next time.
	 *
	 * So don't try to turn off a power domain when the module is not
	 * enabled.
	 */
	if (--pd->ref_count == 0 && pd->module_on) {
		if (pd->vop2->data->delayed_pd)
			schedule_delayed_work(&pd->power_off_work, msecs_to_jiffies(2500));
		else
			vop2_power_domain_off(pd);
	}

	spin_unlock(&pd->lock);
	if (pd->parent)
		vop2_power_domain_put(pd->parent);
}

/*
 * Called if the pd ref_count reach 0 after 2.5
 * seconds.
 */
static void vop2_power_domain_off_work(struct work_struct *work)
{
	struct vop2_power_domain *pd;

	pd = container_of(to_delayed_work(work), struct vop2_power_domain, power_off_work);

	spin_lock(&pd->lock);
	if (pd->ref_count == 0)
		vop2_power_domain_off(pd);
	spin_unlock(&pd->lock);
}

static void vop2_win_enable(struct vop2_win *win)
{
	if (!win->enabled) {
		if (win->pd) {
			vop2_power_domain_get(win->pd);
			win->pd->module_on = true;
		}
		win->enabled = true;
	}
}

static void vop2_win_multi_area_disable(struct vop2_win *parent)
{
	struct vop2 *vop2 = parent->vop2;
	struct vop2_win *area;
	int i;

	for (i = 0; i < vop2->registered_num_wins; i++) {
		area = &vop2->win[i];
		if (area->parent == parent)
			VOP_WIN_SET(vop2, area, enable, 0);
	}
}

static void vop2_win_disable(struct vop2_win *win, bool skip_splice_win)
{
	struct vop2 *vop2 = win->vop2;

	/* Disable the right splice win */
	if (win->splice_win && !skip_splice_win) {
		vop2_win_disable(win->splice_win, false);
		win->left_win = NULL;
		win->splice_win = NULL;
		win->splice_mode_right = false;
	}

	if (win->enabled) {
		VOP_WIN_SET(vop2, win, enable, 0);
		if (win->feature & WIN_FEATURE_CLUSTER_MAIN) {
			struct vop2_win *sub_win;
			int i = 0;

			for (i = 0; i < vop2->registered_num_wins; i++) {
				sub_win = &vop2->win[i];

				if ((sub_win->phys_id == win->phys_id) &&
				    (sub_win->feature & WIN_FEATURE_CLUSTER_SUB))
					VOP_WIN_SET(vop2, sub_win, enable, 0);
			}

			VOP_CLUSTER_SET(vop2, win, enable, 0);
		}

		/*
		 * disable all other multi area win if we want disable area0 here
		 */
		if (!win->parent && (win->feature & WIN_FEATURE_MULTI_AREA))
			vop2_win_multi_area_disable(win);
		if (win->pd) {
			vop2_power_domain_put(win->pd);
			win->pd->module_on = false;
		}
		win->enabled = false;
	}
}

static inline void vop2_write_lut(struct vop2 *vop2, uint32_t offset, uint32_t v)
{
	writel(v, vop2->lut_regs + offset);
}

static inline uint32_t vop2_read_lut(struct vop2 *vop2, uint32_t offset)
{
	return readl(vop2->lut_regs + offset);
}

static enum vop2_data_format vop2_convert_format(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_XRGB2101010:
	case DRM_FORMAT_ARGB2101010:
	case DRM_FORMAT_XBGR2101010:
	case DRM_FORMAT_ABGR2101010:
		return VOP2_FMT_XRGB101010;
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
		return VOP2_FMT_ARGB8888;
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
		return VOP2_FMT_RGB888;
	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_BGR565:
		return VOP2_FMT_RGB565;
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV21:
	case DRM_FORMAT_YUV420_8BIT:
		return VOP2_FMT_YUV420SP;
	case DRM_FORMAT_NV15:
	case DRM_FORMAT_YUV420_10BIT:
		return VOP2_FMT_YUV420SP_10;
	case DRM_FORMAT_NV16:
	case DRM_FORMAT_NV61:
		return VOP2_FMT_YUV422SP;
	case DRM_FORMAT_NV20:
	case DRM_FORMAT_Y210:
		return VOP2_FMT_YUV422SP_10;
	case DRM_FORMAT_NV24:
	case DRM_FORMAT_NV42:
		return VOP2_FMT_YUV444SP;
	case DRM_FORMAT_NV30:
		return VOP2_FMT_YUV444SP_10;
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_YVYU:
		return VOP2_FMT_VYUY422;
	case DRM_FORMAT_VYUY:
	case DRM_FORMAT_UYVY:
		return VOP2_FMT_YUYV422;
	default:
		DRM_ERROR("unsupported format[%08x]\n", format);
		return -EINVAL;
	}
}

static enum vop2_afbc_format vop2_convert_afbc_format(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_XRGB2101010:
	case DRM_FORMAT_ARGB2101010:
	case DRM_FORMAT_XBGR2101010:
	case DRM_FORMAT_ABGR2101010:
		return VOP2_AFBC_FMT_ARGB2101010;
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
		return VOP2_AFBC_FMT_ARGB8888;
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
		return VOP2_AFBC_FMT_RGB888;
	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_BGR565:
		return VOP2_AFBC_FMT_RGB565;
	case DRM_FORMAT_YUV420_8BIT:
		return VOP2_AFBC_FMT_YUV420;
	case DRM_FORMAT_YUV420_10BIT:
		return VOP2_AFBC_FMT_YUV420_10BIT;
	case DRM_FORMAT_YVYU:
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_VYUY:
	case DRM_FORMAT_UYVY:
		return VOP2_AFBC_FMT_YUV422;
	case DRM_FORMAT_Y210:
		return VOP2_AFBC_FMT_YUV422_10BIT;

		/* either of the below should not be reachable */
	default:
		DRM_WARN_ONCE("unsupported AFBC format[%08x]\n", format);
		return VOP2_AFBC_FMT_INVALID;
	}

	return VOP2_AFBC_FMT_INVALID;
}

static enum vop2_wb_format vop2_convert_wb_format(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_ARGB8888:
		return VOP2_WB_ARGB8888;
	case DRM_FORMAT_BGR888:
		return VOP2_WB_BGR888;
	case DRM_FORMAT_RGB565:
		return VOP2_WB_RGB565;
	case DRM_FORMAT_NV12:
		return VOP2_WB_YUV420SP;
	default:
		DRM_ERROR("unsupported wb format[%08x]\n", format);
		return VOP2_WB_INVALID;
	}
}

static void vop2_set_system_status(struct vop2 *vop2)
{
	if (hweight8(vop2->active_vp_mask) > 1)
		rockchip_set_system_status(SYS_STATUS_DUALVIEW);
	else
		rockchip_clear_system_status(SYS_STATUS_DUALVIEW);
}

static bool vop2_win_rb_swap(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_XBGR2101010:
	case DRM_FORMAT_ABGR2101010:
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
	case DRM_FORMAT_BGR888:
	case DRM_FORMAT_BGR565:
		return true;
	default:
		return false;
	}
}
static bool vop2_afbc_rb_swap(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_NV24:
	case DRM_FORMAT_NV30:
		return true;
	default:
		return false;
	}
}

static bool vop2_afbc_uv_swap(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV16:
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_Y210:
	case DRM_FORMAT_YUV420_8BIT:
	case DRM_FORMAT_YUV420_10BIT:
		return true;
	default:
		return false;
	}
}

static bool vop2_win_uv_swap(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV16:
	case DRM_FORMAT_NV24:
	case DRM_FORMAT_NV15:
	case DRM_FORMAT_NV20:
	case DRM_FORMAT_NV30:
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_UYVY:
		return true;
	default:
		return false;
	}
}

static bool vop2_win_dither_up(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_BGR565:
	case DRM_FORMAT_RGB565:
		return true;
	default:
		return false;
	}
}

static bool vop2_output_uv_swap(uint32_t bus_format, uint32_t output_mode)
{
	/*
	 * FIXME:
	 *
	 * There is no media type for YUV444 output,
	 * so when out_mode is AAAA or P888, assume output is YUV444 on
	 * yuv format.
	 *
	 * From H/W testing, YUV444 mode need a rb swap.
	 */
	if (bus_format == MEDIA_BUS_FMT_YVYU8_1X16 ||
	    bus_format == MEDIA_BUS_FMT_VYUY8_1X16 ||
	    bus_format == MEDIA_BUS_FMT_YVYU8_2X8 ||
	    bus_format == MEDIA_BUS_FMT_VYUY8_2X8 ||
	    ((bus_format == MEDIA_BUS_FMT_YUV8_1X24 ||
	      bus_format == MEDIA_BUS_FMT_YUV10_1X30) &&
	     (output_mode == ROCKCHIP_OUT_MODE_AAAA ||
	      output_mode == ROCKCHIP_OUT_MODE_P888)))
		return true;
	else
		return false;
}

static bool vop2_output_yc_swap(uint32_t bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_YUYV8_1X16:
	case MEDIA_BUS_FMT_YVYU8_1X16:
	case MEDIA_BUS_FMT_YUYV8_2X8:
	case MEDIA_BUS_FMT_YVYU8_2X8:
		return true;
	default:
		return false;
	}
}

static bool is_yuv_support(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV15:
	case DRM_FORMAT_NV16:
	case DRM_FORMAT_NV20:
	case DRM_FORMAT_NV24:
	case DRM_FORMAT_NV30:
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_YVYU:
	case DRM_FORMAT_UYVY:
	case DRM_FORMAT_VYUY:
	case DRM_FORMAT_YUV420_8BIT:
	case DRM_FORMAT_YUV420_10BIT:
	case DRM_FORMAT_Y210:
		return true;
	default:
		return false;
	}
}

static bool is_yuv_output(uint32_t bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_YUV8_1X24:
	case MEDIA_BUS_FMT_YUV10_1X30:
	case MEDIA_BUS_FMT_YUYV10_1X20:
	case MEDIA_BUS_FMT_UYYVYY8_0_5X24:
	case MEDIA_BUS_FMT_UYYVYY10_0_5X30:
	case MEDIA_BUS_FMT_YUYV8_2X8:
	case MEDIA_BUS_FMT_YVYU8_2X8:
	case MEDIA_BUS_FMT_UYVY8_2X8:
	case MEDIA_BUS_FMT_VYUY8_2X8:
	case MEDIA_BUS_FMT_YUYV8_1X16:
	case MEDIA_BUS_FMT_YVYU8_1X16:
	case MEDIA_BUS_FMT_UYVY8_1X16:
	case MEDIA_BUS_FMT_VYUY8_1X16:
		return true;
	default:
		return false;
	}
}

static bool is_alpha_support(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_ABGR8888:
		return true;
	default:
		return false;
	}
}

static inline bool rockchip_afbc(struct drm_plane *plane, u64 modifier)
{
	int i;

	if (modifier == DRM_FORMAT_MOD_LINEAR)
		return false;

	for (i = 0 ; i < plane->modifier_count; i++)
		if (plane->modifiers[i] == modifier)
			break;

	return (i < plane->modifier_count) ? true : false;

}

static bool rockchip_vop2_mod_supported(struct drm_plane *plane, u32 format, u64 modifier)
{
	if (modifier == DRM_FORMAT_MOD_INVALID)
		return false;

	if (modifier == DRM_FORMAT_MOD_LINEAR)
		return true;

	if (!rockchip_afbc(plane, modifier)) {
		DRM_ERROR("Unsupported format modifier 0x%llx\n", modifier);

		return false;
	}

	return vop2_convert_afbc_format(format) >= 0;
}

static inline bool vop2_multi_area_sub_window(struct vop2_win *win)
{
	return (win->parent && (win->feature & WIN_FEATURE_MULTI_AREA));
}

static inline bool vop2_cluster_window(struct vop2_win *win)
{
	return  (win->feature & (WIN_FEATURE_CLUSTER_MAIN | WIN_FEATURE_CLUSTER_SUB));
}

static inline bool vop2_cluster_sub_window(struct vop2_win *win)
{
	return (win->feature & WIN_FEATURE_CLUSTER_SUB);
}

static inline bool vop2_has_feature(struct vop2 *vop2, uint64_t feature)
{
	return (vop2->data->feature & feature);
}

/*
 * 0: Full mode, 16 lines for one tail
 * 1: half block mode
 */
static int vop2_afbc_half_block_enable(struct vop2_plane_state *vpstate)
{
	if (vpstate->rotate_270_en || vpstate->rotate_90_en)
		return 0;
	else
		return 1;
}

/*
 * @xoffset: the src x offset of the right win in splice mode, other wise it
 * must be zero.
 */
static uint32_t vop2_afbc_transform_offset(struct vop2_plane_state *vpstate, int xoffset)
{
	struct drm_rect *src = &vpstate->src;
	struct drm_framebuffer *fb = vpstate->base.fb;
	uint32_t bpp = rockchip_drm_get_bpp(fb->format);
	uint32_t vir_width = (fb->pitches[0] << 3) / bpp;
	uint32_t width = drm_rect_width(src) >> 16;
	uint32_t height = drm_rect_height(src) >> 16;
	uint32_t act_xoffset = src->x1 >> 16;
	uint32_t act_yoffset = src->y1 >> 16;
	uint32_t align16_crop = 0;
	uint32_t align64_crop = 0;
	uint32_t height_tmp = 0;
	uint32_t transform_tmp = 0;
	uint8_t transform_xoffset = 0;
	uint8_t transform_yoffset = 0;
	uint8_t top_crop = 0;
	uint8_t top_crop_line_num = 0;
	uint8_t bottom_crop_line_num = 0;

	act_xoffset += xoffset;
	/* 16 pixel align */
	if (height & 0xf)
		align16_crop = 16 - (height & 0xf);

	height_tmp = height + align16_crop;

	/* 64 pixel align */
	if (height_tmp & 0x3f)
		align64_crop = 64 - (height_tmp & 0x3f);

	top_crop_line_num = top_crop << 2;
	if (top_crop == 0)
		bottom_crop_line_num = align16_crop + align64_crop;
	else if (top_crop == 1)
		bottom_crop_line_num = align16_crop + align64_crop + 12;
	else if (top_crop == 2)
		bottom_crop_line_num = align16_crop + align64_crop + 8;

	if (vpstate->xmirror_en) {
		if (vpstate->ymirror_en) {
			if (vpstate->afbc_half_block_en) {
				transform_tmp = act_xoffset + width;
				transform_xoffset = 16 - (transform_tmp & 0xf);
				transform_tmp = bottom_crop_line_num - act_yoffset;
				transform_yoffset = transform_tmp & 0x7;
			} else { //FULL MODEL
				transform_tmp = act_xoffset + width;
				transform_xoffset = 16 - (transform_tmp & 0xf);
				transform_tmp = bottom_crop_line_num - act_yoffset;
				transform_yoffset = (transform_tmp & 0xf);
			}
		} else if (vpstate->rotate_90_en) {
			transform_tmp = bottom_crop_line_num - act_yoffset;
			transform_xoffset = transform_tmp & 0xf;
			transform_tmp = vir_width - width - act_xoffset;
			transform_yoffset = transform_tmp & 0xf;
		} else if (vpstate->rotate_270_en) {
			transform_tmp = top_crop_line_num + act_yoffset;
			transform_xoffset = transform_tmp & 0xf;
			transform_tmp = act_xoffset;
			transform_yoffset = transform_tmp & 0xf;

		} else { //xmir
			if (vpstate->afbc_half_block_en) {
				transform_tmp = act_xoffset + width;
				transform_xoffset = 16 - (transform_tmp & 0xf);
				transform_tmp = top_crop_line_num + act_yoffset;
				transform_yoffset = transform_tmp & 0x7;
			} else {
				transform_tmp = act_xoffset + width;
				transform_xoffset = 16 - (transform_tmp & 0xf);
				transform_tmp = top_crop_line_num + act_yoffset;
				transform_yoffset = transform_tmp & 0xf;
			}
		}
	} else if (vpstate->ymirror_en) {
		if (vpstate->afbc_half_block_en) {
			transform_tmp = act_xoffset;
			transform_xoffset = transform_tmp & 0xf;
			transform_tmp = bottom_crop_line_num - act_yoffset;
			transform_yoffset = transform_tmp & 0x7;
		} else { //full_mode
			transform_tmp = act_xoffset;
			transform_xoffset = transform_tmp & 0xf;
			transform_tmp = bottom_crop_line_num - act_yoffset;
			transform_yoffset = transform_tmp & 0xf;
		}
	} else if (vpstate->rotate_90_en) {
		transform_tmp = bottom_crop_line_num - act_yoffset;
		transform_xoffset = transform_tmp & 0xf;
		transform_tmp = act_xoffset;
		transform_yoffset = transform_tmp & 0xf;
	} else if (vpstate->rotate_270_en) {
		transform_tmp = top_crop_line_num + act_yoffset;
		transform_xoffset = transform_tmp & 0xf;
		transform_tmp = vir_width - width - act_xoffset;
		transform_yoffset = transform_tmp & 0xf;
	} else { //normal
		if (vpstate->afbc_half_block_en) {
			transform_tmp = act_xoffset;
			transform_xoffset = transform_tmp & 0xf;
			transform_tmp = top_crop_line_num + act_yoffset;
			transform_yoffset = transform_tmp & 0x7;
		} else { //full_mode
			transform_tmp = act_xoffset;
			transform_xoffset = transform_tmp & 0xf;
			transform_tmp = top_crop_line_num + act_yoffset;
			transform_yoffset = transform_tmp & 0xf;
		}
	}

	return (transform_xoffset & 0xf) | ((transform_yoffset & 0xf) << 16);
}

/*
 * A Cluster window has 2048 x 16 line buffer, which can
 * works at 2048 x 16(Full) or 4096 x 8 (Half) mode.
 * for Cluster_lb_mode register:
 * 0: half mode, for plane input width range 2048 ~ 4096
 * 1: half mode, for cluster work at 2 * 2048 plane mode
 * 2: half mode, for rotate_90/270 mode
 *
 */
static int vop2_get_cluster_lb_mode(struct vop2_win *win, struct vop2_plane_state *vpstate)
{
	if (vpstate->rotate_270_en || vpstate->rotate_90_en)
		return 2;
	else if (win->feature & WIN_FEATURE_CLUSTER_SUB)
		return 1;
	else
		return 0;
}

/*
 * bli_sd_factor = (src - 1) / (dst - 1) << 12;
 * avg_sd_factor:
 * bli_su_factor:
 * bic_su_factor:
 * = (src - 1) / (dst - 1) << 16;
 *
 * gt2 enable: dst get one line from two line of the src
 * gt4 enable: dst get one line from four line of the src.
 *
 */
#define VOP2_BILI_SCL_DN(src, dst)	(((src - 1) << 12) / (dst - 1))
#define VOP2_COMMON_SCL(src, dst)	(((src - 1) << 16) / (dst - 1))

#define VOP2_BILI_SCL_FAC_CHECK(src, dst, fac)	 \
				(fac * (dst - 1) >> 12 < (src - 1))
#define VOP2_COMMON_SCL_FAC_CHECK(src, dst, fac) \
				(fac * (dst - 1) >> 16 < (src - 1))

static uint16_t vop2_scale_factor(enum scale_mode mode,
				  int32_t filter_mode,
				  uint32_t src, uint32_t dst)
{
	uint32_t fac = 0;
	int i = 0;

	if (mode == SCALE_NONE)
		return 0;

	/*
	 * A workaround to avoid zero div.
	 */
	if ((dst == 1) || (src == 1)) {
		dst = dst + 1;
		src = src + 1;
	}

	if ((mode == SCALE_DOWN) && (filter_mode == VOP2_SCALE_DOWN_BIL)) {
		fac = VOP2_BILI_SCL_DN(src, dst);
		for (i = 0; i < 100; i++) {
			if (VOP2_BILI_SCL_FAC_CHECK(src, dst, fac))
				break;
			fac -= 1;
			DRM_DEBUG("down fac cali: src:%d, dst:%d, fac:0x%x\n", src, dst, fac);
		}
	} else {
		fac = VOP2_COMMON_SCL(src, dst);
		for (i = 0; i < 100; i++) {
			if (VOP2_COMMON_SCL_FAC_CHECK(src, dst, fac))
				break;
			fac -= 1;
			DRM_DEBUG("up fac cali:  src:%d, dst:%d, fac:0x%x\n", src, dst, fac);
		}
	}

	return fac;
}

static void vop2_setup_scale(struct vop2 *vop2, const struct vop2_win *win,
			     uint32_t src_w, uint32_t src_h, uint32_t dst_w,
			     uint32_t dst_h, uint32_t pixel_format)
{
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_win_data *win_data = &vop2_data->win[win->win_id];
	const struct drm_format_info *info = drm_format_info(pixel_format);
	uint8_t hsub = info->hsub;
	uint8_t vsub = info->vsub;
	uint16_t cbcr_src_w = src_w / hsub;
	uint16_t cbcr_src_h = src_h / vsub;
	uint16_t yrgb_hor_scl_mode, yrgb_ver_scl_mode;
	uint16_t cbcr_hor_scl_mode, cbcr_ver_scl_mode;
	uint16_t hscl_filter_mode, vscl_filter_mode;
	uint8_t gt2 = 0;
	uint8_t gt4 = 0;
	uint32_t val;

	if (src_h >= (4 * dst_h))
		gt4 = 1;
	else if (src_h >= (2 * dst_h))
		gt2 = 1;

	if (gt4)
		src_h >>= 2;
	else if (gt2)
		src_h >>= 1;

	yrgb_hor_scl_mode = scl_get_scl_mode(src_w, dst_w);
	yrgb_ver_scl_mode = scl_get_scl_mode(src_h, dst_h);

	if (yrgb_hor_scl_mode == SCALE_UP)
		hscl_filter_mode = win_data->hsu_filter_mode;
	else
		hscl_filter_mode = win_data->hsd_filter_mode;

	if (yrgb_ver_scl_mode == SCALE_UP)
		vscl_filter_mode = win_data->vsu_filter_mode;
	else
		vscl_filter_mode = win_data->vsd_filter_mode;

	/*
	 * RK3568 VOP Esmart/Smart dsp_w should be even pixel
	 * at scale down mode
	 */
	if (!(win->feature & WIN_FEATURE_AFBDC)) {
		if ((yrgb_hor_scl_mode == SCALE_DOWN) && (dst_w & 0x1)) {
			dev_dbg(vop2->dev, "%s dst_w[%d] should align as 2 pixel\n", win->name, dst_w);
			dst_w += 1;
		}
	}

	val = vop2_scale_factor(yrgb_hor_scl_mode, hscl_filter_mode,
				src_w, dst_w);
	VOP_SCL_SET(vop2, win, scale_yrgb_x, val);
	val = vop2_scale_factor(yrgb_ver_scl_mode, vscl_filter_mode,
				src_h, dst_h);
	VOP_SCL_SET(vop2, win, scale_yrgb_y, val);

	VOP_SCL_SET(vop2, win, vsd_yrgb_gt4, gt4);
	VOP_SCL_SET(vop2, win, vsd_yrgb_gt2, gt2);

	VOP_SCL_SET(vop2, win, yrgb_hor_scl_mode, yrgb_hor_scl_mode);
	VOP_SCL_SET(vop2, win, yrgb_ver_scl_mode, yrgb_ver_scl_mode);

	VOP_SCL_SET(vop2, win, yrgb_hscl_filter_mode, hscl_filter_mode);
	VOP_SCL_SET(vop2, win, yrgb_vscl_filter_mode, vscl_filter_mode);

	if (info->is_yuv) {
		gt4 = gt2 = 0;

		if (cbcr_src_h >= (4 * dst_h))
			gt4 = 1;
		else if (cbcr_src_h >= (2 * dst_h))
			gt2 = 1;

		if (gt4)
			cbcr_src_h >>= 2;
		else if (gt2)
			cbcr_src_h >>= 1;

		cbcr_hor_scl_mode = scl_get_scl_mode(cbcr_src_w, dst_w);
		cbcr_ver_scl_mode = scl_get_scl_mode(cbcr_src_h, dst_h);

		val = vop2_scale_factor(cbcr_hor_scl_mode, hscl_filter_mode,
					cbcr_src_w, dst_w);
		VOP_SCL_SET(vop2, win, scale_cbcr_x, val);
		val = vop2_scale_factor(cbcr_ver_scl_mode, vscl_filter_mode,
					cbcr_src_h, dst_h);
		VOP_SCL_SET(vop2, win, scale_cbcr_y, val);

		VOP_SCL_SET(vop2, win, vsd_cbcr_gt4, gt4);
		VOP_SCL_SET(vop2, win, vsd_cbcr_gt2, gt2);
		VOP_SCL_SET(vop2, win, cbcr_hor_scl_mode, cbcr_hor_scl_mode);
		VOP_SCL_SET(vop2, win, cbcr_ver_scl_mode, cbcr_ver_scl_mode);
		VOP_SCL_SET(vop2, win, cbcr_hscl_filter_mode, hscl_filter_mode);
		VOP_SCL_SET(vop2, win, cbcr_vscl_filter_mode, vscl_filter_mode);
	}
}

static int vop2_convert_csc_mode(int csc_mode)
{
	switch (csc_mode) {
	case V4L2_COLORSPACE_SMPTE170M:
	case V4L2_COLORSPACE_470_SYSTEM_M:
	case V4L2_COLORSPACE_470_SYSTEM_BG:
		return CSC_BT601L;
	case V4L2_COLORSPACE_REC709:
	case V4L2_COLORSPACE_SMPTE240M:
	case V4L2_COLORSPACE_DEFAULT:
		return CSC_BT709L;
	case V4L2_COLORSPACE_JPEG:
		return CSC_BT601F;
	case V4L2_COLORSPACE_BT2020:
		return CSC_BT2020;
	default:
		return CSC_BT709L;
	}
}

static bool vop2_is_allwin_disabled(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	unsigned long win_mask = vp->win_mask;
	struct vop2_win *win;
	int phys_id;

	for_each_set_bit(phys_id, &win_mask, ROCKCHIP_MAX_LAYER) {
		win = vop2_find_win_by_phys_id(vop2, phys_id);
		if (VOP_WIN_GET(vop2, win, enable) != 0)
			return false;
	}

	return true;
}

static void vop2_disable_all_planes_for_crtc(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	struct vop2_win *win;
	unsigned long win_mask = vp->win_mask;
	int phys_id, ret;
	bool active, need_wait_win_disabled = false;

	for_each_set_bit(phys_id, &win_mask, ROCKCHIP_MAX_LAYER) {
		win = vop2_find_win_by_phys_id(vop2, phys_id);
		need_wait_win_disabled |= VOP_WIN_GET(vop2, win, enable);
		vop2_win_disable(win, false);
	}

	if (need_wait_win_disabled) {
		vop2_cfg_done(crtc);
		ret = readx_poll_timeout_atomic(vop2_is_allwin_disabled, crtc,
						active, active, 0, 500 * 1000);
		if (ret)
			DRM_DEV_ERROR(vop2->dev, "wait win close timeout\n");
	}
}

/*
 * colorspace path:
 *      Input        Win csc                     Output
 * 1. YUV(2020)  --> Y2R->2020To709->R2Y   --> YUV_OUTPUT(601/709)
 *    RGB        --> R2Y                  __/
 *
 * 2. YUV(2020)  --> bypasss               --> YUV_OUTPUT(2020)
 *    RGB        --> 709To2020->R2Y       __/
 *
 * 3. YUV(2020)  --> Y2R->2020To709        --> RGB_OUTPUT(709)
 *    RGB        --> R2Y                  __/
 *
 * 4. YUV(601/709)-> Y2R->709To2020->R2Y   --> YUV_OUTPUT(2020)
 *    RGB        --> 709To2020->R2Y       __/
 *
 * 5. YUV(601/709)-> bypass                --> YUV_OUTPUT(709)
 *    RGB        --> R2Y                  __/
 *
 * 6. YUV(601/709)-> bypass                --> YUV_OUTPUT(601)
 *    RGB        --> R2Y(601)             __/
 *
 * 7. YUV        --> Y2R(709)              --> RGB_OUTPUT(709)
 *    RGB        --> bypass               __/
 *
 * 8. RGB        --> 709To2020->R2Y        --> YUV_OUTPUT(2020)
 *
 * 9. RGB        --> R2Y(709)              --> YUV_OUTPUT(709)
 *
 * 10. RGB       --> R2Y(601)              --> YUV_OUTPUT(601)
 *
 * 11. RGB       --> bypass                --> RGB_OUTPUT(709)
 */

static void vop2_setup_csc_mode(struct vop2_video_port *vp,
				struct vop2_plane_state *vpstate)
{
	struct drm_plane_state *pstate = &vpstate->base;
	struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(vp->rockchip_crtc.crtc.state);
	int is_input_yuv = is_yuv_support(pstate->fb->format->format);
	int is_output_yuv = vcstate->yuv_overlay;
	int input_csc = vpstate->color_space;
	int output_csc = vcstate->color_space;

	vpstate->y2r_en = 0;
	vpstate->r2y_en = 0;
	vpstate->csc_mode = 0;

	/* hdr2sdr and sdr2hdr will do csc itself */
	if (vpstate->hdr2sdr_en) {
		/*
		 * This is hdr2sdr enabled plane
		 * If it's RGB layer do hdr2sdr, we need to do r2y before send to hdr2sdr,
		 * because hdr2sdr only support yuv input.
		 */
		if (!is_input_yuv) {
			vpstate->r2y_en = 1;
			vpstate->csc_mode = vop2_convert_csc_mode(output_csc);
		}
		return;
	} else if (!vpstate->hdr_in && vp->sdr2hdr_en) {
		/*
		 * This is sdr2hdr enabled plane
		 * If it's YUV layer do sdr2hdr, we need to do y2r before send to sdr2hdr,
		 * because sdr2hdr only support rgb input.
		 */
		if (is_input_yuv) {
			vpstate->y2r_en = 1;
			vpstate->csc_mode = vop2_convert_csc_mode(input_csc);
		}
		return;
	}

	if (is_input_yuv && !is_output_yuv) {
		vpstate->y2r_en = 1;
		vpstate->csc_mode = vop2_convert_csc_mode(input_csc);
	} else if (!is_input_yuv && is_output_yuv) {
		vpstate->r2y_en = 1;
		vpstate->csc_mode = vop2_convert_csc_mode(output_csc);
	}
}

static void vop2_axi_irqs_enable(struct vop2 *vop2)
{
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop_intr *intr;
	uint32_t irqs = BUS_ERROR_INTR;
	uint32_t i;

	for (i = 0; i < vop2_data->nr_axi_intr; i++) {
		intr = &vop2_data->axi_intr[i];
		VOP_INTR_SET_TYPE(vop2, intr, clear, irqs, 1);
		VOP_INTR_SET_TYPE(vop2, intr, enable, irqs, 1);
	}
}

static uint32_t vop2_read_and_clear_axi_irqs(struct vop2 *vop2, int index)
{
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop_intr *intr = &vop2_data->axi_intr[index];
	uint32_t irqs = BUS_ERROR_INTR;
	uint32_t val;

	val = VOP_INTR_GET_TYPE(vop2, intr, status, irqs);
	if (val)
		VOP_INTR_SET_TYPE(vop2, intr, clear, val, 1);

	return val;
}

static void vop2_dsp_hold_valid_irq_enable(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_video_port_data *vp_data = &vop2_data->vp[vp->id];
	const struct vop_intr *intr = vp_data->intr;

	unsigned long flags;

	if (WARN_ON(!vop2->is_enabled))
		return;

	spin_lock_irqsave(&vop2->irq_lock, flags);

	VOP_INTR_SET_TYPE(vop2, intr, clear, DSP_HOLD_VALID_INTR, 1);
	VOP_INTR_SET_TYPE(vop2, intr, enable, DSP_HOLD_VALID_INTR, 1);

	spin_unlock_irqrestore(&vop2->irq_lock, flags);
}

static void vop2_dsp_hold_valid_irq_disable(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_video_port_data *vp_data = &vop2_data->vp[vp->id];
	const struct vop_intr *intr = vp_data->intr;
	unsigned long flags;

	if (WARN_ON(!vop2->is_enabled))
		return;

	spin_lock_irqsave(&vop2->irq_lock, flags);

	VOP_INTR_SET_TYPE(vop2, intr, enable, DSP_HOLD_VALID_INTR, 0);

	spin_unlock_irqrestore(&vop2->irq_lock, flags);
}

static void vop2_debug_irq_enable(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_video_port_data *vp_data = &vop2_data->vp[vp->id];
	const struct vop_intr *intr = vp_data->intr;
	uint32_t irqs = POST_BUF_EMPTY_INTR;

	VOP_INTR_SET_TYPE(vop2, intr, clear, irqs, 1);
	VOP_INTR_SET_TYPE(vop2, intr, enable, irqs, 1);
}

/*
 * (1) each frame starts at the start of the Vsync pulse which is signaled by
 *     the "FRAME_SYNC" interrupt.
 * (2) the active data region of each frame ends at dsp_vact_end
 * (3) we should program this same number (dsp_vact_end) into dsp_line_frag_num,
 *      to get "LINE_FLAG" interrupt at the end of the active on screen data.
 *
 * VOP_INTR_CTRL0.dsp_line_frag_num = VOP_DSP_VACT_ST_END.dsp_vact_end
 * Interrupts
 * LINE_FLAG -------------------------------+
 * FRAME_SYNC ----+                         |
 *                |                         |
 *                v                         v
 *                | Vsync | Vbp |  Vactive  | Vfp |
 *                        ^     ^           ^     ^
 *                        |     |           |     |
 *                        |     |           |     |
 * dsp_vs_end ------------+     |           |     |   VOP_DSP_VTOTAL_VS_END
 * dsp_vact_start --------------+           |     |   VOP_DSP_VACT_ST_END
 * dsp_vact_end ----------------------------+     |   VOP_DSP_VACT_ST_END
 * dsp_total -------------------------------------+   VOP_DSP_VTOTAL_VS_END
 */

static int vop2_core_clks_enable(struct vop2 *vop2)
{
	int ret;

	ret = clk_enable(vop2->hclk);
	if (ret < 0)
		return ret;

	ret = clk_enable(vop2->aclk);
	if (ret < 0)
		goto err_disable_hclk;

	ret = clk_enable(vop2->pclk);
	if (ret < 0)
		goto err_disable_aclk;

	return 0;

err_disable_aclk:
	clk_disable(vop2->aclk);
err_disable_hclk:
	clk_disable(vop2->hclk);
	return ret;
}

static void vop2_core_clks_disable(struct vop2 *vop2)
{
	clk_disable(vop2->pclk);
	clk_disable(vop2->aclk);
	clk_disable(vop2->hclk);
}

static void vop2_wb_connector_reset(struct drm_connector *connector)
{
	struct vop2_wb_connector_state *wb_state;

	if (connector->state) {
		__drm_atomic_helper_connector_destroy_state(connector->state);
		kfree(connector->state);
		connector->state = NULL;
	}

	wb_state = kzalloc(sizeof(*wb_state), GFP_KERNEL);
	if (wb_state)
		__drm_atomic_helper_connector_reset(connector, &wb_state->base);
}

static enum drm_connector_status
vop2_wb_connector_detect(struct drm_connector *connector, bool force)
{
	return connector_status_connected;
}

static void vop2_wb_connector_destroy(struct drm_connector *connector)
{
	drm_connector_cleanup(connector);
}

static struct drm_connector_state *
vop2_wb_connector_duplicate_state(struct drm_connector *connector)
{
	struct vop2_wb_connector_state *wb_state;

	if (WARN_ON(!connector->state))
		return NULL;

	wb_state = kzalloc(sizeof(*wb_state), GFP_KERNEL);
	if (!wb_state)
		return NULL;

	__drm_atomic_helper_connector_duplicate_state(connector, &wb_state->base);

	return &wb_state->base;
}

static const struct drm_connector_funcs vop2_wb_connector_funcs = {
	.reset = vop2_wb_connector_reset,
	.detect = vop2_wb_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = vop2_wb_connector_destroy,
	.atomic_duplicate_state = vop2_wb_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static int vop2_wb_connector_get_modes(struct drm_connector *connector)
{
	struct drm_display_mode *mode;
	int i;

	for (i = 0; i < 2; i++) {
		mode = drm_mode_create(connector->dev);
		if (!mode)
			break;

		mode->type = DRM_MODE_TYPE_PREFERRED | DRM_MODE_TYPE_DRIVER;
		mode->clock = 148500 >> i;
		mode->hdisplay = 1920 >> i;
		mode->hsync_start = 1930 >> i;
		mode->hsync_end = 1940 >> i;
		mode->htotal = 1990 >> i;
		mode->vdisplay = 1080 >> i;
		mode->vsync_start = 1090 >> i;
		mode->vsync_end = 1100 >> i;
		mode->vtotal = 1110 >> i;
		mode->flags = 0;

		drm_mode_set_name(mode);
		drm_mode_probed_add(connector, mode);
	}
	return i;
}

static enum drm_mode_status
vop2_wb_connector_mode_valid(struct drm_connector *connector,
			       struct drm_display_mode *mode)
{

	struct drm_writeback_connector *wb_conn;
	struct vop2_wb *wb;
	struct vop2 *vop2;
	int w, h;

	wb_conn = container_of(connector, struct drm_writeback_connector, base);
	wb = container_of(wb_conn, struct vop2_wb, conn);
	vop2 = container_of(wb, struct vop2, wb);
	w = mode->hdisplay;
	h = mode->vdisplay;


	if (w > vop2->data->wb->max_output.width)
		return MODE_BAD_HVALUE;

	if (h > vop2->data->wb->max_output.height)
		return MODE_BAD_VVALUE;

	return MODE_OK;
}

static int vop2_wb_encoder_atomic_check(struct drm_encoder *encoder,
			       struct drm_crtc_state *cstate,
			       struct drm_connector_state *conn_state)
{
	struct vop2_wb_connector_state *wb_state = to_wb_state(conn_state);
	struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(cstate);
	struct vop2_video_port *vp = to_vop2_video_port(cstate->crtc);
	struct drm_framebuffer *fb;
	struct drm_gem_object *obj, *uv_obj;
	struct rockchip_gem_object *rk_obj, *rk_uv_obj;



	if (!conn_state->writeback_job || !conn_state->writeback_job->fb)
		return 0;

	fb = conn_state->writeback_job->fb;
	DRM_DEV_DEBUG(vp->vop2->dev, "%d x % d\n", fb->width, fb->height);

	if (!is_yuv_support(fb->format->format) && is_yuv_output(vcstate->bus_format)) {
		DRM_ERROR("YUV2RGB is not supported by writeback\n");
		return -EINVAL;
	}

	if ((fb->width > cstate->mode.hdisplay) ||
	    ((fb->height != cstate->mode.vdisplay) &&
	    (fb->height != (cstate->mode.vdisplay >> 1)))) {
		DRM_DEBUG_KMS("Invalid framebuffer size %ux%u, Only support x scale down and 1/2 y scale down\n",
				fb->width, fb->height);
		return -EINVAL;
	}

	wb_state->scale_x_factor = vop2_scale_factor(SCALE_DOWN, VOP2_SCALE_DOWN_BIL,
						      cstate->mode.hdisplay, fb->width);
	wb_state->scale_x_en = (fb->width < cstate->mode.hdisplay) ? 1 : 0;
	wb_state->scale_y_en = (fb->height < cstate->mode.vdisplay) ? 1 : 0;

	wb_state->format = vop2_convert_wb_format(fb->format->format);
	if (wb_state->format < 0) {
		struct drm_format_name_buf format_name;

		DRM_DEBUG_KMS("Invalid pixel format %s\n",
			      drm_get_format_name(fb->format->format,
						  &format_name));
		return -EINVAL;
	}

	wb_state->vp_id = vp->id;
	obj = fb->obj[0];
	rk_obj = to_rockchip_obj(obj);
	wb_state->yrgb_addr = rk_obj->dma_addr + fb->offsets[0];

	if (fb->format->is_yuv) {
		uv_obj = fb->obj[1];
		rk_uv_obj = to_rockchip_obj(uv_obj);

		wb_state->uv_addr = rk_uv_obj->dma_addr + fb->offsets[1];
	}

	return 0;
}

static const struct drm_encoder_helper_funcs vop2_wb_encoder_helper_funcs = {
	.atomic_check = vop2_wb_encoder_atomic_check,
};

static const struct drm_connector_helper_funcs vop2_wb_connector_helper_funcs = {
	.get_modes = vop2_wb_connector_get_modes,
	.mode_valid = vop2_wb_connector_mode_valid,
};


static int vop2_wb_connector_init(struct vop2 *vop2, int nr_crtcs)
{
	const struct vop2_data *vop2_data = vop2->data;
	int ret;

	vop2->wb.regs = vop2_data->wb->regs;
	vop2->wb.conn.encoder.possible_crtcs = (1 << nr_crtcs) - 1;
	spin_lock_init(&vop2->wb.job_lock);
	drm_connector_helper_add(&vop2->wb.conn.base, &vop2_wb_connector_helper_funcs);

	ret = drm_writeback_connector_init(vop2->drm_dev, &vop2->wb.conn,
					   &vop2_wb_connector_funcs,
					   &vop2_wb_encoder_helper_funcs,
					   vop2_data->wb->formats,
					   vop2_data->wb->nformats);
	if (ret)
		DRM_DEV_ERROR(vop2->dev, "writeback connector init failed\n");
	return ret;
}

static void vop2_wb_connector_destory(struct vop2 *vop2)
{
	drm_encoder_cleanup(&vop2->wb.conn.encoder);
	drm_connector_cleanup(&vop2->wb.conn.base);
}

static void vop2_wb_irqs_enable(struct vop2 *vop2)
{
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop_intr *intr = &vop2_data->axi_intr[0];
	uint32_t irqs = WB_UV_FIFO_FULL_INTR | WB_YRGB_FIFO_FULL_INTR;

	VOP_INTR_SET_TYPE(vop2, intr, clear, irqs, 1);
	VOP_INTR_SET_TYPE(vop2, intr, enable, irqs, 1);
}

static uint32_t vop2_read_and_clear_wb_irqs(struct vop2 *vop2)
{
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop_intr *intr = &vop2_data->axi_intr[0];
	uint32_t irqs = WB_UV_FIFO_FULL_INTR | WB_YRGB_FIFO_FULL_INTR;
	uint32_t val;

	val = VOP_INTR_GET_TYPE(vop2, intr, status, irqs);
	if (val)
		VOP_INTR_SET_TYPE(vop2, intr, clear, val, 1);


	return val;
}

static void vop2_wb_commit(struct drm_crtc *crtc)
{
	struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(crtc->state);
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	struct vop2_wb *wb = &vop2->wb;
	struct drm_writeback_connector *wb_conn = &wb->conn;
	struct drm_connector_state *conn_state = wb_conn->base.state;
	struct vop2_wb_connector_state *wb_state;
	unsigned long flags;
	uint32_t fifo_throd;
	uint8_t r2y;

	if (!conn_state)
		return;
	wb_state = to_wb_state(conn_state);

	if (wb_state->vp_id != vp->id)
		return;

	if (conn_state->writeback_job && conn_state->writeback_job->fb) {
		struct drm_framebuffer *fb = conn_state->writeback_job->fb;

		DRM_DEV_DEBUG(vop2->dev, "Enable wb %ux%u  fmt: %u pitches: %d\n",
			      fb->width, fb->height, wb_state->format, fb->pitches[0]);

		drm_writeback_queue_job(wb_conn, conn_state);
		conn_state->writeback_job = NULL;

		spin_lock_irqsave(&wb->job_lock, flags);
		wb->jobs[wb->job_index].pending = true;
		wb->job_index++;
		if (wb->job_index >= VOP2_WB_JOB_MAX)
			wb->job_index = 0;
		spin_unlock_irqrestore(&wb->job_lock, flags);

		fifo_throd = fb->pitches[0] >> 4;
		if (fifo_throd >= vop2->data->wb->fifo_depth)
			fifo_throd = vop2->data->wb->fifo_depth;
		r2y = is_yuv_support(fb->format->format) && (!is_yuv_output(vcstate->bus_format));

		/*
		 * the vp_id register config done immediately
		 */
		VOP_MODULE_SET(vop2, wb, vp_id, wb_state->vp_id);
		VOP_MODULE_SET(vop2, wb, format, wb_state->format);
		VOP_MODULE_SET(vop2, wb, yrgb_mst, wb_state->yrgb_addr);
		VOP_MODULE_SET(vop2, wb, uv_mst, wb_state->uv_addr);
		VOP_MODULE_SET(vop2, wb, fifo_throd, fifo_throd);
		VOP_MODULE_SET(vop2, wb, scale_x_factor, wb_state->scale_x_factor);
		VOP_MODULE_SET(vop2, wb, scale_x_en, wb_state->scale_x_en);
		VOP_MODULE_SET(vop2, wb, scale_y_en, wb_state->scale_y_en);
		VOP_MODULE_SET(vop2, wb, r2y_en, r2y);
		VOP_MODULE_SET(vop2, wb, enable, 1);
		vop2_wb_irqs_enable(vop2);
	}
}

static void rk3568_crtc_load_lut(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	int dle = 0, i = 0;
	u8 vp_enable_gamma_nr = 0;

	for (i = 0; i < vop2->data->nr_vps; i++) {
		struct vop2_video_port *vp = &vop2->vps[i];

		if (vp->gamma_lut_active)
			vp_enable_gamma_nr++;
	}

	if (vop2->data->nr_gammas &&
	    vp_enable_gamma_nr >= vop2->data->nr_gammas &&
	    vp->gamma_lut_active == false) {
		DRM_INFO("only support %d gamma\n", vop2->data->nr_gammas);
		return;
	}

	spin_lock(&vop2->reg_lock);
	VOP_MODULE_SET(vop2, vp, dsp_lut_en, 0);
	vop2_cfg_done(crtc);
	spin_unlock(&vop2->reg_lock);

#define CTRL_GET(name) VOP_MODULE_GET(vop2, vp, name)
	readx_poll_timeout(CTRL_GET, dsp_lut_en, dle, !dle, 5, 33333);

	VOP_CTRL_SET(vop2, gamma_port_sel, vp->id);
	for (i = 0; i < vp->gamma_lut_len; i++)
		vop2_write_lut(vop2, i << 2, vp->lut[i]);

	spin_lock(&vop2->reg_lock);

	VOP_MODULE_SET(vop2, vp, dsp_lut_en, 1);
	VOP_MODULE_SET(vop2, vp, gamma_update_en, 1);
	vop2_cfg_done(crtc);
	vp->gamma_lut_active = true;

	spin_unlock(&vop2->reg_lock);
#undef CTRL_GET
}

static void rk3588_crtc_load_lut(struct drm_crtc *crtc, u32 *lut)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	int i = 0;

	spin_lock(&vop2->reg_lock);

	VOP_CTRL_SET(vop2, gamma_port_sel, vp->id);
	for (i = 0; i < vp->gamma_lut_len; i++)
		vop2_write_lut(vop2, i << 2, lut[i]);

	VOP_MODULE_SET(vop2, vp, dsp_lut_en, 1);
	VOP_MODULE_SET(vop2, vp, gamma_update_en, 1);
	vp->gamma_lut_active = true;

	spin_unlock(&vop2->reg_lock);
}

static void vop2_crtc_load_lut(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;

	if (!vop2->is_enabled || !vp->lut || !vop2->lut_regs)
		return;

	if (WARN_ON(!drm_modeset_is_locked(&crtc->mutex)))
		return;

	if (vop2->version == VOP_VERSION_RK3568)
		return rk3568_crtc_load_lut(crtc);
	else if (vop2->version == VOP_VERSION_RK3588) {
		struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(crtc->state);
		const struct vop2_video_port_data *vp_data = &vop2->data->vp[vp->id];
		struct vop2_video_port *splice_vp = &vop2->vps[vp_data->splice_vp_id];

		rk3588_crtc_load_lut(&vp->rockchip_crtc.crtc, vp->lut);
		if (vcstate->splice_mode)
			rk3588_crtc_load_lut(&splice_vp->rockchip_crtc.crtc, vp->lut);
		vop2_cfg_done(crtc);
	}
}

static void rockchip_vop2_crtc_fb_gamma_set(struct drm_crtc *crtc, u16 red,
					    u16 green, u16 blue, int regno)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	u32 lut_len = vp->gamma_lut_len;
	u32 r, g, b;

	if (regno >= lut_len || !vp->lut)
		return;

	r = red * (lut_len - 1) / 0xffff;
	g = green * (lut_len - 1) / 0xffff;
	b = blue * (lut_len - 1) / 0xffff;
	vp->lut[regno] = b * lut_len * lut_len + g * lut_len + r;
}

static void rockchip_vop2_crtc_fb_gamma_get(struct drm_crtc *crtc, u16 *red,
				       u16 *green, u16 *blue, int regno)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	u32 lut_len = vp->gamma_lut_len;
	u32 r, g, b;

	if (regno >= lut_len || !vp->lut)
		return;

	b = (vp->lut[regno] / lut_len / lut_len) & (lut_len - 1);
	g = (vp->lut[regno] / lut_len) & (lut_len - 1);
	r = vp->lut[regno] & (lut_len - 1);
	*red = r * 0xffff / (lut_len - 1);
	*green = g * 0xffff / (lut_len - 1);
	*blue = b * 0xffff / (lut_len - 1);
}

static int vop2_crtc_legacy_gamma_set(struct drm_crtc *crtc, u16 *red,
				      u16 *green, u16 *blue, uint32_t size,
				      struct drm_modeset_acquire_ctx *ctx)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	int i;

	if (!vp->lut)
		return -EINVAL;

	if (size > vp->gamma_lut_len) {
		DRM_ERROR("gamma size[%d] out of video port%d gamma lut len[%d]\n",
			  size, vp->id, vp->gamma_lut_len);
		return -ENOMEM;
	}
	for (i = 0; i < size; i++)
		rockchip_vop2_crtc_fb_gamma_set(crtc, red[i], green[i],
						blue[i], i);
	vop2_crtc_load_lut(crtc);

	return 0;
}

static int vop2_crtc_atomic_gamma_set(struct drm_crtc *crtc,
				      struct drm_crtc_state *old_state)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct drm_color_lut *lut = vp->gamma_lut;
	unsigned int i;

	for (i = 0; i < vp->gamma_lut_len; i++)
		rockchip_vop2_crtc_fb_gamma_set(crtc, lut[i].red, lut[i].green,
						lut[i].blue, i);
	vop2_crtc_load_lut(crtc);

	return 0;
}

#if defined(CONFIG_ROCKCHIP_DRM_CUBIC_LUT)
static int vop2_crtc_atomic_cubic_lut_set(struct drm_crtc *crtc,
					  struct drm_crtc_state *old_state)
{
	struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(crtc->state);
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct rockchip_drm_private *private = crtc->dev->dev_private;
	struct drm_color_lut *lut = vp->cubic_lut;
	struct vop2 *vop2 = vp->vop2;
	u32 *cubic_lut_kvaddr;
	dma_addr_t cubic_lut_mst;
	unsigned int i;

	if (!vp->cubic_lut_len) {
		DRM_ERROR("Video Port%d unsupported 3D lut\n", vp->id);
		return -ENODEV;
	}

	if (!private->cubic_lut[vp->id].enable) {
		if (!vp->cubic_lut_gem_obj) {
			size_t size = (vp->cubic_lut_len + 1) / 2 * 16;

			vp->cubic_lut_gem_obj = rockchip_gem_create_object(crtc->dev, size, true, 0);
			if (IS_ERR(vp->cubic_lut_gem_obj))
				return -ENOMEM;
		}

		cubic_lut_kvaddr = (u32 *)vp->cubic_lut_gem_obj->kvaddr;
		cubic_lut_mst = vp->cubic_lut_gem_obj->dma_addr;
	} else {
		cubic_lut_kvaddr = private->cubic_lut[vp->id].offset + private->cubic_lut_kvaddr;
		cubic_lut_mst = private->cubic_lut[vp->id].offset + private->cubic_lut_dma_addr;
	}

	for (i = 0; i < vp->cubic_lut_len / 2; i++) {
		*cubic_lut_kvaddr++ = (lut[2 * i].red & 0xfff) +
					((lut[2 * i].green & 0xfff) << 12) +
					((lut[2 * i].blue & 0xff) << 24);
		*cubic_lut_kvaddr++ = ((lut[2 * i].blue & 0xf00) >> 8) +
					((lut[2 * i + 1].red & 0xfff) << 4) +
					((lut[2 * i + 1].green & 0xfff) << 16) +
					((lut[2 * i + 1].blue & 0xf) << 28);
		*cubic_lut_kvaddr++ = (lut[2 * i + 1].blue & 0xff0) >> 4;
		*cubic_lut_kvaddr++ = 0;
	}

	if (vp->cubic_lut_len % 2) {
		*cubic_lut_kvaddr++ = (lut[2 * i].red & 0xfff) +
					((lut[2 * i].green & 0xfff) << 12) +
					((lut[2 * i].blue & 0xff) << 24);
		*cubic_lut_kvaddr++ = (lut[2 * i].blue & 0xf00) >> 8;
		*cubic_lut_kvaddr++ = 0;
		*cubic_lut_kvaddr = 0;
	}

	VOP_MODULE_SET(vop2, vp, lut_dma_rid, vp->lut_dma_rid - vp->id);
	VOP_MODULE_SET(vop2, vp, cubic_lut_mst, cubic_lut_mst);
	VOP_MODULE_SET(vop2, vp, cubic_lut_update_en, 1);
	VOP_MODULE_SET(vop2, vp, cubic_lut_en, 1);
	VOP_CTRL_SET(vop2, lut_dma_en, 1);

	if (vcstate->splice_mode) {
		const struct vop2_video_port_data *vp_data = &vop2->data->vp[vp->id];
		struct vop2_video_port *splice_vp = &vop2->vps[vp_data->splice_vp_id];

		VOP_MODULE_SET(vop2, splice_vp, lut_dma_rid, splice_vp->lut_dma_rid - splice_vp->id);
		VOP_MODULE_SET(vop2, splice_vp, cubic_lut_mst, cubic_lut_mst);
		VOP_MODULE_SET(vop2, splice_vp, cubic_lut_update_en, 1);
		VOP_MODULE_SET(vop2, splice_vp, cubic_lut_en, 1);
	}

	return 0;
}

static void drm_crtc_enable_cubic_lut(struct drm_crtc *crtc, unsigned int cubic_lut_size)
{
	struct drm_device *dev = crtc->dev;
	struct drm_mode_config *config = &dev->mode_config;

	if (cubic_lut_size) {
		drm_object_attach_property(&crtc->base,
					   config->cubic_lut_property, 0);
		drm_object_attach_property(&crtc->base,
					   config->cubic_lut_size_property,
					   cubic_lut_size);
	}
}

static void vop2_cubic_lut_init(struct vop2 *vop2)
{
	const struct vop2_data *vop2_data = vop2->data;
	const struct vop2_video_port_data *vp_data;
	struct vop2_video_port *vp;
	struct drm_crtc *crtc;
	int i;

	for (i = 0; i < vop2_data->nr_vps; i++) {
		vp = &vop2->vps[i];
		crtc = &vp->rockchip_crtc.crtc;
		if (!crtc->dev)
			continue;
		vp_data = &vop2_data->vp[vp->id];
		vp->cubic_lut_len = vp_data->cubic_lut_len;

		if (vp->cubic_lut_len)
			drm_crtc_enable_cubic_lut(crtc, vp->cubic_lut_len);
	}
}
#else
static void vop2_cubic_lut_init(struct vop2 *vop2) { }
#endif

static int vop2_core_clks_prepare_enable(struct vop2 *vop2)
{
	int ret;

	ret = clk_prepare_enable(vop2->hclk);
	if (ret < 0) {
		dev_err(vop2->dev, "failed to enable hclk - %d\n", ret);
		return ret;
	}

	ret = clk_prepare_enable(vop2->aclk);
	if (ret < 0) {
		dev_err(vop2->dev, "failed to enable aclk - %d\n", ret);
		goto err;
	}

	ret = clk_prepare_enable(vop2->pclk);
	if (ret < 0) {
		dev_err(vop2->dev, "failed to enable pclk - %d\n", ret);
		goto err1;
	}

	return 0;
err1:
	clk_disable_unprepare(vop2->aclk);
err:
	clk_disable_unprepare(vop2->hclk);

	return ret;
}

/*
 * VOP2 architecture
 *
 +----------+   +-------------+
 |  Cluster |   | Sel 1 from 6
 |  window0 |   |    Layer0   |              +---------------+    +-------------+    +-----------+
 +----------+   +-------------+              |N from 6 layers|    |             |    | 1 from 3  |
 +----------+   +-------------+              |   Overlay0    |    | Video Port0 |    |    RGB    |
 |  Cluster |   | Sel 1 from 6|              |               |    |             |    +-----------+
 |  window1 |   |    Layer1   |              +---------------+    +-------------+
 +----------+   +-------------+                                                      +-----------+
 +----------+   +-------------+                               +-->                   | 1 from 3  |
 |  Esmart  |   | Sel 1 from 6|              +---------------+    +-------------+    |   LVDS    |
 |  window0 |   |   Layer2    |              |N from 6 Layers     |             |    +-----------+
 +----------+   +-------------+              |   Overlay1    +    | Video Port1 | +--->
 +----------+   +-------------+   -------->  |               |    |             |    +-----------+
 |  Esmart  |   | Sel 1 from 6|   -------->  +---------------+    +-------------+    | 1 from 3  |
 |  Window1 |   |   Layer3    |                               +-->                   |   MIPI    |
 +----------+   +-------------+                                                      +-----------+
 +----------+   +-------------+              +---------------+    +-------------+
 |  Smart   |   | Sel 1 from 6|              |N from 6 Layers|    |             |    +-----------+
 |  Window0 |   |    Layer4   |              |   Overlay2    |    | Video Port2 |    | 1 from 3  |
 +----------+   +-------------+              |               |    |             |    |   HDMI    |
 +----------+   +-------------+              +---------------+    +-------------+    +-----------+
 |  Smart   |   | Sel 1 from 6|                                                      +-----------+
 |  Window1 |   |    Layer5   |                                                      |  1 from 3 |
 +----------+   +-------------+                                                      |    eDP    |
 *                                                                                   +-----------+
 */
static void vop2_layer_map_initial(struct vop2 *vop2, uint32_t current_vp_id)
{
	struct vop2_layer *layer;
	struct vop2_video_port *vp;
	struct vop2_win *win;
	unsigned long win_mask;
	uint32_t used_layers = 0;
	uint16_t port_mux_cfg = 0;
	uint16_t port_mux;
	uint16_t vp_id;
	uint8_t nr_layers;
	int phys_id;
	int i, j;

	for (i = 0; i < vop2->data->nr_vps; i++) {
		vp_id = i;
		j = 0;
		vp = &vop2->vps[vp_id];
		vp->win_mask = vp->plane_mask;
		nr_layers = hweight32(vp->win_mask);
		win_mask = vp->win_mask;
		for_each_set_bit(phys_id, &win_mask, ROCKCHIP_MAX_LAYER) {
			layer = &vop2->layers[used_layers + j];
			win = vop2_find_win_by_phys_id(vop2, phys_id);
			VOP_CTRL_SET(vop2, win_vp_id[phys_id], vp_id);
			VOP_MODULE_SET(vop2, layer, layer_sel, win->layer_sel_id);
			win->vp_mask = BIT(i);
			win->old_vp_mask = win->vp_mask;
			layer->win_phys_id = win->phys_id;
			win->layer_id = layer->id;
			j++;
			DRM_DEV_DEBUG(vop2->dev, "layer%d select %s for vp%d phys_id: %d\n",
				      layer->id, win->name, vp_id, phys_id);
		}
		used_layers += nr_layers;
	}

	/*
	 * The last Video Port(VP2 for RK3568, VP3 for RK3588) is fixed
	 * at the last level of the all the mixers by hardware design,
	 * so we just need to handle (nr_vps - 1) vps here.
	 */
	used_layers = 0;
	for (i = 0; i < vop2->data->nr_vps - 1; i++) {
		vp = &vop2->vps[i];
		used_layers += hweight32(vp->win_mask);
		if (used_layers == 0)
			port_mux = 8;
		else
			port_mux = used_layers - 1;
		port_mux_cfg |= port_mux << (vp->id * 4);
	}

	/* the last VP is fixed */
	if (vop2->data->nr_vps >= 1)
		port_mux_cfg |= 7 << (4 * (vop2->data->nr_vps - 1));
	vop2->port_mux_cfg = port_mux_cfg;
	VOP_CTRL_SET(vop2, ovl_port_mux_cfg, port_mux_cfg);

}

static void rk3588_vop2_regsbak(struct vop2 *vop2)
{
	uint32_t *base = vop2->regs;
	int i;

	/*
	 * No need to backup DSC/GAMMA_LUT/BPP_LUT/MMU
	 */
	for (i = 0; i < (0x2000 >> 2); i++)
		vop2->regsbak[i] = base[i];
}

static void vop2_initial(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;
	uint32_t current_vp_id = vp->id;
	struct vop2_wb *wb = &vop2->wb;
	int ret;

	if (vop2->enable_count == 0) {

		ret = pm_runtime_get_sync(vop2->dev);
		if (ret < 0) {
			DRM_DEV_ERROR(vop2->dev, "failed to get pm runtime: %d\n", ret);
			return;
		}

		ret = vop2_core_clks_prepare_enable(vop2);
		if (ret) {
			pm_runtime_put_sync(vop2->dev);
			return;
		}

		if (vop2_soc_is_rk3566())
			VOP_CTRL_SET(vop2, otp_en, 1);

		/*
		 * rk3588 don't support access mmio by memcpy
		 */
		if (vop2->version == VOP_VERSION_RK3588)
			rk3588_vop2_regsbak(vop2);
		else
			memcpy(vop2->regsbak, vop2->regs, vop2->len);

		VOP_CTRL_SET(vop2, pd_off_imd, 0);
		VOP_MODULE_SET(vop2, wb, axi_yrgb_id, 0xd);
		VOP_MODULE_SET(vop2, wb, axi_uv_id, 0xe);
		vop2_wb_cfg_done(vp);

		VOP_CTRL_SET(vop2, cfg_done_en, 1);
		/*
		 * Disable auto gating, this is a workaround to
		 * avoid display image shift when a window enabled.
		 */
		VOP_CTRL_SET(vop2, auto_gating_en, 0);
		/*
		 * Register OVERLAY_LAYER_SEL and OVERLAY_PORT_SEL should take effect immediately,
		 * than windows configuration(CLUSTER/ESMART/SMART) can take effect according the
		 * video port mux configuration as we wished.
		 */
		VOP_CTRL_SET(vop2, ovl_port_mux_cfg_done_imd, 1);
		/*
		 * Let SYS_DSP_INFACE_EN/SYS_DSP_INFACE_CTRL/SYS_DSP_INFACE_POL take effect
		 * immediately.
		 */
		VOP_CTRL_SET(vop2, if_ctrl_cfg_done_imd, 1);

		vop2_layer_map_initial(vop2, current_vp_id);
		vop2_axi_irqs_enable(vop2);
		vop2->is_enabled = true;
	}

	vop2_debug_irq_enable(crtc);

	vop2->enable_count++;

	ret = clk_prepare_enable(vp->dclk);
	if (ret < 0)
		DRM_DEV_ERROR(vop2->dev, "failed to enable dclk for video port%d - %d\n",
			      vp->id, ret);
}

static void vop2_power_off_all_pd(struct vop2 *vop2)
{
	struct vop2_power_domain *pd, *n;

	VOP_CTRL_SET(vop2, pd_off_imd, 1);
	list_for_each_entry_safe(pd, n, &vop2->pd_list_head, list) {
		VOP_MODULE_SET(vop2, pd->data, pd, 1);
		vop2_wait_power_domain_off(pd);
		pd->on = false;
		pd->module_on = false;
	}
}

static void vop2_disable(struct drm_crtc *crtc)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct vop2 *vop2 = vp->vop2;

	clk_disable_unprepare(vp->dclk);

	if (--vop2->enable_count > 0)
		return;

	vop2->is_enabled = false;
	if (vop2->is_iommu_enabled) {
		/*
		 * vop2 standby complete, so iommu detach is safe.
		 */
		VOP_CTRL_SET(vop2, dma_stop, 1);
		rockchip_drm_dma_detach_device(vop2->drm_dev, vop2->dev);
		vop2->is_iommu_enabled = false;
	}
	if (vop2->version == VOP_VERSION_RK3588)
		vop2_power_off_all_pd(vop2);

	pm_runtime_put_sync(vop2->dev);

	clk_disable_unprepare(vop2->pclk);
	clk_disable_unprepare(vop2->aclk);
	clk_disable_unprepare(vop2->hclk);
}

static void vop2_crtc_disable_dsc(struct vop2 *vop2, u8 dsc_id)
{
	struct vop2_dsc *dsc = &vop2->dscs[dsc_id];

	VOP_MODULE_SET(vop2, dsc, dsc_mer, 1);
	VOP_MODULE_SET(vop2, dsc, dsc_interface_mode, 0);
	VOP_MODULE_SET(vop2, dsc, dsc_en, 0);
	VOP_MODULE_SET(vop2, dsc, rst_deassert, 0);
}

static void vop2_crtc_atomic_disable(struct drm_crtc *crtc,
				     struct drm_crtc_state *old_state)
{
	struct vop2_video_port *vp = to_vop2_video_port(crtc);
	struct rockchip_crtc_state *vcstate = to_rockchip_crtc_state(crtc->state);
	struct vop2 *vop2 = vp->vop2;
	const struct vop2_video_port_data *vp_data = &vop2->data->vp[vp->id];
	struct vop2_video_port *splice_vp = &vop2->vps[vp_data->splice_vp_id];
	bool dual_channel = !!(vcstate->output_flags & ROCKCHIP_OUTPUT_DUAL_CHANNEL_LEFT_RIGHT_MODE);
	int ret;

	WARN_ON(vp->event);
	vop2_lock(vop2);
	DRM_DEV_INFO(vop2->dev, "Crtc atomic disable vp%d\n", vp->id);
	drm_crtc_vblank_off(crtc);
	if (vop2->dscs[vcstate->dsc_id].enabled &&
	    vop2->dscs[vcstate->dsc_id].attach_vp_id == vp->id &&
	    vop2->data->nr_dscs) {
		if (dual_channel) {
			vop2_crtc_disable_dsc(vop2, 0);
			vop2_crtc_disable_dsc(vop2, 1);
		} else {
			vop2_crtc_disable_dsc(vop2, vcstate->dsc_id);
		}
	}
	vop2_disable_all_planes_for_crtc(crtc);
	if (vop2->dscs[vcstate->dsc_id].enabled &&
	    vop2->dscs[vcstate->dsc_id].attach_vp_id == vp->id &&
	    vop2->data->nr_dscs && vop2->dscs[vcstate->dsc_id].pd) {
		if (dual_channel) {
			vop2_power_domain_put(vop2->dscs[0].pd);
			vop2_power_domain_put(vop2->dscs[1].pd);
			vop2->dscs[0].attach_vp_id = -1;
			vop2->dscs[1].attach_vp_id = -1;
		} else {
			vop2_power_domain_put(vop2->dscs[vcstate->dsc_id].pd);
			vop2->dscs[vcstate->dsc_id].attach_vp_id = -1;
		}
		vop2->dscs[vcstate->dsc_id].enabled = false;
		vcstate->dsc_enable = false;
	}

	if (vp->output_if & VOP_OUTPUT_IF_eDP0)
		VOP_GRF_SET(vop2, grf, grf_edp0_en, 0);

	if (vp->output_if & VOP_OUTPUT_IF_eDP1)
		VOP_GRF_SET(vop2, grf, grf_edp1_en, 0);

	if (vp->output_if & VOP_OUTPUT_IF_HDMI0) {
		VOP_GRF_SET(vop2, grf, grf_hdmi0_dsc_en, 0);
		VOP_GRF_SET(vop2, grf, grf_hdmi0_en, 0);
	}

	if (vp->output_if & VOP_OUTPUT_IF_HDMI1) {
		VOP_GRF_SET(vop2, grf, grf_hdmi1_dsc_en, 0);
		VOP_GRF_SET(vop2, grf, grf_hdmi1_en, 0);
	}

	vp->output_if = 0;

	/*
	 * Vop standby will take effect at end of current frame,
	 * if dsp hold valid irq happen, it means standby complete.
	 *
	 * we must wait standby complete when we want to disable aclk,
	 * if not, memory bus maybe dead.
	 */
	reinit_completion(&vp->dsp_hold_completion);
	vop2_dsp_hold_valid_irq_enable(crtc);

	spin_lock(&vop2->reg_lock);

	if (vcstate->splice_mode)
		VOP_MODULE_SET(vop2, splice_vp, standby, 1);
	VOP_MODULE_SET(vop2, vp, standby, 1);

	spin_unlock(&vop2->reg_lock);

	ret = wait_for_completion_timeout(&vp->dsp_hold_completion, msecs_to_jiffies(50));
	if (!ret)
		DRM_DEV_INFO(vop2->dev, "wait for vp%d dsp_hold timeout\n", vp->id);

	vop2_dsp_hold_valid_irq_disable(crtc);

	vop2_disable(crtc);

	vcstate->splice_mode = false;
	vp->splice_mode_right = false;
	vp->loader_protect = false;
	vop2_unlock(vop2);

	vop2->active_vp_mask &= ~BIT(vp->id);
	vop2_set_system_status(vop2);

	if (crtc->state->event && !crtc->state->active) {
		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		spin_unlock_irq(&crtc->dev->event_lock);

		crtc->state->event = NULL;
	}
}

static int vop2_cluster_two_win_mode_check(struct drm_plane_state *pstate)
{
	struct drm_atomic_state *state = pstate->state;
	struct drm_plane *plane = pstate->plane;
	struct vop2_win *win = to_vop2_win(plane);
	struct vop2 *vop2 = win->vop2;
	struct vop2_win *main_win = vop2_find_win_by_phys_id(vop2, win->phys_id);
	struct drm_plane_state *main_pstate;
	int actual_w = drm_rect_width(&pstate->src) >> 16;
	int xoffset;

	if (pstate->fb->modifier == DRM_FORMAT_MOD_LINEAR)
		xoffset = 0;
	else
		xoffset = pstate->src.x1 >> 16;

	if ((actual_w + xoffset % 16) > 2048) {
		DRM_ERROR("%s act_w(%d) + xoffset(%d) / 16  << 2048 in two win mode\n",
				  win->name, actual_w, xoffset);
		return -EINVAL;
	}

	main_pstate = drm_atomic_get_new_plane_state(state, &main_win->base);

	if (pstate->fb->modifier != main_pstate->fb->modifier) {
		DRM_ERROR("%s(fb->modifier: 0x%llx) must use same data layout as %s(fb->modifier: 0x%llx)\n",
				win->name, pstate->fb->modifier, main_win->name, main_pstate->fb->modifier);
		return -EINVAL;
	}

	if (main_pstate->fb->modifier == DRM_FORMAT_MOD_LINEAR)
		xoffset = 0;
	else
		xoffset = main_pstate->src.x1 >> 16;
	actual_w = drm_rect_width(&main_pstate->src) >> 16;

	if ((actual_w + xoffset % 16) > 2048) {
		DRM_ERROR("%s act_w(%d) + xoffset(%d) / 16  << 2048 in two win mode\n",
				  main_win->name, actual_w, xoffset);
		return -EINVAL;
	}

	return 0;
}

static int vop2_cluter_splice_scale_check(struct vop2_win *win, struct drm_plane_state *pstate,
					  u16 hdisplay)
{
	struct drm_rect src = drm_plane_state_src(pstate);
	struct drm_rect dst = drm_plane_state_dest(pstate);
	u16 half_hdisplay = hdisplay >> 1;

	/* scale up is ok */
	if ((drm_rect_width(&src) >> 16) <= drm_rect_width(&dst))
		return 0;

	/*
	 * Cluster scale down limitation in splice mode:
	 * If scale down, must display at horizontal center
	 */
	if ((dst.x1 < half_hdisplay) && (dst.x2 > half_hdisplay)) {
		if ((dst.x2 + dst.x1) != hdisplay) {
			DRM_ERROR("%s dst(%d %d)must scale down at center in splice mode\n",
				  win->name, dst.x1, dst.x2);
			return -EINVAL;
		}

		if (drm_rect_calc_hscale(&src, &dst, 1, FRAC_16_16(6, 5)) < 0) {
			DRM_ERROR("%s %d --> %d scale down factor should < 1.2 in splice mode\n",
				  win->name, drm_rect_width(&src) >> 16, drm_rect_width(&dst));
			return -EINVAL;
		}
	}

	return 0;
}

static int vop2_plane_splice_check(struct drm_plane *plane, struct drm_plane_state *pstate,
				   struct drm_display_mode *mode)
{
	struct vop2_win *win = to_vop2_win(plane);
	int ret = 0;

	if (!(win->feature & WIN_FEATURE_SPLICE_LEFT)) {
		DRM_ERROR("%s can't be left win in splice mode\n", win->name);
		return -EINVAL;
	}

	if (win->feature & WIN_FEATURE_CLUSTER_SUB) {
		DRM_ERROR("%s can't use two win mode in splice mode\n", win->name);
		return -EINVAL;
	}

	if ((pstate->rotation & DRM_MODE_ROTATE_270) ||
	    (pstate->rotation & DRM_MODE_ROTATE_90) ||
	    (pstate->rotation & DRM_MODE_REFLECT_X)) {
		DRM_ERROR("%s can't rotate 270/90 and xmirror in splice mode\n", win->name);
		return -EINVAL;
	}

	/* check for cluster splice scale down */
	if (win->feature & WIN_FEATURE_CLUSTER_MAIN)
		ret = vop2_cluter_splice_scale_check(win, pstate, mode->hdisplay);

	return ret;
}

static int vop2_plane_atomic_check(struct drm_plane *plane, struct drm_plane_state *state)
{
	struct vop2_plane_state *vpstate = to_vop2_plane_state(state);
	struct vop2_win *win = to_vop2_win(plane);
	struct vop2_win *splice_win;
	struct vop2 *vop2 = win->vop2;
	struct drm_framebuffer *fb = state->fb;
	struct drm_display_mode *mode;
	struct drm_crtc *crtc = state->crtc;
	struct drm_crtc_state *cstate;
	struct rockchip_crtc_state *vcstate;
	struct vop2_video_port *vp;
	const struct vop2_data *vop2_data;
	struct drm_rect *dest = &vpstate->dest;
	struct drm_rect *src = &vpstate->src;
	struct drm_gem_object *obj, *uv_obj;
	struct rockchip_gem_object *rk_obj, *rk_uv_obj;
	int min_scale = win->regs->scl ? FRAC_16_16(1, 8) : DRM_PLANE_HELPER_NO_SCALING;
	int max_scale = win->regs->scl ? FRAC_16_16(8, 1) : DRM_PLANE_HELPER_NO_SCALING;
	int max_input_w;
	int max_input_h;
	unsigned long offset;
	dma_addr_t dma_addr;
	int ret;

	crtc = crtc ? crtc : plane->state->crtc;
	if (!crtc || !fb) {
		plane->state->visible = false;
		return 0;
	}

	vp = to_vop2_video_port(crtc);
	vop2_data = vp->vop2->data;

	cstate = drm_atomic_get_existing_crtc_state(state->state, crtc);
	if (WARN_ON(!cstate))
		return -EINVAL;

	mode = &cstate->mode;
	vcstate = to_rockchip_crtc_state(cstate);

	max_input_w = vop2_data->max_input.width;
	max_input_h = vop2_data->max_input.height;

	if (vop2_has_feature(win->vop2, VOP_FEATURE_SPLICE)) {
		if (mode->hdisplay > VOP2_MAX_VP_OUTPUT_WIDTH) {
			vcstate->splice_mode = true;
			ret = vop2_plane_splice_check(plane, state, mode);
			if (ret < 0)
				return ret;
			splice_win = vop2_find_win_by_phys_id(vop2, win->splice_win_id);
			splice_win->splice_mode_right = true;
			splice_win->left_win = win;
			win->splice_win = splice_win;
			max_input_w <<= 1;
		}
	}

	vpstate->xmirror_en = (state->rotation & DRM_MODE_REFLECT_X) ? 1 : 0;
	vpstate->ymirror_en = (state->rotation & DRM_MODE_REFLECT_Y) ? 1 : 0;
	vpstate->rotate_270_en = (state->rotation & DRM_MODE_ROTATE_270) ? 1 : 0;
	vpstate->rotate_90_en = (state->rotation & DRM_MODE_ROTATE_90) ? 1 : 0;

	if (vpstate->rotate_270_en && vpstate->rotate_90_en) {
		DRM_ERROR("Can't rotate 90 and 270 at the same time\n");
		return -EINVAL;
	}

	ret = drm_atomic_helper_check_plane_state(state, cstate,
						  min_scale, max_scale,
						  true, true);
	if (ret)
		return ret;

	if (!state->visible) {
		DRM_ERROR("%s is invisible(src: pos[%d, %d] rect[%d x %d] dst: pos[%d, %d] rect[%d x %d]\n",
			  plane->name, state->src_x >> 16, state->src_y >> 16, state->src_w >> 16,
			  state->src_h >> 16, state->crtc_x, state->crtc_y, state->crtc_w,
			  state->crtc_h);
		return 0;
	}

	src->x1 = state->src.x1;
	src->y1 = state->src.y1;
	src->x2 = state->src.x2;
	src->y2 = state->src.y2;
	dest->x1 = state->dst.x1;
	dest->y1 = state->dst.y1;
	dest->x2 = state->dst.x2;
	dest->y2 = state->dst.y2;

	vpstate->zpos = state->zpos;
	vpstate->global_alpha = state->alpha >> 8;
	vpstate->blend_mode = state->pixel_blend_mode;
	vpstate->format = vop2_convert_format(fb->format->format);
	if (vpstate->format < 0)
		return vpstate->format;

	if (drm_rect_width(src) >> 16 < 4 || drm_rect_height(src) >> 16 < 4 ||
	    drm_rect_width(dest) < 4 || drm_rect_width(dest) < 4) {
		DRM_ERROR("Invalid size: %dx%d->%dx%d, min size is 4x4\n",
			  drm_rect_width(src) >> 16, drm_rect_height(src) >> 16,
			  drm_rect_width(dest), drm_rect_height(dest));
		state->visible = false;
		return 0;
	}

	if (drm_rect_width(src) >> 16 > max_input_w ||
	    drm_rect_height(src) >> 16 > max_input_h) {
		DRM_ERROR("Invalid source: %dx%d. max input: %dx%d\n",
			  drm_rect_width(src) >> 16,
			  drm_rect_height(src) >> 16,
			  max_input_w,
			  max_input_h);
		return -EINVAL;
	}

	if (rockchip_afbc(plane, fb->modifier))
		vpstate->afbc_en = true;
	else
		vpstate->afbc_en = false;

	/*
	 * This is special feature at rk356x, the cluster layer only can support
	 * afbc format and can't support linear format;
	 */
	if (vp->vop2->version == VOP_VERSION_RK3568) {
		if (vop2_cluster_window(win) && !vpstate->afbc_en) {
			DRM_ERROR("Unsupported linear format at %s\n", win->name);
			return -EINVAL;
		}
	}

	if (vp->vop2->version > VOP_VERSION_RK3568) {
		if (vop2_cluster_window(win) && !vpstate->afbc_en && fb->format->is_yuv) {
			DRM_ERROR("Unsupported linear yuv format at %s\n", win->name);
			return -EINVAL;
		}

		if (vop2_cluster_window(win) && !vpstate->afbc_en &&
		    (win->supported_rotations & state->rotation)) {
			DRM_ERROR("Unsupported linear rotation(%d) format at %s\n",
				  state->rotation, win->name);
			return -EINVAL;
		}
	}

	if (win->feature & WIN_FEATURE_CLUSTER_SUB) {
		ret = vop2_cluster_two_win_mode_check(state);
		if (ret < 0)
			return ret;
	}

	/*
	 * Src.x1 can be odd when do clip, but yuv plane start point
	 * need align with 2 pixel.
	 */
	if (fb->format->is_yuv && ((state->src.x1 >> 16) % 2)) {
		DRM_ERROR("Invalid Source: Yuv format not support odd xpos\n");
		return -EINVAL;
	}

	offset = (src->x1 >> 16) * fb->format->cpp[0];
	vpstate->offset = offset + fb->offsets[0];

	/*
	 * AFBC HDR_PTR must set to the zero offset of the framebuffer.
	 */
	if (vpstate->afbc_en)
		offset = 0;
	else if (vpstate->ymirror_en)

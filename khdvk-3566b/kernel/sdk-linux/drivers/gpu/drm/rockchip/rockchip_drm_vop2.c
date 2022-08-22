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

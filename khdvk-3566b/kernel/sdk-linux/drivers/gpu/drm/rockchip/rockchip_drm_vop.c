// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) Fuzhou Rockchip Electronics Co.Ltd
 * Author:Mark Yao <mark.yao@rock-chips.com>
 */

#include <linux/clk.h>
#include <linux/component.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/fixp-arith.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/overflow.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/sort.h>

#include <drm/drm.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_uapi.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_debugfs.h>
#include <drm/drm_flip_work.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_self_refresh_helper.h>
#include <drm/drm_vblank.h>

#ifdef CONFIG_DRM_ANALOGIX_DP
#include <drm/bridge/analogix_dp.h>
#endif
#include <dt-bindings/soc/rockchip-system-status.h>

#include <soc/rockchip/rockchip_dmc.h>
#include <soc/rockchip/rockchip-system-status.h>
#include <uapi/linux/videodev2.h>
#include "../drm_crtc_internal.h"

#include "rockchip_drm_drv.h"
#include "rockchip_drm_gem.h"
#include "rockchip_drm_fb.h"
#include "rockchip_drm_vop.h"
#include "rockchip_rgb.h"

#define VOP_REG_SUPPORT(vop, reg) \
		(reg.mask && \
		 (!reg.major || \
		  (reg.major == VOP_MAJOR(vop->version) && \
		   reg.begin_minor <= VOP_MINOR(vop->version) && \
		   reg.end_minor >= VOP_MINOR(vop->version))))

#define VOP_WIN_SUPPORT(vop, win, name) \
		VOP_REG_SUPPORT(vop, win->phy->name)

#define VOP_WIN_SCL_EXT_SUPPORT(vop, win, name) \
		(win->phy->scl->ext && \
		VOP_REG_SUPPORT(vop, win->phy->scl->ext->name))

#define VOP_CTRL_SUPPORT(vop, name) \
		VOP_REG_SUPPORT(vop, vop->data->ctrl->name)

#define VOP_INTR_SUPPORT(vop, name) \
		VOP_REG_SUPPORT(vop, vop->data->intr->name)

#define __REG_SET(x, off, mask, shift, v, write_mask, relaxed) \
		vop_mask_write(x, off, mask, shift, v, write_mask, relaxed)

#define _REG_SET(vop, name, off, reg, mask, v, relaxed) \
	do { \
		if (VOP_REG_SUPPORT(vop, reg)) \
			__REG_SET(vop, off + reg.offset, mask, reg.shift, \
				  v, reg.write_mask, relaxed); \
		else \
			dev_dbg(vop->dev, "Warning: not support "#name"\n"); \
	} while (0)

#define REG_SET(x, name, off, reg, v, relaxed) \
		_REG_SET(x, name, off, reg, reg.mask, v, relaxed)
#define REG_SET_MASK(x, name, off, reg, mask, v, relaxed) \
		_REG_SET(x, name, off, reg, reg.mask & mask, v, relaxed)

#define VOP_WIN_SET(x, win, name, v) \
		REG_SET(x, name, win->offset, VOP_WIN_NAME(win, name), v, true)
#define VOP_WIN_SET_EXT(x, win, ext, name, v) \
		REG_SET(x, name, 0, win->ext->name, v, true)
#define VOP_SCL_SET(x, win, name, v) \
		REG_SET(x, name, win->offset, win->phy->scl->name, v, true)
#define VOP_SCL_SET_EXT(x, win, name, v) \
		REG_SET(x, name, win->offset, win->phy->scl->ext->name, v, true)

#define VOP_CTRL_SET(x, name, v) \
		REG_SET(x, name, 0, (x)->data->ctrl->name, v, false)

#define VOP_INTR_GET(vop, name) \
		vop_read_reg(vop, 0, &vop->data->ctrl->name)

#define VOP_INTR_SET(vop, name, v) \
		REG_SET(vop, name, 0, vop->data->intr->name, \
			v, false)
#define VOP_INTR_SET_MASK(vop, name, mask, v) \
		REG_SET_MASK(vop, name, 0, vop->data->intr->name, \
			     mask, v, false)


#define VOP_REG_SET(vop, group, name, v) \
		    vop_reg_set(vop, &vop->data->group->name, 0, ~0, v, #name)

#define VOP_INTR_SET_TYPE(vop, name, type, v) \
	do { \
		int i, reg = 0, mask = 0; \
		for (i = 0; i < vop->data->intr->nintrs; i++) { \
			if (vop->data->intr->intrs[i] & type) { \
				reg |= (v) << i; \
				mask |= 1 << i; \
			} \
		} \
		VOP_INTR_SET_MASK(vop, name, mask, reg); \
	} while (0)
#define VOP_INTR_GET_TYPE(vop, name, type) \
		vop_get_intr_type(vop, &vop->data->intr->name, type)

#define VOP_CTRL_GET(x, name) \
		vop_read_reg(x, 0, &vop->data->ctrl->name)

#define VOP_WIN_GET(vop, win, name) \
		vop_read_reg(vop, win->offset, &VOP_WIN_NAME(win, name))

#define VOP_WIN_NAME(win, name) \
		(vop_get_win_phy(win, &win->phy->name)->name)

#define VOP_WIN_TO_INDEX(vop_win) \
	((vop_win) - (vop_win)->vop->win)

#define VOP_GRF_SET(vop, reg, v) \
	do { \
		if (vop->data->grf_ctrl) { \
			vop_grf_writel(vop, vop->data->grf_ctrl->reg, v); \
		} \
	} while (0)

#define to_vop_win(x) container_of(x, struct vop_win, base)
#define to_vop_plane_state(x) container_of(x, struct vop_plane_state, base)

enum vop_pending {
	VOP_PENDING_FB_UNREF,
};

struct vop_zpos {
	int win_id;
	int zpos;
};

struct vop_plane_state {
	struct drm_plane_state base;
	int format;
	int zpos;
	struct drm_rect src;
	struct drm_rect dest;
	dma_addr_t yrgb_mst;
	dma_addr_t uv_mst;
	const uint32_t *y2r_table;
	const uint32_t *r2r_table;
	const uint32_t *r2y_table;
	int eotf;
	bool y2r_en;
	bool r2r_en;
	bool r2y_en;
	int color_space;
	u32 color_key;
	unsigned int csc_mode;
	int global_alpha;
	int blend_mode;
	unsigned long offset;
	int pdaf_data_type;
	bool async_commit;
	struct vop_dump_list *planlist;
};

struct rockchip_mcu_timing {
	int mcu_pix_total;
	int mcu_cs_pst;
	int mcu_cs_pend;
	int mcu_rw_pst;
	int mcu_rw_pend;
	int mcu_hold_mode;
};

struct vop_win {
	struct vop_win *parent;
	struct drm_plane base;

	int win_id;
	int area_id;
	u8 plane_id; /* unique plane id */
	const char *name;

	int zpos;
	uint32_t offset;
	enum drm_plane_type type;
	const struct vop_win_phy *phy;
	const struct vop_csc *csc;
	const uint32_t *data_formats;
	uint32_t nformats;
	const uint64_t *format_modifiers;
	u64 feature;
	struct vop *vop;
	struct vop_plane_state state;

	struct drm_property *input_width_prop;
	struct drm_property *input_height_prop;
	struct drm_property *output_width_prop;
	struct drm_property *output_height_prop;
	struct drm_property *color_key_prop;
	struct drm_property *scale_prop;
	struct drm_property *name_prop;
};

struct vop {
	struct rockchip_crtc rockchip_crtc;
	struct device *dev;
	struct drm_device *drm_dev;
	struct dentry *debugfs;
	struct drm_info_list *debugfs_files;
	struct drm_property *plane_feature_prop;
	struct drm_property *plane_mask_prop;
	struct drm_property *feature_prop;

	bool is_iommu_enabled;
	bool is_iommu_needed;
	bool is_enabled;
	bool support_multi_area;

	u32 version;
	u32 background;
	u32 line_flag;
	u8 id;
	u8 plane_mask;
	u64 soc_id;
	struct drm_prop_enum_list *plane_name_list;

	struct drm_tv_connector_state active_tv_state;
	bool pre_overlay;
	bool loader_protect;
	struct completion dsp_hold_completion;

	/* protected by dev->event_lock */
	struct drm_pending_vblank_event *event;

	struct drm_flip_work fb_unref_work;
	unsigned long pending;

	struct completion line_flag_completion;

	const struct vop_data *data;
	int num_wins;

	uint32_t *regsbak;
	void __iomem *regs;
	struct regmap *grf;

	/* physical map length of vop register */
	uint32_t len;

	void __iomem *lut_regs;
	u32 *lut;
	u32 lut_len;
	bool lut_active;
	/* gamma look up table */
	struct drm_color_lut *gamma_lut;
	bool dual_channel_swap;
	/* one time only one process allowed to config the register */
	spinlock_t reg_lock;
	/* lock vop irq reg */
	spinlock_t irq_lock;
	/* protects crtc enable/disable */
	struct mutex vop_lock;

	unsigned int irq;

	/* vop AHP clk */
	struct clk *hclk;
	/* vop dclk */
	struct clk *dclk;
	/* vop share memory frequency */
	struct clk *aclk;
	/* vop source handling, optional */
	struct clk *dclk_source;

	/* vop dclk reset */
	struct reset_control *dclk_rst;

	struct rockchip_dclk_pll *pll;

	struct rockchip_mcu_timing mcu_timing;

	struct vop_win win[];
};

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
};

static DRM_ENUM_NAME_FN(drm_get_bus_format_name, drm_bus_format_enum_list)

static inline struct vop *to_vop(struct drm_crtc *crtc)
{
	struct rockchip_crtc *rockchip_crtc;

	rockchip_crtc = container_of(crtc, struct rockchip_crtc, crtc);

	return container_of(rockchip_crtc, struct vop, rockchip_crtc);
}

static void vop_lock(struct vop *vop)
{
	mutex_lock(&vop->vop_lock);
	rockchip_dmcfreq_lock();
}

static void vop_unlock(struct vop *vop)
{
	rockchip_dmcfreq_unlock();
	mutex_unlock(&vop->vop_lock);
}

static inline void vop_grf_writel(struct vop *vop, struct vop_reg reg, u32 v)
{
	u32 val = 0;

	if (IS_ERR_OR_NULL(vop->grf))
		return;

	if (VOP_REG_SUPPORT(vop, reg)) {
		val = (v << reg.shift) | (reg.mask << (reg.shift + 16));
		regmap_write(vop->grf, reg.offset, val);
	}
}

static inline void vop_writel(struct vop *vop, uint32_t offset, uint32_t v)
{
	writel(v, vop->regs + offset);
	vop->regsbak[offset >> 2] = v;
}

static inline uint32_t vop_readl(struct vop *vop, uint32_t offset)
{
	return readl(vop->regs + offset);
}

static inline uint32_t vop_read_reg(struct vop *vop, uint32_t base,
				    const struct vop_reg *reg)
{
	return (vop_readl(vop, base + reg->offset) >> reg->shift) & reg->mask;
}

static inline void vop_mask_write(struct vop *vop, uint32_t offset,
				  uint32_t mask, uint32_t shift, uint32_t v,
				  bool write_mask, bool relaxed)
{
	if (!mask)
		return;

	if (write_mask) {
		v = ((v & mask) << shift) | (mask << (shift + 16));
	} else {
		uint32_t cached_val = vop->regsbak[offset >> 2];

		v = (cached_val & ~(mask << shift)) | ((v & mask) << shift);
		vop->regsbak[offset >> 2] = v;
	}

	if (relaxed)
		writel_relaxed(v, vop->regs + offset);
	else
		writel(v, vop->regs + offset);
}

static inline const struct vop_win_phy *
vop_get_win_phy(struct vop_win *win, const struct vop_reg *reg)
{
	if (!reg->mask && win->parent)
		return win->parent->phy;

	return win->phy;
}

static inline uint32_t vop_get_intr_type(struct vop *vop,
					 const struct vop_reg *reg, int type)
{
	uint32_t i, ret = 0;
	uint32_t regs = vop_read_reg(vop, 0, reg);

	for (i = 0; i < vop->data->intr->nintrs; i++) {
		if ((type & vop->data->intr->intrs[i]) && (regs & 1 << i))
			ret |= vop->data->intr->intrs[i];
	}

	return ret;
}

static void vop_load_hdr2sdr_table(struct vop *vop)
{
	int i;
	const struct vop_hdr_table *table = vop->data->hdr_table;
	uint32_t hdr2sdr_eetf_oetf_yn[33];

	for (i = 0; i < 33; i++)
		hdr2sdr_eetf_oetf_yn[i] = table->hdr2sdr_eetf_yn[i] +
				(table->hdr2sdr_bt1886oetf_yn[i] << 16);

	vop_writel(vop, table->hdr2sdr_eetf_oetf_y0_offset,
		   hdr2sdr_eetf_oetf_yn[0]);
	for (i = 1; i < 33; i++)
		vop_writel(vop,
			   table->hdr2sdr_eetf_oetf_y1_offset + (i - 1) * 4,
			   hdr2sdr_eetf_oetf_yn[i]);

	vop_writel(vop, table->hdr2sdr_sat_y0_offset,
		   table->hdr2sdr_sat_yn[0]);
	for (i = 1; i < 9; i++)
		vop_writel(vop, table->hdr2sdr_sat_y1_offset + (i - 1) * 4,
			   table->hdr2sdr_sat_yn[i]);

	VOP_CTRL_SET(vop, hdr2sdr_src_min, table->hdr2sdr_src_range_min);
	VOP_CTRL_SET(vop, hdr2sdr_src_max, table->hdr2sdr_src_range_max);
	VOP_CTRL_SET(vop, hdr2sdr_normfaceetf, table->hdr2sdr_normfaceetf);
	VOP_CTRL_SET(vop, hdr2sdr_dst_min, table->hdr2sdr_dst_range_min);
	VOP_CTRL_SET(vop, hdr2sdr_dst_max, table->hdr2sdr_dst_range_max);
	VOP_CTRL_SET(vop, hdr2sdr_normfacgamma, table->hdr2sdr_normfacgamma);
}

static void vop_load_sdr2hdr_table(struct vop *vop, uint32_t cmd)
{
	int i;
	const struct vop_hdr_table *table = vop->data->hdr_table;
	uint32_t sdr2hdr_eotf_oetf_yn[65];
	uint32_t sdr2hdr_oetf_dx_dxpow[64];

	for (i = 0; i < 65; i++) {
		if (cmd == SDR2HDR_FOR_BT2020)
			sdr2hdr_eotf_oetf_yn[i] =
				table->sdr2hdr_bt1886eotf_yn_for_bt2020[i] +
				(table->sdr2hdr_st2084oetf_yn_for_bt2020[i] << 18);
		else if (cmd == SDR2HDR_FOR_HDR)
			sdr2hdr_eotf_oetf_yn[i] =
				table->sdr2hdr_bt1886eotf_yn_for_hdr[i] +
				(table->sdr2hdr_st2084oetf_yn_for_hdr[i] << 18);
		else if (cmd == SDR2HDR_FOR_HLG_HDR)
			sdr2hdr_eotf_oetf_yn[i] =
				table->sdr2hdr_bt1886eotf_yn_for_hlg_hdr[i] +
				(table->sdr2hdr_st2084oetf_yn_for_hlg_hdr[i] << 18);
	}
	vop_writel(vop, table->sdr2hdr_eotf_oetf_y0_offset,
		   sdr2hdr_eotf_oetf_yn[0]);
	for (i = 1; i < 65; i++)
		vop_writel(vop, table->sdr2hdr_eotf_oetf_y1_offset +
			   (i - 1) * 4, sdr2hdr_eotf_oetf_yn[i]);

	for (i = 0; i < 64; i++) {
		sdr2hdr_oetf_dx_dxpow[i] = table->sdr2hdr_st2084oetf_dxn[i] +
				(table->sdr2hdr_st2084oetf_dxn_pow2[i] << 16);
		vop_writel(vop, table->sdr2hdr_oetf_dx_dxpow1_offset + i * 4,
			   sdr2hdr_oetf_dx_dxpow[i]);
	}

	for (i = 0; i < 63; i++)
		vop_writel(vop, table->sdr2hdr_oetf_xn1_offset + i * 4,
			   table->sdr2hdr_st2084oetf_xn[i]);
}

static void vop_load_csc_table(struct vop *vop, u32 offset, const u32 *table)
{
	int i;

	/*
	 * so far the csc offset is not 0 and in the feature the csc offset
	 * impossible be 0, so when the offset is 0, should return here.
	 */
	if (!table || offset == 0)
		return;

	for (i = 0; i < 8; i++)
		vop_writel(vop, offset + i * 4, table[i]);
}

static inline void vop_cfg_done(struct vop *vop)
{
	VOP_CTRL_SET(vop, cfg_done, 1);
}

static bool vop_is_allwin_disabled(struct vop *vop)
{
	int i;

	for (i = 0; i < vop->num_wins; i++) {
		struct vop_win *win = &vop->win[i];

		if (VOP_WIN_GET(vop, win, enable) != 0)
			return false;
	}

	return true;
}

static void vop_win_disable(struct vop *vop, struct vop_win *win)
{
	/*
	 * FIXUP: some of the vop scale would be abnormal after windows power
	 * on/off so deinit scale to scale_none mode.
	 */
	if (win->phy->scl && win->phy->scl->ext) {
		VOP_SCL_SET_EXT(vop, win, yrgb_hor_scl_mode, SCALE_NONE);
		VOP_SCL_SET_EXT(vop, win, yrgb_ver_scl_mode, SCALE_NONE);
		VOP_SCL_SET_EXT(vop, win, cbcr_hor_scl_mode, SCALE_NONE);
		VOP_SCL_SET_EXT(vop, win, cbcr_ver_scl_mode, SCALE_NONE);
	}

	VOP_WIN_SET(vop, win, enable, 0);
	if (win->area_id == 0)
		VOP_WIN_SET(vop, win, gate, 0);
}

static void vop_disable_allwin(struct vop *vop)
{
	int i;

	for (i = 0; i < vop->num_wins; i++) {
		struct vop_win *win = &vop->win[i];

		vop_win_disable(vop, win);
	}
}

static inline void vop_write_lut(struct vop *vop, uint32_t offset, uint32_t v)
{
	writel(v, vop->lut_regs + offset);
}

static inline uint32_t vop_read_lut(struct vop *vop, uint32_t offset)
{
	return readl(vop->lut_regs + offset);
}

static bool has_rb_swapped(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
	case DRM_FORMAT_BGR888:
	case DRM_FORMAT_BGR565:
		return true;
	default:
		return false;
	}
}

static enum vop_data_format vop_convert_format(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
		return VOP_FMT_ARGB8888;
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
		return VOP_FMT_RGB888;
	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_BGR565:
		return VOP_FMT_RGB565;
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV15:
		return VOP_FMT_YUV420SP;
	case DRM_FORMAT_NV16:
	case DRM_FORMAT_NV20:
		return VOP_FMT_YUV422SP;
	case DRM_FORMAT_NV24:
	case DRM_FORMAT_NV30:
		return VOP_FMT_YUV444SP;
	case DRM_FORMAT_YVYU:
	case DRM_FORMAT_VYUY:
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_UYVY:
		return VOP_FMT_YUYV;
	default:
		DRM_ERROR("unsupported format[%08x]\n", format);
		return -EINVAL;
	}
}

static bool is_uv_swap(uint32_t bus_format, uint32_t output_mode)
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

static bool is_yc_swap(uint32_t bus_format)
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

static bool is_yuv_output(uint32_t bus_format)
{
	switch (bus_format) {
	case MEDIA_BUS_FMT_YUV8_1X24:
	case MEDIA_BUS_FMT_YUV10_1X30:
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

static bool is_yuv_support(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_NV12:
	case DRM_FORMAT_NV15:
	case DRM_FORMAT_NV16:
	case DRM_FORMAT_NV20:
	case DRM_FORMAT_NV24:
	case DRM_FORMAT_NV30:
	case DRM_FORMAT_YVYU:
	case DRM_FORMAT_VYUY:
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_UYVY:
		return true;
	default:
		return false;
	}
}

static bool is_yuyv_format(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_YVYU:
	case DRM_FORMAT_VYUY:
	case DRM_FORMAT_YUYV:
	case DRM_FORMAT_UYVY:
		return true;
	default:
		return false;
	}
}

static bool is_yuv_10bit(uint32_t format)
{
	switch (format) {
	case DRM_FORMAT_NV15:
	case DRM_FORMAT_NV20:
	case DRM_FORMAT_NV30:
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

static uint16_t scl_vop_cal_scale(enum scale_mode mode, uint32_t src,
				  uint32_t dst, bool is_horizontal,
				  int vsu_mode, int *vskiplines)
{
	uint16_t val = 1 << SCL_FT_DEFAULT_FIXPOINT_SHIFT;

	if (vskiplines)
		*vskiplines = 0;

	if (is_horizontal) {
		if (mode == SCALE_UP)
			val = GET_SCL_FT_BIC(src, dst);
		else if (mode == SCALE_DOWN)
			val = GET_SCL_FT_BILI_DN(src, dst);
	} else {
		if (mode == SCALE_UP) {
			if (vsu_mode == SCALE_UP_BIL)
				val = GET_SCL_FT_BILI_UP(src, dst);
			else
				val = GET_SCL_FT_BIC(src, dst);
		} else if (mode == SCALE_DOWN) {
			if (vskiplines) {
				*vskiplines = scl_get_vskiplines(src, dst);
				val = scl_get_bili_dn_vskip(src, dst,
							    *vskiplines);
			} else {
				val = GET_SCL_FT_BILI_DN(src, dst);
			}
		}
	}

	return val;
}

static void scl_vop_cal_scl_fac(struct vop *vop, const struct vop_win *win,
				uint32_t src_w, uint32_t src_h, uint32_t dst_w,
				uint32_t dst_h, uint32_t pixel_format)
{
	uint16_t yrgb_hor_scl_mode, yrgb_ver_scl_mode;
	uint16_t cbcr_hor_scl_mode = SCALE_NONE;
	uint16_t cbcr_ver_scl_mode = SCALE_NONE;
	const struct drm_format_info *info = drm_format_info(pixel_format);
	uint8_t hsub = info->hsub;
	uint8_t vsub = info->vsub;
	bool is_yuv = false;
	uint16_t cbcr_src_w = src_w / hsub;
	uint16_t cbcr_src_h = src_h / vsub;
	uint16_t vsu_mode;
	uint16_t lb_mode;
	uint32_t val;
	const struct vop_data *vop_data = vop->data;
	int vskiplines;

	if (!win->phy->scl)
		return;

	if (!(vop_data->feature & VOP_FEATURE_ALPHA_SCALE)) {
		if (is_alpha_support(pixel_format) &&
		    (src_w != dst_w || src_h != dst_h))
			DRM_ERROR("ERROR: unsupported ppixel alpha&scale\n");
	}

	if (info->is_yuv)
		is_yuv = true;

	if (!win->phy->scl->ext) {
		VOP_SCL_SET(vop, win, scale_yrgb_x,
			    scl_cal_scale2(src_w, dst_w));
		VOP_SCL_SET(vop, win, scale_yrgb_y,
			    scl_cal_scale2(src_h, dst_h));
		if (is_yuv) {
			VOP_SCL_SET(vop, win, scale_cbcr_x,
				    scl_cal_scale2(cbcr_src_w, dst_w));
			VOP_SCL_SET(vop, win, scale_cbcr_y,
				    scl_cal_scale2(cbcr_src_h, dst_h));
		}
		return;
	}

	yrgb_hor_scl_mode = scl_get_scl_mode(src_w, dst_w);
	yrgb_ver_scl_mode = scl_get_scl_mode(src_h, dst_h);

	if (is_yuv) {
		cbcr_hor_scl_mode = scl_get_scl_mode(cbcr_src_w, dst_w);
		cbcr_ver_scl_mode = scl_get_scl_mode(cbcr_src_h, dst_h);
		if (cbcr_hor_scl_mode == SCALE_DOWN)
			lb_mode = scl_vop_cal_lb_mode(dst_w, true);
		else
			lb_mode = scl_vop_cal_lb_mode(cbcr_src_w, true);
	} else {
		if (yrgb_hor_scl_mode == SCALE_DOWN)
			lb_mode = scl_vop_cal_lb_mode(dst_w, false);
		else
			lb_mode = scl_vop_cal_lb_mode(src_w, false);
	}

	VOP_SCL_SET_EXT(vop, win, lb_mode, lb_mode);
	if (lb_mode == LB_RGB_3840X2) {
		if (yrgb_ver_scl_mode != SCALE_NONE) {
			DRM_DEV_ERROR(vop->dev, "not allow yrgb ver scale\n");
			return;
		}
		if (cbcr_ver_scl_mode != SCALE_NONE) {
			DRM_DEV_ERROR(vop->dev, "not allow cbcr ver scale\n");
			return;
		}
		vsu_mode = SCALE_UP_BIL;
	} else if (lb_mode == LB_RGB_2560X4) {
		vsu_mode = SCALE_UP_BIL;
	} else {
		vsu_mode = SCALE_UP_BIC;
	}

	val = scl_vop_cal_scale(yrgb_hor_scl_mode, src_w, dst_w,
				true, 0, NULL);
	VOP_SCL_SET(vop, win, scale_yrgb_x, val);
	val = scl_vop_cal_scale(yrgb_ver_scl_mode, src_h, dst_h,
				false, vsu_mode, &vskiplines);
	VOP_SCL_SET(vop, win, scale_yrgb_y, val);

	VOP_SCL_SET_EXT(vop, win, vsd_yrgb_gt4, vskiplines == 4);
	VOP_SCL_SET_EXT(vop, win, vsd_yrgb_gt2, vskiplines == 2);

	VOP_SCL_SET_EXT(vop, win, yrgb_hor_scl_mode, yrgb_hor_scl_mode);
	VOP_SCL_SET_EXT(vop, win, yrgb_ver_scl_mode, yrgb_ver_scl_mode);
	VOP_SCL_SET_EXT(vop, win, yrgb_hsd_mode, SCALE_DOWN_BIL);
	VOP_SCL_SET_EXT(vop, win, yrgb_vsd_mode, SCALE_DOWN_BIL);
	VOP_SCL_SET_EXT(vop, win, yrgb_vsu_mode, vsu_mode);
	if (is_yuv) {
		val = scl_vop_cal_scale(cbcr_hor_scl_mode, cbcr_src_w,
					dst_w, true, 0, NULL);
		VOP_SCL_SET(vop, win, scale_cbcr_x, val);
		val = scl_vop_cal_scale(cbcr_ver_scl_mode, cbcr_src_h,
					dst_h, false, vsu_mode, &vskiplines);
		VOP_SCL_SET(vop, win, scale_cbcr_y, val);

		VOP_SCL_SET_EXT(vop, win, vsd_cbcr_gt4, vskiplines == 4);
		VOP_SCL_SET_EXT(vop, win, vsd_cbcr_gt2, vskiplines == 2);
		VOP_SCL_SET_EXT(vop, win, cbcr_hor_scl_mode, cbcr_hor_scl_mode);
		VOP_SCL_SET_EXT(vop, win, cbcr_ver_scl_mode, cbcr_ver_scl_mode);
		VOP_SCL_SET_EXT(vop, win, cbcr_hsd_mode, SCALE_DOWN_BIL);
		VOP_SCL_SET_EXT(vop, win, cbcr_vsd_mode, SCALE_DOWN_BIL);
		VOP_SCL_SET_EXT(vop, win, cbcr_vsu_mode, vsu_mode);
	}
}

/*
 * rk3328 HDR/CSC path
 *
 * HDR/SDR --> win0  --> HDR2SDR ----\
 *		  \		      MUX --\
 *                 \ --> SDR2HDR/CSC--/      \
 *                                            \
 * SDR --> win1 -->pre_overlay ->SDR2HDR/CSC --> post_ovrlay-->post CSC-->output
 * SDR --> win2 -/
 *
 */

static int vop_hdr_atomic_check(struct drm_crtc *crtc,
				struct drm_crtc_state *crtc_state)
{
	struct drm_atomic_state *state = crtc_state->state;
	struct rockchip_crtc_state *s = to_rockchip_crtc_state(crtc_state);
	struct drm_plane_state *pstate;
	struct drm_plane *plane;
	struct vop *vop = to_vop(crtc);
	int pre_sdr2hdr_state = 0, post_sdr2hdr_state = 0;
	int pre_sdr2hdr_mode = 0, post_sdr2hdr_mode = 0, sdr2hdr_func = 0;
	bool pre_overlay = false;
	int hdr2sdr_en = 0, plane_id = 0;

	if (!vop->data->hdr_table)
		return 0;
	/* hdr cover */
	drm_atomic_crtc_state_for_each_plane(plane, crtc_state) {
		struct vop_plane_state *vop_plane_state;
		struct vop_win *win = to_vop_win(plane);

		pstate = drm_atomic_get_plane_state(state, plane);
		if (IS_ERR(pstate))
			return PTR_ERR(pstate);
		vop_plane_state = to_vop_plane_state(pstate);
		if (!pstate->fb)
			continue;

		if (vop_plane_state->eotf > s->eotf)
			if (win->feature & WIN_FEATURE_HDR2SDR)
				hdr2sdr_en = 1;
		if (vop_plane_state->eotf < s->eotf) {
			if (win->feature & WIN_FEATURE_PRE_OVERLAY)
				pre_sdr2hdr_state |= BIT(plane_id);
			else
				post_sdr2hdr_state |= BIT(plane_id);
		}
		plane_id++;
	}

	if (pre_sdr2hdr_state || post_sdr2hdr_state || hdr2sdr_en) {
		pre_overlay = true;
		pre_sdr2hdr_mode = BT709_TO_BT2020;
		post_sdr2hdr_mode = BT709_TO_BT2020;
		sdr2hdr_func = SDR2HDR_FOR_HDR;
		goto exit_hdr_convert;
	}

	/* overlay mode */
	plane_id = 0;
	pre_overlay = false;
	pre_sdr2hdr_mode = 0;
	post_sdr2hdr_mode = 0;
	pre_sdr2hdr_state = 0;
	post_sdr2hdr_state = 0;
	drm_atomic_crtc_state_for_each_plane(plane, crtc_state) {
		struct vop_plane_state *vop_plane_state;
		struct vop_win *win = to_vop_win(plane);

		pstate = drm_atomic_get_plane_state(state, plane);
		if (IS_ERR(pstate))
			return PTR_ERR(pstate);
		vop_plane_state = to_vop_plane_state(pstate);
		if (!pstate->fb)
			continue;

		if (vop_plane_state->color_space == V4L2_COLORSPACE_BT2020 &&
		    vop_plane_state->color_space > s->color_space) {
			if (win->feature & WIN_FEATURE_PRE_OVERLAY) {
				pre_sdr2hdr_mode = BT2020_TO_BT709;
				pre_sdr2hdr_state |= BIT(plane_id);
			} else {
				post_sdr2hdr_mode = BT2020_TO_BT709;
				post_sdr2hdr_state |= BIT(plane_id);
			}
		}
		if (s->color_space == V4L2_COLORSPACE_BT2020 &&
		    vop_plane_state->color_space < s->color_space) {
			if (win->feature & WIN_FEATURE_PRE_OVERLAY) {
				pre_sdr2hdr_mode = BT709_TO_BT2020;
				pre_sdr2hdr_state |= BIT(plane_id);
			} else {
				post_sdr2hdr_mode = BT709_TO_BT2020;
				post_sdr2hdr_state |= BIT(plane_id);
			}
		}
		plane_id++;
	}

	if (pre_sdr2hdr_state || post_sdr2hdr_state) {
		pre_overlay = true;
		sdr2hdr_func = SDR2HDR_FOR_BT2020;
	}

exit_hdr_convert:
	s->hdr.pre_overlay = pre_overlay;
	s->hdr.hdr2sdr_en = hdr2sdr_en;
	if (s->hdr.pre_overlay)
		s->yuv_overlay = 0;

	s->hdr.sdr2hdr_state.bt1886eotf_pre_conv_en = !!pre_sdr2hdr_state;
	s->hdr.sdr2hdr_state.rgb2rgb_pre_conv_en = !!pre_sdr2hdr_state;
	s->hdr.sdr2hdr_state.rgb2rgb_pre_conv_mode = pre_sdr2hdr_mode;
	s->hdr.sdr2hdr_state.st2084oetf_pre_conv_en = !!pre_sdr2hdr_state;

	s->hdr.sdr2hdr_state.bt1886eotf_post_conv_en = !!post_sdr2hdr_state;
	s->hdr.sdr2hdr_state.rgb2rgb_post_conv_en = !!post_sdr2hdr_state;
	s->hdr.sdr2hdr_state.rgb2rgb_post_conv_mode = post_sdr2hdr_mode;
	s->hdr.sdr2hdr_state.st2084oetf_post_conv_en = !!post_sdr2hdr_state;
	s->hdr.sdr2hdr_state.sdr2hdr_func = sdr2hdr_func;

	return 0;
}

static int to_vop_csc_mode(int csc_mode)
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

static void vop_disable_all_planes(struct vop *vop)
{
	bool active;
	int ret;

	vop_disable_allwin(vop);
	vop_cfg_done(vop);
	ret = readx_poll_timeout_atomic(vop_is_allwin_disabled,
					vop, active, active,
					0, 500 * 1000);
	if (ret)
		dev_err(vop->dev, "wait win close timeout\n");
}

/*
 * rk3399 colorspace path:
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
static int vop_setup_csc_table(const struct vop_csc_table *csc_table,
			       bool is_input_yuv, bool is_output_yuv,
			       int input_csc, int output_csc,
			       const uint32_t **y2r_table,
			       const uint32_t **r2r_table,
			       const uint32_t **r2y_table)
{
	*y2r_table = NULL;
	*r2r_table = NULL;
	*r2y_table = NULL;

	if (!csc_table)
		return 0;

	if (is_output_yuv) {
		if (output_csc == V4L2_COLORSPACE_BT2020) {
			if (is_input_yuv) {
				if (input_csc == V4L2_COLORSPACE_BT2020)
					return 0;
				*y2r_table = csc_table->y2r_bt709;
			}
			if (input_csc != V4L2_COLORSPACE_BT2020)
				*r2r_table = csc_table->r2r_bt709_to_bt2020;
			*r2y_table = csc_table->r2y_bt2020;
		} else {
			if (is_input_yuv && input_csc == V4L2_COLORSPACE_BT2020)
				*y2r_table = csc_table->y2r_bt2020;
			if (input_csc == V4L2_COLORSPACE_BT2020)
				*r2r_table = csc_table->r2r_bt2020_to_bt709;
			if (!is_input_yuv || *y2r_table) {
				if (output_csc == V4L2_COLORSPACE_REC709 ||
				    output_csc == V4L2_COLORSPACE_SMPTE240M ||
				    output_csc == V4L2_COLORSPACE_DEFAULT)
					*r2y_table = csc_table->r2y_bt709;
				else if (output_csc == V4L2_COLORSPACE_SMPTE170M ||
					 output_csc == V4L2_COLORSPACE_470_SYSTEM_M ||
					 output_csc == V4L2_COLORSPACE_470_SYSTEM_BG)
					*r2y_table = csc_table->r2y_bt601_12_235; /* bt601 limit */
				else
					*r2y_table = csc_table->r2y_bt601; /* bt601 full */
			}
		}
	} else {
		if (!is_input_yuv)
			return 0;

		/*
		 * is possible use bt2020 on rgb mode?
		 */
		if (WARN_ON(output_csc == V4L2_COLORSPACE_BT2020))
			return -EINVAL;

		if (input_csc == V4L2_COLORSPACE_BT2020)
			*y2r_table = csc_table->y2r_bt2020;
		else if (input_csc == V4L2_COLORSPACE_REC709 ||
			 input_csc == V4L2_COLORSPACE_SMPTE240M ||
			 input_csc == V4L2_COLORSPACE_DEFAULT)
			*y2r_table = csc_table->y2r_bt709;
		else if (input_csc == V4L2_COLORSPACE_SMPTE170M ||
			 input_csc == V4L2_COLORSPACE_470_SYSTEM_M ||
			 input_csc == V4L2_COLORSPACE_470_SYSTEM_BG)
			*y2r_table = csc_table->y2r_bt601_12_235; /* bt601 limit */
		else
			*y2r_table = csc_table->y2r_bt601;  /* bt601 full */

		if (input_csc == V4L2_COLORSPACE_BT2020)
			/*
			 * We don't have bt601 to bt709 table, force use bt709.
			 */
			*r2r_table = csc_table->r2r_bt2020_to_bt709;
	}

	return 0;
}

static void vop_setup_csc_mode(bool is_input_yuv, bool is_output_yuv,
			       int input_csc, int output_csc,
			       bool *y2r_en, bool *r2y_en, int *csc_mode)
{
	if (is_input_yuv && !is_output_yuv) {
		*y2r_en = true;
		*csc_mode =  to_vop_csc_mode(input_csc);
	} else if (!is_input_yuv && is_output_yuv) {
		*r2y_en = true;
		*csc_mode = to_vop_csc_mode(output_csc);
	}
}

static int vop_csc_atomic_check(struct drm_crtc *crtc,
				struct drm_crtc_state *crtc_state)
{
	struct vop *vop = to_vop(crtc);
	struct drm_atomic_state *state = crtc_state->state;
	struct rockchip_crtc_state *s = to_rockchip_crtc_state(crtc_state);
	const struct vop_csc_table *csc_table = vop->data->csc_table;
	struct drm_plane_state *pstate;
	struct drm_plane *plane;
	bool is_input_yuv, is_output_yuv;
	int ret;

	is_output_yuv = is_yuv_output(s->bus_format);

	drm_atomic_crtc_state_for_each_plane(plane, crtc_state) {
		struct vop_plane_state *vop_plane_state;
		struct vop_win *win = to_vop_win(plane);

		pstate = drm_atomic_get_plane_state(state, plane);
		if (IS_ERR(pstate))
			return PTR_ERR(pstate);
		vop_plane_state = to_vop_plane_state(pstate);

		if (!pstate->fb)
			continue;
		is_input_yuv = is_yuv_support(pstate->fb->format->format);
		vop_plane_state->y2r_en = false;
		vop_plane_state->r2r_en = false;
		vop_plane_state->r2y_en = false;

		ret = vop_setup_csc_table(csc_table, is_input_yuv,
					  is_output_yuv,
					  vop_plane_state->color_space,
					  s->color_space,
					  &vop_plane_state->y2r_table,
					  &vop_plane_state->r2r_table,
					  &vop_plane_state->r2y_table);
		if (ret)
			return ret;

		vop_setup_csc_mode(is_input_yuv, s->yuv_overlay,
				   vop_plane_state->color_space, s->color_space,
				   &vop_plane_state->y2r_en,
				   &vop_plane_state->r2y_en,
				   &vop_plane_state->csc_mode);

		if (csc_table) {
			vop_plane_state->y2r_en = !!vop_plane_state->y2r_table;
			vop_plane_state->r2r_en = !!vop_plane_state->r2r_table;
			vop_plane_state->r2y_en = !!vop_plane_state->r2y_table;
			continue;
		}

		/*
		 * This is update for IC design not reasonable, when enable
		 * hdr2sdr on rk3328, vop can't support per-pixel alpha * global
		 * alpha,so we must back to gpu, but gpu can't support hdr2sdr,
		 * gpu output hdr UI, vop will do:
		 * UI(rgbx) -> yuv -> rgb ->hdr2sdr -> overlay -> output.
		 */
		if (s->hdr.hdr2sdr_en &&
		    vop_plane_state->eotf == HDMI_EOTF_SMPTE_ST2084 &&
		    !is_yuv_support(pstate->fb->format->format))
			vop_plane_state->r2y_en = true;
		if (win->feature & WIN_FEATURE_PRE_OVERLAY)
			vop_plane_state->r2r_en =
				s->hdr.sdr2hdr_state.rgb2rgb_pre_conv_en;
		else if (win->feature & WIN_FEATURE_HDR2SDR)
			vop_plane_state->r2r_en =
				s->hdr.sdr2hdr_state.rgb2rgb_post_conv_en;
	}

	return 0;
}

static void vop_enable_debug_irq(struct drm_crtc *crtc)
{
	struct vop *vop = to_vop(crtc);
	uint32_t irqs;

	irqs = BUS_ERROR_INTR | WIN0_EMPTY_INTR | WIN1_EMPTY_INTR |
		WIN2_EMPTY_INTR | WIN3_EMPTY_INTR | HWC_EMPTY_INTR |
		POST_BUF_EMPTY_INTR;
	VOP_INTR_SET_TYPE(vop, clear, irqs, 1);
	VOP_INTR_SET_TYPE(vop, enable, irqs, 1);
}

static void vop_dsp_hold_valid_irq_enable(struct vop *vop)
{
	unsigned long flags;

	if (WARN_ON(!vop->is_enabled))
		return;

	spin_lock_irqsave(&vop->irq_lock, flags);

	VOP_INTR_SET_TYPE(vop, clear, DSP_HOLD_VALID_INTR, 1);
	VOP_INTR_SET_TYPE(vop, enable, DSP_HOLD_VALID_INTR, 1);

	spin_unlock_irqrestore(&vop->irq_lock, flags);
}

static void vop_dsp_hold_valid_irq_disable(struct vop *vop)
{
	unsigned long flags;

	if (WARN_ON(!vop->is_enabled))
		return;

	spin_lock_irqsave(&vop->irq_lock, flags);

	VOP_INTR_SET_TYPE(vop, enable, DSP_HOLD_VALID_INTR, 0);

	spin_unlock_irqrestore(&vop->irq_lock, flags);
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
static bool vop_line_flag_irq_is_enabled(struct vop *vop)
{
	uint32_t line_flag_irq;
	unsigned long flags;

	spin_lock_irqsave(&vop->irq_lock, flags);

	line_flag_irq = VOP_INTR_GET_TYPE(vop, enable, LINE_FLAG_INTR);

	spin_unlock_irqrestore(&vop->irq_lock, flags);

	return !!line_flag_irq;
}

static void vop_line_flag_irq_enable(struct vop *vop)
{
	unsigned long flags;

	if (WARN_ON(!vop->is_enabled))
		return;

	spin_lock_irqsave(&vop->irq_lock, flags);

	VOP_INTR_SET_TYPE(vop, clear, LINE_FLAG_INTR, 1);
	VOP_INTR_SET_TYPE(vop, enable, LINE_FLAG_INTR, 1);

	spin_unlock_irqrestore(&vop->irq_lock, flags);
}

static void vop_line_flag_irq_disable(struct vop *vop)
{
	unsigned long flags;

	if (WARN_ON(!vop->is_enabled))
		return;

	spin_lock_irqsave(&vop->irq_lock, flags);

	VOP_INTR_SET_TYPE(vop, enable, LINE_FLAG_INTR, 0);

	spin_unlock_irqrestore(&vop->irq_lock, flags);
}

static int vop_core_clks_enable(struct vop *vop)
{
	int ret;

	ret = clk_enable(vop->hclk);
	if (ret < 0)
		return ret;

	ret = clk_enable(vop->aclk);
	if (ret < 0)
		goto err_disable_hclk;

	return 0;

err_disable_hclk:
	clk_disable(vop->hclk);
	return ret;
}

static void vop_core_clks_disable(struct vop *vop)
{
	clk_disable(vop->aclk);
	clk_disable(vop->hclk);
}

static void vop_crtc_load_lut(struct drm_crtc *crtc)
{
	struct vop *vop = to_vop(crtc);
	int i, dle, lut_idx = 0;

	if (!vop->is_enabled || !vop->lut || !vop->lut_regs)
		return;

	if (WARN_ON(!drm_modeset_is_locked(&crtc->mutex)))
		return;

	if (!VOP_CTRL_SUPPORT(vop, update_gamma_lut)) {
		spin_lock(&vop->reg_lock);
		VOP_CTRL_SET(vop, dsp_lut_en, 0);
		vop_cfg_done(vop);
		spin_unlock(&vop->reg_lock);

#define CTRL_GET(name) VOP_CTRL_GET(vop, name)
		readx_poll_timeout(CTRL_GET, dsp_lut_en,
				dle, !dle, 5, 33333);
	} else {
		lut_idx = CTRL_GET(lut_buffer_index);
	}

	for (i = 0; i < vop->lut_len; i++)
		vop_write_lut(vop, i << 2, vop->lut[i]);

	spin_lock(&vop->reg_lock);

	VOP_CTRL_SET(vop, dsp_lut_en, 1);
	VOP_CTRL_SET(vop, update_gamma_lut, 1);
	vop_cfg_done(vop);
	vop->lut_active = true;

	spin_unlock(&vop->reg_lock);

	if (VOP_CTRL_SUPPORT(vop, update_gamma_lut)) {
		readx_poll_timeout(CTRL_GET, lut_buffer_index,
				   dle, dle != lut_idx, 5, 33333);
		/* FIXME:
		 * update_gamma value auto clean to 0 by HW, should not
		 * bakeup it.
		 */
		VOP_CTRL_SET(vop, update_gamma_lut, 0);
	}
#undef CTRL_GET
}

static void rockchip_vop_crtc_fb_gamma_set(struct drm_crtc *crtc, u16 red,
					   u16 green, u16 blue, int regno)
{
	struct vop *vop = to_vop(crtc);
	u32 lut_len = vop->lut_len;
	u32 r, g, b;

	if (regno >= lut_len || !vop->lut)
		return;

	r = red * (lut_len - 1) / 0xffff;
	g = green * (lut_len - 1) / 0xffff;
	b = blue * (lut_len - 1) / 0xffff;
	vop->lut[regno] = r * lut_len * lut_len + g * lut_len + b;
}

static void rockchip_vop_crtc_fb_gamma_get(struct drm_crtc *crtc, u16 *red,
					   u16 *green, u16 *blue, int regno)
{
	struct vop *vop = to_vop(crtc);
	u32 lut_len = vop->lut_len;
	u32 r, g, b;

	if (regno >= lut_len || !vop->lut)
		return;

	r = (vop->lut[regno] / lut_len / lut_len) & (lut_len - 1);
	g = (vop->lut[regno] / lut_len) & (lut_len - 1);
	b = vop->lut[regno] & (lut_len - 1);
	*red = r * 0xffff / (lut_len - 1);
	*green = g * 0xffff / (lut_len - 1);
	*blue = b * 0xffff / (lut_len - 1);
}

static int vop_crtc_legacy_gamma_set(struct drm_crtc *crtc, u16 *red, u16 *green,
				     u16 *blue, uint32_t size,
				     struct drm_modeset_acquire_ctx *ctx)
{
	struct vop *vop = to_vop(crtc);
	int len = min(size, vop->lut_len);
	int i;

	if (!vop->lut)
		return -EINVAL;

	for (i = 0; i < len; i++)
		rockchip_vop_crtc_fb_gamma_set(crtc, red[i], green[i], blue[i], i);

	vop_crtc_load_lut(crtc);

	return 0;
}

static int vop_crtc_atomic_gamma_set(struct drm_crtc *crtc,
				     struct drm_crtc_state *old_state)
{
	struct vop *vop = to_vop(crtc);
	struct drm_color_lut *lut = vop->gamma_lut;
	unsigned int i;

	for (i = 0; i < vop->lut_len; i++)
		rockchip_vop_crtc_fb_gamma_set(crtc, lut[i].red, lut[i].green,
					       lut[i].blue, i);
	vop_crtc_load_lut(crtc);

	return 0;
}

static void vop_power_enable(struct drm_crtc *crtc)
{
	struct vop *vop = to_vop(crtc);
	int ret;

	ret = clk_prepare_enable(vop->hclk);
	if (ret < 0) {
		dev_err(vop->dev, "failed to enable hclk - %d\n", ret);
		return;
	}

	ret = clk_prepare_enable(vop->dclk);
	if (ret < 0) {
		dev_err(vop->dev, "failed to enable dclk - %d\n", ret);
		goto err_disable_hclk;
	}

	ret = clk_prepare_enable(vop->aclk);
	if (ret < 0) {
		dev_err(vop->dev, "failed to enable aclk - %d\n", ret);
		goto err_disable_dclk;
	}

	ret = pm_runtime_get_sync(vop->dev);
	if (ret < 0) {
		dev_err(vop->dev, "failed to get pm runtime: %d\n", ret);
		return;
	}

	memcpy(vop->regsbak, vop->regs, vop->len);

	if (VOP_CTRL_SUPPORT(vop, version)) {
		uint32_t version = VOP_CTRL_GET(vop, version);

		/*
		 * Fixup rk3288w version.
		 */
		if (version && version == 0x0a05)
			vop->version = VOP_VERSION(3, 1);
	}

	vop->is_enabled = true;

	return;

err_disable_dclk:
	clk_disable_unprepare(vop->dclk);
err_disable_hclk:
	clk_disable_unprepare(vop->hclk);
}

static void vop_initial(struct drm_crtc *crtc)
{
	struct vop *vop = to_vop(crtc);
	int i;

	vop_power_enable(crtc);

	VOP_CTRL_SET(vop, global_regdone_en, 1);
	VOP_CTRL_SET(vop, dsp_blank, 0);
	VOP_CTRL_SET(vop, axi_outstanding_max_num, 30);
	VOP_CTRL_SET(vop, axi_max_outstanding_en, 1);
	VOP_CTRL_SET(vop, dither_up_en, 1);

	/*
	 * We need to make sure that all windows are disabled before resume
	 * the crtc. Otherwise we might try to scan from a destroyed
	 * buffer later.
	 */
	for (i = 0; i < vop->num_wins; i++) {
		struct vop_win *win = &vop->win[i];
		int channel = i * 2 + 1;

		VOP_WIN_SET(vop, win, channel, (channel + 1) << 4 | channel);
	}
	VOP_CTRL_SET(vop, afbdc_en, 0);
	vop_enable_debug_irq(crtc);
}

static void vop_crtc_atomic_disable(struct drm_crtc *crtc,
				    struct drm_crtc_state *old_state)
{
	struct vop *vop = to_vop(crtc);
	int sys_status = drm_crtc_index(crtc) ?
				SYS_STATUS_LCDC1 : SYS_STATUS_LCDC0;

	WARN_ON(vop->event);

	vop_lock(vop);
	VOP_CTRL_SET(vop, reg_done_frm, 1);
	VOP_CTRL_SET(vop, dsp_interlace, 0);
	drm_crtc_vblank_off(crtc);
	VOP_CTRL_SET(vop, out_mode, ROCKCHIP_OUT_MODE_P888);
	VOP_CTRL_SET(vop, afbdc_en, 0);
	vop_disable_all_planes(vop);

	/*
	 * Vop standby will take effect at end of current frame,
	 * if dsp hold valid irq happen, it means standby complete.
	 *
	 * we must wait standby complete when we want to disable aclk,
	 * if not, memory bus maybe dead.
	 */
	reinit_completion(&vop->dsp_hold_completion);
	vop_dsp_hold_valid_irq_enable(vop);

	spin_lock(&vop->reg_lock);

	VOP_CTRL_SET(vop, standby, 1);

	spin_unlock(&vop->reg_lock);

	WARN_ON(!wait_for_completion_timeout(&vop->dsp_hold_completion,
					     msecs_to_jiffies(50)));

	vop_dsp_hold_valid_irq_disable(vop);

	vop->is_enabled = false;
	if (vop->is_iommu_enabled) {
		/*
		 * vop standby complete, so iommu detach is safe.
		 */
		VOP_CTRL_SET(vop, dma_stop, 1);
		rockchip_drm_dma_detach_device(vop->drm_dev, vop->dev);
		vop->is_iommu_enabled = false;
	}

	pm_runtime_put_sync(vop->dev);
	clk_disable_unprepare(vop->dclk);
	clk_disable_unprepare(vop->aclk);
	clk_disable_unprepare(vop->hclk);
	vop_unlock(vop);

	rockchip_clear_system_status(sys_status);

	if (crtc->state->event && !crtc->state->active) {
		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		spin_unlock_irq(&crtc->dev->event_lock);

		crtc->state->event = NULL;
	}
}

static int vop_plane_prepare_fb(struct drm_plane *plane,
				struct drm_plane_state *new_state)
{
	if (plane->state->fb)
		drm_framebuffer_get(plane->state->fb);

	return 0;
}

static void vop_plane_cleanup_fb(struct drm_plane *plane,
				 struct drm_plane_state *old_state)
{
	if (old_state->fb)
		drm_framebuffer_put(old_state->fb);
}

static int vop_plane_atomic_check(struct drm_plane *plane,
			   struct drm_plane_state *state)
{
	struct drm_crtc *crtc = state->crtc;
	struct drm_crtc_state *crtc_state;
	struct drm_framebuffer *fb = state->fb;
	struct vop_win *win = to_vop_win(plane);
	struct vop_plane_state *vop_plane_state = to_vop_plane_state(state);
	const struct vop_data *vop_data;
	struct vop *vop;
	int ret;
	struct drm_rect *dest = &vop_plane_state->dest;
	struct drm_rect *src = &vop_plane_state->src;
	struct drm_gem_object *obj, *uv_obj;
	struct rockchip_gem_object *rk_obj, *rk_uv_obj;
	int min_scale = win->phy->scl ? FRAC_16_16(1, 8) :
					DRM_PLANE_HELPER_NO_SCALING;
	int max_scale = win->phy->scl ? FRAC_16_16(8, 1) :
					DRM_PLANE_HELPER_NO_SCALING;
	unsigned long offset;
	dma_addr_t dma_addr;

	crtc = crtc ? crtc : plane->state->crtc;
	if (!crtc || !fb) {
		plane->state->visible = false;
		return 0;
	}

	crtc_state = drm_atomic_get_existing_crtc_state(state->state, crtc);
	if (WARN_ON(!crtc_state))
		return -EINVAL;

	src->x1 = state->src_x;
	src->y1 = state->src_y;
	src->x2 = state->src_x + state->src_w;
	src->y2 = state->src_y + state->src_h;
	dest->x1 = state->crtc_x;
	dest->y1 = state->crtc_y;
	dest->x2 = state->crtc_x + state->crtc_w;
	dest->y2 = state->crtc_y + state->crtc_h;
	vop_plane_state->zpos = state->zpos;
	vop_plane_state->blend_mode = state->pixel_blend_mode;

	ret = drm_atomic_helper_check_plane_state(state, crtc_state,
						  min_scale, max_scale,
						  true, true);
	if (ret)
		return ret;

	if (!state->visible)
		return 0;

	vop_plane_state->format = vop_convert_format(fb->format->format);
	if (vop_plane_state->format < 0)
		return vop_plane_state->format;

	vop = to_vop(crtc);
	vop_data = vop->data;

	if (state->src_w >> 16 < 4 || state->src_h >> 16 < 4 ||
	    state->crtc_w < 4 || state->crtc_h < 4) {
		DRM_ERROR("Invalid size: %dx%d->%dx%d, min size is 4x4\n",
			  state->src_w >> 16, state->src_h >> 16,
			  state->crtc_w, state->crtc_h);
		return -EINVAL;
	}

	if (drm_rect_width(src) >> 16 > vop_data->max_input.width ||
	    drm_rect_height(src) >> 16 > vop_data->max_input.height) {
		DRM_ERROR("Invalid source: %dx%d. max input: %dx%d\n",
			  drm_rect_width(src) >> 16,
			  drm_rect_height(src) >> 16,
			  vop_data->max_input.width,
			  vop_data->max_input.height);
		return -EINVAL;
	}

	/*
	 * Src.x1 can be odd when do clip, but yuv plane start point
	 * need align with 2 pixel.
	 */
	if (fb->format->is_yuv && ((state->src.x1 >> 16) % 2)) {
		DRM_ERROR("Invalid Source: Yuv format not support odd xpos\n");
		return -EINVAL;
	}

	if (fb->format->is_yuv && state->rotation & DRM_MODE_REFLECT_Y) {
		DRM_ERROR("Invalid Source: Yuv format does not support this rotation\n");
		return -EINVAL;
	}

	offset = (src->x1 >> 16) * fb->format->cpp[0];
	vop_plane_state->offset = offset + fb->offsets[0];
	if (state->rotation & DRM_MODE_REFLECT_Y)
		offset += ((src->y2 >> 16) - 1) * fb->pitches[0];
	else
		offset += (src->y1 >> 16) * fb->pitches[0];

	obj = fb->obj[0];
	rk_obj = to_rockchip_obj(obj);
	vop_plane_state->yrgb_mst = rk_obj->dma_addr + offset + fb->offsets[0];
	if (fb->format->is_yuv) {
		int hsub = fb->format->hsub;
		int vsub = fb->format->vsub;

		offset = (src->x1 >> 16) * fb->format->cpp[1] / hsub;
		offset += (src->y1 >> 16) * fb->pitches[1] / vsub;

		uv_obj = fb->obj[1];
		rk_uv_obj = to_rockchip_obj(uv_obj);

		dma_addr = rk_uv_obj->dma_addr + offset + fb->offsets[1];
		vop_plane_state->uv_mst = dma_addr;
	}

	return 0;
}

static void vop_plane_atomic_disable(struct drm_plane *plane,
				     struct drm_plane_state *old_state)
{
	struct vop_win *win = to_vop_win(plane);
	struct vop *vop = to_vop(old_state->crtc);
#if defined(CONFIG_ROCKCHIP_DRM_DEBUG)
	struct vop_plane_state *vop_plane_state =
					to_vop_plane_state(plane->state);
#endif

	if (!old_state->crtc)
		return;

	spin_lock(&vop->reg_lock);

	vop_win_disable(vop, win);

	/*
	 * IC design bug: in the bandwidth tension environment when close win2,
	 * vop will access the freed memory lead to iommu pagefault.
	 * so we add this reset to workaround.
	 */
	if (VOP_MAJOR(vop->version) == 2 && VOP_MINOR(vop->version) == 5 &&
	    win->win_id == 2)
		VOP_WIN_SET(vop, win, yrgb_mst, 0);

#if defined(CONFIG_ROCKCHIP_DRM_DEBUG)
	kfree(vop_plane_state->planlist);
	vop_plane_state->planlist = NULL;
#endif

	spin_unlock(&vop->reg_lock);
}

static void vop_plane_atomic_update(struct drm_plane *plane,
		struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct drm_crtc *crtc = state->crtc;
	struct drm_display_mode *mode = NULL;
	struct vop_win *win = to_vop_win(plane);
	struct vop_plane_state *vop_plane_state = to_vop_plane_state(state);
	struct drm_display_mode *adjusted_mode = &crtc->state->adjusted_mode;
	struct rockchip_crtc_state *s;
	struct vop *vop = to_vop(state->crtc);
	struct drm_framebuffer *fb = state->fb;
	unsigned int actual_w, actual_h, dsp_w, dsp_h;
	unsigned int dsp_stx, dsp_sty;
	uint32_t act_info, dsp_info, dsp_st;
	struct drm_rect *src = &vop_plane_state->src;
	struct drm_rect *dest = &vop_plane_state->dest;
	const uint32_t *y2r_table = vop_plane_state->y2r_table;
	const uint32_t *r2r_table = vop_plane_state->r2r_table;
	const uint32_t *r2y_table = vop_plane_state->r2y_table;
	uint32_t val;
	bool rb_swap, global_alpha_en;
	int is_yuv = fb->format->is_yuv;

#if defined(CONFIG_ROCKCHIP_DRM_DEBUG)
	bool AFBC_flag = false;
	struct vop_dump_list *planlist;
	unsigned long num_pages;
	struct page **pages;
	struct drm_gem_object *obj;
	struct rockchip_gem_object *rk_obj;

	num_pages = 0;
	pages = NULL;
	obj = fb->obj[0];
	rk_obj = to_rockchip_obj(obj);
	if (rk_obj) {
		num_pages = rk_obj->num_pages;
		pages = rk_obj->pages;
	}
	if (fb->modifier == DRM_FORMAT_MOD_ARM_AFBC(AFBC_FORMAT_MOD_BLOCK_SIZE_16x16))
		AFBC_flag = true;
	else
		AFBC_flag = false;
#endif

	/*
	 * can't update plane when vop is disabled.
	 */
	if (WARN_ON(!crtc))
		return;

	if (WARN_ON(!vop->is_enabled))
		return;

	if (!state->visible) {
		vop_plane_atomic_disable(plane, old_state);
		return;
	}

	mode = &crtc->state->adjusted_mode;
	actual_w = drm_rect_width(src) >> 16;
	actual_h = drm_rect_height(src) >> 16;

	dsp_w = drm_rect_width(dest);
	if (dest->x1 + dsp_w > adjusted_mode->hdisplay) {
		DRM_ERROR("%s win%d dest->x1[%d] + dsp_w[%d] exceed mode hdisplay[%d]\n",
			  crtc->name, win->win_id, dest->x1, dsp_w, adjusted_mode->hdisplay);
		dsp_w = adjusted_mode->hdisplay - dest->x1;
		if (dsp_w < 4)
			dsp_w = 4;
		actual_w = dsp_w * actual_w / drm_rect_width(dest);
	}
	dsp_h = drm_rect_height(dest);
	if (dest->y1 + dsp_h > adjusted_mode->vdisplay) {
		DRM_ERROR("%s win%d dest->y1[%d] + dsp_h[%d] exceed mode vdisplay[%d]\n",
			  crtc->name, win->win_id, dest->y1, dsp_h, adjusted_mode->vdisplay);
		dsp_h = adjusted_mode->vdisplay - dest->y1;
		if (dsp_h < 4)
			dsp_h = 4;
		actual_h = dsp_h * actual_h / drm_rect_height(dest);
	}

	act_info = (actual_h - 1) << 16 | ((actual_w - 1) & 0xffff);

	dsp_info = (dsp_h - 1) << 16;
	dsp_info |= (dsp_w - 1) & 0xffff;

	dsp_stx = dest->x1 + mode->crtc_htotal - mode->crtc_hsync_start;
	dsp_sty = dest->y1 + mode->crtc_vtotal - mode->crtc_vsync_start;
	dsp_st = dsp_sty << 16 | (dsp_stx & 0xffff);

	s = to_rockchip_crtc_state(crtc->state);
	spin_lock(&vop->reg_lock);

	VOP_WIN_SET(vop, win, format, vop_plane_state->format);
	VOP_WIN_SET(vop, win, yrgb_vir, DIV_ROUND_UP(fb->pitches[0], 4));
	VOP_WIN_SET(vop, win, yrgb_mst, vop_plane_state->yrgb_mst);

	VOP_WIN_SET(vop, win, ymirror,
		    (state->rotation & DRM_MODE_REFLECT_Y) ? 1 : 0);
	VOP_WIN_SET(vop, win, xmirror,
		    (state->rotation & DRM_MODE_REFLECT_X) ? 1 : 0);

	if (is_yuv) {
		VOP_WIN_SET(vop, win, uv_vir, DIV_ROUND_UP(fb->pitches[1], 4));
		VOP_WIN_SET(vop, win, uv_mst, vop_plane_state->uv_mst);
	}
	VOP_WIN_SET(vop, win, fmt_10, is_yuv_10bit(fb->format->format));
	VOP_WIN_SET(vop, win, fmt_yuyv, is_yuyv_format(fb->format->format));

	if (win->phy->scl)
		scl_vop_cal_scl_fac(vop, win, actual_w, actual_h,
				    drm_rect_width(dest), drm_rect_height(dest),
				    fb->format->format);

	VOP_WIN_SET(vop, win, act_info, act_info);
	VOP_WIN_SET(vop, win, dsp_info, dsp_info);
	VOP_WIN_SET(vop, win, dsp_st, dsp_st);

	rb_swap = has_rb_swapped(fb->format->format);
	/*
	 * VOP full need to do rb swap to show rgb888/bgr888 format color correctly
	 */
	if ((fb->format->format == DRM_FORMAT_RGB888 || fb->format->format == DRM_FORMAT_BGR888) &&
	    VOP_MAJOR(vop->version) == 3)
		rb_swap = !rb_swap;
	VOP_WIN_SET(vop, win, rb_swap, rb_swap);

	global_alpha_en = (vop_plane_state->global_alpha == 0xff) ? 0 : 1;
	if ((is_alpha_support(fb->format->format) || global_alpha_en) &&
	    (s->dsp_layer_sel & 0x3) != win->win_id) {
		int src_blend_m0;

		if (is_alpha_support(fb->format->format) && global_alpha_en)
			src_blend_m0 = ALPHA_PER_PIX_GLOBAL;
		else if (is_alpha_support(fb->format->format))
			src_blend_m0 = ALPHA_PER_PIX;
		else
			src_blend_m0 = ALPHA_GLOBAL;

		VOP_WIN_SET(vop, win, dst_alpha_ctl,
			    DST_FACTOR_M0(ALPHA_SRC_INVERSE));
		val = SRC_ALPHA_EN(1) | SRC_COLOR_M0(ALPHA_SRC_PRE_MUL) |
			SRC_ALPHA_M0(ALPHA_STRAIGHT) |
			SRC_BLEND_M0(src_blend_m0) |
			SRC_ALPHA_CAL_M0(ALPHA_SATURATION) |
			SRC_FACTOR_M0(global_alpha_en ?
				      ALPHA_SRC_GLOBAL : ALPHA_ONE);
		VOP_WIN_SET(vop, win, src_alpha_ctl, val);
		VOP_WIN_SET(vop, win, alpha_pre_mul,
			    vop_plane_state->blend_mode == DRM_MODE_BLEND_PREMULTI ? 1 : 0);
		VOP_WIN_SET(vop, win, alpha_mode, 1);
		VOP_WIN_SET(vop, win, alpha_en, 1);
	} else {
		VOP_WIN_SET(vop, win, src_alpha_ctl, SRC_ALPHA_EN(0));
		VOP_WIN_SET(vop, win, alpha_en, 0);
	}
	VOP_WIN_SET(vop, win, global_alpha_val, vop_plane_state->global_alpha);

	VOP_WIN_SET(vop, win, csc_mode, vop_plane_state->csc_mode);
	if (win->csc) {
		vop_load_csc_table(vop, win->csc->y2r_offset, y2r_table);
		vop_load_csc_table(vop, win->csc->r2r_offset, r2r_table);
		vop_load_csc_table(vop, win->csc->r2y_offset, r2y_table);
		VOP_WIN_SET_EXT(vop, win, csc, y2r_en, vop_plane_state->y2r_en);
		VOP_WIN_SET_EXT(vop, win, csc, r2r_en, vop_plane_state->r2r_en);
		VOP_WIN_SET_EXT(vop, win, csc, r2y_en, vop_plane_state->r2y_en);
		VOP_WIN_SET_EXT(vop, win, csc, csc_mode, vop_plane_state->csc_mode);
	}
	VOP_WIN_SET(vop, win, enable, 1);
	VOP_WIN_SET(vop, win, gate, 1);
	spin_unlock(&vop->reg_lock);
	/*
	 * spi interface(vop_plane_state->yrgb_kvaddr, fb->pixel_format,
	 * actual_w, actual_h)
	 */
	vop->is_iommu_needed = true;
#if defined(CONFIG_ROCKCHIP_DRM_DEBUG)
	kfree(vop_plane_state->planlist);
	vop_plane_state->planlist = NULL;

	planlist = kmalloc(sizeof(*planlist), GFP_KERNEL);
	if (planlist) {
		planlist->dump_info.AFBC_flag = AFBC_flag;
		planlist->dump_info.area_id = win->area_id;
		planlist->dump_info.win_id = win->win_id;
		planlist->dump_info.yuv_format =
			is_yuv_support(fb->format->format);
		planlist->dump_info.num_pages = num_pages;
		planlist->dump_info.pages = pages;
		planlist->dump_info.offset = vop_plane_state->offset;
		planlist->dump_info.pitches = fb->pitches[0];
		planlist->dump_info.height = actual_h;
		planlist->dump_info.format = fb->format;
		list_add_tail(&planlist->entry, &vop->rockchip_crtc.vop_dump_list_head);
		vop_plane_state->planlist = planlist;
	} else {
		DRM_ERROR("can't alloc a node of planlist %p\n", planlist);
		return;
	}
	if (vop->rockchip_crtc.vop_dump_status == DUMP_KEEP ||
	    vop->rockchip_crtc.vop_dump_times > 0) {
		rockchip_drm_dump_plane_buffer(&planlist->dump_info, vop->rockchip_crtc.frame_count);
		vop->rockchip_crtc.vop_dump_times--;
	}
#endif
}

static const struct drm_plane_helper_funcs plane_helper_funcs = {
	.prepare_fb = vop_plane_prepare_fb,
	.cleanup_fb = vop_plane_cleanup_fb,
	.atomic_check = vop_plane_atomic_check,
	.atomic_update = vop_plane_atomic_update,
	.atomic_disable = vop_plane_atomic_disable,
};

/**
 * rockchip_atomic_helper_update_plane copy from drm_atomic_helper_update_plane
 * be designed to support async commit at ioctl DRM_IOCTL_MODE_SETPLANE.
 * @plane: plane object to update
 * @crtc: owning CRTC of owning plane
 * @fb: framebuffer to flip onto plane
 * @crtc_x: x offset of primary plane on crtc
 * @crtc_y: y offset of primary plane on crtc
 * @crtc_w: width of primary plane rectangle on crtc
 * @crtc_h: height of primary plane rectangle on crtc
 * @src_x: x offset of @fb for panning
 * @src_y: y offset of @fb for panning
 * @src_w: width of source rectangle in @fb
 * @src_h: height of source rectangle in @fb
 * @ctx: lock acquire context
 *
 * Provides a default plane update handler using the atomic driver interface.
 *
 * RETURNS:
 * Zero on success, error code on failure
 */
static int __maybe_unused
rockchip_atomic_helper_update_plane(struct drm_plane *plane,
				    struct drm_crtc *crtc,
				    struct drm_framebuffer *fb,
				    int crtc_x, int crtc_y,
				    unsigned int crtc_w, unsigned int crtc_h,
				    uint32_t src_x, uint32_t src_y,
				    uint32_t src_w, uint32_t src_h,
				    struct drm_modeset_acquire_ctx *ctx)
{
	struct drm_atomic_state *state;
	struct drm_plane_state *plane_state;
	struct vop_plane_state *vop_plane_state;
	int ret = 0;

	state = drm_atomic_state_alloc(plane->dev);
	if (!state)
		return -ENOMEM;

	state->acquire_ctx = ctx;
	plane_state = drm_atomic_get_plane_state(state, plane);
	if (IS_ERR(plane_state)) {
		ret = PTR_ERR(plane_state);
		goto fail;
	}

	vop_plane_state = to_vop_plane_state(plane_state);

	ret = drm_atomic_set_crtc_for_plane(plane_state, crtc);
	if (ret != 0)
		goto fail;
	drm_atomic_set_fb_for_plane(plane_state, fb);
	plane_state->crtc_x = crtc_x;
	plane_state->crtc_y = crtc_y;
	plane_state->crtc_w = crtc_w;
	plane_state->crtc_h = crtc_h;
	plane_state->src_x = src_x;
	plane_state->src_y = src_y;
	plane_state->src_w = src_w;
	plane_state->src_h = src_h;

	if (plane == crtc->cursor || vop_plane_state->async_commit)
		state->legacy_cursor_update = true;

	ret = drm_atomic_commit(state);
fail:
	drm_atomic_state_put(state);
	return ret;
}

/**
 * drm_atomic_helper_disable_plane copy from drm_atomic_helper_disable_plane
 * be designed to support async commit at ioctl DRM_IOCTL_MODE_SETPLANE.
 *
 * @plane: plane to disable
 * @ctx: lock acquire context
 *
 * Provides a default plane disable handler using the atomic driver interface.
 *
 * RETURNS:
 * Zero on success, error code on failure
 */
static int __maybe_unused
rockchip_atomic_helper_disable_plane(struct drm_plane *plane,
				     struct drm_modeset_acquire_ctx *ctx)
{
	struct drm_atomic_state *state;
	struct drm_plane_state *plane_state;
	struct vop_plane_state *vop_plane_state;
	int ret = 0;

	state = drm_atomic_state_alloc(plane->dev);
	if (!state)
		return -ENOMEM;

	state->acquire_ctx = ctx;
	plane_state = drm_atomic_get_plane_state(state, plane);
	if (IS_ERR(plane_state)) {
		ret = PTR_ERR(plane_state);
		goto fail;
	}
	vop_plane_state = to_vop_plane_state(plane_state);

	if ((plane_state->crtc && plane_state->crtc->cursor == plane) ||
	    vop_plane_state->async_commit)
		plane_state->state->legacy_cursor_update = true;

	ret = __drm_atomic_helper_disable_plane(plane, plane_state);
	if (ret != 0)
		goto fail;

	ret = drm_atomic_commit(state);
fail:
	drm_atomic_state_put(state);
	return ret;
}

static void vop_plane_destroy(struct drm_plane *plane)
{
	drm_plane_cleanup(plane);
}

static void vop_atomic_plane_reset(struct drm_plane *plane)
{
	struct vop_plane_state *vop_plane_state =
					to_vop_plane_state(plane->state);
	struct vop_win *win = to_vop_win(plane);

	if (plane->state && plane->state->fb)
		__drm_atomic_helper_plane_destroy_state(plane->state);
	kfree(vop_plane_state);
	vop_plane_state = kzalloc(sizeof(*vop_plane_state), GFP_KERNEL);
	if (!vop_plane_state)
		return;

	__drm_atomic_helper_plane_reset(plane, &vop_plane_state->base);
	win->state.zpos = win->zpos;
	vop_plane_state->global_alpha = 0xff;
}

static struct drm_plane_state *
vop_atomic_plane_duplicate_state(struct drm_plane *plane)
{
	struct vop_plane_state *old_vop_plane_state;
	struct vop_plane_state *vop_plane_state;

	if (WARN_ON(!plane->state))
		return NULL;

	old_vop_plane_state = to_vop_plane_state(plane->state);
	vop_plane_state = kmemdup(old_vop_plane_state,
				  sizeof(*vop_plane_state), GFP_KERNEL);
	if (!vop_plane_state)
		return NULL;

	__drm_atomic_helper_plane_duplicate_state(plane,
						  &vop_plane_state->base);

	return &vop_plane_state->base;
}

static void vop_atomic_plane_destroy_state(struct drm_plane *plane,
					   struct drm_plane_state *state)
{
	struct vop_plane_state *vop_state = to_vop_plane_state(state);

	__drm_atomic_helper_plane_destroy_state(state);

	kfree(vop_state);
}

static int vop_atomic_plane_set_property(struct drm_plane *plane,
					 struct drm_plane_state *state,
					 struct drm_property *property,
					 uint64_t val)
{
	struct rockchip_drm_private *private = plane->dev->dev_private;
	struct vop_win *win = to_vop_win(plane);
	struct vop_plane_state *plane_state = to_vop_plane_state(state);

	if (property == private->eotf_prop) {
		plane_state->eotf = val;
		return 0;
	}

	if (property == private->color_space_prop) {
		plane_state->color_space = val;
		return 0;
	}

	if (property == private->async_commit_prop) {
		plane_state->async_commit = val;
		return 0;
	}

	if (property == win->color_key_prop) {
		plane_state->color_key = val;
		return 0;
	}

	DRM_ERROR("failed to set vop plane property id:%d, name:%s\n",
		   property->base.id, property->name);

	return -EINVAL;
}

static int vop_atomic_plane_get_property(struct drm_plane *plane,
					 const struct drm_plane_state *state,
					 struct drm_property *property,
					 uint64_t *val)
{
	struct vop_plane_state *plane_state = to_vop_plane_state(state);
	struct vop_win *win = to_vop_win(plane);
	struct rockchip_drm_private *private = plane->dev->dev_private;

	if (property == private->eotf_prop) {
		*val = plane_state->eotf;
		return 0;
	}

	if (property == private->color_space_prop) {
		*val = plane_state->color_space;
		return 0;
	}

	if (property == private->async_commit_prop) {
		*val = plane_state->async_commit;
		return 0;
	}

	if (property == private->share_id_prop) {

// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Rockchip Electronics Co., Ltd. */

#include <media/v4l2-common.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-core.h>
#include <media/videobuf2-vmalloc.h>	/* for ISP params */
#include "dev.h"
#include "regs.h"
#include "isp_params_v3x.h"

#define ISP3X_MODULE_EN			BIT(0)
#define ISP3X_SELF_FORCE_UPD		BIT(31)
#define ISP3X_REG_WR_MASK		BIT(31) //disable write protect
#define ISP3X_NOBIG_OVERFLOW_SIZE	(2688 * 1536)
#define ISP3X_AUTO_BIGMODE_WIDTH	2688
#define ISP3X_VIR2_NOBIG_OVERFLOW_SIZE	(1920 * 1080)
#define ISP3X_VIR2_AUTO_BIGMODE_WIDTH	1920
#define ISP3X_VIR4_NOBIG_OVERFLOW_SIZE	(1280 * 800)
#define ISP3X_VIR4_AUTO_BIGMODE_WIDTH	1280

#define ISP3X_VIR2_MAX_WIDTH		3840
#define ISP3X_VIR2_MAX_SIZE		(3840 * 2160)
#define ISP3X_VIR4_MAX_WIDTH		2560
#define ISP3X_VIR4_MAX_SIZE		(2560 * 1536)

static inline void
isp3_param_write_direct(struct rkisp_isp_params_vdev *params_vdev,
			u32 value, u32 addr, u32 id)
{
	if (id == ISP3_LEFT)
		rkisp_write(params_vdev->dev, addr, value, true);
	else
		rkisp_next_write(params_vdev->dev, addr, value, true);
}

static inline void
isp3_param_write(struct rkisp_isp_params_vdev *params_vdev,
		 u32 value, u32 addr, u32 id)
{
	if (id == ISP3_LEFT)
		rkisp_write(params_vdev->dev, addr, value, false);
	else
		rkisp_next_write(params_vdev->dev, addr, value, false);
}

static inline u32
isp3_param_read_direct(struct rkisp_isp_params_vdev *params_vdev,
		       u32 addr, u32 id)
{
	u32 val;

	if (id == ISP3_LEFT)
		val = rkisp_read(params_vdev->dev, addr, true);
	else
		val = rkisp_next_read(params_vdev->dev, addr, true);
	return val;
}

static inline u32
isp3_param_read(struct rkisp_isp_params_vdev *params_vdev,
		u32 addr, u32 id)
{
	u32 val;

	if (id == ISP3_LEFT)
		val = rkisp_read(params_vdev->dev, addr, false);
	else
		val = rkisp_next_read(params_vdev->dev, addr, false);
	return val;
}

static inline u32
isp3_param_read_cache(struct rkisp_isp_params_vdev *params_vdev,
		      u32 addr, u32 id)
{
	u32 val;

	if (id == ISP3_LEFT)
		val = rkisp_read_reg_cache(params_vdev->dev, addr);
	else
		val = rkisp_next_read_reg_cache(params_vdev->dev, addr);
	return val;
}

static inline void
isp3_param_set_bits(struct rkisp_isp_params_vdev *params_vdev,
		    u32 reg, u32 bit_mask, u32 id)
{
	if (id == ISP3_LEFT)
		rkisp_set_bits(params_vdev->dev, reg, 0, bit_mask, false);
	else
		rkisp_next_set_bits(params_vdev->dev, reg, 0, bit_mask, false);
}

static inline void
isp3_param_clear_bits(struct rkisp_isp_params_vdev *params_vdev,
		      u32 reg, u32 bit_mask, u32 id)
{
	if (id == ISP3_LEFT)
		rkisp_clear_bits(params_vdev->dev, reg, bit_mask, false);
	else
		rkisp_next_clear_bits(params_vdev->dev, reg, bit_mask, false);
}

static void
isp_dpcc_config(struct rkisp_isp_params_vdev *params_vdev,
		const struct isp2x_dpcc_cfg *arg, u32 id)
{
	u32 value;
	int i;

	value = isp3_param_read(params_vdev, ISP3X_DPCC0_MODE, id);
	value &= ISP_DPCC_EN;

	value |= (arg->stage1_enable & 0x01) << 2 |
		 (arg->grayscale_mode & 0x01) << 1;
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_MODE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_MODE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_MODE, id);

	value = (arg->sw_rk_out_sel & 0x03) << 5 |
		(arg->sw_dpcc_output_sel & 0x01) << 4 |
		(arg->stage1_rb_3x3 & 0x01) << 3 |
		(arg->stage1_g_3x3 & 0x01) << 2 |
		(arg->stage1_incl_rb_center & 0x01) << 1 |
		(arg->stage1_incl_green_center & 0x01);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_OUTPUT_MODE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_OUTPUT_MODE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_OUTPUT_MODE, id);

	value = (arg->stage1_use_fix_set & 0x01) << 3 |
		(arg->stage1_use_set_3 & 0x01) << 2 |
		(arg->stage1_use_set_2 & 0x01) << 1 |
		(arg->stage1_use_set_1 & 0x01);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_SET_USE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_SET_USE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_SET_USE, id);

	value = (arg->sw_rk_red_blue1_en & 0x01) << 13 |
		(arg->rg_red_blue1_enable & 0x01) << 12 |
		(arg->rnd_red_blue1_enable & 0x01) << 11 |
		(arg->ro_red_blue1_enable & 0x01) << 10 |
		(arg->lc_red_blue1_enable & 0x01) << 9 |
		(arg->pg_red_blue1_enable & 0x01) << 8 |
		(arg->sw_rk_green1_en & 0x01) << 5 |
		(arg->rg_green1_enable & 0x01) << 4 |
		(arg->rnd_green1_enable & 0x01) << 3 |
		(arg->ro_green1_enable & 0x01) << 2 |
		(arg->lc_green1_enable & 0x01) << 1 |
		(arg->pg_green1_enable & 0x01);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_METHODS_SET_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_METHODS_SET_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_METHODS_SET_1, id);

	value = (arg->sw_rk_red_blue2_en & 0x01) << 13 |
		(arg->rg_red_blue2_enable & 0x01) << 12 |
		(arg->rnd_red_blue2_enable & 0x01) << 11 |
		(arg->ro_red_blue2_enable & 0x01) << 10 |
		(arg->lc_red_blue2_enable & 0x01) << 9 |
		(arg->pg_red_blue2_enable & 0x01) << 8 |
		(arg->sw_rk_green2_en & 0x01) << 5 |
		(arg->rg_green2_enable & 0x01) << 4 |
		(arg->rnd_green2_enable & 0x01) << 3 |
		(arg->ro_green2_enable & 0x01) << 2 |
		(arg->lc_green2_enable & 0x01) << 1 |
		(arg->pg_green2_enable & 0x01);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_METHODS_SET_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_METHODS_SET_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_METHODS_SET_2, id);

	value = (arg->sw_rk_red_blue3_en & 0x01) << 13 |
		(arg->rg_red_blue3_enable & 0x01) << 12 |
		(arg->rnd_red_blue3_enable & 0x01) << 11 |
		(arg->ro_red_blue3_enable & 0x01) << 10 |
		(arg->lc_red_blue3_enable & 0x01) << 9 |
		(arg->pg_red_blue3_enable & 0x01) << 8 |
		(arg->sw_rk_green3_en & 0x01) << 5 |
		(arg->rg_green3_enable & 0x01) << 4 |
		(arg->rnd_green3_enable & 0x01) << 3 |
		(arg->ro_green3_enable & 0x01) << 2 |
		(arg->lc_green3_enable & 0x01) << 1 |
		(arg->pg_green3_enable & 0x01);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_METHODS_SET_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_METHODS_SET_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_METHODS_SET_3, id);

	value = ISP_PACK_4BYTE(arg->line_thr_1_g, arg->line_thr_1_rb,
				arg->sw_mindis1_g, arg->sw_mindis1_rb);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_LINE_THRESH_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_LINE_THRESH_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_LINE_THRESH_1, id);

	value = ISP_PACK_4BYTE(arg->line_mad_fac_1_g, arg->line_mad_fac_1_rb,
				arg->sw_dis_scale_max1, arg->sw_dis_scale_min1);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_LINE_MAD_FAC_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_LINE_MAD_FAC_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_LINE_MAD_FAC_1, id);

	value = ISP_PACK_4BYTE(arg->pg_fac_1_g, arg->pg_fac_1_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_PG_FAC_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_PG_FAC_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_PG_FAC_1, id);

	value = ISP_PACK_4BYTE(arg->rnd_thr_1_g, arg->rnd_thr_1_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RND_THRESH_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RND_THRESH_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RND_THRESH_1, id);

	value = ISP_PACK_4BYTE(arg->rg_fac_1_g, arg->rg_fac_1_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RG_FAC_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RG_FAC_1, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RG_FAC_1, id);

	value = ISP_PACK_4BYTE(arg->line_thr_2_g, arg->line_thr_2_rb,
				arg->sw_mindis2_g, arg->sw_mindis2_rb);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_LINE_THRESH_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_LINE_THRESH_2, id);

	value = ISP_PACK_4BYTE(arg->line_mad_fac_2_g, arg->line_mad_fac_2_rb,
				arg->sw_dis_scale_max2, arg->sw_dis_scale_min2);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_LINE_MAD_FAC_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_LINE_MAD_FAC_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_LINE_MAD_FAC_2, id);

	value = ISP_PACK_4BYTE(arg->pg_fac_2_g, arg->pg_fac_2_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_PG_FAC_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_PG_FAC_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_PG_FAC_2, id);

	value = ISP_PACK_4BYTE(arg->rnd_thr_2_g, arg->rnd_thr_2_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RND_THRESH_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RND_THRESH_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RND_THRESH_2, id);

	value = ISP_PACK_4BYTE(arg->rg_fac_2_g, arg->rg_fac_2_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RG_FAC_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RG_FAC_2, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RG_FAC_2, id);

	value = ISP_PACK_4BYTE(arg->line_thr_3_g, arg->line_thr_3_rb,
				 arg->sw_mindis3_g, arg->sw_mindis3_rb);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_LINE_THRESH_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_LINE_THRESH_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_LINE_THRESH_3, id);

	value = ISP_PACK_4BYTE(arg->line_mad_fac_3_g, arg->line_mad_fac_3_rb,
				arg->sw_dis_scale_max3, arg->sw_dis_scale_min3);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_LINE_MAD_FAC_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_LINE_MAD_FAC_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_LINE_MAD_FAC_3, id);

	value = ISP_PACK_4BYTE(arg->pg_fac_3_g, arg->pg_fac_3_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_PG_FAC_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_PG_FAC_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_PG_FAC_3, id);

	value = ISP_PACK_4BYTE(arg->rnd_thr_3_g, arg->rnd_thr_3_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RND_THRESH_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RND_THRESH_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RND_THRESH_3, id);

	value = ISP_PACK_4BYTE(arg->rg_fac_3_g, arg->rg_fac_3_rb, 0, 0);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RG_FAC_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RG_FAC_3, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RG_FAC_3, id);

	value = (arg->ro_lim_3_rb & 0x03) << 10 |
		(arg->ro_lim_3_g & 0x03) << 8 |
		(arg->ro_lim_2_rb & 0x03) << 6 |
		(arg->ro_lim_2_g & 0x03) << 4 |
		(arg->ro_lim_1_rb & 0x03) << 2 |
		(arg->ro_lim_1_g & 0x03);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RO_LIMITS, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RO_LIMITS, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RO_LIMITS, id);

	value = (arg->rnd_offs_3_rb & 0x03) << 10 |
		(arg->rnd_offs_3_g & 0x03) << 8 |
		(arg->rnd_offs_2_rb & 0x03) << 6 |
		(arg->rnd_offs_2_g & 0x03) << 4 |
		(arg->rnd_offs_1_rb & 0x03) << 2 |
		(arg->rnd_offs_1_g & 0x03);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_RND_OFFS, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_RND_OFFS, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_RND_OFFS, id);

	value = (arg->bpt_rb_3x3 & 0x01) << 11 |
		(arg->bpt_g_3x3 & 0x01) << 10 |
		(arg->bpt_incl_rb_center & 0x01) << 9 |
		(arg->bpt_incl_green_center & 0x01) << 8 |
		(arg->bpt_use_fix_set & 0x01) << 7 |
		(arg->bpt_use_set_3 & 0x01) << 6 |
		(arg->bpt_use_set_2 & 0x01) << 5 |
		(arg->bpt_use_set_1 & 0x01) << 4 |
		(arg->bpt_cor_en & 0x01) << 1 |
		(arg->bpt_det_en & 0x01);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_BPT_CTRL, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_BPT_CTRL, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_BPT_CTRL, id);

	isp3_param_write(params_vdev, arg->bp_number, ISP3X_DPCC0_BPT_NUMBER, id);
	isp3_param_write(params_vdev, arg->bp_number, ISP3X_DPCC1_BPT_NUMBER, id);
	isp3_param_write(params_vdev, arg->bp_number, ISP3X_DPCC2_BPT_NUMBER, id);
	isp3_param_write(params_vdev, arg->bp_table_addr, ISP3X_DPCC0_BPT_ADDR, id);
	isp3_param_write(params_vdev, arg->bp_table_addr, ISP3X_DPCC1_BPT_ADDR, id);
	isp3_param_write(params_vdev, arg->bp_table_addr, ISP3X_DPCC2_BPT_ADDR, id);

	value = ISP_PACK_2SHORT(arg->bpt_h_addr, arg->bpt_v_addr);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_BPT_DATA, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_BPT_DATA, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_BPT_DATA, id);

	isp3_param_write(params_vdev, arg->bp_cnt, ISP3X_DPCC0_BP_CNT, id);
	isp3_param_write(params_vdev, arg->bp_cnt, ISP3X_DPCC1_BP_CNT, id);
	isp3_param_write(params_vdev, arg->bp_cnt, ISP3X_DPCC2_BP_CNT, id);

	isp3_param_write(params_vdev, arg->sw_pdaf_en, ISP3X_DPCC0_PDAF_EN, id);
	isp3_param_write(params_vdev, arg->sw_pdaf_en, ISP3X_DPCC1_PDAF_EN, id);
	isp3_param_write(params_vdev, arg->sw_pdaf_en, ISP3X_DPCC2_PDAF_EN, id);

	value = 0;
	for (i = 0; i < ISP3X_DPCC_PDAF_POINT_NUM; i++)
		value |= (arg->pdaf_point_en[i] & 0x01) << i;
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_PDAF_POINT_EN, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_PDAF_POINT_EN, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_PDAF_POINT_EN, id);

	value = ISP_PACK_2SHORT(arg->pdaf_offsetx, arg->pdaf_offsety);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_PDAF_OFFSET, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_PDAF_OFFSET, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_PDAF_OFFSET, id);

	value = ISP_PACK_2SHORT(arg->pdaf_wrapx, arg->pdaf_wrapy);
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_PDAF_WRAP, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_PDAF_WRAP, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_PDAF_WRAP, id);

	value = ISP_PACK_2SHORT(arg->pdaf_wrapx_num, arg->pdaf_wrapy_num);
	isp3_param_write(params_vdev, value, ISP_DPCC0_PDAF_SCOPE, id);
	isp3_param_write(params_vdev, value, ISP_DPCC1_PDAF_SCOPE, id);
	isp3_param_write(params_vdev, value, ISP_DPCC2_PDAF_SCOPE, id);

	for (i = 0; i < ISP3X_DPCC_PDAF_POINT_NUM / 2; i++) {
		value = ISP_PACK_4BYTE(arg->point[2 * i].x, arg->point[2 * i].y,
					arg->point[2 * i + 1].x, arg->point[2 * i + 1].y);
		isp3_param_write(params_vdev, value, ISP3X_DPCC0_PDAF_POINT_0 + 4 * i, id);
		isp3_param_write(params_vdev, value, ISP3X_DPCC1_PDAF_POINT_0 + 4 * i, id);
		isp3_param_write(params_vdev, value, ISP3X_DPCC2_PDAF_POINT_0 + 4 * i, id);
	}

	isp3_param_write(params_vdev, arg->pdaf_forward_med, ISP3X_DPCC0_PDAF_FORWARD_MED, id);
	isp3_param_write(params_vdev, arg->pdaf_forward_med, ISP3X_DPCC1_PDAF_FORWARD_MED, id);
	isp3_param_write(params_vdev, arg->pdaf_forward_med, ISP3X_DPCC2_PDAF_FORWARD_MED, id);
}

static void
isp_dpcc_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	u32 value;

	value = isp3_param_read(params_vdev, ISP3X_DPCC0_MODE, id);
	value &= ~ISP_DPCC_EN;

	if (en)
		value |= ISP_DPCC_EN;
	isp3_param_write(params_vdev, value, ISP3X_DPCC0_MODE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC1_MODE, id);
	isp3_param_write(params_vdev, value, ISP3X_DPCC2_MODE, id);
}

static void
isp_bls_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp21_bls_cfg *arg, u32 id)
{
	const struct isp2x_bls_fixed_val *pval;
	u32 new_control, value;

	new_control = isp3_param_read(params_vdev, ISP3X_BLS_CTRL, id);
	new_control &= ISP_BLS_ENA;

	pval = &arg->bls1_val;
	if (arg->bls1_en) {
		new_control |= ISP_BLS_BLS1_EN;

		switch (params_vdev->raw_type) {
		case RAW_BGGR:
			isp3_param_write(params_vdev, pval->r, ISP_BLS1_D_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS1_C_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS1_B_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS1_A_FIXED, id);
			break;
		case RAW_GBRG:
			isp3_param_write(params_vdev, pval->r, ISP_BLS1_C_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS1_D_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS1_A_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS1_B_FIXED, id);
			break;
		case RAW_GRBG:
			isp3_param_write(params_vdev, pval->r, ISP_BLS1_B_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS1_A_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS1_D_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS1_C_FIXED, id);
			break;
		case RAW_RGGB:
		default:
			isp3_param_write(params_vdev, pval->r, ISP_BLS1_A_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS1_B_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS1_C_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS1_D_FIXED, id);
			break;
		}
	}

	/* fixed subtraction values */
	pval = &arg->fixed_val;
	if (!arg->enable_auto) {
		switch (params_vdev->raw_type) {
		case RAW_BGGR:
			isp3_param_write(params_vdev, pval->r, ISP_BLS_D_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS_C_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS_B_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS_A_FIXED, id);
			break;
		case RAW_GBRG:
			isp3_param_write(params_vdev, pval->r, ISP_BLS_C_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS_D_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS_A_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS_B_FIXED, id);
			break;
		case RAW_GRBG:
			isp3_param_write(params_vdev, pval->r, ISP_BLS_B_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS_A_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS_D_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS_C_FIXED, id);
			break;
		case RAW_RGGB:
		default:
			isp3_param_write(params_vdev, pval->r, ISP_BLS_A_FIXED, id);
			isp3_param_write(params_vdev, pval->gr, ISP_BLS_B_FIXED, id);
			isp3_param_write(params_vdev, pval->gb, ISP_BLS_C_FIXED, id);
			isp3_param_write(params_vdev, pval->b, ISP_BLS_D_FIXED, id);
			break;
		}
	} else {
		if (arg->en_windows & BIT(1)) {
			isp3_param_write(params_vdev, arg->bls_window2.h_offs, ISP3X_BLS_H2_START, id);
			value = arg->bls_window2.h_offs + arg->bls_window2.h_size;
			isp3_param_write(params_vdev, value, ISP3X_BLS_H2_STOP, id);
			isp3_param_write(params_vdev, arg->bls_window2.v_offs, ISP3X_BLS_V2_START, id);
			value = arg->bls_window2.v_offs + arg->bls_window2.v_size;
			isp3_param_write(params_vdev, value, ISP3X_BLS_V2_STOP, id);
			new_control |= ISP_BLS_WINDOW_2;
		}

		if (arg->en_windows & BIT(0)) {
			isp3_param_write(params_vdev, arg->bls_window1.h_offs, ISP3X_BLS_H1_START, id);
			value = arg->bls_window1.h_offs + arg->bls_window1.h_size;
			isp3_param_write(params_vdev, value, ISP3X_BLS_H1_STOP, id);
			isp3_param_write(params_vdev, arg->bls_window1.v_offs, ISP3X_BLS_V1_START, id);
			value = arg->bls_window1.v_offs + arg->bls_window1.v_size;
			isp3_param_write(params_vdev, value, ISP3X_BLS_V1_STOP, id);
			new_control |= ISP_BLS_WINDOW_1;
		}

		isp3_param_write(params_vdev, arg->bls_samples, ISP3X_BLS_SAMPLES, id);

		new_control |= ISP_BLS_MODE_MEASURED;
	}
	isp3_param_write(params_vdev, new_control, ISP3X_BLS_CTRL, id);
}

static void
isp_bls_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	u32 new_control;

	new_control = isp3_param_read(params_vdev, ISP3X_BLS_CTRL, id);
	if (en)
		new_control |= ISP_BLS_ENA;
	else
		new_control &= ~ISP_BLS_ENA;
	isp3_param_write(params_vdev, new_control, ISP3X_BLS_CTRL, id);
}

static void
isp_sdg_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp2x_sdg_cfg *arg, u32 id)
{
	int i;

	isp3_param_write(params_vdev, arg->xa_pnts.gamma_dx0, ISP3X_ISP_GAMMA_DX_LO, id);
	isp3_param_write(params_vdev, arg->xa_pnts.gamma_dx1, ISP3X_ISP_GAMMA_DX_HI, id);

	for (i = 0; i < ISP3X_DEGAMMA_CURVE_SIZE; i++) {
		isp3_param_write(params_vdev, arg->curve_r.gamma_y[i],
				 ISP3X_ISP_GAMMA_R_Y_0 + i * 4, id);
		isp3_param_write(params_vdev, arg->curve_g.gamma_y[i],
				 ISP3X_ISP_GAMMA_G_Y_0 + i * 4, id);
		isp3_param_write(params_vdev, arg->curve_b.gamma_y[i],
				 ISP3X_ISP_GAMMA_B_Y_0 + i * 4, id);
	}
}

static void
isp_sdg_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	if (en) {
		isp3_param_set_bits(params_vdev,
				    ISP3X_ISP_CTRL0,
				    CIF_ISP_CTRL_ISP_GAMMA_IN_ENA, id);
	} else {
		isp3_param_clear_bits(params_vdev,
				      ISP3X_ISP_CTRL0,
				      CIF_ISP_CTRL_ISP_GAMMA_IN_ENA, id);
	}
}

static void
isp_lsc_matrix_cfg_sram(struct rkisp_isp_params_vdev *params_vdev,
			const struct isp3x_lsc_cfg *pconfig,
			bool is_check, u32 id)
{
	struct rkisp_device *dev = params_vdev->dev;
	u32 sram_addr, data, table;
	int i, j;

	if (is_check &&
	    !(isp3_param_read(params_vdev, ISP3X_LSC_CTRL, id) & ISP_LSC_EN))
		return;

	table = isp3_param_read_direct(params_vdev, ISP3X_LSC_STATUS, id);
	table &= ISP3X_LSC_ACTIVE_TABLE;
	/* default table 0 for multi device */
	if (!dev->hw_dev->is_single)
		table = ISP3X_LSC_ACTIVE_TABLE;

	/* CIF_ISP_LSC_TABLE_ADDRESS_153 = ( 17 * 18 ) >> 1 */
	sram_addr = table ? ISP3X_LSC_TABLE_ADDRESS_0 : CIF_ISP_LSC_TABLE_ADDRESS_153;
	isp3_param_write_direct(params_vdev, sram_addr, ISP3X_LSC_R_TABLE_ADDR, id);
	isp3_param_write_direct(params_vdev, sram_addr, ISP3X_LSC_GR_TABLE_ADDR, id);
	isp3_param_write_direct(params_vdev, sram_addr, ISP3X_LSC_GB_TABLE_ADDR, id);
	isp3_param_write_direct(params_vdev, sram_addr, ISP3X_LSC_B_TABLE_ADDR, id);

	/* program data tables (table size is 9 * 17 = 153) */
	for (i = 0; i < CIF_ISP_LSC_SECTORS_MAX * CIF_ISP_LSC_SECTORS_MAX;
	     i += CIF_ISP_LSC_SECTORS_MAX) {
		/*
		 * 17 sectors with 2 values in one DWORD = 9
		 * DWORDs (2nd value of last DWORD unused)
		 */
		for (j = 0; j < CIF_ISP_LSC_SECTORS_MAX - 1; j += 2) {
			data = ISP_ISP_LSC_TABLE_DATA(pconfig->r_data_tbl[i + j],
						      pconfig->r_data_tbl[i + j + 1]);
			isp3_param_write_direct(params_vdev, data, ISP3X_LSC_R_TABLE_DATA, id);

			data = ISP_ISP_LSC_TABLE_DATA(pconfig->gr_data_tbl[i + j],
						      pconfig->gr_data_tbl[i + j + 1]);
			isp3_param_write_direct(params_vdev, data, ISP3X_LSC_GR_TABLE_DATA, id);

			data = ISP_ISP_LSC_TABLE_DATA(pconfig->gb_data_tbl[i + j],
						      pconfig->gb_data_tbl[i + j + 1]);
			isp3_param_write_direct(params_vdev, data, ISP3X_LSC_GB_TABLE_DATA, id);

			data = ISP_ISP_LSC_TABLE_DATA(pconfig->b_data_tbl[i + j],
						      pconfig->b_data_tbl[i + j + 1]);
			isp3_param_write_direct(params_vdev, data, ISP3X_LSC_B_TABLE_DATA, id);
		}

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->r_data_tbl[i + j], 0);
		isp3_param_write_direct(params_vdev, data, ISP3X_LSC_R_TABLE_DATA, id);

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->gr_data_tbl[i + j], 0);
		isp3_param_write_direct(params_vdev, data, ISP3X_LSC_GR_TABLE_DATA, id);

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->gb_data_tbl[i + j], 0);
		isp3_param_write_direct(params_vdev, data, ISP3X_LSC_GB_TABLE_DATA, id);

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->b_data_tbl[i + j], 0);
		isp3_param_write_direct(params_vdev, data, ISP3X_LSC_B_TABLE_DATA, id);
	}
	isp3_param_write_direct(params_vdev, !table, ISP3X_LSC_TABLE_SEL, id);
}

static void
isp_lsc_cfg_sram_task(unsigned long data)
{
	struct rkisp_isp_params_vdev *params_vdev =
		(struct rkisp_isp_params_vdev *)data;
	struct isp3x_isp_params_cfg *params = params_vdev->isp3x_params;

	isp_lsc_matrix_cfg_sram(params_vdev, &params->others.lsc_cfg, true, 0);
	if (params_vdev->dev->hw_dev->is_unite) {
		params++;
		isp_lsc_matrix_cfg_sram(params_vdev, &params->others.lsc_cfg, true, 1);
	}
}

static void
isp_lsc_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp3x_lsc_cfg *arg, u32 id)
{
	struct rkisp_isp_params_val_v3x *priv_val =
		(struct rkisp_isp_params_val_v3x *)params_vdev->priv_val;
	struct isp3x_isp_params_cfg *params_rec = params_vdev->isp3x_params + id;
	struct rkisp_device *dev = params_vdev->dev;
	unsigned int data;
	u32 lsc_ctrl;
	int i;

	/* To config must be off , store the current status firstly */
	lsc_ctrl = isp3_param_read(params_vdev, ISP3X_LSC_CTRL, id);
	isp3_param_clear_bits(params_vdev, ISP3X_LSC_CTRL, ISP_LSC_EN | BIT(2), id);
	params_rec->others.lsc_cfg = *arg;
	if (dev->hw_dev->is_single) {
		if (lsc_ctrl & ISP_LSC_EN) {
			/* latest config for ISP3_LEFT, unite isp or single isp */
			if (id == ISP3_LEFT)
				tasklet_schedule(&priv_val->lsc_tasklet);
		} else {
			isp_lsc_matrix_cfg_sram(params_vdev, arg, false, id);
		}
	}

	for (i = 0; i < ISP3X_LSC_SIZE_TBL_SIZE / 4; i++) {
		/* program x size tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->x_size_tbl[i * 2],
					     arg->x_size_tbl[i * 2 + 1]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_XSIZE_01 + i * 4, id);
		data = CIF_ISP_LSC_SECT_SIZE(arg->x_size_tbl[i * 2 + 8],
					     arg->x_size_tbl[i * 2 + 9]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_XSIZE_89 + i * 4, id);

		/* program x grad tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->x_grad_tbl[i * 2],
					     arg->x_grad_tbl[i * 2 + 1]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_XGRAD_01 + i * 4, id);
		data = CIF_ISP_LSC_SECT_SIZE(arg->x_grad_tbl[i * 2 + 8],
					     arg->x_grad_tbl[i * 2 + 9]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_XGRAD_89 + i * 4, id);

		/* program y size tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->y_size_tbl[i * 2],
					     arg->y_size_tbl[i * 2 + 1]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_YSIZE_01 + i * 4, id);
		data = CIF_ISP_LSC_SECT_SIZE(arg->y_size_tbl[i * 2 + 8],
					     arg->y_size_tbl[i * 2 + 9]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_YSIZE_89 + i * 4, id);

		/* program y grad tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->y_grad_tbl[i * 2],
					     arg->y_grad_tbl[i * 2 + 1]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_YGRAD_01 + i * 4, id);
		data = CIF_ISP_LSC_SECT_SIZE(arg->y_grad_tbl[i * 2 + 8],
					     arg->y_grad_tbl[i * 2 + 9]);
		isp3_param_write(params_vdev, data, ISP3X_LSC_YGRAD_89 + i * 4, id);
	}

	if (arg->sector_16x16)
		lsc_ctrl |= BIT(2);
	isp3_param_set_bits(params_vdev, ISP3X_LSC_CTRL, lsc_ctrl, id);
}

static void
isp_lsc_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	u32 val = ISP_LSC_EN;

	if (en) {
		isp3_param_set_bits(params_vdev, ISP3X_LSC_CTRL, val, id);
	} else {
		isp3_param_clear_bits(params_vdev, ISP3X_LSC_CTRL, ISP_LSC_EN, id);
		isp3_param_clear_bits(params_vdev, ISP3X_GAIN_CTRL, BIT(8), id);
	}
}

static void
isp_debayer_config(struct rkisp_isp_params_vdev *params_vdev,
		   const struct isp2x_debayer_cfg *arg, u32 id)
{
	u32 value;

	value = isp3_param_read(params_vdev, ISP3X_DEBAYER_CONTROL, id);
	value &= ISP_DEBAYER_EN;

	value |= (arg->filter_c_en & 0x01) << 8 |
		 (arg->filter_g_en & 0x01) << 4;
	isp3_param_write(params_vdev, value, ISP3X_DEBAYER_CONTROL, id);

	value = (arg->thed1 & 0x0F) << 12 |
		(arg->thed0 & 0x0F) << 8 |
		(arg->dist_scale & 0x0F) << 4 |
		(arg->max_ratio & 0x07) << 1 |
		(arg->clip_en & 0x01);
	isp3_param_write(params_vdev, value, ISP3X_DEBAYER_G_INTERP, id);

	value = (arg->filter1_coe5 & 0x0F) << 16 |
		(arg->filter1_coe4 & 0x0F) << 12 |
		(arg->filter1_coe3 & 0x0F) << 8 |
		(arg->filter1_coe2 & 0x0F) << 4 |
		(arg->filter1_coe1 & 0x0F);
	isp3_param_write(params_vdev, value, ISP3X_DEBAYER_G_INTERP_FILTER1, id);

	value = (arg->filter2_coe5 & 0x0F) << 16 |
		(arg->filter2_coe4 & 0x0F) << 12 |
		(arg->filter2_coe3 & 0x0F) << 8 |
		(arg->filter2_coe2 & 0x0F) << 4 |
		(arg->filter2_coe1 & 0x0F);
	isp3_param_write(params_vdev, value, ISP3X_DEBAYER_G_INTERP_FILTER2, id);

	value = (arg->hf_offset & 0xFFFF) << 16 |
		(arg->gain_offset & 0x0F) << 8 |
		(arg->offset & 0x1F);
	isp3_param_write(params_vdev, value, ISP3X_DEBAYER_OFFSET, id);

	value = (arg->shift_num & 0x03) << 16 |
		(arg->order_max & 0x1F) << 8 |
		(arg->order_min & 0x1F);
	isp3_param_write(params_vdev, value, ISP3X_DEBAYER_C_FILTER, id);
}

static void
isp_debayer_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	if (en)
		isp3_param_set_bits(params_vdev,
				    ISP3X_DEBAYER_CONTROL,
				    ISP3X_MODULE_EN, id);
	else
		isp3_param_clear_bits(params_vdev,
				      ISP3X_DEBAYER_CONTROL,
				      ISP3X_MODULE_EN, id);
}

static void
isp_awbgain_config(struct rkisp_isp_params_vdev *params_vdev,
		   const struct isp21_awb_gain_cfg *arg, u32 id)
{
	struct rkisp_device *dev = params_vdev->dev;

	if (!arg->gain0_red || !arg->gain0_blue ||
	    !arg->gain1_red || !arg->gain1_blue ||
	    !arg->gain2_red || !arg->gain2_blue ||
	    !arg->gain0_green_r || !arg->gain0_green_b ||
	    !arg->gain1_green_r || !arg->gain1_green_b ||
	    !arg->gain2_green_r || !arg->gain2_green_b) {
		dev_err(dev->dev, "awb gain is zero!\n");
		return;
	}

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->gain0_green_b, arg->gain0_green_r),
			 ISP3X_ISP_AWB_GAIN0_G, id);
	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->gain0_blue, arg->gain0_red),
			 ISP3X_ISP_AWB_GAIN0_RB, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->gain1_green_b, arg->gain1_green_r),
			 ISP3X_ISP_AWB_GAIN1_G, id);
	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->gain1_blue, arg->gain1_red),
			 ISP3X_ISP_AWB_GAIN1_RB, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->gain2_green_b, arg->gain2_green_r),
			 ISP3X_ISP_AWB_GAIN2_G, id);
	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->gain2_blue, arg->gain2_red),
			 ISP3X_ISP_AWB_GAIN2_RB, id);
}

static void
isp_awbgain_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	if (en)
		isp3_param_set_bits(params_vdev, ISP3X_ISP_CTRL0,
				    CIF_ISP_CTRL_ISP_AWB_ENA, id);
	else
		isp3_param_clear_bits(params_vdev, ISP3X_ISP_CTRL0,
				      CIF_ISP_CTRL_ISP_AWB_ENA, id);
}

static void
isp_ccm_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp21_ccm_cfg *arg, u32 id)
{
	u32 value;
	u32 i;

	value = isp3_param_read(params_vdev, ISP3X_CCM_CTRL, id);
	value &= ISP_CCM_EN;

	value |= (arg->highy_adjust_dis & 0x01) << 1;
	isp3_param_write(params_vdev, value, ISP3X_CCM_CTRL, id);

	value = ISP_PACK_2SHORT(arg->coeff0_r, arg->coeff1_r);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF0_R, id);

	value = ISP_PACK_2SHORT(arg->coeff2_r, arg->offset_r);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF1_R, id);

	value = ISP_PACK_2SHORT(arg->coeff0_g, arg->coeff1_g);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF0_G, id);

	value = ISP_PACK_2SHORT(arg->coeff2_g, arg->offset_g);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF1_G, id);

	value = ISP_PACK_2SHORT(arg->coeff0_b, arg->coeff1_b);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF0_B, id);

	value = ISP_PACK_2SHORT(arg->coeff2_b, arg->offset_b);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF1_B, id);

	value = ISP_PACK_2SHORT(arg->coeff0_y, arg->coeff1_y);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF0_Y, id);

	value = ISP_PACK_2SHORT(arg->coeff2_y, 0);
	isp3_param_write(params_vdev, value, ISP3X_CCM_COEFF1_Y, id);

	for (i = 0; i < ISP3X_CCM_CURVE_NUM / 2; i++) {
		value = ISP_PACK_2SHORT(arg->alp_y[2 * i], arg->alp_y[2 * i + 1]);
		isp3_param_write(params_vdev, value, ISP3X_CCM_ALP_Y0 + 4 * i, id);
	}
	value = ISP_PACK_2SHORT(arg->alp_y[2 * i], 0);
	isp3_param_write(params_vdev, value, ISP3X_CCM_ALP_Y0 + 4 * i, id);

	value = arg->bound_bit & 0x0F;
	isp3_param_write(params_vdev, value, ISP3X_CCM_BOUND_BIT, id);
}

static void
isp_ccm_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	if (en)
		isp3_param_set_bits(params_vdev, ISP3X_CCM_CTRL, ISP_CCM_EN, id);
	else
		isp3_param_clear_bits(params_vdev, ISP3X_CCM_CTRL, ISP_CCM_EN, id);
}

static void
isp_goc_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp3x_gammaout_cfg *arg, u32 id)
{
	int i;
	u32 value;

	value = isp3_param_read(params_vdev, ISP3X_GAMMA_OUT_CTRL, id);
	value &= ISP3X_GAMMA_OUT_EN;
	value |= (arg->equ_segm & 0x1) << 1 |
		(arg->finalx4_dense_en & 0x1) << 2;
	isp3_param_write(params_vdev, value, ISP3X_GAMMA_OUT_CTRL, id);

	isp3_param_write(params_vdev, arg->offset, ISP3X_GAMMA_OUT_OFFSET, id);
	for (i = 0; i < ISP3X_GAMMA_OUT_MAX_SAMPLES / 2; i++) {
		value = ISP_PACK_2SHORT(arg->gamma_y[2 * i],
					arg->gamma_y[2 * i + 1]);
		isp3_param_write(params_vdev, value, ISP3X_GAMMA_OUT_Y0 + i * 4, id);
	}
	isp3_param_write(params_vdev, arg->gamma_y[2 * i], ISP3X_GAMMA_OUT_Y0 + i * 4, id);
}

static void
isp_goc_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	if (en)
		isp3_param_set_bits(params_vdev, ISP3X_GAMMA_OUT_CTRL,
				    ISP3X_GAMMA_OUT_EN, id);
	else
		isp3_param_clear_bits(params_vdev, ISP3X_GAMMA_OUT_CTRL,
				      ISP3X_GAMMA_OUT_EN, id);
}

static void
isp_cproc_config(struct rkisp_isp_params_vdev *params_vdev,
		 const struct isp2x_cproc_cfg *arg, u32 id)
{
	struct isp3x_isp_params_cfg *params = params_vdev->isp3x_params + id;
	struct isp3x_isp_other_cfg *cur_other_cfg = &params->others;
	struct isp2x_ie_cfg *cur_ie_config = &cur_other_cfg->ie_cfg;
	u32 effect = cur_ie_config->effect;
	u32 quantization = params_vdev->quantization;

	isp3_param_write(params_vdev, arg->contrast, ISP3X_CPROC_CONTRAST, id);
	isp3_param_write(params_vdev, arg->hue, ISP3X_CPROC_HUE, id);
	isp3_param_write(params_vdev, arg->sat, ISP3X_CPROC_SATURATION, id);
	isp3_param_write(params_vdev, arg->brightness, ISP3X_CPROC_BRIGHTNESS, id);

	if (quantization != V4L2_QUANTIZATION_FULL_RANGE ||
	    effect != V4L2_COLORFX_NONE) {
		isp3_param_clear_bits(params_vdev, ISP3X_CPROC_CTRL,
				      CIF_C_PROC_YOUT_FULL |
				      CIF_C_PROC_YIN_FULL |
				      CIF_C_PROC_COUT_FULL, id);
	} else {
		isp3_param_set_bits(params_vdev, ISP3X_CPROC_CTRL,
				    CIF_C_PROC_YOUT_FULL |
				    CIF_C_PROC_YIN_FULL |
				    CIF_C_PROC_COUT_FULL, id);
	}
}

static void
isp_cproc_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	if (en)
		isp3_param_set_bits(params_vdev, ISP3X_CPROC_CTRL,
				    CIF_C_PROC_CTR_ENABLE, id);
	else
		isp3_param_clear_bits(params_vdev, ISP3X_CPROC_CTRL,
				      CIF_C_PROC_CTR_ENABLE, id);
}

static void
isp_ie_config(struct rkisp_isp_params_vdev *params_vdev,
	      const struct isp2x_ie_cfg *arg, u32 id)
{
	u32 eff_ctrl;

	eff_ctrl = isp3_param_read(params_vdev, ISP3X_IMG_EFF_CTRL, id);
	eff_ctrl &= ~CIF_IMG_EFF_CTRL_MODE_MASK;

	if (params_vdev->quantization == V4L2_QUANTIZATION_FULL_RANGE)
		eff_ctrl |= CIF_IMG_EFF_CTRL_YCBCR_FULL;

	switch (arg->effect) {
	case V4L2_COLORFX_SEPIA:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_SEPIA;
		break;
	case V4L2_COLORFX_SET_CBCR:
		isp3_param_write(params_vdev, arg->eff_tint, ISP3X_IMG_EFF_TINT, id);
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_SEPIA;
		break;
		/*
		 * Color selection is similar to water color(AQUA):
		 * grayscale + selected color w threshold
		 */
	case V4L2_COLORFX_AQUA:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_COLOR_SEL;
		isp3_param_write(params_vdev, arg->color_sel,
				 ISP3X_IMG_EFF_COLOR_SEL, id);
		break;
	case V4L2_COLORFX_EMBOSS:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_EMBOSS;
		isp3_param_write(params_vdev, arg->eff_mat_1,
				 CIF_IMG_EFF_MAT_1, id);
		isp3_param_write(params_vdev, arg->eff_mat_2,
				 CIF_IMG_EFF_MAT_2, id);
		isp3_param_write(params_vdev, arg->eff_mat_3,
				 CIF_IMG_EFF_MAT_3, id);
		break;
	case V4L2_COLORFX_SKETCH:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_SKETCH;
		isp3_param_write(params_vdev, arg->eff_mat_3,
				 CIF_IMG_EFF_MAT_3, id);
		isp3_param_write(params_vdev, arg->eff_mat_4,
				 CIF_IMG_EFF_MAT_4, id);
		isp3_param_write(params_vdev, arg->eff_mat_5,
				 CIF_IMG_EFF_MAT_5, id);
		break;
	case V4L2_COLORFX_BW:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_BLACKWHITE;
		break;
	case V4L2_COLORFX_NEGATIVE:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_NEGATIVE;
		break;
	default:
		break;
	}

	isp3_param_write(params_vdev, eff_ctrl, ISP3X_IMG_EFF_CTRL, id);
}

static void
isp_ie_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	if (en) {
		isp3_param_set_bits(params_vdev, ISP3X_IMG_EFF_CTRL,
				    CIF_IMG_EFF_CTRL_CFG_UPD |
				    CIF_IMG_EFF_CTRL_ENABLE, id);
	} else {
		isp3_param_clear_bits(params_vdev, ISP3X_IMG_EFF_CTRL,
				      CIF_IMG_EFF_CTRL_ENABLE, id);
	}
}

static void
isp_rawaebig_config_foraf(struct rkisp_isp_params_vdev *params_vdev,
		    const struct isp3x_rawaf_meas_cfg *arg, u32 id)
{
	u32 block_hsize, block_vsize;
	u32 addr, value;
	u32 wnd_num_idx = 2;
	const u32 ae_wnd_num[] = {
		1, 5, 15, 15
	};

	addr = ISP3X_RAWAE_BIG1_BASE;
	value = isp3_param_read(params_vdev, addr + ISP3X_RAWAE_BIG_CTRL, id);
	value &= ISP3X_RAWAE_BIG_EN;

	value |= ISP3X_RAWAE_BIG_WND0_NUM(wnd_num_idx);
	isp3_param_write(params_vdev, value, addr + ISP3X_RAWAE_BIG_CTRL, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->win[0].h_offs, arg->win[0].v_offs),
			 addr + ISP3X_RAWAE_BIG_OFFSET, id);

	block_hsize = arg->win[0].h_size / ae_wnd_num[wnd_num_idx];
	block_vsize = arg->win[0].v_size / ae_wnd_num[wnd_num_idx];
	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(block_hsize, block_vsize),
			 addr + ISP3X_RAWAE_BIG_BLK_SIZE, id);
}

static void
isp_rawaf_config(struct rkisp_isp_params_vdev *params_vdev,
		 const struct isp3x_rawaf_meas_cfg *arg, u32 id)
{
	u32 i, var, ctrl;
	u16 h_size, v_size;
	u16 h_offs, v_offs;
	u8 gaus_en, viir_en, v1_fir_sel;
	size_t num_of_win = min_t(size_t, ARRAY_SIZE(arg->win),
				  arg->num_afm_win);

	for (i = 0; i < num_of_win; i++) {
		h_size = arg->win[i].h_size;
		v_size = arg->win[i].v_size;
		h_offs = arg->win[i].h_offs < 2 ? 2 : arg->win[i].h_offs;
		v_offs = arg->win[i].v_offs < 1 ? 1 : arg->win[i].v_offs;

		if (i == 0) {
			h_size = h_size / 15 * 15;
			v_size = v_size / 15 * 15;
		}

		/*
		 * (horizontal left row), value must be greater or equal 2
		 * (vertical top line), value must be greater or equal 1
		 */
		isp3_param_write(params_vdev,
				 ISP_PACK_2SHORT(v_offs, h_offs),
				 ISP3X_RAWAF_OFFSET_WINA + i * 8, id);

		/*
		 * value must be smaller than [width of picture -2]
		 * value must be lower than (number of lines -2)
		 */
		isp3_param_write(params_vdev,
				 ISP_PACK_2SHORT(v_size, h_size),
				 ISP3X_RAWAF_SIZE_WINA + i * 8, id);
	}

	var = 0;
	for (i = 0; i < ISP3X_RAWAF_LINE_NUM; i++) {
		if (arg->line_en[i])
			var |= ISP3X_RAWAF_INTLINE0_EN << i;
		var |= ISP3X_RAWAF_INELINE0(arg->line_num[i]) << 4 * i;
	}
	isp3_param_write(params_vdev, var, ISP3X_RAWAF_INT_LINE, id);

	var = isp3_param_read(params_vdev, ISP3X_RAWAF_THRES, id);
	var &= ~0xFFFF;
	var |= arg->afm_thres;
	isp3_param_write(params_vdev, var, ISP3X_RAWAF_THRES, id);

	var = (arg->lum_var_shift[1] & 0x7) << 20 | (arg->lum_var_shift[0] & 0x7) << 16 |
		(arg->afm_var_shift[1] & 0x7) << 4 | (arg->afm_var_shift[0] & 0x7);
	isp3_param_write(params_vdev, var, ISP3X_RAWAF_VAR_SHIFT, id);

	for (i = 0; i < ISP3X_RAWAF_GAMMA_NUM / 2; i++) {
		var = ISP_PACK_2SHORT(arg->gamma_y[2 * i], arg->gamma_y[2 * i + 1]);
		isp3_param_write(params_vdev, var, ISP3X_RAWAF_GAMMA_Y0 + i * 4, id);
	}
	var = ISP_PACK_2SHORT(arg->gamma_y[16], 0);
	isp3_param_write(params_vdev, var, ISP3X_RAWAF_GAMMA_Y8, id);

	var = (arg->v2iir_var_shift & 0x7) << 12 | (arg->v1iir_var_shift & 0x7) << 8 |
		(arg->h2iir_var_shift & 0x7) << 4 | (arg->h1iir_var_shift & 0x7);
	isp3_param_write(params_vdev, var, ISP3X_RAWAF_HVIIR_VAR_SHIFT, id);

	var = ISP_PACK_2SHORT(arg->h_fv_thresh, arg->v_fv_thresh);
	isp3_param_write(params_vdev, var, ISP3X_RAWAF_HIIR_THRESH, id);

	for (i = 0; i < ISP3X_RAWAF_VFIR_COE_NUM; i++) {
		var = ISP_PACK_2SHORT(arg->v1fir_coe[i], arg->v2fir_coe[i]);
		isp3_param_write(params_vdev, var, ISP3X_RAWAF_V_FIR_COE0 + i * 4, id);
	}

	isp3_param_write(params_vdev, arg->highlit_thresh, ISP3X_RAWAF_HIGHLIT_THRESH, id);

	viir_en = arg->viir_en;
	gaus_en = arg->gaus_en;
	v1_fir_sel = arg->v1_fir_sel;
	if (gaus_en == 0)
		viir_en = 0;
	if (viir_en == 0)
		v1_fir_sel = 0;

	ctrl = isp3_param_read(params_vdev, ISP3X_RAWAF_CTRL, id);
	ctrl &= ISP3X_RAWAF_EN;
	if (arg->hiir_en) {
		ctrl |= ISP3X_RAWAF_HIIR_EN;
		for (i = 0; i < ISP3X_RAWAF_HIIR_COE_NUM / 2; i++) {
			var = ISP_PACK_2SHORT(arg->h1iir1_coe[i * 2], arg->h1iir1_coe[i * 2 + 1]);
			isp3_param_write(params_vdev, var, ISP3X_RAWAF_H1_IIR1_COE01 + i * 4, id);
			var = ISP_PACK_2SHORT(arg->h1iir2_coe[i * 2], arg->h1iir2_coe[i * 2 + 1]);
			isp3_param_write(params_vdev, var, ISP3X_RAWAF_H1_IIR2_COE01 + i * 4, id);
			var = ISP_PACK_2SHORT(arg->h2iir1_coe[i * 2], arg->h2iir1_coe[i * 2 + 1]);
			isp3_param_write(params_vdev, var, ISP3X_RAWAF_H2_IIR1_COE01 + i * 4, id);
			var = ISP_PACK_2SHORT(arg->h2iir2_coe[i * 2], arg->h2iir2_coe[i * 2 + 1]);
			isp3_param_write(params_vdev, var, ISP3X_RAWAF_H2_IIR2_COE01 + i * 4, id);
		}
	}
	if (viir_en) {
		ctrl |= ISP3X_RAWAF_VIIR_EN;
		for (i = 0; i < ISP3X_RAWAF_V2IIR_COE_NUM; i++) {
			var = ISP_PACK_2SHORT(arg->v1iir_coe[i], arg->v2iir_coe[i]);
			isp3_param_write(params_vdev, var, ISP3X_RAWAF_V_IIR_COE0 + i * 4, id);
		}
		for (; i < ISP3X_RAWAF_V1IIR_COE_NUM; i++) {
			var = ISP_PACK_2SHORT(arg->v1iir_coe[i], 0);
			isp3_param_write(params_vdev, var, ISP3X_RAWAF_V_IIR_COE0 + i * 4, id);
		}
	}
	if (arg->ldg_en) {
		ctrl |= ISP3X_RAWAF_LDG_EN;
		for (i = 0; i < ISP3X_RAWAF_CURVE_NUM; i++) {
			isp3_param_write(params_vdev,
					 arg->curve_h[i].ldg_lumth |
					 arg->curve_h[i].ldg_gain << 8 |
					 arg->curve_h[i].ldg_gslp << 16,
					 ISP3X_RAWAF_H_CURVEL + i * 16, id);
			isp3_param_write(params_vdev,
					 arg->curve_v[i].ldg_lumth |
					 arg->curve_v[i].ldg_gain << 8 |
					 arg->curve_v[i].ldg_gslp << 16,
					 ISP3X_RAWAF_V_CURVEL + i * 16, id);
		}
	}

	ctrl |= (arg->y_mode & 0x1) << 13 |
		(arg->ae_mode & 0x1) << 12 |
		(arg->v2_fv_mode & 0x1) << 11 |
		(arg->v1_fv_mode & 0x1) << 10 |
		(arg->h2_fv_mode & 0x1) << 9 |
		(arg->h1_fv_mode & 0x1) << 8 |
		(arg->accu_8bit_mode & 0x1) << 6 |
		(v1_fir_sel & 0x1) << 3 |
		(gaus_en & 0x1) << 2 |
		(arg->gamma_en & 0x1) << 1;
	isp3_param_write(params_vdev, ctrl, ISP3X_RAWAF_CTRL, id);

	ctrl = isp3_param_read(params_vdev, ISP3X_VI_ISP_PATH, id);
	ctrl &= ~(ISP3X_RAWAF_SEL(3));
	ctrl |= ISP3X_RAWAF_SEL(arg->rawaf_sel);
	isp3_param_write(params_vdev, ctrl, ISP3X_VI_ISP_PATH, id);

	params_vdev->afaemode_en = arg->ae_mode;
	if (params_vdev->afaemode_en)
		isp_rawaebig_config_foraf(params_vdev, arg, id);
}

static void
isp_rawaebig_enable_foraf(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	u32 exp_ctrl;
	u32 addr = ISP3X_RAWAE_BIG1_BASE;

	exp_ctrl = isp3_param_read(params_vdev, addr + ISP3X_RAWAE_BIG_CTRL, id);
	exp_ctrl &= ~ISP3X_REG_WR_MASK;
	if (en)
		exp_ctrl |= ISP3X_MODULE_EN;
	else
		exp_ctrl &= ~ISP3X_MODULE_EN;

	isp3_param_write(params_vdev, exp_ctrl, addr + ISP3X_RAWAE_BIG_CTRL, id);
}

static void
isp_rawaf_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	u32 afm_ctrl = isp3_param_read(params_vdev, ISP3X_RAWAF_CTRL, id);

	afm_ctrl &= ~ISP3X_REG_WR_MASK;
	if (en)
		afm_ctrl |= ISP3X_RAWAF_EN;
	else
		afm_ctrl &= ~ISP3X_RAWAF_EN;

	isp3_param_write(params_vdev, afm_ctrl, ISP3X_RAWAF_CTRL, id);
	if (params_vdev->afaemode_en) {
		isp_rawaebig_enable_foraf(params_vdev, en, id);
		if (!en)
			params_vdev->afaemode_en = false;
	}
}

static void
isp_rawaelite_config(struct rkisp_isp_params_vdev *params_vdev,
		     const struct isp2x_rawaelite_meas_cfg *arg, u32 id)
{
	struct rkisp_device *ispdev = params_vdev->dev;
	struct v4l2_rect *out_crop = &ispdev->isp_sdev.out_crop;
	u32 width = out_crop->width;
	u32 block_hsize, block_vsize, value;
	u32 wnd_num_idx = 0;
	const u32 ae_wnd_num[] = {1, 5};

	value = isp3_param_read(params_vdev, ISP3X_RAWAE_LITE_CTRL, id);
	value &= ~(ISP3X_RAWAE_LITE_WNDNUM);
	if (arg->wnd_num) {
		value |= ISP3X_RAWAE_LITE_WNDNUM;
		wnd_num_idx = 1;
	}
	value &= ~ISP3X_REG_WR_MASK;
	isp3_param_write(params_vdev, value, ISP3X_RAWAE_LITE_CTRL, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->win.h_offs, arg->win.v_offs),
			 ISP3X_RAWAE_LITE_OFFSET, id);

	block_hsize = arg->win.h_size / ae_wnd_num[wnd_num_idx];
	value = block_hsize * ae_wnd_num[wnd_num_idx] + arg->win.h_offs;
	if (ispdev->hw_dev->is_unite)
		width = width / 2 + RKMOUDLE_UNITE_EXTEND_PIXEL;
	if (value + 1 > width)
		block_hsize -= 1;
	block_vsize = arg->win.v_size / ae_wnd_num[wnd_num_idx];
	value = block_vsize * ae_wnd_num[wnd_num_idx] + arg->win.v_offs;
	if (value + 2 > out_crop->height)
		block_vsize -= 1;
	if (block_vsize % 2)
		block_vsize -= 1;
	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(block_hsize, block_vsize),
			 ISP3X_RAWAE_LITE_BLK_SIZ, id);

	value = isp3_param_read(params_vdev, ISP3X_VI_ISP_PATH, id);
	value &= ~(ISP3X_RAWAE012_SEL(3));
	value |= ISP3X_RAWAE012_SEL(arg->rawae_sel);
	isp3_param_write(params_vdev, value, ISP3X_VI_ISP_PATH, id);
}

static void
isp_rawaelite_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	u32 exp_ctrl;

	exp_ctrl = isp3_param_read(params_vdev, ISP3X_RAWAE_LITE_CTRL, id);
	exp_ctrl &= ~ISP3X_REG_WR_MASK;
	if (en)
		exp_ctrl |= ISP3X_RAWAE_LITE_EN;
	else
		exp_ctrl &= ~ISP3X_RAWAE_LITE_EN;

	isp3_param_write(params_vdev, exp_ctrl, ISP3X_RAWAE_LITE_CTRL, id);
}

static void
isp_rawaebig_config(struct rkisp_isp_params_vdev *params_vdev,
		    const struct isp2x_rawaebig_meas_cfg *arg,
		    u32 blk_no, u32 id)
{
	struct rkisp_device *ispdev = params_vdev->dev;
	struct v4l2_rect *out_crop = &ispdev->isp_sdev.out_crop;
	u32 width = out_crop->width;
	u32 block_hsize, block_vsize;
	u32 addr, i, value, h_size, v_size;
	u32 wnd_num_idx = 0;
	const u32 ae_wnd_num[] = {
		1, 5, 15, 15
	};

	switch (blk_no) {
	case 1:
		addr = ISP3X_RAWAE_BIG2_BASE;
		break;
	case 2:
		addr = ISP3X_RAWAE_BIG3_BASE;
		break;
	case 0:
	default:
		addr = ISP3X_RAWAE_BIG1_BASE;
		break;
	}

	/* avoid to override the old enable value */
	value = isp3_param_read(params_vdev, addr + ISP3X_RAWAE_BIG_CTRL, id);
	value &= ISP3X_RAWAE_BIG_EN;

	wnd_num_idx = arg->wnd_num;
	value |= ISP3X_RAWAE_BIG_WND0_NUM(wnd_num_idx);

	if (arg->subwin_en[0])
		value |= ISP3X_RAWAE_BIG_WND1_EN;
	if (arg->subwin_en[1])
		value |= ISP3X_RAWAE_BIG_WND2_EN;
	if (arg->subwin_en[2])
		value |= ISP3X_RAWAE_BIG_WND3_EN;
	if (arg->subwin_en[3])
		value |= ISP3X_RAWAE_BIG_WND4_EN;

	isp3_param_write(params_vdev, value, addr + ISP3X_RAWAE_BIG_CTRL, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->win.h_offs, arg->win.v_offs),
			 addr + ISP3X_RAWAE_BIG_OFFSET, id);

	block_hsize = arg->win.h_size / ae_wnd_num[wnd_num_idx];
	value = block_hsize * ae_wnd_num[wnd_num_idx] + arg->win.h_offs;
	if (ispdev->hw_dev->is_unite)
		width = width / 2 + RKMOUDLE_UNITE_EXTEND_PIXEL;
	if (value + 1 > width)
		block_hsize -= 1;
	block_vsize = arg->win.v_size / ae_wnd_num[wnd_num_idx];
	value = block_vsize * ae_wnd_num[wnd_num_idx] + arg->win.v_offs;
	if (value + 2 > out_crop->height)
		block_vsize -= 1;
	if (block_vsize % 2)
		block_vsize -= 1;
	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(block_hsize, block_vsize),
			 addr + ISP3X_RAWAE_BIG_BLK_SIZE, id);

	for (i = 0; i < ISP3X_RAWAEBIG_SUBWIN_NUM; i++) {
		isp3_param_write(params_vdev,
			ISP_PACK_2SHORT(arg->subwin[i].h_offs, arg->subwin[i].v_offs),
			addr + ISP3X_RAWAE_BIG_WND1_OFFSET + 8 * i, id);

		v_size = arg->subwin[i].v_size + arg->subwin[i].v_offs;
		h_size = arg->subwin[i].h_size + arg->subwin[i].h_offs;
		isp3_param_write(params_vdev,
			ISP_PACK_2SHORT(h_size, v_size),
			addr + ISP3X_RAWAE_BIG_WND1_SIZE + 8 * i, id);
	}

	if (blk_no == 0) {
		value = isp3_param_read(params_vdev, ISP3X_VI_ISP_PATH, id);
		value &= ~(ISP3X_RAWAE3_SEL(3));
		value |= ISP3X_RAWAE3_SEL(arg->rawae_sel);
		isp3_param_write(params_vdev, value, ISP3X_VI_ISP_PATH, id);
	} else {
		value = isp3_param_read(params_vdev, ISP3X_VI_ISP_PATH, id);
		value &= ~(ISP3X_RAWAE012_SEL(3));
		value |= ISP3X_RAWAE012_SEL(arg->rawae_sel);
		isp3_param_write(params_vdev, value, ISP3X_VI_ISP_PATH, id);
	}
}

static void
isp_rawaebig_enable(struct rkisp_isp_params_vdev *params_vdev,
		    bool en, u32 blk_no, u32 id)
{
	u32 exp_ctrl;
	u32 addr;

	switch (blk_no) {
	case 1:
		addr = ISP3X_RAWAE_BIG2_BASE;
		break;
	case 2:
		addr = ISP3X_RAWAE_BIG3_BASE;
		break;
	case 0:
	default:
		addr = ISP3X_RAWAE_BIG1_BASE;
		break;
	}

	exp_ctrl = isp3_param_read(params_vdev, addr + ISP3X_RAWAE_BIG_CTRL, id);
	exp_ctrl &= ~ISP3X_REG_WR_MASK;
	if (en)
		exp_ctrl |= ISP3X_MODULE_EN;
	else
		exp_ctrl &= ~ISP3X_MODULE_EN;

	isp3_param_write(params_vdev, exp_ctrl, addr + ISP3X_RAWAE_BIG_CTRL, id);
}

static void
isp_rawae1_config(struct rkisp_isp_params_vdev *params_vdev,
		  const struct isp2x_rawaebig_meas_cfg *arg, u32 id)
{
	isp_rawaebig_config(params_vdev, arg, 1, id);
}

static void
isp_rawae1_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	isp_rawaebig_enable(params_vdev, en, 1, id);
}

static void
isp_rawae2_config(struct rkisp_isp_params_vdev *params_vdev,
		  const struct isp2x_rawaebig_meas_cfg *arg, u32 id)
{
	isp_rawaebig_config(params_vdev, arg, 2, id);
}

static void
isp_rawae2_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	isp_rawaebig_enable(params_vdev, en, 2, id);
}

static void
isp_rawae3_config(struct rkisp_isp_params_vdev *params_vdev,
		  const struct isp2x_rawaebig_meas_cfg *arg, u32 id)
{
	isp_rawaebig_config(params_vdev, arg, 0, id);
}

static void
isp_rawae3_enable(struct rkisp_isp_params_vdev *params_vdev, bool en, u32 id)
{
	isp_rawaebig_enable(params_vdev, en, 0, id);
}

static void
isp_rawawb_config(struct rkisp_isp_params_vdev *params_vdev,
		  const struct isp3x_rawawb_meas_cfg *arg, u32 id)
{
	u32 i, value;

	isp3_param_write(params_vdev,
			 (arg->sw_rawawb_blk_measure_enable & 0x1) |
			 (arg->sw_rawawb_blk_measure_mode & 0x1) << 1 |
			 (arg->sw_rawawb_blk_measure_xytype & 0x1) << 2 |
			 (arg->sw_rawawb_blk_rtdw_measure_en & 0x1) << 3 |
			 (arg->sw_rawawb_blk_measure_illu_idx & 0x7) << 4 |
			 (arg->sw_rawawb_blk_with_luma_wei_en & 0x1) << 8,
			 ISP3X_RAWAWB_BLK_CTRL, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_h_offs, arg->sw_rawawb_v_offs),
			 ISP3X_RAWAWB_WIN_OFFS, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_h_size, arg->sw_rawawb_v_size),
			 ISP3X_RAWAWB_WIN_SIZE, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_r_max, arg->sw_rawawb_g_max),
			 ISP3X_RAWAWB_LIMIT_RG_MAX, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_b_max, arg->sw_rawawb_y_max),
			 ISP3X_RAWAWB_LIMIT_BY_MAX, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_r_min, arg->sw_rawawb_g_min),
			 ISP3X_RAWAWB_LIMIT_RG_MIN, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_b_min, arg->sw_rawawb_y_min),
			 ISP3X_RAWAWB_LIMIT_BY_MIN, id);

	isp3_param_write(params_vdev,
			 (arg->sw_rawawb_wp_luma_wei_en0 & 0x1) |
			 (arg->sw_rawawb_wp_luma_wei_en1 & 0x1) << 1 |
			 (arg->sw_rawawb_wp_blk_wei_en0 & 0x1) << 2 |
			 (arg->sw_rawawb_wp_blk_wei_en1 & 0x1) << 3 |
			 (arg->sw_rawawb_wp_hist_xytype & 0x1) << 4,
			 ISP3X_RAWAWB_WEIGHT_CURVE_CTRL, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_4BYTE(arg->sw_rawawb_wp_luma_weicurve_y0,
					arg->sw_rawawb_wp_luma_weicurve_y1,
					arg->sw_rawawb_wp_luma_weicurve_y2,
					arg->sw_rawawb_wp_luma_weicurve_y3),
			 ISP3X_RAWAWB_YWEIGHT_CURVE_XCOOR03, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_4BYTE(arg->sw_rawawb_wp_luma_weicurve_y4,
					arg->sw_rawawb_wp_luma_weicurve_y5,
					arg->sw_rawawb_wp_luma_weicurve_y6,
					arg->sw_rawawb_wp_luma_weicurve_y7),
			 ISP3X_RAWAWB_YWEIGHT_CURVE_XCOOR47, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_wp_luma_weicurve_y8,
			 ISP3X_RAWAWB_YWEIGHT_CURVE_XCOOR8, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_4BYTE(arg->sw_rawawb_wp_luma_weicurve_w0,
					arg->sw_rawawb_wp_luma_weicurve_w1,
					arg->sw_rawawb_wp_luma_weicurve_w2,
					arg->sw_rawawb_wp_luma_weicurve_w3),
			 ISP3X_RAWAWB_YWEIGHT_CURVE_YCOOR03, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_4BYTE(arg->sw_rawawb_wp_luma_weicurve_w4,
					arg->sw_rawawb_wp_luma_weicurve_w5,
					arg->sw_rawawb_wp_luma_weicurve_w6,
					arg->sw_rawawb_wp_luma_weicurve_w7),
			 ISP3X_RAWAWB_YWEIGHT_CURVE_YCOOR47, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_wp_luma_weicurve_w8,
					 arg->sw_rawawb_pre_wbgain_inv_r),
			 ISP3X_RAWAWB_YWEIGHT_CURVE_YCOOR8, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_pre_wbgain_inv_g,
					 arg->sw_rawawb_pre_wbgain_inv_b),
			 ISP3X_RAWAWB_PRE_WBGAIN_INV, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex0_u_0,
					 arg->sw_rawawb_vertex0_v_0),
			 ISP3X_RAWAWB_UV_DETC_VERTEX0_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex1_u_0,
					 arg->sw_rawawb_vertex1_v_0),
			 ISP3X_RAWAWB_UV_DETC_VERTEX1_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex2_u_0,
					 arg->sw_rawawb_vertex2_v_0),
			 ISP3X_RAWAWB_UV_DETC_VERTEX2_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex3_u_0,
					 arg->sw_rawawb_vertex3_v_0),
			 ISP3X_RAWAWB_UV_DETC_VERTEX3_0, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope01_0,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE01_0, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope12_0,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE12_0, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope23_0,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE23_0, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope30_0,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE30_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex0_u_1,
					 arg->sw_rawawb_vertex0_v_1),
			 ISP3X_RAWAWB_UV_DETC_VERTEX0_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex1_u_1,
					 arg->sw_rawawb_vertex1_v_1),
			 ISP3X_RAWAWB_UV_DETC_VERTEX1_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex2_u_1,
					 arg->sw_rawawb_vertex2_v_1),
			 ISP3X_RAWAWB_UV_DETC_VERTEX2_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex3_u_1,
					 arg->sw_rawawb_vertex3_v_1),
			 ISP3X_RAWAWB_UV_DETC_VERTEX3_1, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope01_1,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE01_1, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope12_1,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE12_1, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope23_1,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE23_1, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope30_1,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE30_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex0_u_2,
					 arg->sw_rawawb_vertex0_v_2),
			 ISP3X_RAWAWB_UV_DETC_VERTEX0_2, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex1_u_2,
					 arg->sw_rawawb_vertex1_v_2),
			 ISP3X_RAWAWB_UV_DETC_VERTEX1_2, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex2_u_2,
					 arg->sw_rawawb_vertex2_v_2),
			 ISP3X_RAWAWB_UV_DETC_VERTEX2_2, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex3_u_2,
					 arg->sw_rawawb_vertex3_v_2),
			 ISP3X_RAWAWB_UV_DETC_VERTEX3_2, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope01_2,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE01_2, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope12_2,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE12_2, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope23_2,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE23_2, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope30_2,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE30_2, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex0_u_3,
					 arg->sw_rawawb_vertex0_v_3),
			 ISP3X_RAWAWB_UV_DETC_VERTEX0_3, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex1_u_3,
					 arg->sw_rawawb_vertex1_v_3),
			 ISP3X_RAWAWB_UV_DETC_VERTEX1_3, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex2_u_3,
					 arg->sw_rawawb_vertex2_v_3),
			 ISP3X_RAWAWB_UV_DETC_VERTEX2_3, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex3_u_3,
					 arg->sw_rawawb_vertex3_v_3),
			 ISP3X_RAWAWB_UV_DETC_VERTEX3_3, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope01_3,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE01_3, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope12_3,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE12_3, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope23_3,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE23_3, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope30_3,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE30_3, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex0_u_4,
					 arg->sw_rawawb_vertex0_v_4),
			 ISP3X_RAWAWB_UV_DETC_VERTEX0_4, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex1_u_4,
					 arg->sw_rawawb_vertex1_v_4),
			 ISP3X_RAWAWB_UV_DETC_VERTEX1_4, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex2_u_4,
					 arg->sw_rawawb_vertex2_v_4),
			 ISP3X_RAWAWB_UV_DETC_VERTEX2_4, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex3_u_4,
					 arg->sw_rawawb_vertex3_v_4),
			 ISP3X_RAWAWB_UV_DETC_VERTEX3_4, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope01_4,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE01_4, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope12_4,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE12_4, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope23_4,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE23_4, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope30_4,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE30_4, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex0_u_5,
					 arg->sw_rawawb_vertex0_v_5),
			 ISP3X_RAWAWB_UV_DETC_VERTEX0_5, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex1_u_5,
					 arg->sw_rawawb_vertex1_v_5),
			 ISP3X_RAWAWB_UV_DETC_VERTEX1_5, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex2_u_5,
					 arg->sw_rawawb_vertex2_v_5),
			 ISP3X_RAWAWB_UV_DETC_VERTEX2_5, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex3_u_5,
					 arg->sw_rawawb_vertex3_v_5),
			 ISP3X_RAWAWB_UV_DETC_VERTEX3_5, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope01_5,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE01_5, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope12_5,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE10_5, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope23_5,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE23_5, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope30_5,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE30_5, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex0_u_6,
					 arg->sw_rawawb_vertex0_v_6),
			 ISP3X_RAWAWB_UV_DETC_VERTEX0_6, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex1_u_6,
					 arg->sw_rawawb_vertex1_v_6),
			 ISP3X_RAWAWB_UV_DETC_VERTEX1_6, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex2_u_6,
					 arg->sw_rawawb_vertex2_v_6),
			 ISP3X_RAWAWB_UV_DETC_VERTEX2_6, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_vertex3_u_6,
					 arg->sw_rawawb_vertex3_v_6),
			 ISP3X_RAWAWB_UV_DETC_VERTEX3_6, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope01_6,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE01_6, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope12_6,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE10_6, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope23_6,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE23_6, id);

	isp3_param_write(params_vdev,
			 arg->sw_rawawb_islope30_6,
			 ISP3X_RAWAWB_UV_DETC_ISLOPE30_6, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_rgb2ryuvmat0_y,
					 arg->sw_rawawb_rgb2ryuvmat1_y),
			 ISP3X_RAWAWB_YUV_RGB2ROTY_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_rgb2ryuvmat2_y,
					 arg->sw_rawawb_rgb2ryuvofs_y),
			 ISP3X_RAWAWB_YUV_RGB2ROTY_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_rgb2ryuvmat0_u,
					 arg->sw_rawawb_rgb2ryuvmat1_u),
			 ISP3X_RAWAWB_YUV_RGB2ROTU_0, id);


	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_rgb2ryuvmat2_u,
					 arg->sw_rawawb_rgb2ryuvofs_u),
			 ISP3X_RAWAWB_YUV_RGB2ROTU_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_rgb2ryuvmat0_v,
					 arg->sw_rawawb_rgb2ryuvmat1_v),
			 ISP3X_RAWAWB_YUV_RGB2ROTV_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_rgb2ryuvmat2_v,
					 arg->sw_rawawb_rgb2ryuvofs_v),
			 ISP3X_RAWAWB_YUV_RGB2ROTV_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_coor_x1_ls0_y,
					 arg->sw_rawawb_vec_x21_ls0_y),
			 ISP3X_RAWAWB_YUV_X_COOR_Y_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_coor_x1_ls0_u,
					 arg->sw_rawawb_vec_x21_ls0_u),
			 ISP3X_RAWAWB_YUV_X_COOR_U_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_coor_x1_ls0_v,
					 arg->sw_rawawb_vec_x21_ls0_v),
			 ISP3X_RAWAWB_YUV_X_COOR_V_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_4BYTE(arg->sw_rawawb_dis_x1x2_ls0,
					0,
					arg->sw_rawawb_rotu0_ls0,
					arg->sw_rawawb_rotu1_ls0),
			 ISP3X_RAWAWB_YUV_X1X2_DIS_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_4BYTE(arg->sw_rawawb_rotu2_ls0,
					arg->sw_rawawb_rotu3_ls0,
					arg->sw_rawawb_rotu4_ls0,
					arg->sw_rawawb_rotu5_ls0),
			 ISP3X_RAWAWB_YUV_INTERP_CURVE_UCOOR_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_th0_ls0,
					 arg->sw_rawawb_th1_ls0),
			 ISP3X_RAWAWB_YUV_INTERP_CURVE_TH0_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_th2_ls0,
					 arg->sw_rawawb_th3_ls0),
			 ISP3X_RAWAWB_YUV_INTERP_CURVE_TH1_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_th4_ls0,
					 arg->sw_rawawb_th5_ls0),
			 ISP3X_RAWAWB_YUV_INTERP_CURVE_TH2_0, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_coor_x1_ls1_y,
					 arg->sw_rawawb_vec_x21_ls1_y),
			 ISP3X_RAWAWB_YUV_X_COOR_Y_1, id);

	isp3_param_write(params_vdev,
			 ISP_PACK_2SHORT(arg->sw_rawawb_coor_x1_ls1_u,
					 arg->sw_rawawb_vec_x21_ls1_u),
			 ISP3X_RAWAWB_YUV_X_COOR_U_1, id);

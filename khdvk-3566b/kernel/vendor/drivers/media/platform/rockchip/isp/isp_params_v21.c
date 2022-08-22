// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Rockchip Electronics Co., Ltd. */

#include <media/v4l2-common.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-core.h>
#include <media/videobuf2-vmalloc.h>	/* for ISP params */
#include <linux/rk-preisp.h>
#include <linux/slab.h>
#include "dev.h"
#include "regs.h"
#include "regs_v2x.h"
#include "isp_params_v21.h"

#define ISP2X_PACK_4BYTE(a, b, c, d)	\
	(((a) & 0xFF) << 0 | ((b) & 0xFF) << 8 | \
	 ((c) & 0xFF) << 16 | ((d) & 0xFF) << 24)

#define ISP2X_PACK_2SHORT(a, b)	\
	(((a) & 0xFFFF) << 0 | ((b) & 0xFFFF) << 16)

#define ISP2X_REG_WR_MASK		BIT(31) //disable write protect
#define ISP2X_NOBIG_OVERFLOW_SIZE	(2688 * 1536)
#define ISP2X_AUTO_BIGMODE_WIDTH	2688

static inline size_t
isp_param_get_insize(struct rkisp_isp_params_vdev *params_vdev)
{
	struct rkisp_device *dev = params_vdev->dev;
	struct rkisp_isp_subdev *isp_sdev = &dev->isp_sdev;

	return isp_sdev->in_crop.width * isp_sdev->in_crop.height;
}

static void
isp_dpcc_config(struct rkisp_isp_params_vdev *params_vdev,
		const struct isp2x_dpcc_cfg *arg)
{
	u32 value;
	int i;

	value = rkisp_ioread32(params_vdev, ISP_DPCC0_MODE);
	value &= ISP_DPCC_EN;

	value |= (arg->stage1_enable & 0x01) << 2 |
		 (arg->grayscale_mode & 0x01) << 1;
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_MODE);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_MODE);

	value = (arg->sw_rk_out_sel & 0x03) << 5 |
		(arg->sw_dpcc_output_sel & 0x01) << 4 |
		(arg->stage1_rb_3x3 & 0x01) << 3 |
		(arg->stage1_g_3x3 & 0x01) << 2 |
		(arg->stage1_incl_rb_center & 0x01) << 1 |
		(arg->stage1_incl_green_center & 0x01);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_OUTPUT_MODE);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_OUTPUT_MODE);

	value = (arg->stage1_use_fix_set & 0x01) << 3 |
		(arg->stage1_use_set_3 & 0x01) << 2 |
		(arg->stage1_use_set_2 & 0x01) << 1 |
		(arg->stage1_use_set_1 & 0x01);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_SET_USE);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_SET_USE);

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
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_METHODS_SET_1);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_METHODS_SET_1);

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
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_METHODS_SET_2);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_METHODS_SET_2);

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
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_METHODS_SET_3);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_METHODS_SET_3);

	value = ISP2X_PACK_4BYTE(arg->line_thr_1_g, arg->line_thr_1_rb,
				 arg->sw_mindis1_g, arg->sw_mindis1_rb);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_LINE_THRESH_1);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_LINE_THRESH_1);

	value = ISP2X_PACK_4BYTE(arg->line_mad_fac_1_g, arg->line_mad_fac_1_rb,
				 arg->sw_dis_scale_max1, arg->sw_dis_scale_min1);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_LINE_MAD_FAC_1);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_LINE_MAD_FAC_1);

	value = ISP2X_PACK_4BYTE(arg->pg_fac_1_g, arg->pg_fac_1_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PG_FAC_1);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PG_FAC_1);

	value = ISP2X_PACK_4BYTE(arg->rnd_thr_1_g, arg->rnd_thr_1_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RND_THRESH_1);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RND_THRESH_1);

	value = ISP2X_PACK_4BYTE(arg->rg_fac_1_g, arg->rg_fac_1_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RG_FAC_1);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RG_FAC_1);

	value = ISP2X_PACK_4BYTE(arg->line_thr_2_g, arg->line_thr_2_rb,
				 arg->sw_mindis2_g, arg->sw_mindis2_rb);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_LINE_THRESH_2);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_LINE_THRESH_2);

	value = ISP2X_PACK_4BYTE(arg->line_mad_fac_2_g, arg->line_mad_fac_2_rb,
				 arg->sw_dis_scale_max2, arg->sw_dis_scale_min2);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_LINE_MAD_FAC_2);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_LINE_MAD_FAC_2);

	value = ISP2X_PACK_4BYTE(arg->pg_fac_2_g, arg->pg_fac_2_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PG_FAC_2);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PG_FAC_2);

	value = ISP2X_PACK_4BYTE(arg->rnd_thr_2_g, arg->rnd_thr_2_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RND_THRESH_2);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RND_THRESH_2);

	value = ISP2X_PACK_4BYTE(arg->rg_fac_2_g, arg->rg_fac_2_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RG_FAC_2);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RG_FAC_2);

	value = ISP2X_PACK_4BYTE(arg->line_thr_3_g, arg->line_thr_3_rb,
				 arg->sw_mindis3_g, arg->sw_mindis3_rb);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_LINE_THRESH_3);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_LINE_THRESH_3);

	value = ISP2X_PACK_4BYTE(arg->line_mad_fac_3_g, arg->line_mad_fac_3_rb,
				 arg->sw_dis_scale_max3, arg->sw_dis_scale_min3);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_LINE_MAD_FAC_3);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_LINE_MAD_FAC_3);

	value = ISP2X_PACK_4BYTE(arg->pg_fac_3_g, arg->pg_fac_3_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PG_FAC_3);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PG_FAC_3);

	value = ISP2X_PACK_4BYTE(arg->rnd_thr_3_g, arg->rnd_thr_3_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RND_THRESH_3);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RND_THRESH_3);

	value = ISP2X_PACK_4BYTE(arg->rg_fac_3_g, arg->rg_fac_3_rb, 0, 0);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RG_FAC_3);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RG_FAC_3);

	value = (arg->ro_lim_3_rb & 0x03) << 10 |
		(arg->ro_lim_3_g & 0x03) << 8 |
		(arg->ro_lim_2_rb & 0x03) << 6 |
		(arg->ro_lim_2_g & 0x03) << 4 |
		(arg->ro_lim_1_rb & 0x03) << 2 |
		(arg->ro_lim_1_g & 0x03);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RO_LIMITS);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RO_LIMITS);

	value = (arg->rnd_offs_3_rb & 0x03) << 10 |
		(arg->rnd_offs_3_g & 0x03) << 8 |
		(arg->rnd_offs_2_rb & 0x03) << 6 |
		(arg->rnd_offs_2_g & 0x03) << 4 |
		(arg->rnd_offs_1_rb & 0x03) << 2 |
		(arg->rnd_offs_1_g & 0x03);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_RND_OFFS);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_RND_OFFS);

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
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_BPT_CTRL);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_BPT_CTRL);

	rkisp_iowrite32(params_vdev, arg->bp_number, ISP_DPCC0_BPT_NUMBER);
	rkisp_iowrite32(params_vdev, arg->bp_number, ISP_DPCC1_BPT_NUMBER);
	rkisp_iowrite32(params_vdev, arg->bp_table_addr, ISP_DPCC0_BPT_ADDR);
	rkisp_iowrite32(params_vdev, arg->bp_table_addr, ISP_DPCC1_BPT_ADDR);

	value = ISP2X_PACK_2SHORT(arg->bpt_h_addr, arg->bpt_v_addr);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_BPT_DATA);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_BPT_DATA);

	rkisp_iowrite32(params_vdev, arg->bp_cnt, ISP_DPCC0_BP_CNT);
	rkisp_iowrite32(params_vdev, arg->bp_cnt, ISP_DPCC1_BP_CNT);

	rkisp_iowrite32(params_vdev, arg->sw_pdaf_en, ISP_DPCC0_PDAF_EN);
	rkisp_iowrite32(params_vdev, arg->sw_pdaf_en, ISP_DPCC1_PDAF_EN);

	value = 0;
	for (i = 0; i < ISP2X_DPCC_PDAF_POINT_NUM; i++)
		value |= (arg->pdaf_point_en[i] & 0x01) << i;
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PDAF_POINT_EN);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PDAF_POINT_EN);

	value = ISP2X_PACK_2SHORT(arg->pdaf_offsetx, arg->pdaf_offsety);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PDAF_OFFSET);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PDAF_OFFSET);

	value = ISP2X_PACK_2SHORT(arg->pdaf_wrapx, arg->pdaf_wrapy);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PDAF_WRAP);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PDAF_WRAP);

	value = ISP2X_PACK_2SHORT(arg->pdaf_wrapx_num, arg->pdaf_wrapy_num);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PDAF_SCOPE);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PDAF_SCOPE);

	for (i = 0; i < ISP2X_DPCC_PDAF_POINT_NUM / 2; i++) {
		value = ISP2X_PACK_4BYTE(arg->point[2 * i].x, arg->point[2 * i].y,
					 arg->point[2 * i + 1].x, arg->point[2 * i + 1].y);
		rkisp_iowrite32(params_vdev, value, ISP_DPCC0_PDAF_POINT_0 + 4 * i);
		rkisp_iowrite32(params_vdev, value, ISP_DPCC1_PDAF_POINT_0 + 4 * i);
	}

	rkisp_iowrite32(params_vdev, arg->pdaf_forward_med, ISP_DPCC0_PDAF_FORWARD_MED);
	rkisp_iowrite32(params_vdev, arg->pdaf_forward_med, ISP_DPCC1_PDAF_FORWARD_MED);
}

static void
isp_dpcc_enable(struct rkisp_isp_params_vdev *params_vdev,
		bool en)
{
	u32 value;

	value = rkisp_ioread32(params_vdev, ISP_DPCC0_MODE);
	value &= ~ISP_DPCC_EN;

	if (en)
		value |= ISP_DPCC_EN;
	rkisp_iowrite32(params_vdev, value, ISP_DPCC0_MODE);
	rkisp_iowrite32(params_vdev, value, ISP_DPCC1_MODE);
}

static void
isp_bls_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp21_bls_cfg *arg)
{
	const struct isp2x_bls_fixed_val *pval;
	u32 new_control, value;

	new_control = rkisp_ioread32(params_vdev, ISP_BLS_CTRL);
	new_control &= ISP_BLS_ENA;

	pval = &arg->bls1_val;
	if (arg->bls1_en) {
		new_control |= ISP_BLS_BLS1_EN;

		switch (params_vdev->raw_type) {
		case RAW_BGGR:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS1_D_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS1_C_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS1_B_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS1_A_FIXED);
			break;
		case RAW_GBRG:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS1_C_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS1_D_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS1_A_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS1_B_FIXED);
			break;
		case RAW_GRBG:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS1_B_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS1_A_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS1_D_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS1_C_FIXED);
			break;
		case RAW_RGGB:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS1_A_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS1_B_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS1_C_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS1_D_FIXED);
			break;
		default:
			break;
		}
	}

	/* fixed subtraction values */
	pval = &arg->fixed_val;
	if (!arg->enable_auto) {
		switch (params_vdev->raw_type) {
		case RAW_BGGR:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS_D_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS_C_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS_B_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS_A_FIXED);
			break;
		case RAW_GBRG:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS_C_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS_D_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS_A_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS_B_FIXED);
			break;
		case RAW_GRBG:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS_B_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS_A_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS_D_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS_C_FIXED);
			break;
		case RAW_RGGB:
			rkisp_iowrite32(params_vdev,
					pval->r, ISP_BLS_A_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gr, ISP_BLS_B_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->gb, ISP_BLS_C_FIXED);
			rkisp_iowrite32(params_vdev,
					pval->b, ISP_BLS_D_FIXED);
			break;
		default:
			break;
		}
	} else {
		if (arg->en_windows & BIT(1)) {
			rkisp_iowrite32(params_vdev, arg->bls_window2.h_offs,
					ISP_BLS_H2_START);
			value = arg->bls_window2.h_offs + arg->bls_window2.h_size;
			rkisp_iowrite32(params_vdev, value, ISP_BLS_H2_STOP);
			rkisp_iowrite32(params_vdev, arg->bls_window2.v_offs,
					ISP_BLS_V2_START);
			value = arg->bls_window2.v_offs + arg->bls_window2.v_size;
			rkisp_iowrite32(params_vdev, value, ISP_BLS_V2_STOP);
			new_control |= ISP_BLS_WINDOW_2;
		}

		if (arg->en_windows & BIT(0)) {
			rkisp_iowrite32(params_vdev, arg->bls_window1.h_offs,
					ISP_BLS_H1_START);
			value = arg->bls_window1.h_offs + arg->bls_window1.h_size;
			rkisp_iowrite32(params_vdev, value, ISP_BLS_H1_STOP);
			rkisp_iowrite32(params_vdev, arg->bls_window1.v_offs,
					ISP_BLS_V1_START);
			value = arg->bls_window1.v_offs + arg->bls_window1.v_size;
			rkisp_iowrite32(params_vdev, value, ISP_BLS_V1_STOP);
			new_control |= ISP_BLS_WINDOW_1;
		}

		rkisp_iowrite32(params_vdev, arg->bls_samples,
				ISP_BLS_SAMPLES);

		new_control |= ISP_BLS_MODE_MEASURED;
	}
	rkisp_iowrite32(params_vdev, new_control, ISP_BLS_CTRL);
}

static void
isp_bls_enable(struct rkisp_isp_params_vdev *params_vdev,
	       bool en)
{
	u32 new_control;

	new_control = rkisp_ioread32(params_vdev, ISP_BLS_CTRL);
	if (en)
		new_control |= ISP_BLS_ENA;
	else
		new_control &= ~ISP_BLS_ENA;
	rkisp_iowrite32(params_vdev, new_control, ISP_BLS_CTRL);
}

static void
isp_sdg_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp2x_sdg_cfg *arg)
{
	int i;

	rkisp_iowrite32(params_vdev,
			arg->xa_pnts.gamma_dx0, ISP_GAMMA_DX_LO);
	rkisp_iowrite32(params_vdev,
			arg->xa_pnts.gamma_dx1, ISP_GAMMA_DX_HI);

	for (i = 0; i < ISP2X_DEGAMMA_CURVE_SIZE; i++) {
		rkisp_iowrite32(params_vdev, arg->curve_r.gamma_y[i],
				ISP_GAMMA_R_Y_0 + i * 4);
		rkisp_iowrite32(params_vdev, arg->curve_g.gamma_y[i],
				ISP_GAMMA_G_Y_0 + i * 4);
		rkisp_iowrite32(params_vdev, arg->curve_b.gamma_y[i],
				ISP_GAMMA_B_Y_0 + i * 4);
	}
}

static void
isp_sdg_enable(struct rkisp_isp_params_vdev *params_vdev,
	       bool en)
{
	if (en) {
		isp_param_set_bits(params_vdev,
				   CIF_ISP_CTRL,
				   CIF_ISP_CTRL_ISP_GAMMA_IN_ENA);
	} else {
		isp_param_clear_bits(params_vdev,
				     CIF_ISP_CTRL,
				     CIF_ISP_CTRL_ISP_GAMMA_IN_ENA);
	}
}

static void __maybe_unused
isp_lsc_matrix_cfg_sram(struct rkisp_isp_params_vdev *params_vdev,
			const struct isp2x_lsc_cfg *pconfig, bool is_check)
{
	int i, j;
	unsigned int sram_addr;
	unsigned int data;

	if (is_check &&
	    !(rkisp_ioread32(params_vdev, ISP_LSC_CTRL) & ISP_LSC_EN))
		return;

	/* CIF_ISP_LSC_TABLE_ADDRESS_153 = ( 17 * 18 ) >> 1 */
	sram_addr = CIF_ISP_LSC_TABLE_ADDRESS_0;
	rkisp_write(params_vdev->dev, ISP_LSC_R_TABLE_ADDR, sram_addr, true);
	rkisp_write(params_vdev->dev, ISP_LSC_GR_TABLE_ADDR, sram_addr, true);
	rkisp_write(params_vdev->dev, ISP_LSC_GB_TABLE_ADDR, sram_addr, true);
	rkisp_write(params_vdev->dev, ISP_LSC_B_TABLE_ADDR, sram_addr, true);

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
			rkisp_write(params_vdev->dev, ISP_LSC_R_TABLE_DATA, data, true);

			data = ISP_ISP_LSC_TABLE_DATA(pconfig->gr_data_tbl[i + j],
						      pconfig->gr_data_tbl[i + j + 1]);
			rkisp_write(params_vdev->dev, ISP_LSC_GR_TABLE_DATA, data, true);

			data = ISP_ISP_LSC_TABLE_DATA(pconfig->gb_data_tbl[i + j],
						      pconfig->gb_data_tbl[i + j + 1]);
			rkisp_write(params_vdev->dev, ISP_LSC_GB_TABLE_DATA, data, true);

			data = ISP_ISP_LSC_TABLE_DATA(pconfig->b_data_tbl[i + j],
						      pconfig->b_data_tbl[i + j + 1]);
			rkisp_write(params_vdev->dev, ISP_LSC_B_TABLE_DATA, data, true);
		}

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->r_data_tbl[i + j], 0);
		rkisp_write(params_vdev->dev, ISP_LSC_R_TABLE_DATA, data, true);

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->gr_data_tbl[i + j], 0);
		rkisp_write(params_vdev->dev, ISP_LSC_GR_TABLE_DATA, data, true);

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->gb_data_tbl[i + j], 0);
		rkisp_write(params_vdev->dev, ISP_LSC_GB_TABLE_DATA, data, true);

		data = ISP_ISP_LSC_TABLE_DATA(pconfig->b_data_tbl[i + j], 0);
		rkisp_write(params_vdev->dev, ISP_LSC_B_TABLE_DATA, data, true);
	}
}

static void __maybe_unused
isp_lsc_matrix_cfg_ddr(struct rkisp_isp_params_vdev *params_vdev,
		       const struct isp2x_lsc_cfg *pconfig)
{
	struct rkisp_isp_params_val_v21 *priv_val;
	u32 data, buf_idx, *vaddr[4], index[4];
	void *buf_vaddr;
	int i, j;

	memset(&index[0], 0, sizeof(index));
	priv_val = (struct rkisp_isp_params_val_v21 *)params_vdev->priv_val;
	buf_idx = (priv_val->buf_lsclut_idx++) % RKISP_PARAM_LSC_LUT_BUF_NUM;
	buf_vaddr = priv_val->buf_lsclut[buf_idx].vaddr;

	vaddr[0] = buf_vaddr;
	vaddr[1] = buf_vaddr + RKISP_PARAM_LSC_LUT_TBL_SIZE;
	vaddr[2] = buf_vaddr + RKISP_PARAM_LSC_LUT_TBL_SIZE * 2;
	vaddr[3] = buf_vaddr + RKISP_PARAM_LSC_LUT_TBL_SIZE * 3;

	/* program data tables (table size is 9 * 17 = 153) */
	for (i = 0; i < CIF_ISP_LSC_SECTORS_MAX * CIF_ISP_LSC_SECTORS_MAX;
	     i += CIF_ISP_LSC_SECTORS_MAX) {
		/*
		 * 17 sectors with 2 values in one DWORD = 9
		 * DWORDs (2nd value of last DWORD unused)
		 */
		for (j = 0; j < CIF_ISP_LSC_SECTORS_MAX - 1; j += 2) {
			data = ISP_ISP_LSC_TABLE_DATA(
					pconfig->r_data_tbl[i + j],
					pconfig->r_data_tbl[i + j + 1]);
			vaddr[0][index[0]++] = data;

			data = ISP_ISP_LSC_TABLE_DATA(
					pconfig->gr_data_tbl[i + j],
					pconfig->gr_data_tbl[i + j + 1]);
			vaddr[1][index[1]++] = data;

			data = ISP_ISP_LSC_TABLE_DATA(
					pconfig->b_data_tbl[i + j],
					pconfig->b_data_tbl[i + j + 1]);
			vaddr[2][index[2]++] = data;

			data = ISP_ISP_LSC_TABLE_DATA(
					pconfig->gb_data_tbl[i + j],
					pconfig->gb_data_tbl[i + j + 1]);
			vaddr[3][index[3]++] = data;
		}

		data = ISP_ISP_LSC_TABLE_DATA(
				pconfig->r_data_tbl[i + j],
				0);
		vaddr[0][index[0]++] = data;

		data = ISP_ISP_LSC_TABLE_DATA(
				pconfig->gr_data_tbl[i + j],
				0);
		vaddr[1][index[1]++] = data;

		data = ISP_ISP_LSC_TABLE_DATA(
				pconfig->b_data_tbl[i + j],
				0);
		vaddr[2][index[2]++] = data;

		data = ISP_ISP_LSC_TABLE_DATA(
				pconfig->gb_data_tbl[i + j],
				0);
		vaddr[3][index[3]++] = data;
	}
	rkisp_prepare_buffer(params_vdev->dev, &priv_val->buf_lsclut[buf_idx]);
	data = priv_val->buf_lsclut[buf_idx].dma_addr;
	rkisp_iowrite32(params_vdev, data, MI_LUT_LSC_RD_BASE);
	rkisp_iowrite32(params_vdev, RKISP_PARAM_LSC_LUT_BUF_SIZE, MI_LUT_LSC_RD_WSIZE);
}

static void
isp_lsc_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp2x_lsc_cfg *arg)
{
	struct isp21_isp_params_cfg *params_rec = params_vdev->isp21_params;
	struct rkisp_device *dev = params_vdev->dev;
	unsigned int data;
	u32 lsc_ctrl;
	int i;

	/* To config must be off , store the current status firstly */
	lsc_ctrl = rkisp_ioread32(params_vdev, ISP_LSC_CTRL);
	isp_param_clear_bits(params_vdev, ISP_LSC_CTRL, ISP_LSC_EN);
	/* online mode lsc lut load from ddr quick for some sensor VB short
	 * readback mode lsc lut AHB config to sram, once for single device,
	 * need record to switch for multi-device.
	 */
	if (!IS_HDR_RDBK(dev->rd_mode))
		isp_lsc_matrix_cfg_ddr(params_vdev, arg);
	else if (dev->hw_dev->is_single)
		isp_lsc_matrix_cfg_sram(params_vdev, arg, false);
	else
		params_rec->others.lsc_cfg = *arg;

	for (i = 0; i < 4; i++) {
		/* program x size tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->x_size_tbl[i * 2],
					     arg->x_size_tbl[i * 2 + 1]);
		rkisp_iowrite32(params_vdev, data,
				ISP_LSC_XSIZE_01 + i * 4);

		/* program x grad tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->x_grad_tbl[i * 2],
					     arg->x_grad_tbl[i * 2 + 1]);
		rkisp_iowrite32(params_vdev, data,
				ISP_LSC_XGRAD_01 + i * 4);

		/* program y size tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->y_size_tbl[i * 2],
					     arg->y_size_tbl[i * 2 + 1]);
		rkisp_iowrite32(params_vdev, data,
				ISP_LSC_YSIZE_01 + i * 4);

		/* program y grad tables */
		data = CIF_ISP_LSC_SECT_SIZE(arg->y_grad_tbl[i * 2],
					     arg->y_grad_tbl[i * 2 + 1]);
		rkisp_iowrite32(params_vdev, data,
				ISP_LSC_YGRAD_01 + i * 4);
	}

	/* restore the lsc ctrl status */
	if (lsc_ctrl & ISP_LSC_EN) {
		if (!IS_HDR_RDBK(dev->rd_mode))
			lsc_ctrl |= ISP_LSC_LUT_EN;
		isp_param_set_bits(params_vdev, ISP_LSC_CTRL, lsc_ctrl);
	} else {
		isp_param_clear_bits(params_vdev, ISP_LSC_CTRL, ISP_LSC_EN);
	}
}

static void
isp_lsc_enable(struct rkisp_isp_params_vdev *params_vdev,
	       bool en)
{
	struct rkisp_device *dev = params_vdev->dev;
	u32 val = ISP_LSC_EN;

	if (!IS_HDR_RDBK(dev->rd_mode))
		val |= ISP_LSC_LUT_EN;

	if (en)
		isp_param_set_bits(params_vdev, ISP_LSC_CTRL, val);
	else
		isp_param_clear_bits(params_vdev, ISP_LSC_CTRL, ISP_LSC_EN);
}

static void
isp_debayer_config(struct rkisp_isp_params_vdev *params_vdev,
		   const struct isp2x_debayer_cfg *arg)
{
	u32 value;

	value = rkisp_ioread32(params_vdev, ISP_DEBAYER_CONTROL);
	value &= ISP_DEBAYER_EN;

	value |= (arg->filter_c_en & 0x01) << 8 |
		 (arg->filter_g_en & 0x01) << 4;
	rkisp_iowrite32(params_vdev, value, ISP_DEBAYER_CONTROL);

	value = (arg->thed1 & 0x0F) << 12 |
		(arg->thed0 & 0x0F) << 8 |
		(arg->dist_scale & 0x0F) << 4 |
		(arg->max_ratio & 0x07) << 1 |
		(arg->clip_en & 0x01);
	rkisp_iowrite32(params_vdev, value, ISP_DEBAYER_G_INTERP);

	value = (arg->filter1_coe5 & 0x0F) << 16 |
		(arg->filter1_coe4 & 0x0F) << 12 |
		(arg->filter1_coe3 & 0x0F) << 8 |
		(arg->filter1_coe2 & 0x0F) << 4 |
		(arg->filter1_coe1 & 0x0F);
	rkisp_iowrite32(params_vdev, value, ISP_DEBAYER_G_INTERP_FILTER1);

	value = (arg->filter2_coe5 & 0x0F) << 16 |
		(arg->filter2_coe4 & 0x0F) << 12 |
		(arg->filter2_coe3 & 0x0F) << 8 |
		(arg->filter2_coe2 & 0x0F) << 4 |
		(arg->filter2_coe1 & 0x0F);
	rkisp_iowrite32(params_vdev, value, ISP_DEBAYER_G_INTERP_FILTER2);

	value = (arg->hf_offset & 0xFFFF) << 16 |
		(arg->gain_offset & 0x0F) << 8 |
		(arg->offset & 0x1F);
	rkisp_iowrite32(params_vdev, value, ISP_DEBAYER_G_FILTER);

	value = (arg->shift_num & 0x03) << 16 |
		(arg->order_max & 0x1F) << 8 |
		(arg->order_min & 0x1F);
	rkisp_iowrite32(params_vdev, value, ISP_DEBAYER_C_FILTER);
}

static void
isp_debayer_enable(struct rkisp_isp_params_vdev *params_vdev,
		   bool en)
{
	if (en)
		isp_param_set_bits(params_vdev,
				   ISP_DEBAYER_CONTROL,
				   ISP_DEBAYER_EN);
	else
		isp_param_clear_bits(params_vdev,
				     ISP_DEBAYER_CONTROL,
				     ISP_DEBAYER_EN);
}

static void
isp_awbgain_config(struct rkisp_isp_params_vdev *params_vdev,
		   const struct isp21_awb_gain_cfg *arg)
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

	rkisp_iowrite32(params_vdev,
			ISP2X_PACK_2SHORT(arg->gain0_green_b, arg->gain0_green_r),
			ISP21_AWB_GAIN0_G);

	rkisp_iowrite32(params_vdev,
			ISP2X_PACK_2SHORT(arg->gain0_blue, arg->gain0_red),
			ISP21_AWB_GAIN0_RB);

	rkisp_iowrite32(params_vdev,
			ISP2X_PACK_2SHORT(arg->gain1_green_b, arg->gain1_green_r),
			ISP21_AWB_GAIN1_G);

	rkisp_iowrite32(params_vdev,
			ISP2X_PACK_2SHORT(arg->gain1_blue, arg->gain1_red),
			ISP21_AWB_GAIN1_RB);

	rkisp_iowrite32(params_vdev,
			ISP2X_PACK_2SHORT(arg->gain2_green_b, arg->gain2_green_r),
			ISP21_AWB_GAIN2_G);

	rkisp_iowrite32(params_vdev,
			ISP2X_PACK_2SHORT(arg->gain2_blue, arg->gain2_red),
			ISP21_AWB_GAIN2_RB);
}

static void
isp_awbgain_enable(struct rkisp_isp_params_vdev *params_vdev,
		   bool en)
{
	if (en)
		isp_param_set_bits(params_vdev, CIF_ISP_CTRL,
				   CIF_ISP_CTRL_ISP_AWB_ENA);
	else
		isp_param_clear_bits(params_vdev, CIF_ISP_CTRL,
				     CIF_ISP_CTRL_ISP_AWB_ENA);
}

static void
isp_ccm_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp21_ccm_cfg *arg)
{
	u32 value;
	u32 i;

	value = rkisp_ioread32(params_vdev, ISP_CCM_CTRL);
	value &= ISP_CCM_EN;

	value |= (arg->highy_adjust_dis & 0x01) << 1;
	rkisp_iowrite32(params_vdev, value, ISP_CCM_CTRL);

	value = ISP2X_PACK_2SHORT(arg->coeff0_r, arg->coeff1_r);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF0_R);

	value = ISP2X_PACK_2SHORT(arg->coeff2_r, arg->offset_r);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF1_R);

	value = ISP2X_PACK_2SHORT(arg->coeff0_g, arg->coeff1_g);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF0_G);

	value = ISP2X_PACK_2SHORT(arg->coeff2_g, arg->offset_g);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF1_G);

	value = ISP2X_PACK_2SHORT(arg->coeff0_b, arg->coeff1_b);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF0_B);

	value = ISP2X_PACK_2SHORT(arg->coeff2_b, arg->offset_b);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF1_B);

	value = ISP2X_PACK_2SHORT(arg->coeff0_y, arg->coeff1_y);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF0_Y);

	value = ISP2X_PACK_2SHORT(arg->coeff2_y, 0);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_COEFF1_Y);

	for (i = 0; i < ISP2X_CCM_CURVE_NUM / 2; i++) {
		value = ISP2X_PACK_2SHORT(arg->alp_y[2 * i], arg->alp_y[2 * i + 1]);
		rkisp_iowrite32(params_vdev, value, ISP_CCM_ALP_Y0 + 4 * i);
	}
	value = ISP2X_PACK_2SHORT(arg->alp_y[2 * i], 0);
	rkisp_iowrite32(params_vdev, value, ISP_CCM_ALP_Y0 + 4 * i);

	value = arg->bound_bit & 0x0F;
	rkisp_iowrite32(params_vdev, value, ISP_CCM_BOUND_BIT);
}

static void
isp_ccm_enable(struct rkisp_isp_params_vdev *params_vdev,
	       bool en)
{
	if (en)
		isp_param_set_bits(params_vdev, ISP_CCM_CTRL, ISP_CCM_EN);
	else
		isp_param_clear_bits(params_vdev, ISP_CCM_CTRL, ISP_CCM_EN);
}

static void
isp_goc_config(struct rkisp_isp_params_vdev *params_vdev,
	       const struct isp2x_gammaout_cfg *arg)
{
	int i;
	u32 value;

	if (arg->equ_segm)
		isp_param_set_bits(params_vdev, ISP_GAMMA_OUT_CTRL, 0x02);
	else
		isp_param_clear_bits(params_vdev, ISP_GAMMA_OUT_CTRL, 0x02);

	rkisp_iowrite32(params_vdev, arg->offset, ISP_GAMMA_OUT_OFFSET);
	for (i = 0; i < ISP2X_GAMMA_OUT_MAX_SAMPLES / 2; i++) {
		value = ISP2X_PACK_2SHORT(
			arg->gamma_y[2 * i],
			arg->gamma_y[2 * i + 1]);
		rkisp_iowrite32(params_vdev, value, ISP_GAMMA_OUT_Y0 + i * 4);
	}

	rkisp_iowrite32(params_vdev, arg->gamma_y[2 * i], ISP_GAMMA_OUT_Y0 + i * 4);
}

static void
isp_goc_enable(struct rkisp_isp_params_vdev *params_vdev,
	       bool en)
{
	if (en)
		isp_param_set_bits(params_vdev, ISP_GAMMA_OUT_CTRL, 0x01);
	else
		isp_param_clear_bits(params_vdev, ISP_GAMMA_OUT_CTRL, 0x01);
}

static void
isp_cproc_config(struct rkisp_isp_params_vdev *params_vdev,
		 const struct isp2x_cproc_cfg *arg)
{
	u32 quantization = params_vdev->quantization;

	rkisp_iowrite32(params_vdev, arg->contrast, CPROC_CONTRAST);
	rkisp_iowrite32(params_vdev, arg->hue, CPROC_HUE);
	rkisp_iowrite32(params_vdev, arg->sat, CPROC_SATURATION);
	rkisp_iowrite32(params_vdev, arg->brightness, CPROC_BRIGHTNESS);

	if (quantization != V4L2_QUANTIZATION_FULL_RANGE) {
		isp_param_clear_bits(params_vdev, CPROC_CTRL,
				     CIF_C_PROC_YOUT_FULL |
				     CIF_C_PROC_YIN_FULL |
				     CIF_C_PROC_COUT_FULL);
	} else {
		isp_param_set_bits(params_vdev, CPROC_CTRL,
				   CIF_C_PROC_YOUT_FULL |
				   CIF_C_PROC_YIN_FULL |
				   CIF_C_PROC_COUT_FULL);
	}
}

static void
isp_cproc_enable(struct rkisp_isp_params_vdev *params_vdev,
		 bool en)
{
	if (en)
		isp_param_set_bits(params_vdev,
				   CPROC_CTRL,
				   CIF_C_PROC_CTR_ENABLE);
	else
		isp_param_clear_bits(params_vdev,
				   CPROC_CTRL,
				   CIF_C_PROC_CTR_ENABLE);
}

static void
isp_ie_config(struct rkisp_isp_params_vdev *params_vdev,
	      const struct isp2x_ie_cfg *arg)
{
	u32 eff_ctrl;

	eff_ctrl = rkisp_ioread32(params_vdev, CIF_IMG_EFF_CTRL);
	eff_ctrl &= ~CIF_IMG_EFF_CTRL_MODE_MASK;

	if (params_vdev->quantization == V4L2_QUANTIZATION_FULL_RANGE)
		eff_ctrl |= CIF_IMG_EFF_CTRL_YCBCR_FULL;

	switch (arg->effect) {
	case V4L2_COLORFX_SEPIA:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_SEPIA;
		break;
	case V4L2_COLORFX_SET_CBCR:
		rkisp_iowrite32(params_vdev, arg->eff_tint, CIF_IMG_EFF_TINT);
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_SEPIA;
		break;
		/*
		 * Color selection is similar to water color(AQUA):
		 * grayscale + selected color w threshold
		 */
	case V4L2_COLORFX_AQUA:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_COLOR_SEL;
		rkisp_iowrite32(params_vdev, arg->color_sel,
				CIF_IMG_EFF_COLOR_SEL);
		break;
	case V4L2_COLORFX_EMBOSS:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_EMBOSS;
		rkisp_iowrite32(params_vdev, arg->eff_mat_1,
				CIF_IMG_EFF_MAT_1);
		rkisp_iowrite32(params_vdev, arg->eff_mat_2,
				CIF_IMG_EFF_MAT_2);
		rkisp_iowrite32(params_vdev, arg->eff_mat_3,
				CIF_IMG_EFF_MAT_3);
		break;
	case V4L2_COLORFX_SKETCH:
		eff_ctrl |= CIF_IMG_EFF_CTRL_MODE_SKETCH;
		rkisp_iowrite32(params_vdev, arg->eff_mat_3,
				CIF_IMG_EFF_MAT_3);
		rkisp_iowrite32(params_vdev, arg->eff_mat_4,
				CIF_IMG_EFF_MAT_4);
		rkisp_iowrite32(params_vdev, arg->eff_mat_5,
				CIF_IMG_EFF_MAT_5);
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

	rkisp_iowrite32(params_vdev, eff_ctrl, CIF_IMG_EFF_CTRL);
}

static void
isp_ie_enable(struct rkisp_isp_params_vdev *params_vdev,
	      bool en)
{
	if (en) {
		isp_param_set_bits(params_vdev, CIF_IMG_EFF_CTRL,
				   CIF_IMG_EFF_CTRL_ENABLE);
		isp_param_set_bits(params_vdev, CIF_IMG_EFF_CTRL,
				   CIF_IMG_EFF_CTRL_CFG_UPD);
	} else {
		isp_param_clear_bits(params_vdev, CIF_IMG_EFF_CTRL,
				     CIF_IMG_EFF_CTRL_ENABLE);
	}
}

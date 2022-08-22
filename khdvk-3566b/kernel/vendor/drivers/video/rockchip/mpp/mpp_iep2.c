// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2020 Rockchip Electronics Co., Ltd.
 *
 * author:
 *	Ding Wei, leo.ding@rock-chips.com
 *	Alpha Lin, alpha.lin@rock-chips.com
 *
 */
#include <asm/cacheflush.h>
#include <linux/delay.h>
#include <linux/iopoll.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/dma-buf.h>
#include <linux/uaccess.h>
#include <linux/regmap.h>
#include <linux/pm_runtime.h>
#include <linux/proc_fs.h>
#include <soc/rockchip/pm_domains.h>

#include "rockchip_iep2_regs.h"
#include "mpp_debug.h"
#include "mpp_common.h"
#include "mpp_iommu.h"

#define IEP2_DRIVER_NAME		"mpp-iep2"

#define	IEP2_SESSION_MAX_BUFFERS		20

#define TILE_WIDTH		16
#define TILE_HEIGHT		4
#define MVL			28
#define MVR			27

enum rockchip_iep2_fmt {
	ROCKCHIP_IEP2_FMT_YUV422 = 2,
	ROCKCHIP_IEP2_FMT_YUV420
};

enum rockchip_iep2_yuv_swap {
	ROCKCHIP_IEP2_YUV_SWAP_SP_UV,
	ROCKCHIP_IEP2_YUV_SWAP_SP_VU,
	ROCKCHIP_IEP2_YUV_SWAP_P0,
	ROCKCHIP_IEP2_YUV_SWAP_P
};

enum rockchip_iep2_dil_ff_order {
	ROCKCHIP_IEP2_DIL_FF_ORDER_TB,
	ROCKCHIP_IEP2_DIL_FF_ORDER_BT
};

enum rockchip_iep2_dil_mode {
	ROCKCHIP_IEP2_DIL_MODE_DISABLE,
	ROCKCHIP_IEP2_DIL_MODE_I5O2,
	ROCKCHIP_IEP2_DIL_MODE_I5O1T,
	ROCKCHIP_IEP2_DIL_MODE_I5O1B,
	ROCKCHIP_IEP2_DIL_MODE_I2O2,
	ROCKCHIP_IEP2_DIL_MODE_I1O1T,
	ROCKCHIP_IEP2_DIL_MODE_I1O1B,
	ROCKCHIP_IEP2_DIL_MODE_PD,
	ROCKCHIP_IEP2_DIL_MODE_BYPASS,
	ROCKCHIP_IEP2_DIL_MODE_DECT
};

enum ROCKCHIP_IEP2_PD_COMP_FLAG {
	ROCKCHIP_IEP2_PD_COMP_FLAG_CC,
	ROCKCHIP_IEP2_PD_COMP_FLAG_CN,
	ROCKCHIP_IEP2_PD_COMP_FLAG_NC,
	ROCKCHIP_IEP2_PD_COMP_FLAG_NON
};

/* default iep2 mtn table */
static u32 iep2_mtn_tab[] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x01010000, 0x06050302, 0x0f0d0a08, 0x1c191512,
	0x2b282420, 0x3634312e, 0x3d3c3a38, 0x40403f3e,
	0x40404040, 0x40404040, 0x40404040, 0x40404040
};

#define to_iep_task(task)		\
		container_of(task, struct iep_task, mpp_task)
#define to_iep2_dev(dev)		\
		container_of(dev, struct iep2_dev, mpp)

struct iep2_addr {
	u32 y;
	u32 cbcr;
	u32 cr;
};

struct iep2_params {
	u32 src_fmt;
	u32 src_yuv_swap;
	u32 dst_fmt;
	u32 dst_yuv_swap;
	u32 tile_cols;
	u32 tile_rows;
	u32 src_y_stride;
	u32 src_uv_stride;
	u32 dst_y_stride;

	/* current, previous, next. */
	struct iep2_addr src[3];
	struct iep2_addr dst[2];
	u32 mv_addr;
	u32 md_addr;

	u32 dil_mode;
	u32 dil_out_mode;
	u32 dil_field_order;

	u32 md_theta;
	u32 md_r;
	u32 md_lambda;

	u32 dect_resi_thr;
	u32 osd_area_num;
	u32 osd_gradh_thr;
	u32 osd_gradv_thr;

	u32 osd_pos_limit_en;
	u32 osd_pos_limit_num;

	u32 osd_limit_area[2];

	u32 osd_line_num;
	u32 osd_pec_thr;

	u32 osd_x_sta[8];
	u32 osd_x_end[8];
	u32 osd_y_sta[8];
	u32 osd_y_end[8];

	u32 me_pena;
	u32 mv_bonus;
	u32 mv_similar_thr;
	u32 mv_similar_num_thr0;
	s32 me_thr_offset;

	u32 mv_left_limit;
	u32 mv_right_limit;

	s8 mv_tru_list[8];
	u32 mv_tru_vld[8];

	u32 eedi_thr0;

	u32 ble_backtoma_num;

	u32 comb_cnt_thr;
	u32 comb_feature_thr;
	u32 comb_t_thr;
	u32 comb_osd_vld[8];

	u32 mtn_en;
	u32 mtn_tab[16];

	u32 pd_mode;

	u32 roi_en;
	u32 roi_layer_num;
	u32 roi_mode[8];
	u32 xsta[8];
	u32 xend[8];
	u32 ysta[8];
	u32 yend[8];
};

struct iep2_output {
	u32 mv_hist[MVL + MVR + 1];
	u32 dect_pd_tcnt;
	u32 dect_pd_bcnt;
	u32 dect_ff_cur_tcnt;
	u32 dect_ff_cur_bcnt;
	u32 dect_ff_nxt_tcnt;
	u32 dect_ff_nxt_bcnt;
	u32 dect_ff_ble_tcnt;
	u32 dect_ff_ble_bcnt;
	u32 dect_ff_nz;
	u32 dect_ff_comb_f;
	u32 dect_osd_cnt;
	u32 out_comb_cnt;
	u32 out_osd_comb_cnt;
	u32 ff_gradt_tcnt;
	u32 ff_gradt_bcnt;
	u32 x_sta[8];
	u32 x_end[8];
	u32 y_sta[8];
	u32 y_end[8];
};

struct iep_task {
	struct mpp_task mpp_task;
	struct mpp_hw_info *hw_info;

	enum MPP_CLOCK_MODE clk_mode;
	struct iep2_params params;
	struct iep2_output output;

	struct reg_offset_info off_inf;
	u32 irq_status;
	/* req for current task */
	u32 w_req_cnt;
	struct mpp_request w_reqs[MPP_MAX_MSG_NUM];
	u32 r_req_cnt;
	struct mpp_request r_reqs[MPP_MAX_MSG_NUM];
};

struct iep2_dev {
	struct mpp_dev mpp;

	struct mpp_clk_info aclk_info;
	struct mpp_clk_info hclk_info;
	struct mpp_clk_info sclk_info;
#ifdef CONFIG_ROCKCHIP_MPP_PROC_FS
	struct proc_dir_entry *procfs;
#endif
	struct reset_control *rst_a;
	struct reset_control *rst_h;
	struct reset_control *rst_s;

	struct mpp_dma_buffer roi;
};

static int iep2_addr_rnum[] = {
	24, 27, 28, /* src cur */
	25, 29, 30, /* src nxt */
	26, 31, 32, /* src prv */
	44, 46, -1, /* dst top */
	45, 47, -1, /* dst bot */
	34, /* mv */
	33, /* md */
};

static int iep2_process_reg_fd(struct mpp_session *session,
			       struct iep_task *task,
			       struct mpp_task_msgs *msgs)
{
	int i;
	/* see the detail at above table iep2_addr_rnum */
	int addr_num =
		ARRAY_SIZE(task->params.src) * 3 +
		ARRAY_SIZE(task->params.dst) * 3 + 2;

	u32 *paddr = &task->params.src[0].y;

	for (i = 0; i < addr_num; ++i) {
		int usr_fd;
		u32 offset;
		struct mpp_mem_region *mem_region = NULL;

		if (session->msg_flags & MPP_FLAGS_REG_NO_OFFSET) {
			usr_fd = paddr[i];
			offset = 0;
		} else {
			usr_fd = paddr[i] & 0x3ff;
			offset = paddr[i] >> 10;
		}

		if (usr_fd == 0 || iep2_addr_rnum[i] == -1)
			continue;

		mem_region = mpp_task_attach_fd(&task->mpp_task, usr_fd);
		if (IS_ERR(mem_region)) {
			mpp_debug(DEBUG_IOMMU, "reg[%3d]: %08x failed\n",
				  iep2_addr_rnum[i], paddr[i]);
			return PTR_ERR(mem_region);
		}

		mem_region->reg_idx = iep2_addr_rnum[i];
		mpp_debug(DEBUG_IOMMU, "reg[%3d]: %3d => %pad + offset %10d\n",
			  iep2_addr_rnum[i], usr_fd, &mem_region->iova, offset);
		paddr[i] = mem_region->iova + offset;
	}

	return 0;
}

static int iep2_extract_task_msg(struct iep_task *task,
				 struct mpp_task_msgs *msgs)
{
	u32 i;
	struct mpp_request *req;

	for (i = 0; i < msgs->req_cnt; i++) {
		req = &msgs->reqs[i];
		if (!req->size)
			continue;

		switch (req->cmd) {
		case MPP_CMD_SET_REG_WRITE: {
			if (copy_from_user(&task->params,
					   req->data, req->size)) {
				mpp_err("copy_from_user params failed\n");
				return -EIO;
			}
		} break;
		case MPP_CMD_SET_REG_READ: {
			memcpy(&task->r_reqs[task->r_req_cnt++],
			       req, sizeof(*req));
		} break;
		case MPP_CMD_SET_REG_ADDR_OFFSET: {
			mpp_extract_reg_offset_info(&task->off_inf, req);
		} break;
		default:
			break;
		}
	}
	mpp_debug(DEBUG_TASK_INFO, "w_req_cnt %d, r_req_cnt %d\n",
		  task->w_req_cnt, task->r_req_cnt);

	return 0;
}

static void *iep2_alloc_task(struct mpp_session *session,
			     struct mpp_task_msgs *msgs)
{
	int ret;
	struct iep_task *task = NULL;

	mpp_debug_enter();

	task = kzalloc(sizeof(*task), GFP_KERNEL);
	if (!task)
		return NULL;

	mpp_task_init(session, &task->mpp_task);
	/* extract reqs for current task */
	ret = iep2_extract_task_msg(task, msgs);
	if (ret)
		goto fail;
	/* process fd in register */
	if (!(msgs->flags & MPP_FLAGS_REG_FD_NO_TRANS)) {
		ret = iep2_process_reg_fd(session, task, msgs);
		if (ret)
			goto fail;
	}
	task->clk_mode = CLK_MODE_NORMAL;

	mpp_debug_leave();

	return &task->mpp_task;

fail:
	mpp_task_finalize(session, &task->mpp_task);
	kfree(task);
	return NULL;
}

static void iep2_config(struct mpp_dev *mpp, struct iep_task *task)
{
	struct iep2_dev *iep = to_iep2_dev(mpp);
	struct iep2_params *cfg = &task->params;
	u32 reg;
	u32 width, height;

	width = cfg->tile_cols * TILE_WIDTH;
	height = cfg->tile_rows * TILE_HEIGHT;

	reg = IEP2_REG_SRC_FMT(cfg->src_fmt)
		| IEP2_REG_SRC_YUV_SWAP(cfg->src_yuv_swap)
		| IEP2_REG_DST_FMT(cfg->dst_fmt)
		| IEP2_REG_DST_YUV_SWAP(cfg->dst_yuv_swap)
		| IEP2_REG_DEBUG_DATA_EN;
	mpp_write_relaxed(mpp, IEP2_REG_IEP_CONFIG0, reg);

	reg = IEP2_REG_SRC_PIC_WIDTH(width - 1)
		| IEP2_REG_SRC_PIC_HEIGHT(height - 1);
	mpp_write_relaxed(mpp, IEP2_REG_SRC_IMG_SIZE, reg);

	reg = IEP2_REG_SRC_VIR_Y_STRIDE(cfg->src_y_stride)
		| IEP2_REG_SRC_VIR_UV_STRIDE(cfg->src_uv_stride);
	mpp_write_relaxed(mpp, IEP2_REG_VIR_SRC_IMG_WIDTH, reg);

	reg = IEP2_REG_DST_VIR_STRIDE(cfg->dst_y_stride);
	mpp_write_relaxed(mpp, IEP2_REG_VIR_DST_IMG_WIDTH, reg);

	reg = IEP2_REG_DIL_MV_HIST_EN
		| IEP2_REG_DIL_COMB_EN
		| IEP2_REG_DIL_BLE_EN
		| IEP2_REG_DIL_EEDI_EN
		| IEP2_REG_DIL_MEMC_EN
		| IEP2_REG_DIL_OSD_EN
		| IEP2_REG_DIL_PD_EN
		| IEP2_REG_DIL_FF_EN
		| IEP2_REG_DIL_MD_PRE_EN
		| IEP2_REG_DIL_FIELD_ORDER(cfg->dil_field_order)
		| IEP2_REG_DIL_OUT_MODE(cfg->dil_out_mode)
		| IEP2_REG_DIL_MODE(cfg->dil_mode);
	if (cfg->roi_en)
		reg |= IEP2_REG_DIL_ROI_EN;
	mpp_write_relaxed(mpp, IEP2_REG_DIL_CONFIG0, reg);

	if (cfg->dil_mode != ROCKCHIP_IEP2_DIL_MODE_PD) {
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_CURY,
				  cfg->src[0].y);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_CURUV,
				  cfg->src[0].cbcr);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_CURV,
				  cfg->src[0].cr);

		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_NXTY,
				  cfg->src[1].y);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_NXTUV,
				  cfg->src[1].cbcr);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_NXTV,
				  cfg->src[1].cr);
	} else {
		struct iep2_addr *top, *bot;

		switch (cfg->pd_mode) {
		default:
		case ROCKCHIP_IEP2_PD_COMP_FLAG_CC:
			top = &cfg->src[0];
			bot = &cfg->src[0];
			break;
		case ROCKCHIP_IEP2_PD_COMP_FLAG_CN:
			top = &cfg->src[0];
			bot = &cfg->src[1];
			break;
		case ROCKCHIP_IEP2_PD_COMP_FLAG_NC:
			top = &cfg->src[1];
			bot = &cfg->src[0];
			break;
		}

		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_CURY, top->y);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_CURUV, top->cbcr);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_CURV, top->cr);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_NXTY, bot->y);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_NXTUV, bot->cbcr);
		mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_NXTV, bot->cr);
	}

	mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_PREY, cfg->src[2].y);
	mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_PREUV, cfg->src[2].cbcr);
	mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_PREV, cfg->src[2].cr);

	mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_MD, cfg->md_addr);
	mpp_write_relaxed(mpp, IEP2_REG_SRC_ADDR_MV, cfg->mv_addr);
	mpp_write_relaxed(mpp, IEP2_REG_DST_ADDR_MD, cfg->md_addr);
	mpp_write_relaxed(mpp, IEP2_REG_DST_ADDR_MV, cfg->mv_addr);
	mpp_write_relaxed(mpp, IEP2_REG_ROI_ADDR, (u32)iep->roi.iova);

	mpp_write_relaxed(mpp, IEP2_REG_DST_ADDR_TOPY, cfg->dst[0].y);
	mpp_write_relaxed(mpp, IEP2_REG_DST_ADDR_TOPC, cfg->dst[0].cbcr);
	mpp_write_relaxed(mpp, IEP2_REG_DST_ADDR_BOTY, cfg->dst[1].y);
	mpp_write_relaxed(mpp, IEP2_REG_DST_ADDR_BOTC, cfg->dst[1].cbcr);

	reg = IEP2_REG_MD_THETA(cfg->md_theta)
		| IEP2_REG_MD_R(cfg->md_r)
		| IEP2_REG_MD_LAMBDA(cfg->md_lambda);
	mpp_write_relaxed(mpp, IEP2_REG_MD_CONFIG0, reg);

	reg = IEP2_REG_DECT_RESI_THR(cfg->dect_resi_thr)
		| IEP2_REG_OSD_AREA_NUM(cfg->osd_area_num)
		| IEP2_REG_OSD_GRADH_THR(cfg->osd_gradh_thr)
		| IEP2_REG_OSD_GRADV_THR(cfg->osd_gradv_thr);
	mpp_write_relaxed(mpp, IEP2_REG_DECT_CONFIG0, reg);

	reg = IEP2_REG_OSD_POS_LIMIT_NUM(cfg->osd_pos_limit_num);
	if (cfg->osd_pos_limit_en)
		reg |= IEP2_REG_OSD_POS_LIMIT_EN;
	mpp_write_relaxed(mpp, IEP2_REG_OSD_LIMIT_CONFIG, reg);

	mpp_write_relaxed(mpp, IEP2_REG_OSD_LIMIT_AREA(0),
			  cfg->osd_limit_area[0]);
	mpp_write_relaxed(mpp, IEP2_REG_OSD_LIMIT_AREA(1),
			  cfg->osd_limit_area[1]);

	reg = IEP2_REG_OSD_PEC_THR(cfg->osd_pec_thr)
		| IEP2_REG_OSD_LINE_NUM(cfg->osd_line_num);
	mpp_write_relaxed(mpp, IEP2_REG_OSD_CONFIG0, reg);

	reg = IEP2_REG_ME_PENA(cfg->me_pena)
		| IEP2_REG_MV_BONUS(cfg->mv_bonus)
		| IEP2_REG_MV_SIMILAR_THR(cfg->mv_similar_thr)
		| IEP2_REG_MV_SIMILAR_NUM_THR0(cfg->mv_similar_num_thr0)
		| IEP2_REG_ME_THR_OFFSET(cfg->me_thr_offset);
	mpp_write_relaxed(mpp, IEP2_REG_ME_CONFIG0, reg);

	reg = IEP2_REG_MV_LEFT_LIMIT((~cfg->mv_left_limit) + 1)
		| IEP2_REG_MV_RIGHT_LIMIT(cfg->mv_right_limit);
	mpp_write_relaxed(mpp, IEP2_REG_ME_LIMIT_CONFIG, reg);

	mpp_write_relaxed(mpp, IEP2_REG_EEDI_CONFIG0,
			  IEP2_REG_EEDI_THR0(cfg->eedi_thr0));
	mpp_write_relaxed(mpp, IEP2_REG_BLE_CONFIG0,
			  IEP2_REG_BLE_BACKTOMA_NUM(cfg->ble_backtoma_num));
}

static void iep2_osd_cfg(struct mpp_dev *mpp, struct iep_task *task)
{
	struct iep2_params *hw_cfg = &task->params;
	int i;
	u32 reg;

	for (i = 0; i < hw_cfg->osd_area_num; ++i) {
		reg = IEP2_REG_OSD_X_STA(hw_cfg->osd_x_sta[i])
			| IEP2_REG_OSD_X_END(hw_cfg->osd_x_end[i])
			| IEP2_REG_OSD_Y_STA(hw_cfg->osd_y_sta[i])
			| IEP2_REG_OSD_Y_END(hw_cfg->osd_y_end[i]);
		mpp_write_relaxed(mpp, IEP2_REG_OSD_AREA_CONF(i), reg);
	}

	for (; i < ARRAY_SIZE(hw_cfg->osd_x_sta); ++i)
		mpp_write_relaxed(mpp, IEP2_REG_OSD_AREA_CONF(i), 0);
}

static void iep2_mtn_tab_cfg(struct mpp_dev *mpp, struct iep_task *task)
{
	struct iep2_params *hw_cfg = &task->params;
	int i;
	u32 *mtn_tab = hw_cfg->mtn_en ? hw_cfg->mtn_tab : iep2_mtn_tab;

	for (i = 0; i < ARRAY_SIZE(hw_cfg->mtn_tab); ++i)
		mpp_write_relaxed(mpp, IEP2_REG_DIL_MTN_TAB(i), mtn_tab[i]);
}

static u32 iep2_tru_list_vld_tab[] = {
	IEP2_REG_MV_TRU_LIST0_4_VLD, IEP2_REG_MV_TRU_LIST1_5_VLD,
	IEP2_REG_MV_TRU_LIST2_6_VLD, IEP2_REG_MV_TRU_LIST3_7_VLD,
	IEP2_REG_MV_TRU_LIST0_4_VLD, IEP2_REG_MV_TRU_LIST1_5_VLD,
	IEP2_REG_MV_TRU_LIST2_6_VLD, IEP2_REG_MV_TRU_LIST3_7_VLD
};

static void iep2_tru_list_cfg(struct mpp_dev *mpp, struct iep_task *task)
{
	struct iep2_params *cfg = &task->params;
	int i;
	u32 reg;

	for (i = 0; i < ARRAY_SIZE(cfg->mv_tru_list); i += 4) {
		reg = 0;

		if (cfg->mv_tru_vld[i])
			reg |= IEP2_REG_MV_TRU_LIST0_4(cfg->mv_tru_list[i])
				| iep2_tru_list_vld_tab[i];

		if (cfg->mv_tru_vld[i + 1])
			reg |= IEP2_REG_MV_TRU_LIST1_5(cfg->mv_tru_list[i + 1])
				| iep2_tru_list_vld_tab[i + 1];

		if (cfg->mv_tru_vld[i + 2])
			reg |= IEP2_REG_MV_TRU_LIST2_6(cfg->mv_tru_list[i + 2])
				| iep2_tru_list_vld_tab[i + 2];

		if (cfg->mv_tru_vld[i + 3])
			reg |= IEP2_REG_MV_TRU_LIST3_7(cfg->mv_tru_list[i + 3])
				| iep2_tru_list_vld_tab[i + 3];

		mpp_write_relaxed(mpp, IEP2_REG_MV_TRU_LIST(i / 4), reg);
	}
}



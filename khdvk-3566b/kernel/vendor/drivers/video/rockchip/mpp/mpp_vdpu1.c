// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2019 Fuzhou Rockchip Electronics Co., Ltd
 *
 * author:
 *	Alpha Lin, alpha.lin@rock-chips.com
 *	Randy Li, randy.li@rock-chips.com
 *	Ding Wei, leo.ding@rock-chips.com
 *
 */
#include <asm/cacheflush.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/iopoll.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/regmap.h>
#include <linux/proc_fs.h>
#include <soc/rockchip/pm_domains.h>

#include "mpp_debug.h"
#include "mpp_common.h"
#include "mpp_iommu.h"

#define VDPU1_DRIVER_NAME		"mpp_vdpu1"

#define	VDPU1_SESSION_MAX_BUFFERS	40
/* The maximum registers number of all the version */
#define VDPU1_REG_NUM			60
#define VDPU1_REG_HW_ID_INDEX		0
#define VDPU1_REG_START_INDEX		0
#define VDPU1_REG_END_INDEX		59

#define VDPU1_REG_PP_NUM		101
#define VDPU1_REG_PP_START_INDEX	0
#define VDPU1_REG_PP_END_INDEX		100

#define VDPU1_REG_DEC_INT_EN		0x004
#define VDPU1_REG_DEC_INT_EN_INDEX	(1)
/* B slice detected, used in 8190 decoder and later */
#define	VDPU1_INT_PIC_INF		BIT(24)
#define	VDPU1_INT_TIMEOUT		BIT(18)
#define	VDPU1_INT_SLICE			BIT(17)
#define	VDPU1_INT_STRM_ERROR		BIT(16)
#define	VDPU1_INT_ASO_ERROR		BIT(15)
#define	VDPU1_INT_BUF_EMPTY		BIT(14)
#define	VDPU1_INT_BUS_ERROR		BIT(13)
#define	VDPU1_DEC_INT			BIT(12)
#define	VDPU1_DEC_INT_RAW		BIT(8)
#define	VDPU1_DEC_IRQ_DIS		BIT(4)
#define	VDPU1_DEC_START			BIT(0)

/* NOTE: Don't enable it or decoding AVC would meet problem at rk3288 */
#define VDPU1_REG_DEC_EN		0x008
#define	VDPU1_CLOCK_GATE_EN		BIT(10)

#define VDPU1_REG_SYS_CTRL		0x00c
#define VDPU1_REG_SYS_CTRL_INDEX	(3)
#define VDPU1_RGE_WIDTH_INDEX		(4)
#define	VDPU1_GET_FORMAT(x)		(((x) >> 28) & 0xf)
#define VDPU1_GET_PROD_NUM(x)		(((x) >> 16) & 0xffff)
#define VDPU1_GET_WIDTH(x)		(((x) & 0xff800000) >> 19)
#define	VDPU1_FMT_H264D			0
#define	VDPU1_FMT_MPEG4D		1
#define	VDPU1_FMT_H263D			2
#define	VDPU1_FMT_JPEGD			3
#define	VDPU1_FMT_VC1D			4
#define	VDPU1_FMT_MPEG2D		5
#define	VDPU1_FMT_MPEG1D		6
#define	VDPU1_FMT_VP6D			7
#define	VDPU1_FMT_RESERVED		8
#define	VDPU1_FMT_VP7D			9
#define	VDPU1_FMT_VP8D			10
#define	VDPU1_FMT_AVSD			11

#define VDPU1_REG_STREAM_RLC_BASE	0x030
#define VDPU1_REG_STREAM_RLC_BASE_INDEX	(12)

#define VDPU1_REG_DIR_MV_BASE		0x0a4
#define VDPU1_REG_DIR_MV_BASE_INDEX	(41)

#define VDPU1_REG_CLR_CACHE_BASE	0x810

#define to_vdpu_task(task)		\
		container_of(task, struct vdpu_task, mpp_task)
#define to_vdpu_dev(dev)		\
		container_of(dev, struct vdpu_dev, mpp)

enum VPUD1_HW_ID {
	VDPU1_ID_0102 = 0x0102,
	VDPU1_ID_9190 = 0x6731,
};

struct vdpu_task {
	struct mpp_task mpp_task;
	/* enable of post process */
	bool pp_enable;

	enum MPP_CLOCK_MODE clk_mode;
	u32 reg[VDPU1_REG_PP_NUM];

	struct reg_offset_info off_inf;
	u32 strm_addr;
	u32 irq_status;
	/* req for current task */
	u32 w_req_cnt;
	struct mpp_request w_reqs[MPP_MAX_MSG_NUM];
	u32 r_req_cnt;
	struct mpp_request r_reqs[MPP_MAX_MSG_NUM];
};

struct vdpu_dev {
	struct mpp_dev mpp;

	struct mpp_clk_info aclk_info;
	struct mpp_clk_info hclk_info;
#ifdef CONFIG_ROCKCHIP_MPP_PROC_FS
	struct proc_dir_entry *procfs;
#endif
	struct reset_control *rst_a;
	struct reset_control *rst_h;
};

static struct mpp_hw_info vdpu_v1_hw_info = {
	.reg_num = VDPU1_REG_NUM,
	.reg_id = VDPU1_REG_HW_ID_INDEX,
	.reg_start = VDPU1_REG_START_INDEX,
	.reg_end = VDPU1_REG_END_INDEX,
	.reg_en = VDPU1_REG_DEC_INT_EN_INDEX,
};

static struct mpp_hw_info vdpu_pp_v1_hw_info = {
	.reg_num = VDPU1_REG_PP_NUM,
	.reg_id = VDPU1_REG_HW_ID_INDEX,
	.reg_start = VDPU1_REG_PP_START_INDEX,
	.reg_end = VDPU1_REG_PP_END_INDEX,
	.reg_en = VDPU1_REG_DEC_INT_EN_INDEX,
};

/*
 * file handle translate information
 */
static const u16 trans_tbl_avsd[] = {
	12, 13, 14, 15, 16, 17, 40, 41, 45
};

static const u16 trans_tbl_default[] = {
	12, 13, 14, 15, 16, 17, 40, 41
};

static const u16 trans_tbl_jpegd[] = {
	12, 13, 14, 40, 66, 67
};

static const u16 trans_tbl_h264d[] = {
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	28, 29, 40
};

static const u16 trans_tbl_vc1d[] = {
	12, 13, 14, 15, 16, 17, 27, 41
};

static const u16 trans_tbl_vp6d[] = {
	12, 13, 14, 18, 27, 40
};

static const u16 trans_tbl_vp8d[] = {
	10, 12, 13, 14, 18, 19, 22, 23, 24, 25, 26, 27, 28, 29, 40
};

static struct mpp_trans_info vdpu_v1_trans[] = {
	[VDPU1_FMT_H264D] = {
		.count = ARRAY_SIZE(trans_tbl_h264d),
		.table = trans_tbl_h264d,
	},
	[VDPU1_FMT_H263D] = {
		.count = ARRAY_SIZE(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[VDPU1_FMT_MPEG4D] = {
		.count = ARRAY_SIZE(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[VDPU1_FMT_JPEGD] = {
		.count = ARRAY_SIZE(trans_tbl_jpegd),
		.table = trans_tbl_jpegd,
	},
	[VDPU1_FMT_VC1D] = {
		.count = ARRAY_SIZE(trans_tbl_vc1d),
		.table = trans_tbl_vc1d,
	},
	[VDPU1_FMT_MPEG2D] = {
		.count = ARRAY_SIZE(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[VDPU1_FMT_MPEG1D] = {
		.count = ARRAY_SIZE(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[VDPU1_FMT_VP6D] = {
		.count = ARRAY_SIZE(trans_tbl_vp6d),
		.table = trans_tbl_vp6d,
	},
	[VDPU1_FMT_RESERVED] = {
		.count = 0,
		.table = NULL,
	},
	[VDPU1_FMT_VP7D] = {
		.count = ARRAY_SIZE(trans_tbl_default),
		.table = trans_tbl_default,
	},
	[VDPU1_FMT_VP8D] = {
		.count = ARRAY_SIZE(trans_tbl_vp8d),
		.table = trans_tbl_vp8d,
	},
	[VDPU1_FMT_AVSD] = {
		.count = ARRAY_SIZE(trans_tbl_avsd),
		.table = trans_tbl_avsd,
	},
};

static int vdpu_process_reg_fd(struct mpp_session *session,
			       struct vdpu_task *task,
			       struct mpp_task_msgs *msgs)
{
	int ret = 0;
	int fmt = VDPU1_GET_FORMAT(task->reg[VDPU1_REG_SYS_CTRL_INDEX]);

	ret = mpp_translate_reg_address(session, &task->mpp_task,
					fmt, task->reg, &task->off_inf);
	if (ret)
		return ret;
	/*
	 * special offset scale case
	 *
	 * This translation is for fd + offset translation.
	 * One register has 32bits. We need to transfer both buffer file
	 * handle and the start address offset so we packet file handle
	 * and offset together using below format.
	 *
	 *  0~9  bit for buffer file handle range 0 ~ 1023
	 * 10~31 bit for offset range 0 ~ 4M
	 *
	 * But on 4K case the offset can be larger the 4M
	 */
	if (likely(fmt == VDPU1_FMT_H264D)) {
		int fd;
		u32 offset;
		dma_addr_t iova = 0;
		u32 idx = VDPU1_REG_DIR_MV_BASE_INDEX;
		struct mpp_mem_region *mem_region = NULL;

		if (session->msg_flags & MPP_FLAGS_REG_NO_OFFSET) {
			fd = task->reg[idx];
			offset = 0;
		} else {
			fd = task->reg[idx] & 0x3ff;
			offset = task->reg[idx] >> 10 << 4;
		}
		mem_region = mpp_task_attach_fd(&task->mpp_task, fd);
		if (IS_ERR(mem_region))
			goto fail;

		iova = mem_region->iova;
		mpp_debug(DEBUG_IOMMU, "DMV[%3d]: %3d => %pad + offset %10d\n",
			  idx, fd, &iova, offset);
		task->reg[idx] = iova + offset;
	}

	mpp_translate_reg_offset_info(&task->mpp_task,
				      &task->off_inf, task->reg);
	return 0;
fail:
	return -EFAULT;
}

static int vdpu_extract_task_msg(struct vdpu_task *task,
				 struct mpp_task_msgs *msgs)
{
	u32 i;
	int ret;
	struct mpp_request *req;
	struct mpp_hw_info *hw_info = task->mpp_task.hw_info;

	for (i = 0; i < msgs->req_cnt; i++) {
		u32 off_s, off_e;

		req = &msgs->reqs[i];
		if (!req->size)
			continue;

		switch (req->cmd) {
		case MPP_CMD_SET_REG_WRITE: {
			off_s = hw_info->reg_start * sizeof(u32);
			off_e = hw_info->reg_end * sizeof(u32);
			ret = mpp_check_req(req, 0, sizeof(task->reg),
					    off_s, off_e);
			if (ret)
				continue;
			if (copy_from_user((u8 *)task->reg + req->offset,
					   req->data, req->size)) {
				mpp_err("copy_from_user reg failed\n");
				return -EIO;
			}
			memcpy(&task->w_reqs[task->w_req_cnt++],
			       req, sizeof(*req));
		} break;
		case MPP_CMD_SET_REG_READ: {
			off_s = hw_info->reg_start * sizeof(u32);
			off_e = hw_info->reg_end * sizeof(u32);
			ret = mpp_check_req(req, 0, sizeof(task->reg),
					    off_s, off_e);
			if (ret)
				continue;
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

static void *vdpu_alloc_task(struct mpp_session *session,
			     struct mpp_task_msgs *msgs)
{
	int ret;
	struct mpp_task *mpp_task = NULL;
	struct vdpu_task *task = NULL;
	struct mpp_dev *mpp = session->mpp;

	mpp_debug_enter();

	task = kzalloc(sizeof(*task), GFP_KERNEL);
	if (!task)
		return NULL;

	mpp_task = &task->mpp_task;
	mpp_task_init(session, mpp_task);
	if (session->device_type == MPP_DEVICE_VDPU1_PP) {
		task->pp_enable = true;
		mpp_task->hw_info = &vdpu_pp_v1_hw_info;
	} else {
		mpp_task->hw_info = mpp->var->hw_info;
	}
	mpp_task->reg = task->reg;
	/* extract reqs for current task */
	ret = vdpu_extract_task_msg(task, msgs);
	if (ret)
		goto fail;
	/* process fd in register */
	if (!(msgs->flags & MPP_FLAGS_REG_FD_NO_TRANS)) {
		ret = vdpu_process_reg_fd(session, task, msgs);
		if (ret)
			goto fail;
	}
	task->strm_addr = task->reg[VDPU1_REG_STREAM_RLC_BASE_INDEX];
	task->clk_mode = CLK_MODE_NORMAL;

	mpp_debug_leave();

	return mpp_task;

fail:
	mpp_task_dump_mem_region(mpp, mpp_task);
	mpp_task_dump_reg(mpp, mpp_task);
	mpp_task_finalize(session, mpp_task);
	kfree(task);
	return NULL;
}

static int vdpu_run(struct mpp_dev *mpp,
		    struct mpp_task *mpp_task)
{
	u32 i;
	u32 reg_en;
	struct vdpu_task *task = to_vdpu_task(mpp_task);

	mpp_debug_enter();

	/* clear cache */
	mpp_write_relaxed(mpp, VDPU1_REG_CLR_CACHE_BASE, 1);
	/* set registers for hardware */
	reg_en = mpp_task->hw_info->reg_en;
	for (i = 0; i < task->w_req_cnt; i++) {
		struct mpp_request *req = &task->w_reqs[i];
		int s = req->offset / sizeof(u32);
		int e = s + req->size / sizeof(u32);

		mpp_write_req(mpp, task->reg, s, e, reg_en);
	}
	/* init current task */
	mpp->cur_task = mpp_task;
	/* Flush the register before the start the device */
	wmb();
	mpp_write(mpp, VDPU1_REG_DEC_INT_EN,
		  task->reg[reg_en] | VDPU1_DEC_START);

	mpp_debug_leave();

	return 0;
}


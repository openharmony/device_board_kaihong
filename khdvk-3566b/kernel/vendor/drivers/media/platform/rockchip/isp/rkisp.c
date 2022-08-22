/*
 * Rockchip isp1 driver
 *
 * Copyright (C) 2017 Rockchip Electronics Co., Ltd.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/clk.h>
#include <linux/compat.h>
#include <linux/iopoll.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/rk-camera-module.h>
#include <linux/videodev2.h>
#include <linux/vmalloc.h>
#include <linux/kfifo.h>
#include <linux/interrupt.h>
#include <linux/rk-preisp.h>
#include <linux/rkisp21-config.h>
#include <linux/iommu.h>
#include <media/v4l2-event.h>
#include <media/media-entity.h>

#include "common.h"
#include "isp_external.h"
#include "regs.h"
#include "rkisp_tb_helper.h"

#define ISP_SUBDEV_NAME DRIVER_NAME "-isp-subdev"
/*
 * NOTE: MIPI controller and input MUX are also configured in this file,
 * because ISP Subdev is not only describe ISP submodule(input size,format, output size, format),
 * but also a virtual route device.
 */

/*
 * There are many variables named with format/frame in below code,
 * please see here for their meaning.
 *
 * Cropping regions of ISP
 *
 * +---------------------------------------------------------+
 * | Sensor image/ISP in_frm                                 |
 * | +---------------------------------------------------+   |
 * | | ISP_ACQ (for black level)                         |   |
 * | | in_crop                                           |   |
 * | | +--------------------------------------------+    |   |
 * | | |    ISP_IS                                  |    |   |
 * | | |    rkisp_isp_subdev: out_crop              |    |   |
 * | | |                                            |    |   |
 * | | |                                            |    |   |
 * | | |                                            |    |   |
 * | | |                                            |    |   |
 * | | +--------------------------------------------+    |   |
 * | +---------------------------------------------------+   |
 * +---------------------------------------------------------+
 */

static void rkisp_config_cmsk(struct rkisp_device *dev);

struct backup_reg {
	const u32 base;
	const u32 shd;
	u32 val;
};

static inline struct rkisp_device *sd_to_isp_dev(struct v4l2_subdev *sd)
{
	return container_of(sd->v4l2_dev, struct rkisp_device, v4l2_dev);
}

static int mbus_pixelcode_to_mipi_dt(u32 pixelcode)
{
	int mipi_dt;

	switch (pixelcode) {
	case MEDIA_BUS_FMT_Y8_1X8:
	case MEDIA_BUS_FMT_SRGGB8_1X8:
	case MEDIA_BUS_FMT_SBGGR8_1X8:
	case MEDIA_BUS_FMT_SGBRG8_1X8:
	case MEDIA_BUS_FMT_SGRBG8_1X8:
		mipi_dt = CIF_CSI2_DT_RAW8;
		break;
	case MEDIA_BUS_FMT_Y10_1X10:
	case MEDIA_BUS_FMT_SBGGR10_1X10:
	case MEDIA_BUS_FMT_SRGGB10_1X10:
	case MEDIA_BUS_FMT_SGBRG10_1X10:
	case MEDIA_BUS_FMT_SGRBG10_1X10:
		mipi_dt = CIF_CSI2_DT_RAW10;
		break;
	case MEDIA_BUS_FMT_Y12_1X12:
	case MEDIA_BUS_FMT_SRGGB12_1X12:
	case MEDIA_BUS_FMT_SBGGR12_1X12:
	case MEDIA_BUS_FMT_SGBRG12_1X12:
	case MEDIA_BUS_FMT_SGRBG12_1X12:
		mipi_dt = CIF_CSI2_DT_RAW12;
		break;
	case MEDIA_BUS_FMT_YUYV8_2X8:
	case MEDIA_BUS_FMT_YVYU8_2X8:
	case MEDIA_BUS_FMT_UYVY8_2X8:
	case MEDIA_BUS_FMT_VYUY8_2X8:
		mipi_dt = CIF_CSI2_DT_YUV422_8b;
		break;
	case MEDIA_BUS_FMT_EBD_1X8:
		mipi_dt = CIF_CSI2_DT_EBD;
		break;
	case MEDIA_BUS_FMT_SPD_2X8:
		mipi_dt = CIF_CSI2_DT_SPD;
		break;
	default:
		mipi_dt = -EINVAL;
	}
	return mipi_dt;
}

/* Get sensor by enabled media link */
static struct v4l2_subdev *get_remote_sensor(struct v4l2_subdev *sd)
{
	struct media_pad *local, *remote;
	struct media_entity *sensor_me;
	struct v4l2_subdev *remote_sd = NULL;

	local = &sd->entity.pads[0];
	if (!local)
		goto end;
	remote = rkisp_media_entity_remote_pad(local);
	if (!remote)
		goto end;

	//skip csi subdev
	if (!strcmp(remote->entity->name, CSI_DEV_NAME)) {
		local = &remote->entity->pads[CSI_SINK];
		if (!local)
			goto end;
		remote = media_entity_remote_pad(local);
		if (!remote)
			goto end;
	}

	sensor_me = remote->entity;
	remote_sd = media_entity_to_v4l2_subdev(sensor_me);
end:
	return remote_sd;
}

static struct rkisp_sensor_info *sd_to_sensor(struct rkisp_device *dev,
					       struct v4l2_subdev *sd)
{
	int i;

	for (i = 0; i < dev->num_sensors; ++i)
		if (dev->sensors[i].sd == sd)
			return &dev->sensors[i];

	return NULL;
}

int rkisp_align_sensor_resolution(struct rkisp_device *dev,
				  struct v4l2_rect *crop, bool user)
{
	struct v4l2_subdev *sensor = NULL;
	struct v4l2_subdev_selection sel;
	u32 code = dev->isp_sdev.in_frm.code;
	u32 src_w = dev->isp_sdev.in_frm.width;
	u32 src_h = dev->isp_sdev.in_frm.height;
	u32 dest_w, dest_h, w, h;
	int ret = 0;

	if (!crop)
		return -EINVAL;

	switch (dev->isp_ver) {
	case ISP_V12:
		w = clamp_t(u32, src_w,
			    CIF_ISP_INPUT_W_MIN,
			    CIF_ISP_INPUT_W_MAX_V12);
		h = clamp_t(u32, src_h,
			    CIF_ISP_INPUT_H_MIN,
			    CIF_ISP_INPUT_H_MAX_V12);
		break;
	case ISP_V13:
		w = clamp_t(u32, src_w,
			    CIF_ISP_INPUT_W_MIN,
			    CIF_ISP_INPUT_W_MAX_V13);
		h = clamp_t(u32, src_h,
			    CIF_ISP_INPUT_H_MIN,
			    CIF_ISP_INPUT_H_MAX_V13);
		break;
	case ISP_V21:
		w = clamp_t(u32, src_w,
			    CIF_ISP_INPUT_W_MIN,
			    CIF_ISP_INPUT_W_MAX_V21);
		h = clamp_t(u32, src_h,
			    CIF_ISP_INPUT_H_MIN,
			    CIF_ISP_INPUT_H_MAX_V21);
		break;
	case ISP_V30:
		w = dev->hw_dev->is_unite ?
			CIF_ISP_INPUT_W_MAX_V30_UNITE : CIF_ISP_INPUT_W_MAX_V30;
		w = clamp_t(u32, src_w, CIF_ISP_INPUT_W_MIN, w);
		h = dev->hw_dev->is_unite ?
			CIF_ISP_INPUT_H_MAX_V30_UNITE : CIF_ISP_INPUT_H_MAX_V30;
		h = clamp_t(u32, src_h, CIF_ISP_INPUT_H_MIN, h);
		break;
	default:
		w  = clamp_t(u32, src_w,
			     CIF_ISP_INPUT_W_MIN,
			     CIF_ISP_INPUT_W_MAX);
		h = clamp_t(u32, src_h,
			    CIF_ISP_INPUT_H_MIN,
			    CIF_ISP_INPUT_H_MAX);
	}

	if (dev->active_sensor)
		sensor = dev->active_sensor->sd;
	if (sensor) {
		/* crop info from sensor */
		sel.pad = 0;
		sel.which = V4L2_SUBDEV_FORMAT_ACTIVE;
		sel.target = V4L2_SEL_TGT_CROP;
		/* crop by sensor, isp don't input crop */
		ret = v4l2_subdev_call(sensor, pad, get_selection, NULL, &sel);
		if (!ret && !user) {
			crop->left = 0;
			crop->top = 0;
			crop->width = clamp_t(u32, sel.r.width,
				CIF_ISP_INPUT_W_MIN, w);
			crop->height = clamp_t(u32, sel.r.height,
				CIF_ISP_INPUT_H_MIN, h);
			return 0;
		}

		if (ret) {
			sel.target = V4L2_SEL_TGT_CROP_BOUNDS;
			/* only crop bounds, want to isp to do input crop */
			ret = v4l2_subdev_call(sensor, pad, get_selection, NULL, &sel);
			if (!ret) {
				crop->left = ALIGN(sel.r.left, 2);
				crop->width = ALIGN(sel.r.width, 2);

				crop->left = clamp_t(u32, crop->left, 0, w);
				crop->top = clamp_t(u32, sel.r.top, 0, h);
				crop->width = clamp_t(u32, crop->width,
					CIF_ISP_INPUT_W_MIN, w - crop->left);
				crop->height = clamp_t(u32, sel.r.height,
					CIF_ISP_INPUT_H_MIN, h - crop->top);
				return 0;
			}
		}
	}

	/* crop from user */
	if (user) {
		crop->left = clamp_t(u32, crop->left, 0, w);
		crop->top = clamp_t(u32, crop->top, 0, h);
		crop->width = clamp_t(u32, crop->width,
				CIF_ISP_INPUT_W_MIN, w - crop->left);
		crop->height = clamp_t(u32, crop->height,
				CIF_ISP_INPUT_H_MIN, h - crop->top);
		if ((code & RKISP_MEDIA_BUS_FMT_MASK) == RKISP_MEDIA_BUS_FMT_BAYER &&
		    (ALIGN_DOWN(crop->width, 16) != crop->width ||
		     ALIGN_DOWN(crop->height, 8) != crop->height))
			v4l2_warn(&dev->v4l2_dev,
				  "Note: bayer raw need width 16 align, height 8 align!\n"
				  "suggest (%d,%d)/%dx%d, specical requirements, Ignore!\n",
				  ALIGN_DOWN(crop->left, 4), crop->top,
				  ALIGN_DOWN(crop->width, 16), ALIGN_DOWN(crop->height, 8));
		return 0;
	}

	/* yuv format */
	if ((code & RKISP_MEDIA_BUS_FMT_MASK) != RKISP_MEDIA_BUS_FMT_BAYER) {
		crop->left = 0;
		crop->top = 0;
		crop->width = min_t(u32, src_w, CIF_ISP_INPUT_W_MAX);
		crop->height = min_t(u32, src_h, CIF_ISP_INPUT_H_MAX);
		return 0;
	}

	/* bayer raw processed by isp need:
	 * width 16 align
	 * height 8 align
	 * width and height no exceeding the max limit
	 */
	dest_w = ALIGN_DOWN(w, 16);
	dest_h = ALIGN_DOWN(h, 8);

	/* try to center of crop
	 *4 align to no change bayer raw format
	 */
	crop->left = ALIGN_DOWN((src_w - dest_w) >> 1, 4);
	crop->top = (src_h - dest_h) >> 1;
	crop->width = dest_w;
	crop->height = dest_h;
	return 0;
}

struct media_pad *rkisp_media_entity_remote_pad(struct media_pad *pad)
{
	struct media_link *link;

	list_for_each_entry(link, &pad->entity->links, list) {
		if (!(link->flags & MEDIA_LNK_FL_ENABLED) ||
		    !strcmp(link->source->entity->name,
			    DMARX0_VDEV_NAME) ||
		    !strcmp(link->source->entity->name,
			    DMARX1_VDEV_NAME) ||
		    !strcmp(link->source->entity->name,
			    DMARX2_VDEV_NAME))
			continue;
		if (link->source == pad)
			return link->sink;
		if (link->sink == pad)
			return link->source;
	}

	return NULL;
}

int rkisp_update_sensor_info(struct rkisp_device *dev)
{
	struct v4l2_subdev *sd = &dev->isp_sdev.sd;
	struct rkisp_sensor_info *sensor;
	struct v4l2_subdev *sensor_sd;
	struct v4l2_subdev_format *fmt;
	int i, ret = 0;

	sensor_sd = get_remote_sensor(sd);
	if (!sensor_sd)
		return -ENODEV;

	sensor = sd_to_sensor(dev, sensor_sd);
	ret = v4l2_subdev_call(sensor->sd, pad, get_mbus_config,
			       0, &sensor->mbus);
	if (ret && ret != -ENOIOCTLCMD)
		return ret;

	sensor->fmt[0].pad = 0;
	sensor->fmt[0].which = V4L2_SUBDEV_FORMAT_ACTIVE;
	ret = v4l2_subdev_call(sensor->sd, pad, get_fmt,
			       &sensor->cfg, &sensor->fmt[0]);
	if (ret && ret != -ENOIOCTLCMD)
		return ret;

	if (sensor->mbus.type == V4L2_MBUS_CSI2_DPHY) {
		u8 vc = 0;

		memset(dev->csi_dev.mipi_di, 0,
		       sizeof(dev->csi_dev.mipi_di));
		for (i = 0; i < dev->csi_dev.max_pad - 1; i++) {
			struct rkmodule_channel_info ch = { 0 };

			fmt = &sensor->fmt[i];
			ch.index = i;
			ret = v4l2_subdev_call(sensor->sd, core, ioctl,
					       RKMODULE_GET_CHANNEL_INFO, &ch);
			if (ret) {
				if (i)
					*fmt = sensor->fmt[0];
			} else {
				fmt->format.width = ch.width;
				fmt->format.height = ch.height;
				fmt->format.code = ch.bus_fmt;
			}
			ret = mbus_pixelcode_to_mipi_dt(fmt->format.code);
			if (ret < 0) {
				v4l2_err(&dev->v4l2_dev,
					 "Invalid mipi data type\n");
				return ret;
			}

			switch (ch.vc) {
			case V4L2_MBUS_CSI2_CHANNEL_3:
				vc = 3;
				break;
			case V4L2_MBUS_CSI2_CHANNEL_2:
				vc = 2;
				break;
			case V4L2_MBUS_CSI2_CHANNEL_1:
				vc = 1;
				break;
			case V4L2_MBUS_CSI2_CHANNEL_0:
			default:
				vc = 0;
			}
			dev->csi_dev.mipi_di[i] = CIF_MIPI_DATA_SEL_DT(ret) |
				CIF_MIPI_DATA_SEL_VC(vc);
			v4l2_dbg(1, rkisp_debug, &dev->v4l2_dev,
				  "CSI ch%d vc:%d dt:0x%x %dx%d\n",
				  i, vc, ret,
				  fmt->format.width,
				  fmt->format.height);
		}
	}

	v4l2_subdev_call(sensor->sd, video, g_frame_interval, &sensor->fi);
	dev->active_sensor = sensor;

	return ret;
}

u32 rkisp_mbus_pixelcode_to_v4l2(u32 pixelcode)
{
	u32 pixelformat;

	switch (pixelcode) {
	case MEDIA_BUS_FMT_Y8_1X8:
		pixelformat = V4L2_PIX_FMT_GREY;
		break;
	case MEDIA_BUS_FMT_SBGGR8_1X8:
		pixelformat = V4L2_PIX_FMT_SBGGR8;
		break;
	case MEDIA_BUS_FMT_SGBRG8_1X8:
		pixelformat = V4L2_PIX_FMT_SGBRG8;
		break;
	case MEDIA_BUS_FMT_SGRBG8_1X8:
		pixelformat = V4L2_PIX_FMT_SGRBG8;
		break;
	case MEDIA_BUS_FMT_SRGGB8_1X8:
		pixelformat = V4L2_PIX_FMT_SRGGB8;
		break;
	case MEDIA_BUS_FMT_Y10_1X10:
		pixelformat = V4L2_PIX_FMT_Y10;
		break;
	case MEDIA_BUS_FMT_SBGGR10_1X10:
		pixelformat = V4L2_PIX_FMT_SBGGR10;
		break;
	case MEDIA_BUS_FMT_SGBRG10_1X10:
		pixelformat = V4L2_PIX_FMT_SGBRG10;
		break;
	case MEDIA_BUS_FMT_SGRBG10_1X10:
		pixelformat = V4L2_PIX_FMT_SGRBG10;
		break;
	case MEDIA_BUS_FMT_SRGGB10_1X10:
		pixelformat = V4L2_PIX_FMT_SRGGB10;
		break;
	case MEDIA_BUS_FMT_Y12_1X12:
		pixelformat = V4L2_PIX_FMT_Y12;
		break;
	case MEDIA_BUS_FMT_SBGGR12_1X12:
		pixelformat = V4L2_PIX_FMT_SBGGR12;
		break;
	case MEDIA_BUS_FMT_SGBRG12_1X12:
		pixelformat = V4L2_PIX_FMT_SGBRG12;
		break;
	case MEDIA_BUS_FMT_SGRBG12_1X12:
		pixelformat = V4L2_PIX_FMT_SGRBG12;
		break;
	case MEDIA_BUS_FMT_SRGGB12_1X12:
		pixelformat = V4L2_PIX_FMT_SRGGB12;
		break;
	case MEDIA_BUS_FMT_EBD_1X8:
		pixelformat = V4l2_PIX_FMT_EBD8;
		break;
	case MEDIA_BUS_FMT_SPD_2X8:
		pixelformat = V4l2_PIX_FMT_SPD16;
		break;
	default:
		pixelformat = V4L2_PIX_FMT_SRGGB10;
	}

	return pixelformat;
}


/*
 * for hdr read back mode, rawrd read back data
 * this will update rawrd base addr to shadow.
 */
void rkisp_trigger_read_back(struct rkisp_device *dev, u8 dma2frm, u32 mode, bool is_try)
{
	struct rkisp_isp_params_vdev *params_vdev = &dev->params_vdev;
	struct rkisp_hw_dev *hw = dev->hw_dev;
	u32 val, cur_frame_id, tmp, rd_mode;
	u64 iq_feature = hw->iq_feature;
	bool is_feature_on = hw->is_feature_on;
	bool is_upd = false, is_3dlut_upd = false;

	hw->cur_dev_id = dev->dev_id;
	rkisp_dmarx_get_frame(dev, &cur_frame_id, NULL, NULL, true);

	val = 0;
	if (mode & T_START_X1) {
		rd_mode = HDR_RDBK_FRAME1;
	} else if (mode & T_START_X2) {
		rd_mode = HDR_RDBK_FRAME2;
		val = SW_HDRMGE_EN | SW_HDRMGE_MODE_FRAMEX2;
	} else if (mode & T_START_X3) {
		rd_mode = HDR_RDBK_FRAME3;
		val = SW_HDRMGE_EN | SW_HDRMGE_MODE_FRAMEX3;
	} else {
		rd_mode = dev->rd_mode;
		val = rkisp_read(dev, ISP_HDRMGE_BASE, false) & 0xf;
	}

	if (is_feature_on) {
		if ((ISP2X_MODULE_HDRMGE & ~iq_feature) && (val & SW_HDRMGE_EN)) {
			v4l2_err(&dev->v4l2_dev, "hdrmge is not supported\n");
			return;
		}
	}

	if (rd_mode != dev->rd_mode) {
		rkisp_unite_set_bits(dev, ISP_HDRMGE_BASE, ISP_HDRMGE_MODE_MASK,
				     val, false, hw->is_unite);
		dev->skip_frame = 2;
		is_upd = true;
	}

	if (dev->isp_ver == ISP_V20 && dev->dmarx_dev.trigger == T_MANUAL && !is_try) {
		if (dev->rd_mode != rd_mode && dev->br_dev.en) {
			tmp = dev->isp_sdev.in_crop.height;
			val = rkisp_read(dev, CIF_DUAL_CROP_CTRL, false);
			if (rd_mode == HDR_RDBK_FRAME1) {
				val |= CIF_DUAL_CROP_MP_MODE_YUV;
				tmp += RKMODULE_EXTEND_LINE;
			} else {
				val &= ~CIF_DUAL_CROP_MP_MODE_YUV;
			}
			rkisp_write(dev, CIF_DUAL_CROP_CTRL, val, false);
			rkisp_write(dev, CIF_ISP_ACQ_V_SIZE, tmp, false);
			rkisp_write(dev, CIF_ISP_OUT_V_SIZE, tmp, false);
		}
		dev->rd_mode = rd_mode;
		rkisp_rawrd_set_pic_size(dev,
			dev->dmarx_dev.stream[RKISP_STREAM_RAWRD2].out_fmt.width,
			dev->dmarx_dev.stream[RKISP_STREAM_RAWRD2].out_fmt.height);
	}
	dev->rd_mode = rd_mode;

	rkisp_params_first_cfg(&dev->params_vdev, &dev->isp_sdev.in_fmt,
			       dev->isp_sdev.quantization);
	rkisp_params_cfg(params_vdev, cur_frame_id);
	rkisp_config_cmsk(dev);
	if (!hw->is_single && !is_try) {
		rkisp_update_regs(dev, CTRL_VI_ISP_PATH, SUPER_IMP_COLOR_CR);
		rkisp_update_regs(dev, DUAL_CROP_M_H_OFFS, DUAL_CROP_S_V_SIZE);
		rkisp_update_regs(dev, ISP_ACQ_PROP, DUAL_CROP_CTRL);
		rkisp_update_regs(dev, MAIN_RESIZE_SCALE_HY, MI_WR_CTRL);
		rkisp_update_regs(dev, SELF_RESIZE_SCALE_HY, MAIN_RESIZE_CTRL);
		rkisp_update_regs(dev, ISP_GAMMA_OUT_CTRL, SELF_RESIZE_CTRL);
		rkisp_update_regs(dev, MI_RD_CTRL2, ISP_LSC_CTRL);
		rkisp_update_regs(dev, MI_MP_WR_Y_BASE, MI_MP_WR_Y_LLENGTH);
		rkisp_update_regs(dev, ISP_LSC_XGRAD_01, ISP_RAWAWB_RAM_DATA);
		if (dev->isp_ver == ISP_V20 &&
		    (rkisp_read(dev, ISP_DHAZ_CTRL, false) & ISP_DHAZ_ENMUX ||
		     rkisp_read(dev, ISP_HDRTMO_CTRL, false) & ISP_HDRTMO_EN)) {
			dma2frm += (dma2frm ? 0 : 1);
		} else if (dev->isp_ver == ISP_V21) {
			val = rkisp_read(dev, MI_WR_CTRL2, false);
			rkisp_set_bits(dev, MI_WR_CTRL2, 0, val, true);
			rkisp_write(dev, MI_WR_INIT, ISP21_SP_FORCE_UPD | ISP21_MP_FORCE_UPD, true);
			/* sensor mode & index */
			val = rkisp_read_reg_cache(dev, ISP_ACQ_H_OFFS);
			val |= ISP21_SENSOR_MODE(hw->dev_num >= 3 ? 2 : hw->dev_num - 1) |
				ISP21_SENSOR_INDEX(dev->dev_id);
			writel(val, hw->base_addr + ISP_ACQ_H_OFFS);
		} else if (dev->isp_ver == ISP_V30) {
			val = rkisp_read(dev, MI_WR_CTRL2, false);
			val |= ISP3X_MPSELF_UPD | ISP3X_SPSELF_UPD | ISP3X_BPSELF_UPD |
				ISP3X_BAY3D_RDSELF_UPD | ISP3X_DBR_RDSELF_UPD |
				ISP3X_DBR_WRSELF_UPD | ISP3X_GAINSELF_UPD |
				ISP3X_BAY3D_IIRSELF_UPD | ISP3X_BAY3D_CURSELF_UPD |
				ISP3X_BAY3D_DSSELF_UPD;
			writel(val, hw->base_addr + MI_WR_CTRL2);

			val = rkisp_read(dev, ISP3X_MPFBC_CTRL, false);
			val |= ISP3X_MPFBC_FORCE_UPD;
			writel(val, hw->base_addr + ISP3X_MPFBC_CTRL);

			/* sensor mode & index */
			val = rkisp_read_reg_cache(dev, ISP_ACQ_H_OFFS);
			val |= ISP21_SENSOR_MODE(hw->dev_num >= 3 ? 2 : hw->dev_num - 1) |
			       ISP21_SENSOR_INDEX(dev->dev_id);
			writel(val, hw->base_addr + ISP_ACQ_H_OFFS);
		}
		is_upd = true;
	}

	if (dev->isp_ver == ISP_V21 || dev->isp_ver == ISP_V30)
		dma2frm = 0;
	if (dma2frm > 2)
		dma2frm = 2;
	if (dma2frm == 2)
		dev->rdbk_cnt_x3++;
	else if (dma2frm == 1)
		dev->rdbk_cnt_x2++;
	else
		dev->rdbk_cnt_x1++;
	dev->rdbk_cnt++;

	rkisp_params_cfgsram(params_vdev);
	params_vdev->rdbk_times = dma2frm + 1;

	/* read 3d lut at frame end */
	if (hw->is_single && is_upd &&
	    rkisp_read_reg_cache(dev, ISP_3DLUT_UPDATE) & 0x1) {
		rkisp_write(dev, ISP_3DLUT_UPDATE, 0, true);
		is_3dlut_upd = true;
	}
	if (is_upd) {
		val = rkisp_read(dev, ISP_CTRL, false);
		val |= CIF_ISP_CTRL_ISP_CFG_UPD;
		rkisp_write(dev, ISP_CTRL, val, true);
	}
	if (is_3dlut_upd)
		rkisp_write(dev, ISP_3DLUT_UPDATE, 1, true);

	memset(dev->filt_state, 0, sizeof(dev->filt_state));
	dev->filt_state[RDBK_F_VS] = dma2frm;

	val = rkisp_read(dev, CSI2RX_CTRL0, true);
	val &= ~SW_IBUF_OP_MODE(0xf);
	tmp = SW_IBUF_OP_MODE(dev->rd_mode);
	val |= tmp | SW_CSI2RX_EN | SW_DMA_2FRM_MODE(dma2frm);
	v4l2_dbg(2, rkisp_debug, &dev->v4l2_dev,
		 "readback frame:%d time:%d 0x%x\n",
		 cur_frame_id, dma2frm + 1, val);
	if (!dma2frm)
		rkisp_bridge_update_mi(dev, 0);
	if (!hw->is_shutdown)
		rkisp_unite_write(dev, CSI2RX_CTRL0, val, true, hw->is_unite);
}

static void rkisp_rdbk_trigger_handle(struct rkisp_device *dev, u32 cmd)
{
	struct rkisp_hw_dev *hw = dev->hw_dev;
	struct rkisp_device *isp = NULL;
	struct isp2x_csi_trigger t = { 0 };
	unsigned long lock_flags = 0;
	int i, times = -1, max = 0, id = 0;
	int len[DEV_MAX] = { 0 };
	u32 mode = 0;

	spin_lock_irqsave(&hw->rdbk_lock, lock_flags);
	if (cmd == T_CMD_END)
		hw->is_idle = true;
	if (hw->is_shutdown)
		hw->is_idle = false;
	if (!hw->is_idle)
		goto end;
	if (hw->monitor.state & ISP_MIPI_ERROR && hw->monitor.is_en)
		goto end;

	for (i = 0; i < hw->dev_num; i++) {
		isp = hw->isp[i];
		if (!(isp->isp_state & ISP_START))
			continue;
		rkisp_rdbk_trigger_event(isp, T_CMD_LEN, &len[i]);
		if (max < len[i]) {
			max = len[i];
			id = i;
		}
	}

	if (max) {
		v4l2_dbg(2, rkisp_debug, &dev->v4l2_dev,
			 "trigger fifo len:%d\n", max);
		isp = hw->isp[id];
		rkisp_rdbk_trigger_event(isp, T_CMD_DEQUEUE, &t);
		isp->dmarx_dev.pre_frame = isp->dmarx_dev.cur_frame;
		if (t.frame_id > isp->dmarx_dev.pre_frame.id &&
		    t.frame_id - isp->dmarx_dev.pre_frame.id > 1)
			isp->isp_sdev.dbg.frameloss +=
				t.frame_id - isp->dmarx_dev.pre_frame.id + 1;
		isp->dmarx_dev.cur_frame.id = t.frame_id;
		isp->dmarx_dev.cur_frame.sof_timestamp = t.sof_timestamp;
		isp->dmarx_dev.cur_frame.timestamp = t.frame_timestamp;
		isp->isp_sdev.frm_timestamp = t.sof_timestamp;
		mode = t.mode;
		times = t.times;
		hw->cur_dev_id = id;
		hw->is_idle = false;
	}
end:
	spin_unlock_irqrestore(&hw->rdbk_lock, lock_flags);
	if (times >= 0)
		rkisp_trigger_read_back(isp, times, mode, false);
}

int rkisp_rdbk_trigger_event(struct rkisp_device *dev, u32 cmd, void *arg)
{
	struct kfifo *fifo = &dev->rdbk_kfifo;
	struct isp2x_csi_trigger *trigger = NULL;
	unsigned long lock_flags = 0;
	int val, ret = 0;

	if (dev->dmarx_dev.trigger != T_MANUAL)
		return 0;

	spin_lock_irqsave(&dev->rdbk_lock, lock_flags);
	switch (cmd) {
	case T_CMD_QUEUE:
		trigger = arg;
		if (!trigger)
			break;
		if (!kfifo_is_full(fifo))
			kfifo_in(fifo, trigger, sizeof(*trigger));
		else
			v4l2_err(&dev->v4l2_dev, "rdbk fifo is full\n");
		break;
	case T_CMD_DEQUEUE:
		if (!kfifo_is_empty(fifo))
			ret = kfifo_out(fifo, arg, sizeof(struct isp2x_csi_trigger));
		if (!ret)
			ret = -EINVAL;
		break;
	case T_CMD_LEN:
		val = kfifo_len(fifo) / sizeof(struct isp2x_csi_trigger);
		*(u32 *)arg = val;
		break;
	default:
		break;
	}
	spin_unlock_irqrestore(&dev->rdbk_lock, lock_flags);

	if (cmd == T_CMD_QUEUE || cmd == T_CMD_END)
		rkisp_rdbk_trigger_handle(dev, cmd);
	return ret;
}

void rkisp_check_idle(struct rkisp_device *dev, u32 irq)
{
	u32 val = 0;

	dev->irq_ends |= (irq & dev->irq_ends_mask);
	v4l2_dbg(3, rkisp_debug, &dev->v4l2_dev,
		 "%s irq:0x%x ends:0x%x mask:0x%x\n",
		 __func__, irq, dev->irq_ends, dev->irq_ends_mask);
	if (dev->irq_ends == dev->irq_ends_mask && dev->hw_dev->monitor.is_en) {
		dev->hw_dev->monitor.retry = 0;
		dev->hw_dev->monitor.state |= ISP_FRAME_END;
		if (!completion_done(&dev->hw_dev->monitor.cmpl))
			complete(&dev->hw_dev->monitor.cmpl);
	}
	if (dev->irq_ends != dev->irq_ends_mask || !IS_HDR_RDBK(dev->rd_mode))
		return;

	/* check output stream is off */
	val = ISP_FRAME_MP | ISP_FRAME_SP | ISP_FRAME_MPFBC | ISP_FRAME_BP;
	if (!(dev->irq_ends_mask & val))
		dev->isp_state = ISP_STOP;

	val = 0;
	dev->irq_ends = 0;
	switch (dev->rd_mode) {
	case HDR_RDBK_FRAME3://for rd1 rd0 rd2
		val |= RAW1_RD_FRAME;
		/* FALLTHROUGH */
	case HDR_RDBK_FRAME2://for rd0 rd2
		val |= RAW0_RD_FRAME;
		/* FALLTHROUGH */
	default:// for rd2
		val |= RAW2_RD_FRAME;
		/* FALLTHROUGH */
	}
	rkisp2_rawrd_isr(val, dev);
	if (dev->dmarx_dev.trigger == T_MANUAL)
		rkisp_rdbk_trigger_event(dev, T_CMD_END, NULL);
	if (dev->isp_state == ISP_STOP)
		wake_up(&dev->sync_onoff);
}

static void rkisp_set_state(u32 *state, u32 val)
{
	u32 mask = 0xff;

	if (val < ISP_STOP)
		mask = 0xff00;
	*state &= mask;
	*state |= val;
}

/*
 * Image Stabilization.
 * This should only be called when configuring CIF
 * or at the frame end interrupt
 */
static void rkisp_config_ism(struct rkisp_device *dev)
{
	struct v4l2_rect *out_crop = &dev->isp_sdev.out_crop;
	u32 width = out_crop->width, mult = 1;
	bool is_unite = dev->hw_dev->is_unite;

	/* isp2.0 no ism */
	if (dev->isp_ver == ISP_V20 || dev->isp_ver == ISP_V21)
		return;

	if (is_unite)
		width = width / 2 + RKMOUDLE_UNITE_EXTEND_PIXEL;
	rkisp_unite_write(dev, CIF_ISP_IS_RECENTER, 0, false, is_unite);
	rkisp_unite_write(dev, CIF_ISP_IS_MAX_DX, 0, false, is_unite);
	rkisp_unite_write(dev, CIF_ISP_IS_MAX_DY, 0, false, is_unite);
	rkisp_unite_write(dev, CIF_ISP_IS_DISPLACE, 0, false, is_unite);
	rkisp_unite_write(dev, CIF_ISP_IS_H_OFFS, out_crop->left, false, is_unite);
	rkisp_unite_write(dev, CIF_ISP_IS_V_OFFS, out_crop->top, false, is_unite);
	rkisp_unite_write(dev, CIF_ISP_IS_H_SIZE, width, false, is_unite);
	if (dev->cap_dev.stream[RKISP_STREAM_SP].interlaced)
		mult = 2;
	rkisp_unite_write(dev, CIF_ISP_IS_V_SIZE, out_crop->height / mult,
			  false, is_unite);

	if (dev->isp_ver == ISP_V30)
		return;

	/* IS(Image Stabilization) is always on, working as output crop */
	rkisp_write(dev, CIF_ISP_IS_CTRL, 1, false);
}

static int rkisp_reset_handle_v2x(struct rkisp_device *dev)
{
	void __iomem *base = dev->base_addr;
	void *reg_buf = NULL;
	u32 *reg, *reg1, i;
	struct backup_reg backup[] = {
		{
			.base = MI_MP_WR_Y_BASE,
			.shd = MI_MP_WR_Y_BASE_SHD,
		}, {
			.base = MI_MP_WR_CB_BASE,
			.shd = MI_MP_WR_CB_BASE_SHD,
		}, {
			.base = MI_MP_WR_CR_BASE,
			.shd = MI_MP_WR_CR_BASE_SHD,
		}, {
			.base = MI_SP_WR_Y_BASE,
			.shd = MI_SP_WR_Y_BASE_SHD,
		}, {
			.base = MI_SP_WR_CB_BASE,
			.shd = MI_SP_WR_CB_BASE_AD_SHD,
		}, {
			.base = MI_SP_WR_CR_BASE,
			.shd = MI_SP_WR_CR_BASE_AD_SHD,
		}, {
			.base = MI_RAW0_WR_BASE,
			.shd = MI_RAW0_WR_BASE_SHD,
		}, {
			.base = MI_RAW1_WR_BASE,
			.shd = MI_RAW1_WR_BASE_SHD,
		}, {
			.base = MI_RAW2_WR_BASE,
			.shd = MI_RAW2_WR_BASE_SHD,
		}, {
			.base = MI_RAW3_WR_BASE,
			.shd = MI_RAW3_WR_BASE_SHD,
		}, {
			.base = MI_RAW0_RD_BASE,
			.shd = MI_RAW0_RD_BASE_SHD,
		}, {
			.base = MI_RAW1_RD_BASE,
			.shd = MI_RAW1_RD_BASE_SHD,
		}, {
			.base = MI_RAW2_RD_BASE,
			.shd = MI_RAW2_RD_BASE_SHD,
		}, {
			.base = MI_GAIN_WR_BASE,
			.shd = MI_GAIN_WR_BASE_SHD,
		}
	};

	reg_buf = kzalloc(RKISP_ISP_SW_REG_SIZE, GFP_KERNEL);
	if (!reg_buf)
		return -ENOMEM;

	dev_info(dev->dev, "%s enter\n", __func__);

	memcpy_fromio(reg_buf, base, RKISP_ISP_SW_REG_SIZE);
	rkisp_soft_reset(dev->hw_dev, true);

	/* process special reg */
	reg = reg_buf + ISP_CTRL;
	*reg &= ~(CIF_ISP_CTRL_ISP_ENABLE |
		  CIF_ISP_CTRL_ISP_INFORM_ENABLE |
		  CIF_ISP_CTRL_ISP_CFG_UPD);
	reg = reg_buf + MI_WR_INIT;
	*reg = 0;
	reg = reg_buf + CSI2RX_CTRL0;
	*reg &= ~SW_CSI2RX_EN;
	/* skip mmu range */
	memcpy_toio(base, reg_buf, ISP21_MI_BAY3D_RD_BASE_SHD);
	memcpy_toio(base + CSI2RX_CTRL0, reg_buf + CSI2RX_CTRL0,
		    RKISP_ISP_SW_REG_SIZE - CSI2RX_CTRL0);
	/* config shd_reg to base_reg */
	for (i = 0; i < ARRAY_SIZE(backup); i++) {
		reg = reg_buf + backup[i].base;
		reg1 = reg_buf + backup[i].shd;
		backup[i].val = *reg;
		writel(*reg1, base + backup[i].base);
	}

	/* clear state */
	dev->isp_err_cnt = 0;
	dev->isp_state &= ~ISP_ERROR;
	rkisp_set_state(&dev->isp_state, ISP_FRAME_END);
	dev->hw_dev->monitor.state = ISP_FRAME_END;

	/* update module */
	reg = reg_buf + DUAL_CROP_CTRL;
	if (*reg & 0xf)
		writel(*reg | CIF_DUAL_CROP_CFG_UPD, base + DUAL_CROP_CTRL);
	reg = reg_buf + SELF_RESIZE_CTRL;
	if (*reg & 0xf)
		writel(*reg | CIF_RSZ_CTRL_CFG_UPD, base + SELF_RESIZE_CTRL);
	reg = reg_buf + MAIN_RESIZE_CTRL;
	if (*reg & 0xf)
		writel(*reg | CIF_RSZ_CTRL_CFG_UPD, base + MAIN_RESIZE_CTRL);

	/* update mi and isp, base_reg will update to shd_reg */
	force_cfg_update(dev);
	reg = reg_buf + ISP_CTRL;
	*reg |= CIF_ISP_CTRL_ISP_ENABLE |
		CIF_ISP_CTRL_ISP_INFORM_ENABLE |
		CIF_ISP_CTRL_ISP_CFG_UPD;
	writel(*reg, base + ISP_CTRL);
	udelay(50);
	/* config base_reg */
	for (i = 0; i < ARRAY_SIZE(backup); i++)
		writel(backup[i].val, base + backup[i].base);
	/* mpfbc base_reg = shd_reg, write is base but read is shd */
	if (dev->isp_ver == ISP_V20)
		writel(rkisp_read_reg_cache(dev, ISP_MPFBC_HEAD_PTR),
		       base + ISP_MPFBC_HEAD_PTR);
	rkisp_set_bits(dev, CIF_ISP_IMSC, 0, CIF_ISP_DATA_LOSS | CIF_ISP_PIC_SIZE_ERROR, true);
	if (IS_HDR_RDBK(dev->hdr.op_mode)) {
		if (!dev->hw_dev->is_idle)
			rkisp_trigger_read_back(dev, 1, 0, true);
		else
			rkisp_rdbk_trigger_event(dev, T_CMD_QUEUE, NULL);
	}
	kfree(reg_buf);
	dev_info(dev->dev, "%s exit\n", __func__);
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Rockchip CIF Driver
 *
 * Copyright (C) 2018 Rockchip Electronics Co., Ltd.
 */

#include <linux/delay.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <linux/iommu.h>
#include <media/v4l2-common.h>
#include <media/v4l2-event.h>
#include <media/v4l2-fh.h>
#include <media/v4l2-fwnode.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-subdev.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-dma-sg.h>
#include <soc/rockchip/rockchip-system-status.h>
#include <dt-bindings/soc/rockchip-system-status.h>
#include <soc/rockchip/rockchip_iommu.h>

#include "dev.h"
#include "mipi-csi2.h"
#include "common.h"

#define CIF_REQ_BUFS_MIN	3
#define CIF_MIN_WIDTH		64
#define CIF_MIN_HEIGHT		64
#define CIF_MAX_WIDTH		8192
#define CIF_MAX_HEIGHT		8192

#define OUTPUT_STEP_WISE	8

#define RKCIF_PLANE_Y		0
#define RKCIF_PLANE_CBCR	1
#define RKCIF_MAX_PLANE		3

#define STREAM_PAD_SINK		0
#define STREAM_PAD_SOURCE	1

#define CIF_TIMEOUT_FRAME_NUM	(2)

#define CIF_DVP_PCLK_DUAL_EDGE	(V4L2_MBUS_PCLK_SAMPLE_RISING |\
				 V4L2_MBUS_PCLK_SAMPLE_FALLING)

/*
 * Round up height when allocate memory so that Rockchip encoder can
 * use DMA buffer directly, though this may waste a bit of memory.
 */
#define MEMORY_ALIGN_ROUND_UP_HEIGHT		16

/* Get xsubs and ysubs for fourcc formats
 *
 * @xsubs: horizontal color samples in a 4*4 matrix, for yuv
 * @ysubs: vertical color samples in a 4*4 matrix, for yuv
 */
static int fcc_xysubs(u32 fcc, u32 *xsubs, u32 *ysubs)
{
	switch (fcc) {
	case V4L2_PIX_FMT_NV16:
	case V4L2_PIX_FMT_NV61:
	case V4L2_PIX_FMT_UYVY:
	case V4L2_PIX_FMT_VYUY:
	case V4L2_PIX_FMT_YUYV:
	case V4L2_PIX_FMT_YVYU:
		*xsubs = 2;
		*ysubs = 1;
		break;
	case V4L2_PIX_FMT_NV21:
	case V4L2_PIX_FMT_NV12:
		*xsubs = 2;
		*ysubs = 2;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct cif_output_fmt out_fmts[] = {
	{
		.fourcc = V4L2_PIX_FMT_NV16,
		.cplanes = 2,
		.mplanes = 1,
		.fmt_val = YUV_OUTPUT_422 | UV_STORAGE_ORDER_UVUV,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_YUV422,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_NV61,
		.fmt_val = YUV_OUTPUT_422 | UV_STORAGE_ORDER_VUVU,
		.cplanes = 2,
		.mplanes = 1,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_YUV422,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_NV12,
		.fmt_val = YUV_OUTPUT_420 | UV_STORAGE_ORDER_UVUV,
		.cplanes = 2,
		.mplanes = 1,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_YUV420SP,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_NV21,
		.fmt_val = YUV_OUTPUT_420 | UV_STORAGE_ORDER_VUVU,
		.cplanes = 2,
		.mplanes = 1,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_YUV420SP,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_YUYV,
		.cplanes = 2,
		.mplanes = 1,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_YVYU,
		.cplanes = 2,
		.mplanes = 1,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_UYVY,
		.cplanes = 2,
		.mplanes = 1,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_VYUY,
		.cplanes = 2,
		.mplanes = 1,
		.bpp = { 8, 16 },
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_YUV,
	}, {
		.fourcc = V4L2_PIX_FMT_RGB24,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 24 },
		.csi_fmt_val = CSI_WRDDR_TYPE_RGB888,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_RGB565,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_BGR666,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 18 },
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SRGGB8,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 8 },
		.raw_bpp = 8,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGRBG8,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 8 },
		.raw_bpp = 8,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGBRG8,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 8 },
		.raw_bpp = 8,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SBGGR8,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 8 },
		.raw_bpp = 8,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SRGGB10,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 10,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW10,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGRBG10,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 10,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW10,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGBRG10,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 10,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW10,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SBGGR10,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 10,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW10,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SRGGB12,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 12,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW12,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGRBG12,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 12,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW12,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGBRG12,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 12,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW12,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SBGGR12,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 12,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW12,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SBGGR16,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 16,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGBRG16,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 16,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SGRBG16,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 16,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_SRGGB16,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 16,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_Y16,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 16,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_GREY,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = {8},
		.raw_bpp = 8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4l2_PIX_FMT_EBD8,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = {8},
		.raw_bpp = 8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4l2_PIX_FMT_SPD16,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = {16},
		.raw_bpp = 16,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_Y12,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 12,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW12,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}, {
		.fourcc = V4L2_PIX_FMT_Y10,
		.cplanes = 1,
		.mplanes = 1,
		.bpp = { 16 },
		.raw_bpp = 10,
		.csi_fmt_val = CSI_WRDDR_TYPE_RAW10,
		.fmt_type = CIF_FMT_TYPE_RAW,
	}

	/* TODO: We can support NV12M/NV21M/NV16M/NV61M too */
};

static const struct cif_input_fmt in_fmts[] = {
	{
		.mbus_code	= MEDIA_BUS_FMT_YUYV8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_YUYV,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_YUYV,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_YUYV8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_YUYV,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_YUYV,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_INTERLACED,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_YVYU8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_YVYU,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_YVYU,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_YVYU8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_YVYU,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_YVYU,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_INTERLACED,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_UYVY8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_UYVY,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_UYVY,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_UYVY8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_UYVY,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_UYVY,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_INTERLACED,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_VYUY8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_VYUY,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_VYUY,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_VYUY8_2X8,
		.dvp_fmt_val	= YUV_INPUT_422 | YUV_INPUT_ORDER_VYUY,
		.csi_fmt_val	= CSI_WRDDR_TYPE_YUV422,
		.csi_yuv_order	= CSI_YUV_INPUT_ORDER_VYUY,
		.fmt_type	= CIF_FMT_TYPE_YUV,
		.field		= V4L2_FIELD_INTERLACED,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SBGGR8_1X8,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SGBRG8_1X8,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SGRBG8_1X8,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SRGGB8_1X8,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SBGGR10_1X10,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_10,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW10,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SGBRG10_1X10,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_10,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW10,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SGRBG10_1X10,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_10,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW10,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SRGGB10_1X10,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_10,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW10,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SBGGR12_1X12,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_12,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW12,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SGBRG12_1X12,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_12,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW12,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SGRBG12_1X12,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_12,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW12,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SRGGB12_1X12,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_12,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW12,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_RGB888_1X24,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RGB888,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_Y8_1X8,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_Y10_1X10,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_10,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW10,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_Y12_1X12,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_12,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW12,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_EBD_1X8,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_8,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW8,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}, {
		.mbus_code	= MEDIA_BUS_FMT_SPD_2X8,
		.dvp_fmt_val	= INPUT_MODE_RAW | RAW_DATA_WIDTH_12,
		.csi_fmt_val	= CSI_WRDDR_TYPE_RAW12,
		.fmt_type	= CIF_FMT_TYPE_RAW,
		.field		= V4L2_FIELD_NONE,
	}
};

static inline
struct rkcif_rx_buffer *to_cif_rx_buf(struct rkisp_rx_buf *dbufs)
{
	return container_of(dbufs, struct rkcif_rx_buffer, dbufs);
}

static struct v4l2_subdev *get_remote_sensor(struct rkcif_stream *stream, u16 *index)
{
	struct media_pad *local, *remote;
	struct media_entity *sensor_me;
	struct v4l2_subdev *sub = NULL;

	local = &stream->vnode.vdev.entity.pads[0];
	if (!local) {
		v4l2_err(&stream->cifdev->v4l2_dev,
			 "%s: video pad[0] is null\n", __func__);
		return NULL;
	}

	remote = media_entity_remote_pad(local);
	if (!remote) {
		v4l2_err(&stream->cifdev->v4l2_dev,
			 "%s: remote pad is null\n", __func__);
		return NULL;
	}

	if (index)
		*index = remote->index;

	sensor_me = remote->entity;

	sub = media_entity_to_v4l2_subdev(sensor_me);

	return sub;

}

static void get_remote_terminal_sensor(struct rkcif_stream *stream,
				       struct v4l2_subdev **sensor_sd)
{
	struct media_graph graph;
	struct media_entity *entity = &stream->vnode.vdev.entity;
	struct media_device *mdev = entity->graph_obj.mdev;
	int ret;

	/* Walk the graph to locate sensor nodes. */
	mutex_lock(&mdev->graph_mutex);
	ret = media_graph_walk_init(&graph, mdev);
	if (ret) {
		mutex_unlock(&mdev->graph_mutex);
		*sensor_sd = NULL;
		return;
	}

	media_graph_walk_start(&graph, entity);
	while ((entity = media_graph_walk_next(&graph))) {
		if (entity->function == MEDIA_ENT_F_CAM_SENSOR)
			break;
	}
	mutex_unlock(&mdev->graph_mutex);
	media_graph_walk_cleanup(&graph);

	if (entity)
		*sensor_sd = media_entity_to_v4l2_subdev(entity);
	else
		*sensor_sd = NULL;
}

static struct rkcif_sensor_info *sd_to_sensor(struct rkcif_device *dev,
					      struct v4l2_subdev *sd)
{
	u32 i;

	for (i = 0; i < dev->num_sensors; ++i)
		if (dev->sensors[i].sd == sd)
			return &dev->sensors[i];

	if (i == dev->num_sensors) {
		for (i = 0; i < dev->num_sensors; ++i) {
			if (dev->sensors[i].mbus.type == V4L2_MBUS_CCP2)
				return &dev->lvds_subdev.sensor_self;
		}
	}

	return NULL;
}

static unsigned char get_data_type(u32 pixelformat, u8 cmd_mode_en)
{
	switch (pixelformat) {
	/* csi raw8 */
	case MEDIA_BUS_FMT_SBGGR8_1X8:
	case MEDIA_BUS_FMT_SGBRG8_1X8:
	case MEDIA_BUS_FMT_SGRBG8_1X8:
	case MEDIA_BUS_FMT_SRGGB8_1X8:
		return 0x2a;
	/* csi raw10 */
	case MEDIA_BUS_FMT_SBGGR10_1X10:
	case MEDIA_BUS_FMT_SGBRG10_1X10:
	case MEDIA_BUS_FMT_SGRBG10_1X10:
	case MEDIA_BUS_FMT_SRGGB10_1X10:
		return 0x2b;
	/* csi raw12 */
	case MEDIA_BUS_FMT_SBGGR12_1X12:
	case MEDIA_BUS_FMT_SGBRG12_1X12:
	case MEDIA_BUS_FMT_SGRBG12_1X12:
	case MEDIA_BUS_FMT_SRGGB12_1X12:
		return 0x2c;
	/* csi uyvy 422 */
	case MEDIA_BUS_FMT_UYVY8_2X8:
	case MEDIA_BUS_FMT_VYUY8_2X8:
	case MEDIA_BUS_FMT_YUYV8_2X8:
	case MEDIA_BUS_FMT_YVYU8_2X8:
		return 0x1e;
	case MEDIA_BUS_FMT_RGB888_1X24: {
		if (cmd_mode_en) /* dsi command mode*/
			return 0x39;
		else /* dsi video mode */
			return 0x3e;
	}
	case MEDIA_BUS_FMT_EBD_1X8:
		return 0x12;
	case MEDIA_BUS_FMT_SPD_2X8:
		return 0x2f;

	default:
		return 0x2b;
	}
}

static int get_csi_crop_align(const struct cif_input_fmt *fmt_in)
{
	switch (fmt_in->csi_fmt_val) {
	case CSI_WRDDR_TYPE_RGB888:
		return 24;
	case CSI_WRDDR_TYPE_RAW10:
	case CSI_WRDDR_TYPE_RAW12:
		return 4;
	case CSI_WRDDR_TYPE_RAW8:
	case CSI_WRDDR_TYPE_YUV422:
		return 8;
	default:
		return -1;
	}
}

const struct
cif_input_fmt *get_input_fmt(struct v4l2_subdev *sd, struct v4l2_rect *rect,
			     u32 pad_id, struct csi_channel_info *csi_info)
{
	struct v4l2_subdev_format fmt;
	struct rkmodule_channel_info ch_info = {0};
	int ret;
	u32 i;

	fmt.pad = 0;
	fmt.which = V4L2_SUBDEV_FORMAT_ACTIVE;
	fmt.reserved[0] = 0;
	fmt.format.field = V4L2_FIELD_NONE;
	ret = v4l2_subdev_call(sd, pad, get_fmt, NULL, &fmt);
	if (ret < 0) {
		v4l2_warn(sd->v4l2_dev,
			  "sensor fmt invalid, set to default size\n");
		goto set_default;
	}
	ch_info.index = pad_id;
	ret = v4l2_subdev_call(sd,
			       core, ioctl,
			       RKMODULE_GET_CHANNEL_INFO,
			       &ch_info);
	if (!ret) {
		fmt.format.width = ch_info.width;
		fmt.format.height = ch_info.height;
		fmt.format.code = ch_info.bus_fmt;
		switch (ch_info.vc) {
		case V4L2_MBUS_CSI2_CHANNEL_3:
			csi_info->vc = 3;
			break;
		case V4L2_MBUS_CSI2_CHANNEL_2:
			csi_info->vc = 2;
			break;
		case V4L2_MBUS_CSI2_CHANNEL_1:
			csi_info->vc = 1;
			break;
		case V4L2_MBUS_CSI2_CHANNEL_0:
			csi_info->vc = 0;
			break;
		default:
			csi_info->vc = -1;
		}
		if (ch_info.bus_fmt == MEDIA_BUS_FMT_SPD_2X8 ||
		    ch_info.bus_fmt == MEDIA_BUS_FMT_EBD_1X8) {
			if (ch_info.data_type > 0)
				csi_info->data_type = ch_info.data_type;
			if (ch_info.data_bit > 0)
				csi_info->data_bit = ch_info.data_bit;
		}
	}

	v4l2_dbg(1, rkcif_debug, sd->v4l2_dev,
		 "remote fmt: mbus code:0x%x, size:%dx%d, field: %d\n",
		 fmt.format.code, fmt.format.width,
		 fmt.format.height, fmt.format.field);
	rect->left = 0;
	rect->top = 0;
	rect->width = fmt.format.width;
	rect->height = fmt.format.height;

	for (i = 0; i < ARRAY_SIZE(in_fmts); i++)
		if (fmt.format.code == in_fmts[i].mbus_code &&
		    fmt.format.field == in_fmts[i].field)
			return &in_fmts[i];

	v4l2_err(sd->v4l2_dev, "remote sensor mbus code not supported\n");

set_default:
	rect->left = 0;
	rect->top = 0;
	rect->width = RKCIF_DEFAULT_WIDTH;
	rect->height = RKCIF_DEFAULT_HEIGHT;

	return NULL;
}

static const struct
cif_output_fmt *find_output_fmt(struct rkcif_stream *stream, u32 pixelfmt)
{
	const struct cif_output_fmt *fmt;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(out_fmts); i++) {
		fmt = &out_fmts[i];
		if (fmt->fourcc == pixelfmt)
			return fmt;
	}

	return NULL;
}

static enum cif_reg_index get_reg_index_of_id_ctrl0(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_ID0_CTRL0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_ID1_CTRL0;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_ID2_CTRL0;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_ID3_CTRL0;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_ID0_CTRL0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_id_ctrl1(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_ID0_CTRL1;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_ID1_CTRL1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_ID2_CTRL1;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_ID3_CTRL1;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_ID0_CTRL1;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm0_y_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_Y_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_Y_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_Y_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_Y_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_Y_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm1_y_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_Y_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_Y_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_Y_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_Y_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_Y_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm0_uv_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_UV_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_UV_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_UV_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_UV_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME0_ADDR_UV_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm1_uv_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_UV_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_UV_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_UV_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_UV_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME1_ADDR_UV_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm0_y_vlw(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_Y_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_Y_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_Y_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_Y_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_Y_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm1_y_vlw(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_Y_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_Y_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_Y_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_Y_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_Y_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm0_uv_vlw(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_UV_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_UV_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_UV_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_UV_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME0_VLW_UV_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_frm1_uv_vlw(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_UV_ID0;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_UV_ID1;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_UV_ID2;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_UV_ID3;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_FRAME1_VLW_UV_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_id_crop_start(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_MIPI_LVDS_ID0_CROP_START;
		break;
	case 1:
		index = CIF_REG_MIPI_LVDS_ID1_CROP_START;
		break;
	case 2:
		index = CIF_REG_MIPI_LVDS_ID2_CROP_START;
		break;
	case 3:
		index = CIF_REG_MIPI_LVDS_ID3_CROP_START;
		break;
	default:
		index = CIF_REG_MIPI_LVDS_ID0_CROP_START;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_lvds_sav_eav_act0(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_LVDS_SAV_EAV_ACT0_ID0;
		break;
	case 1:
		index = CIF_REG_LVDS_SAV_EAV_ACT0_ID1;
		break;
	case 2:
		index = CIF_REG_LVDS_SAV_EAV_ACT0_ID2;
		break;
	case 3:
		index = CIF_REG_LVDS_SAV_EAV_ACT0_ID3;
		break;
	default:
		index = CIF_REG_LVDS_SAV_EAV_ACT0_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_lvds_sav_eav_act1(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_LVDS_SAV_EAV_ACT1_ID0;
		break;
	case 1:
		index = CIF_REG_LVDS_SAV_EAV_ACT1_ID1;
		break;
	case 2:
		index = CIF_REG_LVDS_SAV_EAV_ACT1_ID2;
		break;
	case 3:
		index = CIF_REG_LVDS_SAV_EAV_ACT1_ID3;
		break;
	default:
		index = CIF_REG_LVDS_SAV_EAV_ACT1_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_lvds_sav_eav_blk0(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_LVDS_SAV_EAV_BLK0_ID0;
		break;
	case 1:
		index = CIF_REG_LVDS_SAV_EAV_BLK0_ID1;
		break;
	case 2:
		index = CIF_REG_LVDS_SAV_EAV_BLK0_ID2;
		break;
	case 3:
		index = CIF_REG_LVDS_SAV_EAV_BLK0_ID3;
		break;
	default:
		index = CIF_REG_LVDS_SAV_EAV_BLK0_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_reg_index_of_lvds_sav_eav_blk1(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_LVDS_SAV_EAV_BLK1_ID0;
		break;
	case 1:
		index = CIF_REG_LVDS_SAV_EAV_BLK1_ID1;
		break;
	case 2:
		index = CIF_REG_LVDS_SAV_EAV_BLK1_ID2;
		break;
	case 3:
		index = CIF_REG_LVDS_SAV_EAV_BLK1_ID3;
		break;
	default:
		index = CIF_REG_LVDS_SAV_EAV_BLK1_ID0;
		break;
	}

	return index;
}

static enum cif_reg_index get_dvp_reg_index_of_frm0_y_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_DVP_FRM0_ADDR_Y;
		break;
	case 1:
		index = CIF_REG_DVP_FRM0_ADDR_Y_ID1;
		break;
	case 2:
		index = CIF_REG_DVP_FRM0_ADDR_Y_ID2;
		break;
	case 3:
		index = CIF_REG_DVP_FRM0_ADDR_Y_ID3;
		break;
	default:
		index = CIF_REG_DVP_FRM0_ADDR_Y;
		break;
	}

	return index;
}

static enum cif_reg_index get_dvp_reg_index_of_frm1_y_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_DVP_FRM1_ADDR_Y;
		break;
	case 1:
		index = CIF_REG_DVP_FRM1_ADDR_Y_ID1;
		break;
	case 2:
		index = CIF_REG_DVP_FRM1_ADDR_Y_ID2;
		break;
	case 3:
		index = CIF_REG_DVP_FRM1_ADDR_Y_ID3;
		break;
	default:
		index = CIF_REG_DVP_FRM0_ADDR_Y;
		break;
	}

	return index;
}

static enum cif_reg_index get_dvp_reg_index_of_frm0_uv_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_DVP_FRM0_ADDR_UV;
		break;
	case 1:
		index = CIF_REG_DVP_FRM0_ADDR_UV_ID1;
		break;
	case 2:
		index = CIF_REG_DVP_FRM0_ADDR_UV_ID2;
		break;
	case 3:
		index = CIF_REG_DVP_FRM0_ADDR_UV_ID3;
		break;
	default:
		index = CIF_REG_DVP_FRM0_ADDR_UV;
		break;
	}

	return index;
}

static enum cif_reg_index get_dvp_reg_index_of_frm1_uv_addr(int channel_id)
{
	enum cif_reg_index index;

	switch (channel_id) {
	case 0:
		index = CIF_REG_DVP_FRM1_ADDR_UV;
		break;
	case 1:
		index = CIF_REG_DVP_FRM1_ADDR_UV_ID1;
		break;
	case 2:
		index = CIF_REG_DVP_FRM1_ADDR_UV_ID2;
		break;
	case 3:
		index = CIF_REG_DVP_FRM1_ADDR_UV_ID3;
		break;
	default:
		index = CIF_REG_DVP_FRM1_ADDR_UV;
		break;
	}

	return index;
}

/***************************** stream operations ******************************/
static int rkcif_assign_new_buffer_oneframe(struct rkcif_stream *stream,
					     enum rkcif_yuvaddr_state stat)
{
	struct rkcif_device *dev = stream->cifdev;
	struct rkcif_dummy_buffer *dummy_buf = &dev->dummy_buf;
	struct rkcif_buffer *buffer = NULL;
	u32 frm_addr_y = CIF_REG_DVP_FRM0_ADDR_Y;
	u32 frm_addr_uv = CIF_REG_DVP_FRM0_ADDR_UV;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&stream->vbq_lock, flags);
	if (stat == RKCIF_YUV_ADDR_STATE_INIT) {
		if (!stream->curr_buf) {
			if (!list_empty(&stream->buf_head)) {
				stream->curr_buf = list_first_entry(&stream->buf_head,
								    struct rkcif_buffer,
								    queue);
				list_del(&stream->curr_buf->queue);
			}
		}

		if (stream->curr_buf) {
			rkcif_write_register(dev, CIF_REG_DVP_FRM0_ADDR_Y,
					     stream->curr_buf->buff_addr[RKCIF_PLANE_Y]);
			rkcif_write_register(dev, CIF_REG_DVP_FRM0_ADDR_UV,
					     stream->curr_buf->buff_addr[RKCIF_PLANE_CBCR]);
		} else {
			if (dummy_buf->vaddr) {
				rkcif_write_register(dev, CIF_REG_DVP_FRM0_ADDR_Y,
						     dummy_buf->dma_addr);
				rkcif_write_register(dev, CIF_REG_DVP_FRM0_ADDR_UV,
						     dummy_buf->dma_addr);
			}
		}

		if (!stream->next_buf) {
			if (!list_empty(&stream->buf_head)) {
				stream->next_buf = list_first_entry(&stream->buf_head,
								    struct rkcif_buffer, queue);
				list_del(&stream->next_buf->queue);
			}
		}

		if (stream->next_buf) {
			rkcif_write_register(dev, CIF_REG_DVP_FRM1_ADDR_Y,
					     stream->next_buf->buff_addr[RKCIF_PLANE_Y]);
			rkcif_write_register(dev, CIF_REG_DVP_FRM1_ADDR_UV,
					     stream->next_buf->buff_addr[RKCIF_PLANE_CBCR]);
		} else {
			if (dummy_buf->vaddr) {
				rkcif_write_register(dev, CIF_REG_DVP_FRM1_ADDR_Y,
						     dummy_buf->dma_addr);
				rkcif_write_register(dev, CIF_REG_DVP_FRM1_ADDR_UV,
						     dummy_buf->dma_addr);
			}
		}
	} else if (stat == RKCIF_YUV_ADDR_STATE_UPDATE) {
		if (!list_empty(&stream->buf_head)) {
			if (stream->frame_phase == CIF_CSI_FRAME0_READY) {
				stream->curr_buf = list_first_entry(&stream->buf_head,
								    struct rkcif_buffer, queue);
				list_del(&stream->curr_buf->queue);
				buffer = stream->curr_buf;
			} else if (stream->frame_phase == CIF_CSI_FRAME1_READY) {
				stream->next_buf = list_first_entry(&stream->buf_head,
								    struct rkcif_buffer, queue);
				list_del(&stream->next_buf->queue);
				buffer = stream->next_buf;
			}
		} else {
			if (dummy_buf->vaddr && stream->frame_phase == CIF_CSI_FRAME0_READY)
				stream->curr_buf = NULL;
			if (dummy_buf->vaddr && stream->frame_phase == CIF_CSI_FRAME1_READY)
				stream->next_buf = NULL;
			buffer = NULL;
		}
		if (stream->frame_phase == CIF_CSI_FRAME0_READY) {
			frm_addr_y = CIF_REG_DVP_FRM0_ADDR_Y;
			frm_addr_uv = CIF_REG_DVP_FRM0_ADDR_UV;
		} else if (stream->frame_phase == CIF_CSI_FRAME1_READY) {
			frm_addr_y = CIF_REG_DVP_FRM1_ADDR_Y;
			frm_addr_uv = CIF_REG_DVP_FRM1_ADDR_UV;
		}

		if (buffer) {
			rkcif_write_register(dev, frm_addr_y,
					     buffer->buff_addr[RKCIF_PLANE_Y]);
			rkcif_write_register(dev, frm_addr_uv,
					     buffer->buff_addr[RKCIF_PLANE_CBCR]);
		} else {
			if (dummy_buf->vaddr) {
				rkcif_write_register(dev, frm_addr_y,
					     dummy_buf->dma_addr);
				rkcif_write_register(dev, frm_addr_uv,
					     dummy_buf->dma_addr);
			} else {
				ret = -EINVAL;
			}
			v4l2_dbg(1, rkcif_debug, &dev->v4l2_dev,
				 "not active buffer, frame Drop\n");
		}
	}
	spin_unlock_irqrestore(&stream->vbq_lock, flags);
	return ret;
}

static void rkcif_s_rx_buffer(struct rkcif_device *dev, struct rkisp_rx_buf *dbufs)
{
	struct media_pad *pad = media_entity_remote_pad(&dev->sditf->pads);
	struct v4l2_subdev *sd;

	if (pad)
		sd = media_entity_to_v4l2_subdev(pad->entity);
	else
		return;

	v4l2_subdev_call(sd, video, s_rx_buffer, dbufs, NULL);
}

static void rkcif_assign_new_buffer_init_toisp(struct rkcif_stream *stream,
					 int channel_id)
{
	struct rkcif_device *dev = stream->cifdev;
	struct rkisp_rx_buf *dbufs;
	struct v4l2_mbus_config *mbus_cfg = &dev->active_sensor->mbus;
	u32 frm0_addr_y;
	u32 frm1_addr_y;
	unsigned long flags;

	if (mbus_cfg->type == V4L2_MBUS_CSI2_DPHY ||
	    mbus_cfg->type == V4L2_MBUS_CSI2_CPHY ||
	    mbus_cfg->type == V4L2_MBUS_CCP2) {
		frm0_addr_y = get_reg_index_of_frm0_y_addr(channel_id);
		frm1_addr_y = get_reg_index_of_frm1_y_addr(channel_id);
	} else {
		frm0_addr_y = get_dvp_reg_index_of_frm0_y_addr(channel_id);
		frm1_addr_y = get_dvp_reg_index_of_frm1_y_addr(channel_id);
	}

	spin_lock_irqsave(&stream->vbq_lock, flags);

	if (!stream->curr_buf_toisp) {
		if (!list_empty(&stream->rx_buf_head)) {
			dbufs = list_first_entry(&stream->rx_buf_head,
						 struct rkisp_rx_buf,
						 list);
			if (dbufs)
				list_del(&dbufs->list);
			stream->curr_buf_toisp = to_cif_rx_buf(dbufs);
		}
	}

	if (stream->curr_buf_toisp)
		rkcif_write_register(dev, frm0_addr_y,
				     stream->curr_buf_toisp->dummy.dma_addr);

	if (!stream->next_buf_toisp) {
		if (!list_empty(&stream->rx_buf_head)) {
			dbufs = list_first_entry(&stream->rx_buf_head,
						 struct rkisp_rx_buf, list);
			if (dbufs) {
				list_del(&dbufs->list);
				stream->next_buf_toisp = to_cif_rx_buf(dbufs);
			} else {
				stream->next_buf_toisp = stream->curr_buf_toisp;
			}
		} else {
			stream->next_buf_toisp = stream->curr_buf_toisp;
		}
	}

	if (stream->next_buf_toisp)
		rkcif_write_register(dev, frm1_addr_y,
				     stream->next_buf_toisp->dummy.dma_addr);

	spin_unlock_irqrestore(&stream->vbq_lock, flags);
}

static int rkcif_assign_new_buffer_update_toisp(struct rkcif_stream *stream,
					   int channel_id)
{
	struct rkcif_device *dev = stream->cifdev;
	struct v4l2_mbus_config *mbus_cfg = &dev->active_sensor->mbus;
	struct rkcif_rx_buffer *buffer = NULL;
	struct rkisp_rx_buf *dbufs;
	u32 frm_addr_y;
	int ret = 0;
	unsigned long flags;

	if (mbus_cfg->type == V4L2_MBUS_CSI2_DPHY ||
	    mbus_cfg->type == V4L2_MBUS_CSI2_CPHY ||
	    mbus_cfg->type == V4L2_MBUS_CCP2) {
		frm_addr_y = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			     get_reg_index_of_frm0_y_addr(channel_id) :
			     get_reg_index_of_frm1_y_addr(channel_id);
	} else {
		frm_addr_y = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			     get_dvp_reg_index_of_frm0_y_addr(channel_id) :
			     get_dvp_reg_index_of_frm1_y_addr(channel_id);
	}
	spin_lock_irqsave(&stream->vbq_lock, flags);
	if (!list_empty(&stream->rx_buf_head)) {
		if (stream->frame_phase == CIF_CSI_FRAME0_READY) {

			dbufs = list_first_entry(&stream->rx_buf_head,
						 struct rkisp_rx_buf, list);
			if (dbufs) {
				list_del(&dbufs->list);
				stream->curr_buf_toisp = to_cif_rx_buf(dbufs);
				buffer = stream->curr_buf_toisp;
			}
		} else if (stream->frame_phase == CIF_CSI_FRAME1_READY) {
			dbufs = list_first_entry(&stream->rx_buf_head,
						 struct rkisp_rx_buf, list);
			if (dbufs) {
				list_del(&dbufs->list);
				stream->next_buf_toisp = to_cif_rx_buf(dbufs);
				buffer = stream->next_buf_toisp;
			}
		}
	} else {
		buffer = NULL;
	}
	spin_unlock_irqrestore(&stream->vbq_lock, flags);

	if (buffer) {
		rkcif_write_register(dev, frm_addr_y,
				     buffer->dummy.dma_addr);
	}
	return ret;
}

static int rkcif_assign_new_buffer_pingpong_toisp(struct rkcif_stream *stream,
					     int init, int channel_id)
{
	int ret = 0;

	if (init)
		rkcif_assign_new_buffer_init_toisp(stream, channel_id);
	else
		ret = rkcif_assign_new_buffer_update_toisp(stream, channel_id);
	return ret;
}

static void rkcif_assign_new_buffer_init(struct rkcif_stream *stream,
					 int channel_id)
{
	struct rkcif_device *dev = stream->cifdev;
	struct v4l2_mbus_config *mbus_cfg = &dev->active_sensor->mbus;
	u32 frm0_addr_y, frm0_addr_uv;
	u32 frm1_addr_y, frm1_addr_uv;
	unsigned long flags;
	struct rkcif_dummy_buffer *dummy_buf = &dev->dummy_buf;
	struct csi_channel_info *channel = &dev->channels[channel_id];

	if (mbus_cfg->type == V4L2_MBUS_CSI2_DPHY ||
	    mbus_cfg->type == V4L2_MBUS_CSI2_CPHY ||
	    mbus_cfg->type == V4L2_MBUS_CCP2) {
		frm0_addr_y = get_reg_index_of_frm0_y_addr(channel_id);
		frm0_addr_uv = get_reg_index_of_frm0_uv_addr(channel_id);
		frm1_addr_y = get_reg_index_of_frm1_y_addr(channel_id);
		frm1_addr_uv = get_reg_index_of_frm1_uv_addr(channel_id);
	} else {
		frm0_addr_y = get_dvp_reg_index_of_frm0_y_addr(channel_id);
		frm0_addr_uv = get_dvp_reg_index_of_frm0_uv_addr(channel_id);
		frm1_addr_y = get_dvp_reg_index_of_frm1_y_addr(channel_id);
		frm1_addr_uv = get_dvp_reg_index_of_frm1_uv_addr(channel_id);
	}

	spin_lock_irqsave(&stream->vbq_lock, flags);

	if (!stream->curr_buf) {
		if (!list_empty(&stream->buf_head)) {
			stream->curr_buf = list_first_entry(&stream->buf_head,
							    struct rkcif_buffer,
							    queue);
			list_del(&stream->curr_buf->queue);
		}
	}

	if (stream->curr_buf) {
		rkcif_write_register(dev, frm0_addr_y,
				     stream->curr_buf->buff_addr[RKCIF_PLANE_Y]);
		if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
			rkcif_write_register(dev, frm0_addr_uv,
					     stream->curr_buf->buff_addr[RKCIF_PLANE_CBCR]);
	} else {
		if (dummy_buf->vaddr) {
			rkcif_write_register(dev, frm0_addr_y, dummy_buf->dma_addr);
			if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
				rkcif_write_register(dev, frm0_addr_uv, dummy_buf->dma_addr);
		}
	}

	if (stream->cif_fmt_in->field == V4L2_FIELD_INTERLACED) {
		stream->next_buf = stream->curr_buf;
		if (stream->next_buf) {
			rkcif_write_register(dev, frm1_addr_y,
					     stream->next_buf->buff_addr[RKCIF_PLANE_Y] + (channel->virtual_width / 2));
			if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
				rkcif_write_register(dev, frm1_addr_uv,
						     stream->next_buf->buff_addr[RKCIF_PLANE_CBCR] + (channel->virtual_width / 2));
		}
	} else {
		if (!stream->next_buf) {
			if (!list_empty(&stream->buf_head)) {
				stream->next_buf = list_first_entry(&stream->buf_head,
								    struct rkcif_buffer, queue);
				list_del(&stream->next_buf->queue);
			}
		}

		if (stream->next_buf) {
			rkcif_write_register(dev, frm1_addr_y,
					     stream->next_buf->buff_addr[RKCIF_PLANE_Y]);
			if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
				rkcif_write_register(dev, frm1_addr_uv,
						     stream->next_buf->buff_addr[RKCIF_PLANE_CBCR]);
		} else {
			if (dummy_buf->vaddr) {
				rkcif_write_register(dev, frm1_addr_y, dummy_buf->dma_addr);
				if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
					rkcif_write_register(dev, frm1_addr_uv, dummy_buf->dma_addr);
			}
		}
	}
	spin_unlock_irqrestore(&stream->vbq_lock, flags);

	stream->is_dvp_yuv_addr_init = true;

	/* for BT.656/BT.1120 multi channels function,
	 * yuv addr of unused channel must be set
	 */
	if (mbus_cfg->type == V4L2_MBUS_BT656) {
		int ch_id;

		for (ch_id = 0; ch_id < RKCIF_MAX_STREAM_DVP; ch_id++) {
			if (dev->stream[ch_id].is_dvp_yuv_addr_init)
				continue;
			if (dummy_buf->dma_addr) {
				rkcif_write_register(dev,
						     get_dvp_reg_index_of_frm0_y_addr(ch_id),
						     dummy_buf->dma_addr);
				rkcif_write_register(dev,
						     get_dvp_reg_index_of_frm0_uv_addr(ch_id),
						     dummy_buf->dma_addr);
				rkcif_write_register(dev,
						     get_dvp_reg_index_of_frm1_y_addr(ch_id),
						     dummy_buf->dma_addr);
				rkcif_write_register(dev,
						     get_dvp_reg_index_of_frm1_uv_addr(ch_id),
						     dummy_buf->dma_addr);
			}
		}
	}

}

static int rkcif_assign_new_buffer_update(struct rkcif_stream *stream,
					   int channel_id)
{
	struct rkcif_device *dev = stream->cifdev;
	struct rkcif_dummy_buffer *dummy_buf = &dev->dummy_buf;
	struct v4l2_mbus_config *mbus_cfg = &dev->active_sensor->mbus;
	struct rkcif_buffer *buffer = NULL;
	u32 frm_addr_y, frm_addr_uv;
	struct csi_channel_info *channel = &dev->channels[channel_id];
	int ret = 0;
	unsigned long flags;

	if (mbus_cfg->type == V4L2_MBUS_CSI2_DPHY ||
	    mbus_cfg->type == V4L2_MBUS_CSI2_CPHY ||
	    mbus_cfg->type == V4L2_MBUS_CCP2) {
		frm_addr_y = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			     get_reg_index_of_frm0_y_addr(channel_id) :
			     get_reg_index_of_frm1_y_addr(channel_id);
		frm_addr_uv = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			      get_reg_index_of_frm0_uv_addr(channel_id) :
			      get_reg_index_of_frm1_uv_addr(channel_id);
	} else {
		frm_addr_y = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			     get_dvp_reg_index_of_frm0_y_addr(channel_id) :
			     get_dvp_reg_index_of_frm1_y_addr(channel_id);
		frm_addr_uv = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			      get_dvp_reg_index_of_frm0_uv_addr(channel_id) :
			      get_dvp_reg_index_of_frm1_uv_addr(channel_id);
	}

	spin_lock_irqsave(&stream->vbq_lock, flags);
	if (!list_empty(&stream->buf_head)) {
		if (!dummy_buf->vaddr &&
		    stream->curr_buf == stream->next_buf &&
		    stream->cif_fmt_in->field != V4L2_FIELD_INTERLACED)
			ret = -EINVAL;
		if (stream->frame_phase == CIF_CSI_FRAME0_READY) {
			stream->curr_buf = list_first_entry(&stream->buf_head,
							    struct rkcif_buffer, queue);
			if (stream->curr_buf) {
				list_del(&stream->curr_buf->queue);
				buffer = stream->curr_buf;
			}
		} else if (stream->frame_phase == CIF_CSI_FRAME1_READY) {
			if (stream->cif_fmt_in->field == V4L2_FIELD_INTERLACED) {
				if (stream->next_buf != stream->curr_buf) {
					stream->next_buf = stream->curr_buf;
					buffer = stream->next_buf;
				} else {
					buffer = NULL;
				}

			} else {
				stream->next_buf = list_first_entry(&stream->buf_head,
								    struct rkcif_buffer, queue);
				if (stream->next_buf) {
					list_del(&stream->next_buf->queue);
					buffer = stream->next_buf;
				}
			}
		}
	} else {
		buffer = NULL;
		if (dummy_buf->vaddr) {
			if (stream->frame_phase == CIF_CSI_FRAME0_READY) {
				stream->curr_buf = NULL;
			} else if (stream->frame_phase == CIF_CSI_FRAME1_READY) {
				if (stream->cif_fmt_in->field == V4L2_FIELD_INTERLACED) {
					stream->next_buf = stream->curr_buf;
					buffer = stream->next_buf;
				} else {
					stream->next_buf = NULL;
				}
			}
		} else if (stream->curr_buf != stream->next_buf) {
			if (stream->frame_phase == CIF_CSI_FRAME0_READY) {
				stream->curr_buf = stream->next_buf;
				buffer = stream->next_buf;
			} else if (stream->frame_phase == CIF_CSI_FRAME1_READY) {
				stream->next_buf = stream->curr_buf;
				buffer = stream->curr_buf;
			}

		}

	}
	stream->frame_phase_cache = stream->frame_phase;
	spin_unlock_irqrestore(&stream->vbq_lock, flags);

	if (buffer) {
		if (stream->cif_fmt_in->field == V4L2_FIELD_INTERLACED &&
		    stream->frame_phase == CIF_CSI_FRAME1_READY) {
			rkcif_write_register(dev, frm_addr_y,
					     buffer->buff_addr[RKCIF_PLANE_Y] + (channel->virtual_width / 2));
			if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
				rkcif_write_register(dev, frm_addr_uv,
						     buffer->buff_addr[RKCIF_PLANE_CBCR] + (channel->virtual_width / 2));
		} else {
			rkcif_write_register(dev, frm_addr_y,
					     buffer->buff_addr[RKCIF_PLANE_Y]);
			if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
				rkcif_write_register(dev, frm_addr_uv,
						     buffer->buff_addr[RKCIF_PLANE_CBCR]);
		}
	} else {
		if (dummy_buf->vaddr) {
			rkcif_write_register(dev, frm_addr_y, dummy_buf->dma_addr);
			if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
				rkcif_write_register(dev, frm_addr_uv, dummy_buf->dma_addr);
		} else {
			ret = -EINVAL;
		}
		v4l2_info(&dev->v4l2_dev,
			 "not active buffer, skip current frame, %s stream[%d]\n",
			 (mbus_cfg->type == V4L2_MBUS_CSI2_DPHY ||
			  mbus_cfg->type == V4L2_MBUS_CSI2_CPHY ||
			  mbus_cfg->type == V4L2_MBUS_CCP2) ? "mipi/lvds" : "dvp",
			  stream->id);
	}
	return ret;
}

static int rkcif_get_new_buffer_wake_up_mode(struct rkcif_stream *stream)
{
	struct rkcif_device *dev = stream->cifdev;
	struct rkcif_dummy_buffer *dummy_buf = &dev->dummy_buf;
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&stream->vbq_lock, flags);
	if (!list_empty(&stream->buf_head)) {
		if (!dummy_buf->vaddr &&
		    stream->curr_buf == stream->next_buf)
			ret = -EINVAL;
		if (stream->line_int_cnt % 2) {
			stream->curr_buf = list_first_entry(&stream->buf_head,
							    struct rkcif_buffer, queue);
			if (stream->curr_buf)
				list_del(&stream->curr_buf->queue);
		} else {
			stream->next_buf = list_first_entry(&stream->buf_head,
							    struct rkcif_buffer, queue);
			if (stream->next_buf)
				list_del(&stream->next_buf->queue);
		}
		stream->is_buf_active = true;
	} else {
		stream->is_buf_active = false;
		if (dummy_buf->vaddr) {
			if (stream->line_int_cnt % 2)
				stream->curr_buf = NULL;
			else
				stream->next_buf = NULL;
		} else if (stream->curr_buf != stream->next_buf) {
			if (stream->line_int_cnt % 2) {
				stream->curr_buf = stream->next_buf;
				stream->frame_phase_cache = CIF_CSI_FRAME0_READY;
			} else {
				stream->next_buf = stream->curr_buf;
				stream->frame_phase_cache = CIF_CSI_FRAME1_READY;
			}
			stream->is_buf_active = true;
		} else {
			ret = -EINVAL;
		}
	}
	spin_unlock_irqrestore(&stream->vbq_lock, flags);

	return ret;
}

static int rkcif_update_new_buffer_wake_up_mode(struct rkcif_stream *stream)
{
	struct rkcif_device *dev = stream->cifdev;
	struct rkcif_dummy_buffer *dummy_buf = &dev->dummy_buf;
	struct v4l2_mbus_config *mbus_cfg = &dev->active_sensor->mbus;
	struct rkcif_buffer *buffer = NULL;
	u32 frm_addr_y, frm_addr_uv;
	int channel_id = stream->id;
	int ret = 0;
	unsigned long flags;

	if (mbus_cfg->type == V4L2_MBUS_CSI2_DPHY ||
	    mbus_cfg->type == V4L2_MBUS_CSI2_CPHY ||
	    mbus_cfg->type == V4L2_MBUS_CCP2) {
		frm_addr_y = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			     get_reg_index_of_frm0_y_addr(channel_id) :
			     get_reg_index_of_frm1_y_addr(channel_id);
		frm_addr_uv = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			      get_reg_index_of_frm0_uv_addr(channel_id) :
			      get_reg_index_of_frm1_uv_addr(channel_id);
	} else {
		frm_addr_y = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			     get_dvp_reg_index_of_frm0_y_addr(channel_id) :
			     get_dvp_reg_index_of_frm1_y_addr(channel_id);
		frm_addr_uv = stream->frame_phase & CIF_CSI_FRAME0_READY ?
			      get_dvp_reg_index_of_frm0_uv_addr(channel_id) :
			      get_dvp_reg_index_of_frm1_uv_addr(channel_id);
	}
	spin_lock_irqsave(&stream->vbq_lock, flags);
	if (stream->is_buf_active) {
		if (stream->frame_phase == CIF_CSI_FRAME0_READY)
			buffer = stream->curr_buf;
		else if (stream->frame_phase == CIF_CSI_FRAME1_READY)
			buffer = stream->next_buf;
	}
	spin_unlock_irqrestore(&stream->vbq_lock, flags);
	if (buffer) {
		rkcif_write_register(dev, frm_addr_y,
				     buffer->buff_addr[RKCIF_PLANE_Y]);
		if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
			rkcif_write_register(dev, frm_addr_uv,
					     buffer->buff_addr[RKCIF_PLANE_CBCR]);
	} else {
		if (dummy_buf->vaddr) {
			rkcif_write_register(dev, frm_addr_y, dummy_buf->dma_addr);
			if (stream->cif_fmt_out->fmt_type != CIF_FMT_TYPE_RAW)
				rkcif_write_register(dev, frm_addr_uv, dummy_buf->dma_addr);
		} else {
			ret = -EINVAL;
		}
		v4l2_info(&dev->v4l2_dev,
			 "not active buffer, skip current frame, %s stream[%d]\n",
			 (mbus_cfg->type == V4L2_MBUS_CSI2_DPHY ||
			  mbus_cfg->type == V4L2_MBUS_CSI2_CPHY ||
			  mbus_cfg->type == V4L2_MBUS_CCP2) ? "mipi/lvds" : "dvp",
			  stream->id);
	}

	return ret;
}

static void rkcif_assign_dummy_buffer(struct rkcif_stream *stream)
{
	struct rkcif_device *dev = stream->cifdev;
	struct v4l2_mbus_config *mbus_cfg = &dev->active_sensor->mbus;
	struct rkcif_dummy_buffer *dummy_buf = &dev->dummy_buf;
	unsigned long flags;

	spin_lock_irqsave(&stream->vbq_lock, flags);

	/* for BT.656/BT.1120 multi channels function,
	 * yuv addr of unused channel must be set
	 */
	if (mbus_cfg->type == V4L2_MBUS_BT656 && dummy_buf->vaddr) {
		rkcif_write_register(dev,
				     get_dvp_reg_index_of_frm0_y_addr(stream->id),
				     dummy_buf->dma_addr);
		rkcif_write_register(dev,
				     get_dvp_reg_index_of_frm0_uv_addr(stream->id),
				     dummy_buf->dma_addr);
		rkcif_write_register(dev,
				     get_dvp_reg_index_of_frm1_y_addr(stream->id),
				     dummy_buf->dma_addr);
		rkcif_write_register(dev,
				     get_dvp_reg_index_of_frm1_uv_addr(stream->id),
				     dummy_buf->dma_addr);
	}

	spin_unlock_irqrestore(&stream->vbq_lock, flags);
}

static int rkcif_assign_new_buffer_pingpong(struct rkcif_stream *stream,
					     int init, int channel_id)
{
	int ret = 0;

	if (init)
		rkcif_assign_new_buffer_init(stream, channel_id);
	else
		ret = rkcif_assign_new_buffer_update(stream, channel_id);
	return ret;
}

static void rkcif_csi_get_vc_num(struct rkcif_device *dev,
				 unsigned int mbus_flags)
{
	int i, vc_num = 0;

	for (i = 0; i < RKCIF_MAX_CSI_CHANNEL; i++) {
		if (mbus_flags & V4L2_MBUS_CSI2_CHANNEL_0) {
			dev->channels[vc_num].vc = vc_num;
			vc_num++;
			mbus_flags ^= V4L2_MBUS_CSI2_CHANNEL_0;
			continue;
		}
		if (mbus_flags & V4L2_MBUS_CSI2_CHANNEL_1) {
			dev->channels[vc_num].vc = vc_num;
			vc_num++;
			mbus_flags ^= V4L2_MBUS_CSI2_CHANNEL_1;
			continue;
		}

		if (mbus_flags & V4L2_MBUS_CSI2_CHANNEL_2) {
			dev->channels[vc_num].vc = vc_num;
			vc_num++;
			mbus_flags ^= V4L2_MBUS_CSI2_CHANNEL_2;
			continue;
		}

		if (mbus_flags & V4L2_MBUS_CSI2_CHANNEL_3) {
			dev->channels[vc_num].vc = vc_num;
			vc_num++;
			mbus_flags ^= V4L2_MBUS_CSI2_CHANNEL_3;
			continue;
		}
	}

	dev->num_channels = vc_num ? vc_num : 1;
	if (dev->num_channels == 1)
		dev->channels[0].vc = 0;
}

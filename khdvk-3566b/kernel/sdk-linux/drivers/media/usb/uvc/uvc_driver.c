// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *      uvc_driver.c  --  USB Video Class driver
 *
 *      Copyright (C) 2005-2010
 *          Laurent Pinchart (laurent.pinchart@ideasonboard.com)
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/usb/quirks.h>
#include <linux/videodev2.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/version.h>
#include <asm/unaligned.h>

#include <media/v4l2-common.h>
#include <media/v4l2-ioctl.h>

#include "uvcvideo.h"

#define DRIVER_AUTHOR		"Laurent Pinchart " \
				"<laurent.pinchart@ideasonboard.com>"
#define DRIVER_DESC		"USB Video Class driver"

unsigned int uvc_clock_param = CLOCK_MONOTONIC;
unsigned int uvc_hw_timestamps_param;
unsigned int uvc_no_drop_param;
static unsigned int uvc_quirks_param = -1;
unsigned int uvc_trace_param;
unsigned int uvc_timeout_param = UVC_CTRL_STREAMING_TIMEOUT;

/* ------------------------------------------------------------------------
 * Video formats
 */

static struct uvc_format_desc uvc_fmts[] = {
	{
		.name		= "YUV 4:2:2 (YUYV)",
		.guid		= UVC_GUID_FORMAT_YUY2,
		.fcc		= V4L2_PIX_FMT_YUYV,
	},
	{
		.name		= "YUV 4:2:2 (YUYV)",
		.guid		= UVC_GUID_FORMAT_YUY2_ISIGHT,
		.fcc		= V4L2_PIX_FMT_YUYV,
	},
	{
		.name		= "YUV 4:2:0 (NV12)",
		.guid		= UVC_GUID_FORMAT_NV12,
		.fcc		= V4L2_PIX_FMT_NV12,
	},
	{
		.name		= "MJPEG",
		.guid		= UVC_GUID_FORMAT_MJPEG,
		.fcc		= V4L2_PIX_FMT_MJPEG,
	},
	{
		.name		= "YVU 4:2:0 (YV12)",
		.guid		= UVC_GUID_FORMAT_YV12,
		.fcc		= V4L2_PIX_FMT_YVU420,
	},
	{
		.name		= "YUV 4:2:0 (I420)",
		.guid		= UVC_GUID_FORMAT_I420,
		.fcc		= V4L2_PIX_FMT_YUV420,
	},
	{
		.name		= "YUV 4:2:0 (M420)",
		.guid		= UVC_GUID_FORMAT_M420,
		.fcc		= V4L2_PIX_FMT_M420,
	},
	{
		.name		= "YUV 4:2:2 (UYVY)",
		.guid		= UVC_GUID_FORMAT_UYVY,
		.fcc		= V4L2_PIX_FMT_UYVY,
	},
	{
		.name		= "Greyscale 8-bit (Y800)",
		.guid		= UVC_GUID_FORMAT_Y800,
		.fcc		= V4L2_PIX_FMT_GREY,
	},
	{
		.name		= "Greyscale 8-bit (Y8  )",
		.guid		= UVC_GUID_FORMAT_Y8,
		.fcc		= V4L2_PIX_FMT_GREY,
	},
	{
		.name		= "Greyscale 8-bit (D3DFMT_L8)",
		.guid		= UVC_GUID_FORMAT_D3DFMT_L8,
		.fcc		= V4L2_PIX_FMT_GREY,
	},
	{
		.name		= "IR 8-bit (L8_IR)",
		.guid		= UVC_GUID_FORMAT_KSMEDIA_L8_IR,
		.fcc		= V4L2_PIX_FMT_GREY,
	},
	{
		.name		= "Greyscale 10-bit (Y10 )",
		.guid		= UVC_GUID_FORMAT_Y10,
		.fcc		= V4L2_PIX_FMT_Y10,
	},
	{
		.name		= "Greyscale 12-bit (Y12 )",
		.guid		= UVC_GUID_FORMAT_Y12,
		.fcc		= V4L2_PIX_FMT_Y12,
	},
	{
		.name		= "Greyscale 16-bit (Y16 )",
		.guid		= UVC_GUID_FORMAT_Y16,
		.fcc		= V4L2_PIX_FMT_Y16,
	},
	{
		.name		= "BGGR Bayer (BY8 )",
		.guid		= UVC_GUID_FORMAT_BY8,
		.fcc		= V4L2_PIX_FMT_SBGGR8,
	},
	{
		.name		= "BGGR Bayer (BA81)",
		.guid		= UVC_GUID_FORMAT_BA81,
		.fcc		= V4L2_PIX_FMT_SBGGR8,
	},
	{
		.name		= "GBRG Bayer (GBRG)",
		.guid		= UVC_GUID_FORMAT_GBRG,
		.fcc		= V4L2_PIX_FMT_SGBRG8,
	},
	{
		.name		= "GRBG Bayer (GRBG)",
		.guid		= UVC_GUID_FORMAT_GRBG,
		.fcc		= V4L2_PIX_FMT_SGRBG8,
	},
	{
		.name		= "RGGB Bayer (RGGB)",
		.guid		= UVC_GUID_FORMAT_RGGB,
		.fcc		= V4L2_PIX_FMT_SRGGB8,
	},
	{
		.name		= "RGB565",
		.guid		= UVC_GUID_FORMAT_RGBP,
		.fcc		= V4L2_PIX_FMT_RGB565,
	},
	{
		.name		= "BGR 8:8:8 (BGR3)",
		.guid		= UVC_GUID_FORMAT_BGR3,
		.fcc		= V4L2_PIX_FMT_BGR24,
	},
	{
		.name		= "H.264",
		.guid		= UVC_GUID_FORMAT_H264,
		.fcc		= V4L2_PIX_FMT_H264,
	},
	{
		.name		= "Greyscale 8 L/R (Y8I)",
		.guid		= UVC_GUID_FORMAT_Y8I,
		.fcc		= V4L2_PIX_FMT_Y8I,
	},
	{
		.name		= "Greyscale 12 L/R (Y12I)",
		.guid		= UVC_GUID_FORMAT_Y12I,
		.fcc		= V4L2_PIX_FMT_Y12I,
	},
	{
		.name		= "Depth data 16-bit (Z16)",
		.guid		= UVC_GUID_FORMAT_Z16,
		.fcc		= V4L2_PIX_FMT_Z16,
	},
	{
		.name		= "Bayer 10-bit (SRGGB10P)",
		.guid		= UVC_GUID_FORMAT_RW10,
		.fcc		= V4L2_PIX_FMT_SRGGB10P,
	},
	{
		.name		= "Bayer 16-bit (SBGGR16)",
		.guid		= UVC_GUID_FORMAT_BG16,
		.fcc		= V4L2_PIX_FMT_SBGGR16,
	},
	{
		.name		= "Bayer 16-bit (SGBRG16)",
		.guid		= UVC_GUID_FORMAT_GB16,
		.fcc		= V4L2_PIX_FMT_SGBRG16,
	},
	{
		.name		= "Bayer 16-bit (SRGGB16)",
		.guid		= UVC_GUID_FORMAT_RG16,
		.fcc		= V4L2_PIX_FMT_SRGGB16,
	},
	{
		.name		= "Bayer 16-bit (SGRBG16)",
		.guid		= UVC_GUID_FORMAT_GR16,
		.fcc		= V4L2_PIX_FMT_SGRBG16,
	},
	{
		.name		= "Depth data 16-bit (Z16)",
		.guid		= UVC_GUID_FORMAT_INVZ,
		.fcc		= V4L2_PIX_FMT_Z16,
	},
	{
		.name		= "Greyscale 10-bit (Y10 )",
		.guid		= UVC_GUID_FORMAT_INVI,
		.fcc		= V4L2_PIX_FMT_Y10,
	},
	{
		.name		= "IR:Depth 26-bit (INZI)",
		.guid		= UVC_GUID_FORMAT_INZI,
		.fcc		= V4L2_PIX_FMT_INZI,
	},
	{
		.name		= "4-bit Depth Confidence (Packed)",
		.guid		= UVC_GUID_FORMAT_CNF4,
		.fcc		= V4L2_PIX_FMT_CNF4,
	},
	{
		.name		= "HEVC",
		.guid		= UVC_GUID_FORMAT_HEVC,
		.fcc		= V4L2_PIX_FMT_HEVC,
	},
};

/* ------------------------------------------------------------------------
 * Utility functions
 */

struct usb_host_endpoint *uvc_find_endpoint(struct usb_host_interface *alts,
		u8 epaddr)
{
	struct usb_host_endpoint *ep;
	unsigned int i;

	for (i = 0; i < alts->desc.bNumEndpoints; ++i) {
		ep = &alts->endpoint[i];
		if (ep->desc.bEndpointAddress == epaddr)
			return ep;
	}

	return NULL;
}

static struct uvc_format_desc *uvc_format_by_guid(const u8 guid[16])
{
	unsigned int len = ARRAY_SIZE(uvc_fmts);
	unsigned int i;

	for (i = 0; i < len; ++i) {
		if (memcmp(guid, uvc_fmts[i].guid, 16) == 0)
			return &uvc_fmts[i];
	}

	return NULL;
}

static enum v4l2_colorspace uvc_colorspace(const u8 primaries)
{
	static const enum v4l2_colorspace colorprimaries[] = {
		V4L2_COLORSPACE_DEFAULT,  /* Unspecified */
		V4L2_COLORSPACE_SRGB,
		V4L2_COLORSPACE_470_SYSTEM_M,
		V4L2_COLORSPACE_470_SYSTEM_BG,
		V4L2_COLORSPACE_SMPTE170M,
		V4L2_COLORSPACE_SMPTE240M,
	};

	if (primaries < ARRAY_SIZE(colorprimaries))
		return colorprimaries[primaries];

	return V4L2_COLORSPACE_DEFAULT;  /* Reserved */
}

static enum v4l2_xfer_func uvc_xfer_func(const u8 transfer_characteristics)
{
	/*
	 * V4L2 does not currently have definitions for all possible values of
	 * UVC transfer characteristics. If v4l2_xfer_func is extended with new
	 * values, the mapping below should be updated.
	 *
	 * Substitutions are taken from the mapping given for
	 * V4L2_XFER_FUNC_DEFAULT documented in videodev2.h.
	 */
	static const enum v4l2_xfer_func xfer_funcs[] = {
		V4L2_XFER_FUNC_DEFAULT,    /* Unspecified */
		V4L2_XFER_FUNC_709,
		V4L2_XFER_FUNC_709,        /* Substitution for BT.470-2 M */
		V4L2_XFER_FUNC_709,        /* Substitution for BT.470-2 B, G */
		V4L2_XFER_FUNC_709,        /* Substitution for SMPTE 170M */
		V4L2_XFER_FUNC_SMPTE240M,
		V4L2_XFER_FUNC_NONE,
		V4L2_XFER_FUNC_SRGB,
	};

	if (transfer_characteristics < ARRAY_SIZE(xfer_funcs))
		return xfer_funcs[transfer_characteristics];

	return V4L2_XFER_FUNC_DEFAULT;  /* Reserved */
}

static enum v4l2_ycbcr_encoding uvc_ycbcr_enc(const u8 matrix_coefficients)
{
	/*
	 * V4L2 does not currently have definitions for all possible values of
	 * UVC matrix coefficients. If v4l2_ycbcr_encoding is extended with new
	 * values, the mapping below should be updated.
	 *
	 * Substitutions are taken from the mapping given for
	 * V4L2_YCBCR_ENC_DEFAULT documented in videodev2.h.
	 *
	 * FCC is assumed to be close enough to 601.
	 */
	static const enum v4l2_ycbcr_encoding ycbcr_encs[] = {
		V4L2_YCBCR_ENC_DEFAULT,  /* Unspecified */
		V4L2_YCBCR_ENC_709,
		V4L2_YCBCR_ENC_601,      /* Substitution for FCC */
		V4L2_YCBCR_ENC_601,      /* Substitution for BT.470-2 B, G */
		V4L2_YCBCR_ENC_601,
		V4L2_YCBCR_ENC_SMPTE240M,
	};

	if (matrix_coefficients < ARRAY_SIZE(ycbcr_encs))
		return ycbcr_encs[matrix_coefficients];

	return V4L2_YCBCR_ENC_DEFAULT;  /* Reserved */
}

/* Simplify a fraction using a simple continued fraction decomposition. The
 * idea here is to convert fractions such as 333333/10000000 to 1/30 using
 * 32 bit arithmetic only. The algorithm is not perfect and relies upon two
 * arbitrary parameters to remove non-significative terms from the simple
 * continued fraction decomposition. Using 8 and 333 for n_terms and threshold
 * respectively seems to give nice results.
 */
void uvc_simplify_fraction(u32 *numerator, u32 *denominator,
		unsigned int n_terms, unsigned int threshold)
{
	u32 *an;
	u32 x, y, r;
	unsigned int i, n;

	an = kmalloc_array(n_terms, sizeof(*an), GFP_KERNEL);
	if (an == NULL)
		return;

	/* Convert the fraction to a simple continued fraction. See
	 * https://mathforum.org/dr.math/faq/faq.fractions.html
	 * Stop if the current term is bigger than or equal to the given
	 * threshold.
	 */
	x = *numerator;
	y = *denominator;

	for (n = 0; n < n_terms && y != 0; ++n) {
		an[n] = x / y;
		if (an[n] >= threshold) {
			if (n < 2)
				n++;
			break;
		}

		r = x - an[n] * y;
		x = y;
		y = r;
	}

	/* Expand the simple continued fraction back to an integer fraction. */
	x = 0;
	y = 1;

	for (i = n; i > 0; --i) {
		r = y;
		y = an[i-1] * y + x;
		x = r;
	}

	*numerator = y;
	*denominator = x;
	kfree(an);
}

/* Convert a fraction to a frame interval in 100ns multiples. The idea here is
 * to compute numerator / denominator * 10000000 using 32 bit fixed point
 * arithmetic only.
 */
u32 uvc_fraction_to_interval(u32 numerator, u32 denominator)
{
	u32 multiplier;

	/* Saturate the result if the operation would overflow. */
	if (denominator == 0 ||
	    numerator/denominator >= ((u32)-1)/10000000)
		return (u32)-1;

	/* Divide both the denominator and the multiplier by two until
	 * numerator * multiplier doesn't overflow. If anyone knows a better
	 * algorithm please let me know.
	 */
	multiplier = 10000000;
	while (numerator > ((u32)-1)/multiplier) {
		multiplier /= 2;
		denominator /= 2;
	}

	return denominator ? numerator * multiplier / denominator : 0;
}

/* ------------------------------------------------------------------------
 * Terminal and unit management
 */

struct uvc_entity *uvc_entity_by_id(struct uvc_device *dev, int id)
{
	struct uvc_entity *entity;

	list_for_each_entry(entity, &dev->entities, list) {
		if (entity->id == id)
			return entity;
	}

	return NULL;
}

static struct uvc_entity *uvc_entity_by_reference(struct uvc_device *dev,
	int id, struct uvc_entity *entity)
{
	unsigned int i;

	if (entity == NULL)
		entity = list_entry(&dev->entities, struct uvc_entity, list);

	list_for_each_entry_continue(entity, &dev->entities, list) {
		for (i = 0; i < entity->bNrInPins; ++i)
			if (entity->baSourceID[i] == id)
				return entity;
	}

	return NULL;
}

static struct uvc_streaming *uvc_stream_by_id(struct uvc_device *dev, int id)
{
	struct uvc_streaming *stream;

	list_for_each_entry(stream, &dev->streams, list) {
		if (stream->header.bTerminalLink == id)
			return stream;
	}

	return NULL;
}

/* ------------------------------------------------------------------------
 * Streaming Object Management
 */

static void uvc_stream_delete(struct uvc_streaming *stream)
{
	if (stream->async_wq)
		destroy_workqueue(stream->async_wq);

	mutex_destroy(&stream->mutex);

	usb_put_intf(stream->intf);

	kfree(stream->format);
	kfree(stream->header.bmaControls);
	kfree(stream);
}

static struct uvc_streaming *uvc_stream_new(struct uvc_device *dev,
					    struct usb_interface *intf)
{
	struct uvc_streaming *stream;

	stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (stream == NULL)
		return NULL;

	mutex_init(&stream->mutex);

	stream->dev = dev;
	stream->intf = usb_get_intf(intf);
	stream->intfnum = intf->cur_altsetting->desc.bInterfaceNumber;

	/* Allocate a stream specific work queue for asynchronous tasks. */
	stream->async_wq = alloc_workqueue("uvcvideo", WQ_UNBOUND | WQ_HIGHPRI,
					   0);
	if (!stream->async_wq) {
		uvc_stream_delete(stream);
		return NULL;
	}

	return stream;
}

/* ------------------------------------------------------------------------
 * Descriptors parsing
 */

static int uvc_parse_format(struct uvc_device *dev,
	struct uvc_streaming *streaming, struct uvc_format *format,
	u32 **intervals, unsigned char *buffer, int buflen)
{
	struct usb_interface *intf = streaming->intf;
	struct usb_host_interface *alts = intf->cur_altsetting;
	struct uvc_format_desc *fmtdesc;
	struct uvc_frame *frame;
	const unsigned char *start = buffer;
	unsigned int width_multiplier = 1;
	unsigned int interval;
	unsigned int i, n;
	u8 ftype;

	format->type = buffer[2];
	format->index = buffer[3];

	switch (buffer[2]) {
	case UVC_VS_FORMAT_UNCOMPRESSED:
	case UVC_VS_FORMAT_FRAME_BASED:
		n = buffer[2] == UVC_VS_FORMAT_UNCOMPRESSED ? 27 : 28;
		if (buflen < n) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
			       "interface %d FORMAT error\n",
			       dev->udev->devnum,
			       alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		/* Find the format descriptor from its GUID. */
		fmtdesc = uvc_format_by_guid(&buffer[5]);

		if (fmtdesc != NULL) {
			strscpy(format->name, fmtdesc->name,
				sizeof(format->name));
			format->fcc = fmtdesc->fcc;
		} else {
			uvc_printk(KERN_INFO, "Unknown video format %pUl\n",
				&buffer[5]);
			snprintf(format->name, sizeof(format->name), "%pUl\n",
				&buffer[5]);
			format->fcc = 0;
		}

		format->bpp = buffer[21];

		/* Some devices report a format that doesn't match what they
		 * really send.
		 */
		if (dev->quirks & UVC_QUIRK_FORCE_Y8) {
			if (format->fcc == V4L2_PIX_FMT_YUYV) {
				strscpy(format->name, "Greyscale 8-bit (Y8  )",
					sizeof(format->name));
				format->fcc = V4L2_PIX_FMT_GREY;
				format->bpp = 8;
				width_multiplier = 2;
			}
		}

		/* Some devices report bpp that doesn't match the format. */
		if (dev->quirks & UVC_QUIRK_FORCE_BPP) {
			const struct v4l2_format_info *info =
				v4l2_format_info(format->fcc);

			if (info) {
				unsigned int div = info->hdiv * info->vdiv;

				n = info->bpp[0] * div;
				for (i = 1; i < info->comp_planes; i++)
					n += info->bpp[i];

				format->bpp = DIV_ROUND_UP(8 * n, div);
			}
		}

		if (buffer[2] == UVC_VS_FORMAT_UNCOMPRESSED) {
			ftype = UVC_VS_FRAME_UNCOMPRESSED;
		} else {
			ftype = UVC_VS_FRAME_FRAME_BASED;
			if (buffer[27])
				format->flags = UVC_FMT_FLAG_COMPRESSED;
		}
		break;

	case UVC_VS_FORMAT_MJPEG:
		if (buflen < 11) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
			       "interface %d FORMAT error\n",
			       dev->udev->devnum,
			       alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		strscpy(format->name, "MJPEG", sizeof(format->name));
		format->fcc = V4L2_PIX_FMT_MJPEG;
		format->flags = UVC_FMT_FLAG_COMPRESSED;
		format->bpp = 0;
		ftype = UVC_VS_FRAME_MJPEG;
		break;

	case UVC_VS_FORMAT_DV:
		if (buflen < 9) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
			       "interface %d FORMAT error\n",
			       dev->udev->devnum,
			       alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		switch (buffer[8] & 0x7f) {
		case 0:
			strscpy(format->name, "SD-DV", sizeof(format->name));
			break;
		case 1:
			strscpy(format->name, "SDL-DV", sizeof(format->name));
			break;
		case 2:
			strscpy(format->name, "HD-DV", sizeof(format->name));
			break;
		default:
			uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
			       "interface %d: unknown DV format %u\n",
			       dev->udev->devnum,
			       alts->desc.bInterfaceNumber, buffer[8]);
			return -EINVAL;
		}

		strlcat(format->name, buffer[8] & (1 << 7) ? " 60Hz" : " 50Hz",
			sizeof(format->name));

		format->fcc = V4L2_PIX_FMT_DV;
		format->flags = UVC_FMT_FLAG_COMPRESSED | UVC_FMT_FLAG_STREAM;
		format->bpp = 0;
		ftype = 0;

		/* Create a dummy frame descriptor. */
		frame = &format->frame[0];
		memset(&format->frame[0], 0, sizeof(format->frame[0]));
		frame->bFrameIntervalType = 1;
		frame->dwDefaultFrameInterval = 1;
		frame->dwFrameInterval = *intervals;
		*(*intervals)++ = 1;
		format->nframes = 1;
		break;

	case UVC_VS_FORMAT_MPEG2TS:
	case UVC_VS_FORMAT_STREAM_BASED:
		/* Not supported yet. */
	default:
		uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
		       "interface %d unsupported format %u\n",
		       dev->udev->devnum, alts->desc.bInterfaceNumber,
		       buffer[2]);
		return -EINVAL;
	}

	uvc_trace(UVC_TRACE_DESCR, "Found format %s.\n", format->name);

	buflen -= buffer[0];
	buffer += buffer[0];

	/* Parse the frame descriptors. Only uncompressed, MJPEG and frame
	 * based formats have frame descriptors.
	 */
	while (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE &&
	       buffer[2] == ftype) {
		frame = &format->frame[format->nframes];
		if (ftype != UVC_VS_FRAME_FRAME_BASED)
			n = buflen > 25 ? buffer[25] : 0;
		else
			n = buflen > 21 ? buffer[21] : 0;

		n = n ? n : 3;

		if (buflen < 26 + 4*n) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
			       "interface %d FRAME error\n", dev->udev->devnum,
			       alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		frame->bFrameIndex = buffer[3];
		frame->bmCapabilities = buffer[4];
		frame->wWidth = get_unaligned_le16(&buffer[5])
			      * width_multiplier;
		frame->wHeight = get_unaligned_le16(&buffer[7]);
		frame->dwMinBitRate = get_unaligned_le32(&buffer[9]);
		frame->dwMaxBitRate = get_unaligned_le32(&buffer[13]);
		if (ftype != UVC_VS_FRAME_FRAME_BASED) {
			frame->dwMaxVideoFrameBufferSize =
				get_unaligned_le32(&buffer[17]);
			frame->dwDefaultFrameInterval =
				get_unaligned_le32(&buffer[21]);
			frame->bFrameIntervalType = buffer[25];
		} else {
			frame->dwMaxVideoFrameBufferSize = 0;
			frame->dwDefaultFrameInterval =
				get_unaligned_le32(&buffer[17]);
			frame->bFrameIntervalType = buffer[21];
		}
		frame->dwFrameInterval = *intervals;

		/* Several UVC chipsets screw up dwMaxVideoFrameBufferSize
		 * completely. Observed behaviours range from setting the
		 * value to 1.1x the actual frame size to hardwiring the
		 * 16 low bits to 0. This results in a higher than necessary
		 * memory usage as well as a wrong image size information. For
		 * uncompressed formats this can be fixed by computing the
		 * value from the frame size.
		 */
		if (!(format->flags & UVC_FMT_FLAG_COMPRESSED))
			frame->dwMaxVideoFrameBufferSize = format->bpp
				* frame->wWidth * frame->wHeight / 8;

		/* Some bogus devices report dwMinFrameInterval equal to
		 * dwMaxFrameInterval and have dwFrameIntervalStep set to
		 * zero. Setting all null intervals to 1 fixes the problem and
		 * some other divisions by zero that could happen.
		 */
		for (i = 0; i < n; ++i) {
			interval = get_unaligned_le32(&buffer[26+4*i]);
			*(*intervals)++ = interval ? interval : 1;
		}

		/* Make sure that the default frame interval stays between
		 * the boundaries.
		 */
		n -= frame->bFrameIntervalType ? 1 : 2;
		frame->dwDefaultFrameInterval =
			min(frame->dwFrameInterval[n],
			    max(frame->dwFrameInterval[0],
				frame->dwDefaultFrameInterval));

		if (dev->quirks & UVC_QUIRK_RESTRICT_FRAME_RATE) {
			frame->bFrameIntervalType = 1;
			frame->dwFrameInterval[0] =
				frame->dwDefaultFrameInterval;
		}

		uvc_trace(UVC_TRACE_DESCR, "- %ux%u (%u.%u fps)\n",
			frame->wWidth, frame->wHeight,
			10000000/frame->dwDefaultFrameInterval,
			(100000000/frame->dwDefaultFrameInterval)%10);

		format->nframes++;
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE &&
	    buffer[2] == UVC_VS_STILL_IMAGE_FRAME) {
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE &&
	    buffer[2] == UVC_VS_COLORFORMAT) {
		if (buflen < 6) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
			       "interface %d COLORFORMAT error\n",
			       dev->udev->devnum,
			       alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		format->colorspace = uvc_colorspace(buffer[3]);
		format->xfer_func = uvc_xfer_func(buffer[4]);
		format->ycbcr_enc = uvc_ycbcr_enc(buffer[5]);

		buflen -= buffer[0];
		buffer += buffer[0];
	}

	return buffer - start;
}

static int uvc_parse_streaming(struct uvc_device *dev,
	struct usb_interface *intf)
{
	struct uvc_streaming *streaming = NULL;
	struct uvc_format *format;
	struct uvc_frame *frame;
	struct usb_host_interface *alts = &intf->altsetting[0];
	unsigned char *_buffer, *buffer = alts->extra;
	int _buflen, buflen = alts->extralen;
	unsigned int nformats = 0, nframes = 0, nintervals = 0;
	unsigned int size, i, n, p;
	u32 *interval;
	u16 psize;
	int ret = -EINVAL;

	if (intf->cur_altsetting->desc.bInterfaceSubClass
		!= UVC_SC_VIDEOSTREAMING) {
		uvc_trace(UVC_TRACE_DESCR, "device %d interface %d isn't a "
			"video streaming interface\n", dev->udev->devnum,
			intf->altsetting[0].desc.bInterfaceNumber);
		return -EINVAL;
	}

	if (usb_driver_claim_interface(&uvc_driver.driver, intf, dev)) {
		uvc_trace(UVC_TRACE_DESCR, "device %d interface %d is already "
			"claimed\n", dev->udev->devnum,
			intf->altsetting[0].desc.bInterfaceNumber);
		return -EINVAL;
	}

	streaming = uvc_stream_new(dev, intf);
	if (streaming == NULL) {
		usb_driver_release_interface(&uvc_driver.driver, intf);
		return -ENOMEM;
	}

	/* The Pico iMage webcam has its class-specific interface descriptors
	 * after the endpoint descriptors.
	 */
	if (buflen == 0) {
		for (i = 0; i < alts->desc.bNumEndpoints; ++i) {
			struct usb_host_endpoint *ep = &alts->endpoint[i];

			if (ep->extralen == 0)
				continue;

			if (ep->extralen > 2 &&
			    ep->extra[1] == USB_DT_CS_INTERFACE) {
				uvc_trace(UVC_TRACE_DESCR, "trying extra data "
					"from endpoint %u.\n", i);
				buffer = alts->endpoint[i].extra;
				buflen = alts->endpoint[i].extralen;
				break;
			}
		}
	}

	/* Skip the standard interface descriptors. */
	while (buflen > 2 && buffer[1] != USB_DT_CS_INTERFACE) {
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen <= 2) {
		uvc_trace(UVC_TRACE_DESCR, "no class-specific streaming "
			"interface descriptors found.\n");
		goto error;
	}

	/* Parse the header descriptor. */
	switch (buffer[2]) {
	case UVC_VS_OUTPUT_HEADER:
		streaming->type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
		size = 9;
		break;

	case UVC_VS_INPUT_HEADER:
		streaming->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		size = 13;
		break;

	default:
		uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming interface "
			"%d HEADER descriptor not found.\n", dev->udev->devnum,
			alts->desc.bInterfaceNumber);
		goto error;
	}

	p = buflen >= 4 ? buffer[3] : 0;
	n = buflen >= size ? buffer[size-1] : 0;

	if (buflen < size + p*n) {
		uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
			"interface %d HEADER descriptor is invalid.\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber);
		goto error;
	}

	streaming->header.bNumFormats = p;
	streaming->header.bEndpointAddress = buffer[6];
	if (buffer[2] == UVC_VS_INPUT_HEADER) {
		streaming->header.bmInfo = buffer[7];
		streaming->header.bTerminalLink = buffer[8];
		streaming->header.bStillCaptureMethod = buffer[9];
		streaming->header.bTriggerSupport = buffer[10];
		streaming->header.bTriggerUsage = buffer[11];
	} else {
		streaming->header.bTerminalLink = buffer[7];
	}
	streaming->header.bControlSize = n;

	streaming->header.bmaControls = kmemdup(&buffer[size], p * n,
						GFP_KERNEL);
	if (streaming->header.bmaControls == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	buflen -= buffer[0];
	buffer += buffer[0];

	_buffer = buffer;
	_buflen = buflen;

	/* Count the format and frame descriptors. */
	while (_buflen > 2 && _buffer[1] == USB_DT_CS_INTERFACE) {
		switch (_buffer[2]) {
		case UVC_VS_FORMAT_UNCOMPRESSED:
		case UVC_VS_FORMAT_MJPEG:
		case UVC_VS_FORMAT_FRAME_BASED:
			nformats++;
			break;

		case UVC_VS_FORMAT_DV:
			/* DV format has no frame descriptor. We will create a
			 * dummy frame descriptor with a dummy frame interval.
			 */
			nformats++;
			nframes++;
			nintervals++;
			break;

		case UVC_VS_FORMAT_MPEG2TS:
		case UVC_VS_FORMAT_STREAM_BASED:
			uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming "
				"interface %d FORMAT %u is not supported.\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber, _buffer[2]);
			break;

		case UVC_VS_FRAME_UNCOMPRESSED:
		case UVC_VS_FRAME_MJPEG:
			nframes++;
			if (_buflen > 25)
				nintervals += _buffer[25] ? _buffer[25] : 3;
			break;

		case UVC_VS_FRAME_FRAME_BASED:
			nframes++;
			if (_buflen > 21)
				nintervals += _buffer[21] ? _buffer[21] : 3;
			break;
		}

		_buflen -= _buffer[0];
		_buffer += _buffer[0];
	}

	if (nformats == 0) {
		uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming interface "
			"%d has no supported formats defined.\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber);
		goto error;
	}

	size = nformats * sizeof(*format) + nframes * sizeof(*frame)
	     + nintervals * sizeof(*interval);
	format = kzalloc(size, GFP_KERNEL);
	if (format == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	frame = (struct uvc_frame *)&format[nformats];
	interval = (u32 *)&frame[nframes];

	streaming->format = format;
	streaming->nformats = nformats;

	/* Parse the format descriptors. */
	while (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE) {
		switch (buffer[2]) {
		case UVC_VS_FORMAT_UNCOMPRESSED:
		case UVC_VS_FORMAT_MJPEG:
		case UVC_VS_FORMAT_DV:
		case UVC_VS_FORMAT_FRAME_BASED:
			format->frame = frame;
			ret = uvc_parse_format(dev, streaming, format,
				&interval, buffer, buflen);
			if (ret < 0)
				goto error;

			frame += format->nframes;
			format++;

			buflen -= ret;
			buffer += ret;
			continue;

		default:
			break;
		}

		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen)
		uvc_trace(UVC_TRACE_DESCR, "device %d videostreaming interface "
			"%d has %u bytes of trailing descriptor garbage.\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber, buflen);

	/* Parse the alternate settings to find the maximum bandwidth. */
	for (i = 0; i < intf->num_altsetting; ++i) {
		struct usb_host_endpoint *ep;
		alts = &intf->altsetting[i];
		ep = uvc_find_endpoint(alts,
				streaming->header.bEndpointAddress);
		if (ep == NULL)
			continue;

		psize = le16_to_cpu(ep->desc.wMaxPacketSize);
		psize = (psize & 0x07ff) * (1 + ((psize >> 11) & 3));
		if (psize > streaming->maxpsize)
			streaming->maxpsize = psize;
	}

	list_add_tail(&streaming->list, &dev->streams);
	return 0;

error:
	usb_driver_release_interface(&uvc_driver.driver, intf);
	uvc_stream_delete(streaming);
	return ret;
}

static struct uvc_entity *uvc_alloc_entity(u16 type, u8 id,
		unsigned int num_pads, unsigned int extra_size)
{
	struct uvc_entity *entity;
	unsigned int num_inputs;
	unsigned int size;
	unsigned int i;

	extra_size = roundup(extra_size, sizeof(*entity->pads));
	if (num_pads)
		num_inputs = type & UVC_TERM_OUTPUT ? num_pads : num_pads - 1;
	else
		num_inputs = 0;
	size = sizeof(*entity) + extra_size + sizeof(*entity->pads) * num_pads
	     + num_inputs;
	entity = kzalloc(size, GFP_KERNEL);
	if (entity == NULL)
		return NULL;

	entity->id = id;
	entity->type = type;

	entity->num_links = 0;
	entity->num_pads = num_pads;
	entity->pads = ((void *)(entity + 1)) + extra_size;

	for (i = 0; i < num_inputs; ++i)
		entity->pads[i].flags = MEDIA_PAD_FL_SINK;
	if (!UVC_ENTITY_IS_OTERM(entity) && num_pads)
		entity->pads[num_pads-1].flags = MEDIA_PAD_FL_SOURCE;

	entity->bNrInPins = num_inputs;
	entity->baSourceID = (u8 *)(&entity->pads[num_pads]);

	return entity;
}

/* Parse vendor-specific extensions. */
static int uvc_parse_vendor_control(struct uvc_device *dev,
	const unsigned char *buffer, int buflen)
{
	struct usb_device *udev = dev->udev;
	struct usb_host_interface *alts = dev->intf->cur_altsetting;
	struct uvc_entity *unit;
	unsigned int n, p;
	int handled = 0;

	switch (le16_to_cpu(dev->udev->descriptor.idVendor)) {
	case 0x046d:		/* Logitech */
		if (buffer[1] != 0x41 || buffer[2] != 0x01)
			break;

		/* Logitech implements several vendor specific functions
		 * through vendor specific extension units (LXU).
		 *
		 * The LXU descriptors are similar to XU descriptors
		 * (see "USB Device Video Class for Video Devices", section
		 * 3.7.2.6 "Extension Unit Descriptor") with the following
		 * differences:
		 *
		 * ----------------------------------------------------------
		 * 0		bLength		1	 Number
		 *	Size of this descriptor, in bytes: 24+p+n*2
		 * ----------------------------------------------------------
		 * 23+p+n	bmControlsType	N	Bitmap
		 *	Individual bits in the set are defined:
		 *	0: Absolute
		 *	1: Relative
		 *
		 *	This bitset is mapped exactly the same as bmControls.
		 * ----------------------------------------------------------
		 * 23+p+n*2	bReserved	1	Boolean
		 * ----------------------------------------------------------
		 * 24+p+n*2	iExtension	1	Index
		 *	Index of a string descriptor that describes this
		 *	extension unit.
		 * ----------------------------------------------------------
		 */
		p = buflen >= 22 ? buffer[21] : 0;
		n = buflen >= 25 + p ? buffer[22+p] : 0;

		if (buflen < 25 + p + 2*n) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d EXTENSION_UNIT error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			break;
		}

		unit = uvc_alloc_entity(UVC_VC_EXTENSION_UNIT, buffer[3],
					p + 1, 2*n);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->extension.guidExtensionCode, &buffer[4], 16);
		unit->extension.bNumControls = buffer[20];
		memcpy(unit->baSourceID, &buffer[22], p);
		unit->extension.bControlSize = buffer[22+p];
		unit->extension.bmControls = (u8 *)unit + sizeof(*unit);
		unit->extension.bmControlsType = (u8 *)unit + sizeof(*unit)
					       + n;
		memcpy(unit->extension.bmControls, &buffer[23+p], 2*n);

		if (buffer[24+p+2*n] != 0)
			usb_string(udev, buffer[24+p+2*n], unit->name,
				   sizeof(unit->name));
		else
			sprintf(unit->name, "Extension %u", buffer[3]);

		list_add_tail(&unit->list, &dev->entities);
		handled = 1;
		break;
	}

	return handled;
}

static int uvc_parse_standard_control(struct uvc_device *dev,
	const unsigned char *buffer, int buflen)
{
	struct usb_device *udev = dev->udev;
	struct uvc_entity *unit, *term;
	struct usb_interface *intf;
	struct usb_host_interface *alts = dev->intf->cur_altsetting;
	unsigned int i, n, p, len;
	u16 type;

	switch (buffer[2]) {
	case UVC_VC_HEADER:
		n = buflen >= 12 ? buffer[11] : 0;

		if (buflen < 12 + n) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d HEADER error\n", udev->devnum,
				alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		dev->uvc_version = get_unaligned_le16(&buffer[3]);
		dev->clock_frequency = get_unaligned_le32(&buffer[7]);

		/* Parse all USB Video Streaming interfaces. */
		for (i = 0; i < n; ++i) {
			intf = usb_ifnum_to_if(udev, buffer[12+i]);
			if (intf == NULL) {
				uvc_trace(UVC_TRACE_DESCR, "device %d "
					"interface %d doesn't exists\n",
					udev->devnum, i);
				continue;
			}

			uvc_parse_streaming(dev, intf);
		}
		break;

	case UVC_VC_INPUT_TERMINAL:
		if (buflen < 8) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d INPUT_TERMINAL error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		/*
		 * Reject invalid terminal types that would cause issues:
		 *
		 * - The high byte must be non-zero, otherwise it would be
		 *   confused with a unit.
		 *
		 * - Bit 15 must be 0, as we use it internally as a terminal
		 *   direction flag.
		 *
		 * Other unknown types are accepted.
		 */
		type = get_unaligned_le16(&buffer[4]);
		if ((type & 0x7f00) == 0 || (type & 0x8000) != 0) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d INPUT_TERMINAL %d has invalid "
				"type 0x%04x, skipping\n", udev->devnum,
				alts->desc.bInterfaceNumber,
				buffer[3], type);
			return 0;
		}

		n = 0;
		p = 0;
		len = 8;

		if (type == UVC_ITT_CAMERA) {
			n = buflen >= 15 ? buffer[14] : 0;
			len = 15;

		} else if (type == UVC_ITT_MEDIA_TRANSPORT_INPUT) {
			n = buflen >= 9 ? buffer[8] : 0;
			p = buflen >= 10 + n ? buffer[9+n] : 0;
			len = 10;
		}

		if (buflen < len + n + p) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d INPUT_TERMINAL error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		term = uvc_alloc_entity(type | UVC_TERM_INPUT, buffer[3],
					1, n + p);
		if (term == NULL)
			return -ENOMEM;

		if (UVC_ENTITY_TYPE(term) == UVC_ITT_CAMERA) {
			term->camera.bControlSize = n;
			term->camera.bmControls = (u8 *)term + sizeof(*term);
			term->camera.wObjectiveFocalLengthMin =
				get_unaligned_le16(&buffer[8]);
			term->camera.wObjectiveFocalLengthMax =
				get_unaligned_le16(&buffer[10]);
			term->camera.wOcularFocalLength =
				get_unaligned_le16(&buffer[12]);
			memcpy(term->camera.bmControls, &buffer[15], n);
		} else if (UVC_ENTITY_TYPE(term) ==
			   UVC_ITT_MEDIA_TRANSPORT_INPUT) {
			term->media.bControlSize = n;
			term->media.bmControls = (u8 *)term + sizeof(*term);
			term->media.bTransportModeSize = p;
			term->media.bmTransportModes = (u8 *)term
						     + sizeof(*term) + n;
			memcpy(term->media.bmControls, &buffer[9], n);
			memcpy(term->media.bmTransportModes, &buffer[10+n], p);
		}

		if (buffer[7] != 0)
			usb_string(udev, buffer[7], term->name,
				   sizeof(term->name));
		else if (UVC_ENTITY_TYPE(term) == UVC_ITT_CAMERA)
			sprintf(term->name, "Camera %u", buffer[3]);
		else if (UVC_ENTITY_TYPE(term) == UVC_ITT_MEDIA_TRANSPORT_INPUT)
			sprintf(term->name, "Media %u", buffer[3]);
		else
			sprintf(term->name, "Input %u", buffer[3]);

		list_add_tail(&term->list, &dev->entities);
		break;

	case UVC_VC_OUTPUT_TERMINAL:
		if (buflen < 9) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d OUTPUT_TERMINAL error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		/* Make sure the terminal type MSB is not null, otherwise it
		 * could be confused with a unit.
		 */
		type = get_unaligned_le16(&buffer[4]);
		if ((type & 0xff00) == 0) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d OUTPUT_TERMINAL %d has invalid "
				"type 0x%04x, skipping\n", udev->devnum,
				alts->desc.bInterfaceNumber, buffer[3], type);
			return 0;
		}

		term = uvc_alloc_entity(type | UVC_TERM_OUTPUT, buffer[3],
					1, 0);
		if (term == NULL)
			return -ENOMEM;

		memcpy(term->baSourceID, &buffer[7], 1);

		if (buffer[8] != 0)
			usb_string(udev, buffer[8], term->name,
				   sizeof(term->name));
		else
			sprintf(term->name, "Output %u", buffer[3]);

		list_add_tail(&term->list, &dev->entities);
		break;

	case UVC_VC_SELECTOR_UNIT:
		p = buflen >= 5 ? buffer[4] : 0;

		if (buflen < 5 || buflen < 6 + p) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d SELECTOR_UNIT error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		unit = uvc_alloc_entity(buffer[2], buffer[3], p + 1, 0);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->baSourceID, &buffer[5], p);

		if (buffer[5+p] != 0)
			usb_string(udev, buffer[5+p], unit->name,
				   sizeof(unit->name));
		else
			sprintf(unit->name, "Selector %u", buffer[3]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	case UVC_VC_PROCESSING_UNIT:
		n = buflen >= 8 ? buffer[7] : 0;
		p = dev->uvc_version >= 0x0110 ? 10 : 9;

		if (buflen < p + n) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d PROCESSING_UNIT error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		unit = uvc_alloc_entity(buffer[2], buffer[3], 2, n);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->baSourceID, &buffer[4], 1);
		unit->processing.wMaxMultiplier =
			get_unaligned_le16(&buffer[5]);
		unit->processing.bControlSize = buffer[7];
		unit->processing.bmControls = (u8 *)unit + sizeof(*unit);
		memcpy(unit->processing.bmControls, &buffer[8], n);
		if (dev->uvc_version >= 0x0110)
			unit->processing.bmVideoStandards = buffer[9+n];

		if (buffer[8+n] != 0)
			usb_string(udev, buffer[8+n], unit->name,
				   sizeof(unit->name));
		else
			sprintf(unit->name, "Processing %u", buffer[3]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	case UVC_VC_EXTENSION_UNIT:
		p = buflen >= 22 ? buffer[21] : 0;
		n = buflen >= 24 + p ? buffer[22+p] : 0;

		if (buflen < 24 + p + n) {
			uvc_trace(UVC_TRACE_DESCR, "device %d videocontrol "
				"interface %d EXTENSION_UNIT error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		unit = uvc_alloc_entity(buffer[2], buffer[3], p + 1, n);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->extension.guidExtensionCode, &buffer[4], 16);
		unit->extension.bNumControls = buffer[20];
		memcpy(unit->baSourceID, &buffer[22], p);
		unit->extension.bControlSize = buffer[22+p];
		unit->extension.bmControls = (u8 *)unit + sizeof(*unit);
		memcpy(unit->extension.bmControls, &buffer[23+p], n);

		if (buffer[23+p+n] != 0)
			usb_string(udev, buffer[23+p+n], unit->name,
				   sizeof(unit->name));
		else
			sprintf(unit->name, "Extension %u", buffer[3]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	default:
		uvc_trace(UVC_TRACE_DESCR, "Found an unknown CS_INTERFACE "
			"descriptor (%u)\n", buffer[2]);
		break;
	}

	return 0;
}

static int uvc_parse_control(struct uvc_device *dev)
{
	struct usb_host_interface *alts = dev->intf->cur_altsetting;
	unsigned char *buffer = alts->extra;
	int buflen = alts->extralen;
	int ret;

	/* Parse the default alternate setting only, as the UVC specification
	 * defines a single alternate setting, the default alternate setting
	 * zero.
	 */

	while (buflen > 2) {
		if (uvc_parse_vendor_control(dev, buffer, buflen) ||
		    buffer[1] != USB_DT_CS_INTERFACE)
			goto next_descriptor;

		if ((ret = uvc_parse_standard_control(dev, buffer, buflen)) < 0)
			return ret;

next_descriptor:
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	/* Check if the optional status endpoint is present. Built-in iSight
	 * webcams have an interrupt endpoint but spit proprietary data that
	 * don't conform to the UVC status endpoint messages. Don't try to
	 * handle the interrupt endpoint for those cameras.
	 */
	if (alts->desc.bNumEndpoints == 1 &&
	    !(dev->quirks & UVC_QUIRK_BUILTIN_ISIGHT)) {
		struct usb_host_endpoint *ep = &alts->endpoint[0];
		struct usb_endpoint_descriptor *desc = &ep->desc;

		if (usb_endpoint_is_int_in(desc) &&
		    le16_to_cpu(desc->wMaxPacketSize) >= 8 &&
		    desc->bInterval != 0) {
			uvc_trace(UVC_TRACE_DESCR, "Found a Status endpoint "
				"(addr %02x).\n", desc->bEndpointAddress);
			dev->int_ep = ep;
		}
	}

	return 0;
}

/* ------------------------------------------------------------------------
 * UVC device scan
 */

/*
 * Scan the UVC descriptors to locate a chain starting at an Output Terminal
 * and containing the following units:
 *
 * - one or more Output Terminals (USB Streaming or Display)
 * - zero or one Processing Unit
 * - zero, one or more single-input Selector Units
 * - zero or one multiple-input Selector Units, provided all inputs are
 *   connected to input terminals
 * - zero, one or mode single-input Extension Units
 * - one or more Input Terminals (Camera, External or USB Streaming)
 *
 * The terminal and units must match on of the following structures:
 *
 * ITT_*(0) -> +---------+    +---------+    +---------+ -> TT_STREAMING(0)
 * ...         | SU{0,1} | -> | PU{0,1} | -> | XU{0,n} |    ...
 * ITT_*(n) -> +---------+    +---------+    +---------+ -> TT_STREAMING(n)
 *
 *                 +---------+    +---------+ -> OTT_*(0)
 * TT_STREAMING -> | PU{0,1} | -> | XU{0,n} |    ...
 *                 +---------+    +---------+ -> OTT_*(n)
 *
 * The Processing Unit and Extension Units can be in any order. Additional
 * Extension Units connected to the main chain as single-unit branches are
 * also supported. Single-input Selector Units are ignored.
 */
static int uvc_scan_chain_entity(struct uvc_video_chain *chain,
	struct uvc_entity *entity)
{
	switch (UVC_ENTITY_TYPE(entity)) {
	case UVC_VC_EXTENSION_UNIT:
		if (uvc_trace_param & UVC_TRACE_PROBE)
			printk(KERN_CONT " <- XU %d", entity->id);

		if (entity->bNrInPins != 1) {
			uvc_trace(UVC_TRACE_DESCR, "Extension unit %d has more "
				"than 1 input pin.\n", entity->id);
			return -1;
		}

		break;

	case UVC_VC_PROCESSING_UNIT:
		if (uvc_trace_param & UVC_TRACE_PROBE)
			printk(KERN_CONT " <- PU %d", entity->id);

		if (chain->processing != NULL) {
			uvc_trace(UVC_TRACE_DESCR, "Found multiple "
				"Processing Units in chain.\n");
			return -1;
		}

		chain->processing = entity;
		break;

	case UVC_VC_SELECTOR_UNIT:
		if (uvc_trace_param & UVC_TRACE_PROBE)
			printk(KERN_CONT " <- SU %d", entity->id);

		/* Single-input selector units are ignored. */
		if (entity->bNrInPins == 1)
			break;

		if (chain->selector != NULL) {
			uvc_trace(UVC_TRACE_DESCR, "Found multiple Selector "
				"Units in chain.\n");
			return -1;
		}

		chain->selector = entity;
		break;

	case UVC_ITT_VENDOR_SPECIFIC:
	case UVC_ITT_CAMERA:
	case UVC_ITT_MEDIA_TRANSPORT_INPUT:
		if (uvc_trace_param & UVC_TRACE_PROBE)
			printk(KERN_CONT " <- IT %d\n", entity->id);

		break;

	case UVC_OTT_VENDOR_SPECIFIC:
	case UVC_OTT_DISPLAY:
	case UVC_OTT_MEDIA_TRANSPORT_OUTPUT:
		if (uvc_trace_param & UVC_TRACE_PROBE)
			printk(KERN_CONT " OT %d", entity->id);

		break;

	case UVC_TT_STREAMING:
		if (UVC_ENTITY_IS_ITERM(entity)) {
			if (uvc_trace_param & UVC_TRACE_PROBE)
				printk(KERN_CONT " <- IT %d\n", entity->id);
		} else {
			if (uvc_trace_param & UVC_TRACE_PROBE)
				printk(KERN_CONT " OT %d", entity->id);
		}

		break;

	default:
		uvc_trace(UVC_TRACE_DESCR, "Unsupported entity type "
			"0x%04x found in chain.\n", UVC_ENTITY_TYPE(entity));
		return -1;
	}

	list_add_tail(&entity->chain, &chain->entities);
	return 0;
}

static int uvc_scan_chain_forward(struct uvc_video_chain *chain,
	struct uvc_entity *entity, struct uvc_entity *prev)
{
	struct uvc_entity *forward;
	int found;

	/* Forward scan */
	forward = NULL;
	found = 0;

	while (1) {
		forward = uvc_entity_by_reference(chain->dev, entity->id,
			forward);
		if (forward == NULL)
			break;
		if (forward == prev)
			continue;
		if (forward->chain.next || forward->chain.prev) {
			uvc_trace(UVC_TRACE_DESCR, "Found reference to "
				"entity %d already in chain.\n", forward->id);
			return -EINVAL;
		}

		switch (UVC_ENTITY_TYPE(forward)) {
		case UVC_VC_EXTENSION_UNIT:
			if (forward->bNrInPins != 1) {
				uvc_trace(UVC_TRACE_DESCR, "Extension unit %d "
					  "has more than 1 input pin.\n",
					  entity->id);
				return -EINVAL;
			}

			/*
			 * Some devices reference an output terminal as the
			 * source of extension units. This is incorrect, as
			 * output terminals only have an input pin, and thus
			 * can't be connected to any entity in the forward
			 * direction. The resulting topology would cause issues
			 * when registering the media controller graph. To
			 * avoid this problem, connect the extension unit to
			 * the source of the output terminal instead.
			 */
			if (UVC_ENTITY_IS_OTERM(entity)) {
				struct uvc_entity *source;

				source = uvc_entity_by_id(chain->dev,
							  entity->baSourceID[0]);
				if (!source) {
					uvc_trace(UVC_TRACE_DESCR,
						"Can't connect extension unit %u in chain\n",
						forward->id);
					break;
				}

				forward->baSourceID[0] = source->id;
			}

			list_add_tail(&forward->chain, &chain->entities);
			if (uvc_trace_param & UVC_TRACE_PROBE) {
				if (!found)
					printk(KERN_CONT " (->");

				printk(KERN_CONT " XU %d", forward->id);
				found = 1;
			}
			break;

		case UVC_OTT_VENDOR_SPECIFIC:
		case UVC_OTT_DISPLAY:
		case UVC_OTT_MEDIA_TRANSPORT_OUTPUT:
		case UVC_TT_STREAMING:
			if (UVC_ENTITY_IS_ITERM(forward)) {
				uvc_trace(UVC_TRACE_DESCR, "Unsupported input "
					"terminal %u.\n", forward->id);
				return -EINVAL;
			}

			if (UVC_ENTITY_IS_OTERM(entity)) {
				uvc_trace(UVC_TRACE_DESCR,
					"Unsupported connection between output terminals %u and %u\n",
					entity->id, forward->id);
				break;
			}

			list_add_tail(&forward->chain, &chain->entities);
			if (uvc_trace_param & UVC_TRACE_PROBE) {
				if (!found)
					printk(KERN_CONT " (->");

				printk(KERN_CONT " OT %d", forward->id);
				found = 1;
			}
			break;
		}
	}
	if (found)
		printk(KERN_CONT ")");

	return 0;
}

static int uvc_scan_chain_backward(struct uvc_video_chain *chain,
	struct uvc_entity **_entity)
{
	struct uvc_entity *entity = *_entity;
	struct uvc_entity *term;
	int id = -EINVAL, i;

	switch (UVC_ENTITY_TYPE(entity)) {
	case UVC_VC_EXTENSION_UNIT:
	case UVC_VC_PROCESSING_UNIT:
		id = entity->baSourceID[0];
		break;

	case UVC_VC_SELECTOR_UNIT:
		/* Single-input selector units are ignored. */
		if (entity->bNrInPins == 1) {
			id = entity->baSourceID[0];
			break;
		}

		if (uvc_trace_param & UVC_TRACE_PROBE)
			printk(KERN_CONT " <- IT");

		chain->selector = entity;
		for (i = 0; i < entity->bNrInPins; ++i) {
			id = entity->baSourceID[i];
			term = uvc_entity_by_id(chain->dev, id);
			if (term == NULL || !UVC_ENTITY_IS_ITERM(term)) {
				uvc_trace(UVC_TRACE_DESCR, "Selector unit %d "
					"input %d isn't connected to an "
					"input terminal\n", entity->id, i);
				return -1;
			}

			if (term->chain.next || term->chain.prev) {
				uvc_trace(UVC_TRACE_DESCR, "Found reference to "
					"entity %d already in chain.\n",
					term->id);
				return -EINVAL;
			}

			if (uvc_trace_param & UVC_TRACE_PROBE)
				printk(KERN_CONT " %d", term->id);

			list_add_tail(&term->chain, &chain->entities);
			uvc_scan_chain_forward(chain, term, entity);
		}

		if (uvc_trace_param & UVC_TRACE_PROBE)
			printk(KERN_CONT "\n");

		id = 0;
		break;

	case UVC_ITT_VENDOR_SPECIFIC:
	case UVC_ITT_CAMERA:
	case UVC_ITT_MEDIA_TRANSPORT_INPUT:
	case UVC_OTT_VENDOR_SPECIFIC:
	case UVC_OTT_DISPLAY:
	case UVC_OTT_MEDIA_TRANSPORT_OUTPUT:
	case UVC_TT_STREAMING:
		id = UVC_ENTITY_IS_OTERM(entity) ? entity->baSourceID[0] : 0;
		break;
	}

	if (id <= 0) {
		*_entity = NULL;
		return id;
	}

	entity = uvc_entity_by_id(chain->dev, id);
	if (entity == NULL) {
		uvc_trace(UVC_TRACE_DESCR, "Found reference to "
			"unknown entity %d.\n", id);
		return -EINVAL;
	}

	*_entity = entity;
	return 0;
}

static int uvc_scan_chain(struct uvc_video_chain *chain,
			  struct uvc_entity *term)
{
	struct uvc_entity *entity, *prev;

	uvc_trace(UVC_TRACE_PROBE, "Scanning UVC chain:");

	entity = term;
	prev = NULL;

	while (entity != NULL) {
		/* Entity must not be part of an existing chain */
		if (entity->chain.next || entity->chain.prev) {
			uvc_trace(UVC_TRACE_DESCR, "Found reference to "
				"entity %d already in chain.\n", entity->id);
			return -EINVAL;
		}

		/* Process entity */
		if (uvc_scan_chain_entity(chain, entity) < 0)
			return -EINVAL;

		/* Forward scan */
		if (uvc_scan_chain_forward(chain, entity, prev) < 0)
			return -EINVAL;

		/* Backward scan */
		prev = entity;
		if (uvc_scan_chain_backward(chain, &entity) < 0)
			return -EINVAL;
	}

	return 0;
}

static unsigned int uvc_print_terms(struct list_head *terms, u16 dir,
		char *buffer)
{
	struct uvc_entity *term;
	unsigned int nterms = 0;
	char *p = buffer;

	list_for_each_entry(term, terms, chain) {
		if (!UVC_ENTITY_IS_TERM(term) ||
		    UVC_TERM_DIRECTION(term) != dir)
			continue;

		if (nterms)
			p += sprintf(p, ",");
		if (++nterms >= 4) {
			p += sprintf(p, "...");
			break;
		}
		p += sprintf(p, "%u", term->id);
	}

	return p - buffer;
}

static const char *uvc_print_chain(struct uvc_video_chain *chain)
{
	static char buffer[43];
	char *p = buffer;

	p += uvc_print_terms(&chain->entities, UVC_TERM_INPUT, p);
	p += sprintf(p, " -> ");
	uvc_print_terms(&chain->entities, UVC_TERM_OUTPUT, p);

	return buffer;
}

static struct uvc_video_chain *uvc_alloc_chain(struct uvc_device *dev)
{
	struct uvc_video_chain *chain;

	chain = kzalloc(sizeof(*chain), GFP_KERNEL);
	if (chain == NULL)
		return NULL;

	INIT_LIST_HEAD(&chain->entities);
	mutex_init(&chain->ctrl_mutex);
	chain->dev = dev;
	v4l2_prio_init(&chain->prio);

	return chain;
}

/*
 * Fallback heuristic for devices that don't connect units and terminals in a
 * valid chain.
 *
 * Some devices have invalid baSourceID references, causing uvc_scan_chain()
 * to fail, but if we just take the entities we can find and put them together
 * in the most sensible chain we can think of, turns out they do work anyway.
 * Note: This heuristic assumes there is a single chain.
 *
 * At the time of writing, devices known to have such a broken chain are
 *  - Acer Integrated Camera (5986:055a)
 *  - Realtek rtl157a7 (0bda:57a7)
 */
static int uvc_scan_fallback(struct uvc_device *dev)
{
	struct uvc_video_chain *chain;
	struct uvc_entity *iterm = NULL;
	struct uvc_entity *oterm = NULL;
	struct uvc_entity *entity;
	struct uvc_entity *prev;

	/*
	 * Start by locating the input and output terminals. We only support
	 * devices with exactly one of each for now.
	 */
	list_for_each_entry(entity, &dev->entities, list) {
		if (UVC_ENTITY_IS_ITERM(entity)) {
			if (iterm)
				return -EINVAL;
			iterm = entity;
		}

		if (UVC_ENTITY_IS_OTERM(entity)) {
			if (oterm)
				return -EINVAL;
			oterm = entity;
		}
	}

	if (iterm == NULL || oterm == NULL)
		return -EINVAL;

	/* Allocate the chain and fill it. */
	chain = uvc_alloc_chain(dev);
	if (chain == NULL)
		return -ENOMEM;

	if (uvc_scan_chain_entity(chain, oterm) < 0)
		goto error;

	prev = oterm;

	/*
	 * Add all Processing and Extension Units with two pads. The order
	 * doesn't matter much, use reverse list traversal to connect units in
	 * UVC descriptor order as we build the chain from output to input. This
	 * leads to units appearing in the order meant by the manufacturer for
	 * the cameras known to require this heuristic.
	 */
	list_for_each_entry_reverse(entity, &dev->entities, list) {
		if (entity->type != UVC_VC_PROCESSING_UNIT &&
		    entity->type != UVC_VC_EXTENSION_UNIT)
			continue;

		if (entity->num_pads != 2)
			continue;

		if (uvc_scan_chain_entity(chain, entity) < 0)
			goto error;

		prev->baSourceID[0] = entity->id;
		prev = entity;
	}

	if (uvc_scan_chain_entity(chain, iterm) < 0)
		goto error;

	prev->baSourceID[0] = iterm->id;

	list_add_tail(&chain->list, &dev->chains);

	uvc_trace(UVC_TRACE_PROBE,
		  "Found a video chain by fallback heuristic (%s).\n",
		  uvc_print_chain(chain));

	return 0;

error:
	kfree(chain);
	return -EINVAL;
}

/*
 * Scan the device for video chains and register video devices.
 *
 * Chains are scanned starting at their output terminals and walked backwards.
 */
static int uvc_scan_device(struct uvc_device *dev)
{
	struct uvc_video_chain *chain;
	struct uvc_entity *term;

	list_for_each_entry(term, &dev->entities, list) {
		if (!UVC_ENTITY_IS_OTERM(term))
			continue;

		/* If the terminal is already included in a chain, skip it.
		 * This can happen for chains that have multiple output
		 * terminals, where all output terminals beside the first one
		 * will be inserted in the chain in forward scans.
		 */
		if (term->chain.next || term->chain.prev)
			continue;

		chain = uvc_alloc_chain(dev);
		if (chain == NULL)
			return -ENOMEM;

		term->flags |= UVC_ENTITY_FLAG_DEFAULT;

		if (uvc_scan_chain(chain, term) < 0) {
			kfree(chain);
			continue;
		}

		uvc_trace(UVC_TRACE_PROBE, "Found a valid video chain (%s).\n",
			  uvc_print_chain(chain));

		list_add_tail(&chain->list, &dev->chains);
	}

	if (list_empty(&dev->chains))
		uvc_scan_fallback(dev);

	if (list_empty(&dev->chains)) {
		uvc_printk(KERN_INFO, "No valid video chain found.\n");
		return -1;
	}

	return 0;
}

/* ------------------------------------------------------------------------
 * Video device registration and unregistration
 */

/*
 * Delete the UVC device.
 *
 * Called by the kernel when the last reference to the uvc_device structure
 * is released.
 *
 * As this function is called after or during disconnect(), all URBs have
 * already been cancelled by the USB core. There is no need to kill the
 * interrupt URB manually.
 */
static void uvc_delete(struct kref *kref)
{

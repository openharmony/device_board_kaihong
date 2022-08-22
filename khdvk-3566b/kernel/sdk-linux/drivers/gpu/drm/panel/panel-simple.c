/*
 * Copyright (C) 2013, NVIDIA Corporation.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sub license,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>

#include <video/display_timing.h>
#include <video/mipi_display.h>
#include <video/of_display_timing.h>
#include <video/videomode.h>

#include <drm/drm_crtc.h>
#include <drm/drm_device.h>
#include <drm/drm_mipi_dsi.h>
#include <drm/drm_panel.h>
#include <drm/drm_dsc.h>

#include "panel-simple.h"

struct panel_cmd_header {
	u8 data_type;
	u8 delay;
	u8 payload_length;
} __packed;

struct panel_cmd_desc {
	struct panel_cmd_header header;
	u8 *payload;
};

struct panel_cmd_seq {
	struct panel_cmd_desc *cmds;
	unsigned int cmd_cnt;
};

/**
 * @modes: Pointer to array of fixed modes appropriate for this panel.  If
 *         only one mode then this can just be the address of this the mode.
 *         NOTE: cannot be used with "timings" and also if this is specified
 *         then you cannot override the mode in the device tree.
 * @num_modes: Number of elements in modes array.
 * @timings: Pointer to array of display timings.  NOTE: cannot be used with
 *           "modes" and also these will be used to validate a device tree
 *           override if one is present.
 * @num_timings: Number of elements in timings array.
 * @bpc: Bits per color.
 * @size: Structure containing the physical size of this panel.
 * @delay: Structure containing various delay values for this panel.
 * @bus_format: See MEDIA_BUS_FMT_... defines.
 * @bus_flags: See DRM_BUS_FLAG_... defines.
 */
struct panel_desc {
	const struct drm_display_mode *modes;
	unsigned int num_modes;
	const struct display_timing *timings;
	unsigned int num_timings;

	unsigned int bpc;

	/**
	 * @width: width (in millimeters) of the panel's active display area
	 * @height: height (in millimeters) of the panel's active display area
	 */
	struct {
		unsigned int width;
		unsigned int height;
	} size;

	/**
	 * @prepare: the time (in milliseconds) that it takes for the panel to
	 *           become ready and start receiving video data
	 * @hpd_absent_delay: Add this to the prepare delay if we know Hot
	 *                    Plug Detect isn't used.
	 * @enable: the time (in milliseconds) that it takes for the panel to
	 *          display the first valid frame after starting to receive
	 *          video data
	 * @disable: the time (in milliseconds) that it takes for the panel to
	 *           turn the display off (no content is visible)
	 * @unprepare: the time (in milliseconds) that it takes for the panel
	 *             to power itself down completely
	 * @reset: the time (in milliseconds) that it takes for the panel
	 *         to reset itself completely
	 * @init: the time (in milliseconds) that it takes for the panel to
	 *	  send init command sequence after reset deassert
	 */
	struct {
		unsigned int prepare;
		unsigned int hpd_absent_delay;
		unsigned int enable;
		unsigned int disable;
		unsigned int unprepare;
		unsigned int reset;
		unsigned int init;
	} delay;

	u32 bus_format;
	u32 bus_flags;
	int connector_type;

	struct panel_cmd_seq *init_seq;
	struct panel_cmd_seq *exit_seq;
};

struct panel_simple {
	struct drm_panel base;
	struct mipi_dsi_device *dsi;
	bool prepared;
	bool enabled;
	bool power_invert;
	bool no_hpd;

	const struct panel_desc *desc;

	struct regulator *supply;
	struct i2c_adapter *ddc;

	struct gpio_desc *enable_gpio;
	struct gpio_desc *reset_gpio;
	struct gpio_desc *hpd_gpio;

	struct drm_display_mode override_mode;

	struct drm_dsc_picture_parameter_set *pps;
	enum drm_panel_orientation orientation;
};

static inline struct panel_simple *to_panel_simple(struct drm_panel *panel)
{
	return container_of(panel, struct panel_simple, base);
}

static int panel_simple_parse_cmd_seq(struct device *dev,
				      const u8 *data, int length,
				      struct panel_cmd_seq *seq)
{
	struct panel_cmd_header *header;
	struct panel_cmd_desc *desc;
	char *buf, *d;
	unsigned int i, cnt, len;

	if (!seq)
		return -EINVAL;

	buf = devm_kmemdup(dev, data, length, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	d = buf;
	len = length;
	cnt = 0;
	while (len > sizeof(*header)) {
		header = (struct panel_cmd_header *)d;

		d += sizeof(*header);
		len -= sizeof(*header);

		if (header->payload_length > len)
			return -EINVAL;

		d += header->payload_length;
		len -= header->payload_length;
		cnt++;
	}

	if (len)
		return -EINVAL;

	seq->cmd_cnt = cnt;
	seq->cmds = devm_kcalloc(dev, cnt, sizeof(*desc), GFP_KERNEL);
	if (!seq->cmds)
		return -ENOMEM;

	d = buf;
	len = length;

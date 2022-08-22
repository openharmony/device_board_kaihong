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
	for (i = 0; i < cnt; i++) {
		header = (struct panel_cmd_header *)d;
		len -= sizeof(*header);
		d += sizeof(*header);

		desc = &seq->cmds[i];
		desc->header = *header;
		desc->payload = d;

		d += header->payload_length;
		len -= header->payload_length;
	}

	return 0;
}

static int panel_simple_xfer_dsi_cmd_seq(struct panel_simple *panel,
					 struct panel_cmd_seq *seq)
{
	struct device *dev = panel->base.dev;
	struct mipi_dsi_device *dsi = panel->dsi;
	unsigned int i;
	int err;

	if (!IS_ENABLED(CONFIG_DRM_MIPI_DSI))
		return -EINVAL;
	if (!seq)
		return -EINVAL;

	for (i = 0; i < seq->cmd_cnt; i++) {
		struct panel_cmd_desc *cmd = &seq->cmds[i];

		switch (cmd->header.data_type) {
		case MIPI_DSI_COMPRESSION_MODE:
			err = mipi_dsi_compression_mode(dsi, cmd->payload[0]);
			break;
		case MIPI_DSI_GENERIC_SHORT_WRITE_0_PARAM:
		case MIPI_DSI_GENERIC_SHORT_WRITE_1_PARAM:
		case MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM:
		case MIPI_DSI_GENERIC_LONG_WRITE:
			err = mipi_dsi_generic_write(dsi, cmd->payload,
						     cmd->header.payload_length);
			break;
		case MIPI_DSI_DCS_SHORT_WRITE:
		case MIPI_DSI_DCS_SHORT_WRITE_PARAM:
		case MIPI_DSI_DCS_LONG_WRITE:
			err = mipi_dsi_dcs_write_buffer(dsi, cmd->payload,
							cmd->header.payload_length);
			break;
		case MIPI_DSI_PICTURE_PARAMETER_SET:
			if (!panel->pps) {
				panel->pps = devm_kzalloc(dev, sizeof(*panel->pps),
							  GFP_KERNEL);
				if (!panel->pps)
					return -ENOMEM;

				memcpy(panel->pps, cmd->payload, cmd->header.payload_length);
			}

			err = mipi_dsi_picture_parameter_set(dsi, panel->pps);
			break;
		default:
			return -EINVAL;
		}

		if (err < 0)
			dev_err(dev, "failed to write dcs cmd: %d\n", err);

		if (cmd->header.delay)
			msleep(cmd->header.delay);
	}

	return 0;
}

static unsigned int panel_simple_get_timings_modes(struct panel_simple *panel,
						   struct drm_connector *connector)
{
	struct drm_display_mode *mode;
	unsigned int i, num = 0;

	for (i = 0; i < panel->desc->num_timings; i++) {
		const struct display_timing *dt = &panel->desc->timings[i];
		struct videomode vm;

		videomode_from_timing(dt, &vm);
		mode = drm_mode_create(connector->dev);
		if (!mode) {
			dev_err(panel->base.dev, "failed to add mode %ux%u\n",
				dt->hactive.typ, dt->vactive.typ);
			continue;
		}

		drm_display_mode_from_videomode(&vm, mode);

		mode->type |= DRM_MODE_TYPE_DRIVER;

		if (panel->desc->num_timings == 1)
			mode->type |= DRM_MODE_TYPE_PREFERRED;

		drm_mode_probed_add(connector, mode);
		num++;
	}

	return num;
}

static unsigned int panel_simple_get_display_modes(struct panel_simple *panel,
						   struct drm_connector *connector)
{
	struct drm_display_mode *mode;
	unsigned int i, num = 0;

	for (i = 0; i < panel->desc->num_modes; i++) {
		const struct drm_display_mode *m = &panel->desc->modes[i];

		mode = drm_mode_duplicate(connector->dev, m);
		if (!mode) {
			dev_err(panel->base.dev, "failed to add mode %ux%u@%u\n",
				m->hdisplay, m->vdisplay,
				drm_mode_vrefresh(m));
			continue;
		}

		mode->type |= DRM_MODE_TYPE_DRIVER;

		if (panel->desc->num_modes == 1)
			mode->type |= DRM_MODE_TYPE_PREFERRED;

		drm_mode_set_name(mode);

		drm_mode_probed_add(connector, mode);
		num++;
	}

	return num;
}

static int panel_simple_get_non_edid_modes(struct panel_simple *panel,
					   struct drm_connector *connector)
{
	struct drm_display_mode *mode;
	bool has_override = panel->override_mode.type;
	unsigned int num = 0;

	if (!panel->desc)
		return 0;

	if (has_override) {
		mode = drm_mode_duplicate(connector->dev,
					  &panel->override_mode);
		if (mode) {
			drm_mode_probed_add(connector, mode);
			num = 1;
		} else {
			dev_err(panel->base.dev, "failed to add override mode\n");
		}
	}

	/* Only add timings if override was not there or failed to validate */
	if (num == 0 && panel->desc->num_timings)
		num = panel_simple_get_timings_modes(panel, connector);

	/*
	 * Only add fixed modes if timings/override added no mode.
	 *
	 * We should only ever have either the display timings specified
	 * or a fixed mode. Anything else is rather bogus.
	 */
	WARN_ON(panel->desc->num_timings && panel->desc->num_modes);
	if (num == 0)
		num = panel_simple_get_display_modes(panel, connector);

	if (panel->desc->bpc)
		connector->display_info.bpc = panel->desc->bpc;
	if (panel->desc->size.width)
		connector->display_info.width_mm = panel->desc->size.width;
	if (panel->desc->size.height)
		connector->display_info.height_mm = panel->desc->size.height;
	if (panel->desc->bus_format)
		drm_display_info_set_bus_formats(&connector->display_info,
						 &panel->desc->bus_format, 1);
	if (panel->desc->bus_flags)
		connector->display_info.bus_flags = panel->desc->bus_flags;

	return num;
}

static int panel_simple_regulator_enable(struct panel_simple *p)
{
	int err;

	if (p->power_invert) {
		if (regulator_is_enabled(p->supply) > 0)
			regulator_disable(p->supply);
	} else {
		err = regulator_enable(p->supply);
		if (err < 0)
			return err;
	}

	return 0;
}

static int panel_simple_regulator_disable(struct panel_simple *p)
{
	int err;

	if (p->power_invert) {
		if (!regulator_is_enabled(p->supply)) {
			err = regulator_enable(p->supply);
			if (err < 0)
				return err;
		}
	} else {
		regulator_disable(p->supply);
	}

	return 0;
}

int panel_simple_loader_protect(struct drm_panel *panel)
{
	struct panel_simple *p = to_panel_simple(panel);
	int err;

	err = panel_simple_regulator_enable(p);
	if (err < 0) {
		dev_err(panel->dev, "failed to enable supply: %d\n", err);
		return err;
	}

	p->prepared = true;
	p->enabled = true;

	return 0;
}
EXPORT_SYMBOL(panel_simple_loader_protect);

static int panel_simple_disable(struct drm_panel *panel)
{
	struct panel_simple *p = to_panel_simple(panel);

	if (!p->enabled)
		return 0;

	if (p->desc->delay.disable)
		msleep(p->desc->delay.disable);

	p->enabled = false;

	return 0;
}

static int panel_simple_unprepare(struct drm_panel *panel)
{
	struct panel_simple *p = to_panel_simple(panel);

	if (!p->prepared)
		return 0;

	if (p->desc->exit_seq)
		if (p->dsi)
			panel_simple_xfer_dsi_cmd_seq(p, p->desc->exit_seq);

	gpiod_direction_output(p->reset_gpio, 1);
	gpiod_direction_output(p->enable_gpio, 0);

	panel_simple_regulator_disable(p);

	if (p->desc->delay.unprepare)
		msleep(p->desc->delay.unprepare);

	p->prepared = false;

	return 0;
}

static int panel_simple_get_hpd_gpio(struct device *dev,
				     struct panel_simple *p, bool from_probe)
{
	int err;

	p->hpd_gpio = devm_gpiod_get_optional(dev, "hpd", GPIOD_IN);
	if (IS_ERR(p->hpd_gpio)) {
		err = PTR_ERR(p->hpd_gpio);

		/*
		 * If we're called from probe we won't consider '-EPROBE_DEFER'
		 * to be an error--we'll leave the error code in "hpd_gpio".
		 * When we try to use it we'll try again.  This allows for
		 * circular dependencies where the component providing the
		 * hpd gpio needs the panel to init before probing.
		 */
		if (err != -EPROBE_DEFER || !from_probe) {
			dev_err(dev, "failed to get 'hpd' GPIO: %d\n", err);
			return err;
		}
	}

	return 0;
}

static int panel_simple_prepare(struct drm_panel *panel)
{
	struct panel_simple *p = to_panel_simple(panel);
	unsigned int delay;
	int err;
	int hpd_asserted;

	if (p->prepared)
		return 0;

	err = panel_simple_regulator_enable(p);
	if (err < 0) {
		dev_err(panel->dev, "failed to enable supply: %d\n", err);
		return err;
	}

	gpiod_direction_output(p->enable_gpio, 1);

	if (p->desc->delay.reset)
		msleep(p->desc->delay.prepare);

	gpiod_direction_output(p->reset_gpio, 1);

	if (p->desc->delay.reset)
		msleep(p->desc->delay.reset);

	gpiod_direction_output(p->reset_gpio, 0);

	delay = p->desc->delay.prepare;
	if (p->no_hpd)
		delay += p->desc->delay.hpd_absent_delay;
	if (delay)
		msleep(delay);

	if (p->hpd_gpio) {
		if (IS_ERR(p->hpd_gpio)) {
			err = panel_simple_get_hpd_gpio(panel->dev, p, false);
			if (err)
				return err;
		}

		err = readx_poll_timeout(gpiod_get_value_cansleep, p->hpd_gpio,
					 hpd_asserted, hpd_asserted,
					 1000, 2000000);
		if (hpd_asserted < 0)
			err = hpd_asserted;

		if (err) {
			dev_err(panel->dev,
				"error waiting for hpd GPIO: %d\n", err);
			return err;
		}
	}

	if (p->desc->init_seq)
		if (p->dsi)
			panel_simple_xfer_dsi_cmd_seq(p, p->desc->init_seq);

	if (p->desc->delay.init)
		msleep(p->desc->delay.init);

	p->prepared = true;

	return 0;
}

static int panel_simple_enable(struct drm_panel *panel)
{
	struct panel_simple *p = to_panel_simple(panel);

	if (p->enabled)
		return 0;

	if (p->desc->delay.enable)
		msleep(p->desc->delay.enable);

	p->enabled = true;

	return 0;
}

static int panel_simple_get_modes(struct drm_panel *panel,
				  struct drm_connector *connector)
{
	struct panel_simple *p = to_panel_simple(panel);
	int num = 0;

	/* probe EDID if a DDC bus is available */
	if (p->ddc) {
		struct edid *edid = drm_get_edid(connector, p->ddc);

		drm_connector_update_edid_property(connector, edid);
		if (edid) {
			num += drm_add_edid_modes(connector, edid);
			kfree(edid);
		}
	}

	/* add hard-coded panel modes */
	num += panel_simple_get_non_edid_modes(p, connector);

	/* set up connector's "panel orientation" property */
	drm_connector_set_panel_orientation(connector, p->orientation);

	return num;
}

static int panel_simple_get_timings(struct drm_panel *panel,
				    unsigned int num_timings,
				    struct display_timing *timings)
{
	struct panel_simple *p = to_panel_simple(panel);
	unsigned int i;

	if (p->desc->num_timings < num_timings)
		num_timings = p->desc->num_timings;

	if (timings)
		for (i = 0; i < num_timings; i++)
			timings[i] = p->desc->timings[i];

	return p->desc->num_timings;
}

static const struct drm_panel_funcs panel_simple_funcs = {
	.disable = panel_simple_disable,
	.unprepare = panel_simple_unprepare,
	.prepare = panel_simple_prepare,
	.enable = panel_simple_enable,
	.get_modes = panel_simple_get_modes,
	.get_timings = panel_simple_get_timings,
};

static struct panel_desc panel_dpi;

static int panel_dpi_probe(struct device *dev,
			   struct panel_simple *panel)
{
	struct display_timing *timing;
	const struct device_node *np;
	struct panel_desc *desc;
	unsigned int bus_flags;
	struct videomode vm;
	int ret;

	np = dev->of_node;
	desc = devm_kzalloc(dev, sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	timing = devm_kzalloc(dev, sizeof(*timing), GFP_KERNEL);
	if (!timing)
		return -ENOMEM;

	ret = of_get_display_timing(np, "panel-timing", timing);
	if (ret < 0) {
		dev_err(dev, "%pOF: no panel-timing node found for \"panel-dpi\" binding\n",
			np);
		return ret;
	}

	desc->timings = timing;
	desc->num_timings = 1;

	of_property_read_u32(np, "width-mm", &desc->size.width);
	of_property_read_u32(np, "height-mm", &desc->size.height);

	/* Extract bus_flags from display_timing */
	bus_flags = 0;
	vm.flags = timing->flags;
	drm_bus_flags_from_videomode(&vm, &bus_flags);
	desc->bus_flags = bus_flags;

	/* We do not know the connector for the DT node, so guess it */
	desc->connector_type = DRM_MODE_CONNECTOR_DPI;

	panel->desc = desc;

	return 0;
}

#define PANEL_SIMPLE_BOUNDS_CHECK(to_check, bounds, field) \
	(to_check->field.typ >= bounds->field.min && \
	 to_check->field.typ <= bounds->field.max)
static void panel_simple_parse_panel_timing_node(struct device *dev,
						 struct panel_simple *panel,
						 const struct display_timing *ot)
{
	const struct panel_desc *desc = panel->desc;
	struct videomode vm;
	unsigned int i;

	if (WARN_ON(desc->num_modes)) {
		dev_err(dev, "Reject override mode: panel has a fixed mode\n");
		return;
	}
	if (WARN_ON(!desc->num_timings)) {
		dev_err(dev, "Reject override mode: no timings specified\n");
		return;
	}

	for (i = 0; i < panel->desc->num_timings; i++) {
		const struct display_timing *dt = &panel->desc->timings[i];

		if (!PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, hactive) ||
		    !PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, hfront_porch) ||
		    !PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, hback_porch) ||
		    !PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, hsync_len) ||
		    !PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, vactive) ||
		    !PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, vfront_porch) ||
		    !PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, vback_porch) ||
		    !PANEL_SIMPLE_BOUNDS_CHECK(ot, dt, vsync_len))
			continue;

		if (ot->flags != dt->flags)
			continue;

		videomode_from_timing(ot, &vm);
		drm_display_mode_from_videomode(&vm, &panel->override_mode);
		panel->override_mode.type |= DRM_MODE_TYPE_DRIVER |
					     DRM_MODE_TYPE_PREFERRED;
		break;
	}

	if (WARN_ON(!panel->override_mode.type))
		dev_err(dev, "Reject override mode: No display_timing found\n");
}

static int dcs_bl_update_status(struct backlight_device *bl)
{
	struct panel_simple *p = bl_get_data(bl);
	struct mipi_dsi_device *dsi = p->dsi;
	int ret;

	if (!p->prepared)
		return 0;

	dsi->mode_flags &= ~MIPI_DSI_MODE_LPM;

	ret = mipi_dsi_dcs_set_display_brightness(dsi, bl->props.brightness);
	if (ret < 0)
		return ret;

	dsi->mode_flags |= MIPI_DSI_MODE_LPM;

	return 0;
}

static int dcs_bl_get_brightness(struct backlight_device *bl)
{
	struct panel_simple *p = bl_get_data(bl);
	struct mipi_dsi_device *dsi = p->dsi;
	u16 brightness = bl->props.brightness;
	int ret;

	if (!p->prepared)
		return 0;

	dsi->mode_flags &= ~MIPI_DSI_MODE_LPM;

	ret = mipi_dsi_dcs_get_display_brightness(dsi, &brightness);
	if (ret < 0)
		return ret;

	dsi->mode_flags |= MIPI_DSI_MODE_LPM;

	return brightness & 0xff;
}

static const struct backlight_ops dcs_bl_ops = {
	.update_status = dcs_bl_update_status,
	.get_brightness = dcs_bl_get_brightness,
};

static int panel_simple_probe(struct device *dev, const struct panel_desc *desc)
{
	struct panel_simple *panel;
	struct display_timing dt;
	struct device_node *ddc;
	int connector_type;
	u32 bus_flags;
	int err;

	panel = devm_kzalloc(dev, sizeof(*panel), GFP_KERNEL);
	if (!panel)
		return -ENOMEM;

	panel->enabled = false;
	panel->prepared = false;
	panel->desc = desc;

	panel->no_hpd = of_property_read_bool(dev->of_node, "no-hpd");
	if (!panel->no_hpd) {
		err = panel_simple_get_hpd_gpio(dev, panel, true);
		if (err)
			return err;
	}

	panel->supply = devm_regulator_get(dev, "power");
	if (IS_ERR(panel->supply))
		return PTR_ERR(panel->supply);

	panel->enable_gpio = devm_gpiod_get_optional(dev, "enable", GPIOD_ASIS);
	if (IS_ERR(panel->enable_gpio)) {
		err = PTR_ERR(panel->enable_gpio);
		if (err != -EPROBE_DEFER)
			dev_err(dev, "failed to get enable GPIO: %d\n", err);
		return err;
	}

	panel->reset_gpio = devm_gpiod_get_optional(dev, "reset", GPIOD_ASIS);
	if (IS_ERR(panel->reset_gpio)) {
		err = PTR_ERR(panel->reset_gpio);
		if (err != -EPROBE_DEFER)
			dev_err(dev, "failed to get reset GPIO: %d\n", err);
		return err;
	}

	err = of_drm_get_panel_orientation(dev->of_node, &panel->orientation);
	if (err) {
		dev_err(dev, "%pOF: failed to get orientation %d\n", dev->of_node, err);
		return err;
	}

	panel->power_invert = of_property_read_bool(dev->of_node, "power-invert");

	ddc = of_parse_phandle(dev->of_node, "ddc-i2c-bus", 0);
	if (ddc) {
		panel->ddc = of_find_i2c_adapter_by_node(ddc);
		of_node_put(ddc);

		if (!panel->ddc)
			return -EPROBE_DEFER;
	}

	if (desc == &panel_dpi) {
		/* Handle the generic panel-dpi binding */
		err = panel_dpi_probe(dev, panel);
		if (err)
			goto free_ddc;
	} else {
		if (!of_get_display_timing(dev->of_node, "panel-timing", &dt))
			panel_simple_parse_panel_timing_node(dev, panel, &dt);
	}

	connector_type = desc->connector_type;
	/* Catch common mistakes for panels. */
	switch (connector_type) {
	case 0:
		dev_dbg(dev, "Specify missing connector_type\n");
		connector_type = DRM_MODE_CONNECTOR_DPI;
		break;
	case DRM_MODE_CONNECTOR_LVDS:
		WARN_ON(desc->bus_flags &
			~(DRM_BUS_FLAG_DE_LOW |
			  DRM_BUS_FLAG_DE_HIGH |
			  DRM_BUS_FLAG_DATA_MSB_TO_LSB |
			  DRM_BUS_FLAG_DATA_LSB_TO_MSB));
		WARN_ON(desc->bus_format != MEDIA_BUS_FMT_RGB666_1X7X3_SPWG &&
			desc->bus_format != MEDIA_BUS_FMT_RGB888_1X7X4_SPWG &&
			desc->bus_format != MEDIA_BUS_FMT_RGB888_1X7X4_JEIDA);
		WARN_ON(desc->bus_format == MEDIA_BUS_FMT_RGB666_1X7X3_SPWG &&
			desc->bpc != 6);
		WARN_ON((desc->bus_format == MEDIA_BUS_FMT_RGB888_1X7X4_SPWG ||
			 desc->bus_format == MEDIA_BUS_FMT_RGB888_1X7X4_JEIDA) &&
			desc->bpc != 8);
		break;
	case DRM_MODE_CONNECTOR_eDP:
		if (desc->bus_format == 0)
			dev_warn(dev, "Specify missing bus_format\n");
		if (desc->bpc != 6 && desc->bpc != 8)
			dev_warn(dev, "Expected bpc in {6,8} but got: %u\n", desc->bpc);
		break;
	case DRM_MODE_CONNECTOR_DSI:
		if (desc->bpc != 6 && desc->bpc != 8)
			dev_warn(dev, "Expected bpc in {6,8} but got: %u\n", desc->bpc);
		break;
	case DRM_MODE_CONNECTOR_DPI:
		bus_flags = DRM_BUS_FLAG_DE_LOW |
			    DRM_BUS_FLAG_DE_HIGH |
			    DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE |
			    DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE |
			    DRM_BUS_FLAG_DATA_MSB_TO_LSB |
			    DRM_BUS_FLAG_DATA_LSB_TO_MSB |
			    DRM_BUS_FLAG_SYNC_SAMPLE_POSEDGE |
			    DRM_BUS_FLAG_SYNC_SAMPLE_NEGEDGE;
		if (desc->bus_flags & ~bus_flags)
			dev_warn(dev, "Unexpected bus_flags(%d)\n", desc->bus_flags & ~bus_flags);
		if (!(desc->bus_flags & bus_flags))
			dev_warn(dev, "Specify missing bus_flags\n");
		if (desc->bus_format == 0)
			dev_warn(dev, "Specify missing bus_format\n");
		if (desc->bpc != 6 && desc->bpc != 8)
			dev_warn(dev, "Expected bpc in {6,8} but got: %u\n", desc->bpc);
		break;
	default:
		dev_warn(dev, "Specify a valid connector_type: %d\n", desc->connector_type);
		connector_type = DRM_MODE_CONNECTOR_DPI;
		break;
	}

	drm_panel_init(&panel->base, dev, &panel_simple_funcs, connector_type);

	err = drm_panel_of_backlight(&panel->base);
	if (err)
		goto free_ddc;

	drm_panel_add(&panel->base);

	dev_set_drvdata(dev, panel);

	return 0;

free_ddc:
	if (panel->ddc)
		put_device(&panel->ddc->dev);

	return err;
}

static int panel_simple_remove(struct device *dev)
{
	struct panel_simple *panel = dev_get_drvdata(dev);

	drm_panel_remove(&panel->base);
	drm_panel_disable(&panel->base);
	drm_panel_unprepare(&panel->base);

	if (panel->ddc)
		put_device(&panel->ddc->dev);

	return 0;
}

static void panel_simple_shutdown(struct device *dev)
{
	struct panel_simple *panel = dev_get_drvdata(dev);

	drm_panel_disable(&panel->base);
	drm_panel_unprepare(&panel->base);
}

static const struct drm_display_mode ampire_am_1280800n3tzqw_t00h_mode = {
	.clock = 71100,
	.hdisplay = 1280,
	.hsync_start = 1280 + 40,
	.hsync_end = 1280 + 40 + 80,
	.htotal = 1280 + 40 + 80 + 40,
	.vdisplay = 800,
	.vsync_start = 800 + 3,
	.vsync_end = 800 + 3 + 10,
	.vtotal = 800 + 3 + 10 + 10,
	.flags = DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC,
};

static const struct panel_desc ampire_am_1280800n3tzqw_t00h = {
	.modes = &ampire_am_1280800n3tzqw_t00h_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 217,
		.height = 136,
	},
	.bus_flags = DRM_BUS_FLAG_DE_HIGH,
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode ampire_am_480272h3tmqw_t01h_mode = {
	.clock = 9000,
	.hdisplay = 480,
	.hsync_start = 480 + 2,
	.hsync_end = 480 + 2 + 41,
	.htotal = 480 + 2 + 41 + 2,
	.vdisplay = 272,
	.vsync_start = 272 + 2,
	.vsync_end = 272 + 2 + 10,
	.vtotal = 272 + 2 + 10 + 2,
	.flags = DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC,
};

static const struct panel_desc ampire_am_480272h3tmqw_t01h = {
	.modes = &ampire_am_480272h3tmqw_t01h_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 105,
		.height = 67,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X24,
};

static const struct drm_display_mode ampire_am800480r3tmqwa1h_mode = {
	.clock = 33333,
	.hdisplay = 800,
	.hsync_start = 800 + 0,
	.hsync_end = 800 + 0 + 255,
	.htotal = 800 + 0 + 255 + 0,
	.vdisplay = 480,
	.vsync_start = 480 + 2,
	.vsync_end = 480 + 2 + 45,
	.vtotal = 480 + 2 + 45 + 0,
	.flags = DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC,
};

static const struct panel_desc ampire_am800480r3tmqwa1h = {
	.modes = &ampire_am800480r3tmqwa1h_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 152,
		.height = 91,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
};

static const struct display_timing santek_st0700i5y_rbslw_f_timing = {
	.pixelclock = { 26400000, 33300000, 46800000 },
	.hactive = { 800, 800, 800 },
	.hfront_porch = { 16, 210, 354 },
	.hback_porch = { 45, 36, 6 },
	.hsync_len = { 1, 10, 40 },
	.vactive = { 480, 480, 480 },
	.vfront_porch = { 7, 22, 147 },
	.vback_porch = { 22, 13, 3 },
	.vsync_len = { 1, 10, 20 },
	.flags = DISPLAY_FLAGS_HSYNC_LOW | DISPLAY_FLAGS_VSYNC_LOW |
		DISPLAY_FLAGS_DE_HIGH | DISPLAY_FLAGS_PIXDATA_POSEDGE
};

static const struct panel_desc armadeus_st0700_adapt = {
	.timings = &santek_st0700i5y_rbslw_f_timing,
	.num_timings = 1,
	.bpc = 6,
	.size = {
		.width = 154,
		.height = 86,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE,
};

static const struct drm_display_mode auo_b101aw03_mode = {
	.clock = 51450,
	.hdisplay = 1024,
	.hsync_start = 1024 + 156,
	.hsync_end = 1024 + 156 + 8,
	.htotal = 1024 + 156 + 8 + 156,
	.vdisplay = 600,
	.vsync_start = 600 + 16,
	.vsync_end = 600 + 16 + 6,
	.vtotal = 600 + 16 + 6 + 16,
};

static const struct panel_desc auo_b101aw03 = {
	.modes = &auo_b101aw03_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 223,
		.height = 125,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X7X3_SPWG,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct display_timing auo_b101ean01_timing = {
	.pixelclock = { 65300000, 72500000, 75000000 },
	.hactive = { 1280, 1280, 1280 },
	.hfront_porch = { 18, 119, 119 },
	.hback_porch = { 21, 21, 21 },
	.hsync_len = { 32, 32, 32 },
	.vactive = { 800, 800, 800 },
	.vfront_porch = { 4, 4, 4 },
	.vback_porch = { 8, 8, 8 },
	.vsync_len = { 18, 20, 20 },
};

static const struct panel_desc auo_b101ean01 = {
	.timings = &auo_b101ean01_timing,
	.num_timings = 1,
	.bpc = 6,
	.size = {
		.width = 217,
		.height = 136,
	},
};

static const struct drm_display_mode auo_b101xtn01_mode = {
	.clock = 72000,
	.hdisplay = 1366,
	.hsync_start = 1366 + 20,
	.hsync_end = 1366 + 20 + 70,
	.htotal = 1366 + 20 + 70,
	.vdisplay = 768,
	.vsync_start = 768 + 14,
	.vsync_end = 768 + 14 + 42,
	.vtotal = 768 + 14 + 42,
	.flags = DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static const struct panel_desc auo_b101xtn01 = {
	.modes = &auo_b101xtn01_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 223,
		.height = 125,
	},
};

static const struct drm_display_mode auo_b116xak01_mode = {
	.clock = 69300,
	.hdisplay = 1366,
	.hsync_start = 1366 + 48,
	.hsync_end = 1366 + 48 + 32,
	.htotal = 1366 + 48 + 32 + 10,
	.vdisplay = 768,
	.vsync_start = 768 + 4,
	.vsync_end = 768 + 4 + 6,
	.vtotal = 768 + 4 + 6 + 15,
	.flags = DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static const struct panel_desc auo_b116xak01 = {
	.modes = &auo_b116xak01_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 256,
		.height = 144,
	},
	.delay = {
		.hpd_absent_delay = 200,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.connector_type = DRM_MODE_CONNECTOR_eDP,
};

static const struct drm_display_mode auo_b116xw03_mode = {
	.clock = 70589,
	.hdisplay = 1366,
	.hsync_start = 1366 + 40,
	.hsync_end = 1366 + 40 + 40,
	.htotal = 1366 + 40 + 40 + 32,
	.vdisplay = 768,
	.vsync_start = 768 + 10,
	.vsync_end = 768 + 10 + 12,
	.vtotal = 768 + 10 + 12 + 6,
	.flags = DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static const struct panel_desc auo_b116xw03 = {
	.modes = &auo_b116xw03_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 256,
		.height = 144,
	},
	.delay = {
		.enable = 400,
	},
	.bus_flags = DRM_BUS_FLAG_SYNC_DRIVE_NEGEDGE,
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.connector_type = DRM_MODE_CONNECTOR_eDP,
};

static const struct drm_display_mode auo_b133xtn01_mode = {
	.clock = 69500,
	.hdisplay = 1366,
	.hsync_start = 1366 + 48,
	.hsync_end = 1366 + 48 + 32,
	.htotal = 1366 + 48 + 32 + 20,
	.vdisplay = 768,
	.vsync_start = 768 + 3,
	.vsync_end = 768 + 3 + 6,
	.vtotal = 768 + 3 + 6 + 13,
};

static const struct panel_desc auo_b133xtn01 = {
	.modes = &auo_b133xtn01_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 293,
		.height = 165,
	},
};

static const struct drm_display_mode auo_b133htn01_mode = {
	.clock = 150660,
	.hdisplay = 1920,
	.hsync_start = 1920 + 172,
	.hsync_end = 1920 + 172 + 80,
	.htotal = 1920 + 172 + 80 + 60,
	.vdisplay = 1080,
	.vsync_start = 1080 + 25,
	.vsync_end = 1080 + 25 + 10,
	.vtotal = 1080 + 25 + 10 + 10,
};

static const struct panel_desc auo_b133htn01 = {
	.modes = &auo_b133htn01_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 293,
		.height = 165,
	},
	.delay = {
		.prepare = 105,
		.enable = 20,
		.unprepare = 50,
	},
};

static const struct display_timing auo_g070vvn01_timings = {
	.pixelclock = { 33300000, 34209000, 45000000 },
	.hactive = { 800, 800, 800 },
	.hfront_porch = { 20, 40, 200 },
	.hback_porch = { 87, 40, 1 },
	.hsync_len = { 1, 48, 87 },
	.vactive = { 480, 480, 480 },
	.vfront_porch = { 5, 13, 200 },
	.vback_porch = { 31, 31, 29 },
	.vsync_len = { 1, 1, 3 },
};

static const struct panel_desc auo_g070vvn01 = {
	.timings = &auo_g070vvn01_timings,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 152,
		.height = 91,
	},
	.delay = {
		.prepare = 200,
		.enable = 50,
		.disable = 50,
		.unprepare = 1000,
	},
};

static const struct drm_display_mode auo_g101evn010_mode = {
	.clock = 68930,
	.hdisplay = 1280,
	.hsync_start = 1280 + 82,
	.hsync_end = 1280 + 82 + 2,
	.htotal = 1280 + 82 + 2 + 84,
	.vdisplay = 800,
	.vsync_start = 800 + 8,
	.vsync_end = 800 + 8 + 2,
	.vtotal = 800 + 8 + 2 + 6,
};

static const struct panel_desc auo_g101evn010 = {
	.modes = &auo_g101evn010_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 216,
		.height = 135,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X7X3_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode auo_g104sn02_mode = {
	.clock = 40000,
	.hdisplay = 800,
	.hsync_start = 800 + 40,
	.hsync_end = 800 + 40 + 216,
	.htotal = 800 + 40 + 216 + 128,
	.vdisplay = 600,
	.vsync_start = 600 + 10,
	.vsync_end = 600 + 10 + 35,
	.vtotal = 600 + 10 + 35 + 2,
};

static const struct panel_desc auo_g104sn02 = {
	.modes = &auo_g104sn02_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 211,
		.height = 158,
	},
};

static const struct drm_display_mode auo_g121ean01_mode = {
	.clock = 66700,
	.hdisplay = 1280,
	.hsync_start = 1280 + 58,
	.hsync_end = 1280 + 58 + 8,
	.htotal = 1280 + 58 + 8 + 70,
	.vdisplay = 800,
	.vsync_start = 800 + 6,
	.vsync_end = 800 + 6 + 4,
	.vtotal = 800 + 6 + 4 + 10,
};

static const struct panel_desc auo_g121ean01 = {
	.modes = &auo_g121ean01_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 261,
		.height = 163,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct display_timing auo_g133han01_timings = {
	.pixelclock = { 134000000, 141200000, 149000000 },
	.hactive = { 1920, 1920, 1920 },
	.hfront_porch = { 39, 58, 77 },
	.hback_porch = { 59, 88, 117 },
	.hsync_len = { 28, 42, 56 },
	.vactive = { 1080, 1080, 1080 },
	.vfront_porch = { 3, 8, 11 },
	.vback_porch = { 5, 14, 19 },
	.vsync_len = { 4, 14, 19 },
};

static const struct panel_desc auo_g133han01 = {
	.timings = &auo_g133han01_timings,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 293,
		.height = 165,
	},
	.delay = {
		.prepare = 200,
		.enable = 50,
		.disable = 50,
		.unprepare = 1000,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_JEIDA,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode auo_g156xtn01_mode = {
	.clock = 76000,
	.hdisplay = 1366,
	.hsync_start = 1366 + 33,
	.hsync_end = 1366 + 33 + 67,
	.htotal = 1560,
	.vdisplay = 768,
	.vsync_start = 768 + 4,
	.vsync_end = 768 + 4 + 4,
	.vtotal = 806,
};

static const struct panel_desc auo_g156xtn01 = {
	.modes = &auo_g156xtn01_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 344,
		.height = 194,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct display_timing auo_g185han01_timings = {
	.pixelclock = { 120000000, 144000000, 175000000 },
	.hactive = { 1920, 1920, 1920 },
	.hfront_porch = { 36, 120, 148 },
	.hback_porch = { 24, 88, 108 },
	.hsync_len = { 20, 48, 64 },
	.vactive = { 1080, 1080, 1080 },
	.vfront_porch = { 6, 10, 40 },
	.vback_porch = { 2, 5, 20 },
	.vsync_len = { 2, 5, 20 },
};

static const struct panel_desc auo_g185han01 = {
	.timings = &auo_g185han01_timings,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 409,
		.height = 230,
	},
	.delay = {
		.prepare = 50,
		.enable = 200,
		.disable = 110,
		.unprepare = 1000,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct display_timing auo_g190ean01_timings = {
	.pixelclock = { 90000000, 108000000, 135000000 },
	.hactive = { 1280, 1280, 1280 },
	.hfront_porch = { 126, 184, 1266 },
	.hback_porch = { 84, 122, 844 },
	.hsync_len = { 70, 102, 704 },
	.vactive = { 1024, 1024, 1024 },
	.vfront_porch = { 4, 26, 76 },
	.vback_porch = { 2, 8, 25 },
	.vsync_len = { 2, 8, 25 },
};

static const struct panel_desc auo_g190ean01 = {
	.timings = &auo_g190ean01_timings,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 376,
		.height = 301,
	},
	.delay = {
		.prepare = 50,
		.enable = 200,
		.disable = 110,
		.unprepare = 1000,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct display_timing auo_p320hvn03_timings = {
	.pixelclock = { 106000000, 148500000, 164000000 },
	.hactive = { 1920, 1920, 1920 },
	.hfront_porch = { 25, 50, 130 },
	.hback_porch = { 25, 50, 130 },
	.hsync_len = { 20, 40, 105 },
	.vactive = { 1080, 1080, 1080 },
	.vfront_porch = { 8, 17, 150 },
	.vback_porch = { 8, 17, 150 },
	.vsync_len = { 4, 11, 100 },
};

static const struct panel_desc auo_p320hvn03 = {
	.timings = &auo_p320hvn03_timings,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 698,
		.height = 393,
	},
	.delay = {
		.prepare = 1,
		.enable = 450,
		.unprepare = 500,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode auo_t215hvn01_mode = {
	.clock = 148800,
	.hdisplay = 1920,
	.hsync_start = 1920 + 88,
	.hsync_end = 1920 + 88 + 44,
	.htotal = 1920 + 88 + 44 + 148,
	.vdisplay = 1080,
	.vsync_start = 1080 + 4,
	.vsync_end = 1080 + 4 + 5,
	.vtotal = 1080 + 4 + 5 + 36,
};

static const struct panel_desc auo_t215hvn01 = {
	.modes = &auo_t215hvn01_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 430,
		.height = 270,
	},
	.delay = {
		.disable = 5,
		.unprepare = 1000,
	}
};

static const struct drm_display_mode avic_tm070ddh03_mode = {
	.clock = 51200,
	.hdisplay = 1024,
	.hsync_start = 1024 + 160,
	.hsync_end = 1024 + 160 + 4,
	.htotal = 1024 + 160 + 4 + 156,
	.vdisplay = 600,
	.vsync_start = 600 + 17,
	.vsync_end = 600 + 17 + 1,
	.vtotal = 600 + 17 + 1 + 17,
};

static const struct panel_desc avic_tm070ddh03 = {
	.modes = &avic_tm070ddh03_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 154,
		.height = 90,
	},
	.delay = {
		.prepare = 20,
		.enable = 200,
		.disable = 200,
	},
};

static const struct drm_display_mode bananapi_s070wv20_ct16_mode = {
	.clock = 30000,
	.hdisplay = 800,
	.hsync_start = 800 + 40,
	.hsync_end = 800 + 40 + 48,
	.htotal = 800 + 40 + 48 + 40,
	.vdisplay = 480,
	.vsync_start = 480 + 13,
	.vsync_end = 480 + 13 + 3,
	.vtotal = 480 + 13 + 3 + 29,
};

static const struct panel_desc bananapi_s070wv20_ct16 = {
	.modes = &bananapi_s070wv20_ct16_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 154,
		.height = 86,
	},
};

static const struct drm_display_mode boe_hv070wsa_mode = {
	.clock = 42105,
	.hdisplay = 1024,
	.hsync_start = 1024 + 30,
	.hsync_end = 1024 + 30 + 30,
	.htotal = 1024 + 30 + 30 + 30,
	.vdisplay = 600,
	.vsync_start = 600 + 10,
	.vsync_end = 600 + 10 + 10,
	.vtotal = 600 + 10 + 10 + 10,
};

static const struct panel_desc boe_hv070wsa = {
	.modes = &boe_hv070wsa_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 154,
		.height = 90,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode boe_nv101wxmn51_modes[] = {
	{
		.clock = 71900,
		.hdisplay = 1280,
		.hsync_start = 1280 + 48,
		.hsync_end = 1280 + 48 + 32,
		.htotal = 1280 + 48 + 32 + 80,
		.vdisplay = 800,
		.vsync_start = 800 + 3,
		.vsync_end = 800 + 3 + 5,
		.vtotal = 800 + 3 + 5 + 24,
	},
	{
		.clock = 57500,
		.hdisplay = 1280,
		.hsync_start = 1280 + 48,
		.hsync_end = 1280 + 48 + 32,
		.htotal = 1280 + 48 + 32 + 80,
		.vdisplay = 800,
		.vsync_start = 800 + 3,
		.vsync_end = 800 + 3 + 5,
		.vtotal = 800 + 3 + 5 + 24,
	},
};

static const struct panel_desc boe_nv101wxmn51 = {
	.modes = boe_nv101wxmn51_modes,
	.num_modes = ARRAY_SIZE(boe_nv101wxmn51_modes),
	.bpc = 8,
	.size = {
		.width = 217,
		.height = 136,
	},
	.delay = {
		.prepare = 210,
		.enable = 50,
		.unprepare = 160,
	},
};

/* Also used for boe_nv133fhm_n62 */
static const struct drm_display_mode boe_nv133fhm_n61_modes = {
	.clock = 147840,
	.hdisplay = 1920,
	.hsync_start = 1920 + 48,
	.hsync_end = 1920 + 48 + 32,
	.htotal = 1920 + 48 + 32 + 200,
	.vdisplay = 1080,
	.vsync_start = 1080 + 3,
	.vsync_end = 1080 + 3 + 6,
	.vtotal = 1080 + 3 + 6 + 31,
	.flags = DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_NVSYNC,
};

/* Also used for boe_nv133fhm_n62 */
static const struct panel_desc boe_nv133fhm_n61 = {
	.modes = &boe_nv133fhm_n61_modes,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 294,
		.height = 165,
	},
	.delay = {
		/*
		 * When power is first given to the panel there's a short
		 * spike on the HPD line.  It was explained that this spike
		 * was until the TCON data download was complete.  On
		 * one system this was measured at 8 ms.  We'll put 15 ms
		 * in the prepare delay just to be safe and take it away
		 * from the hpd_absent_delay (which would otherwise be 200 ms)
		 * to handle this.  That means:
		 * - If HPD isn't hooked up you still have 200 ms delay.
		 * - If HPD is hooked up we won't try to look at it for the
		 *   first 15 ms.
		 */
		.prepare = 15,
		.hpd_absent_delay = 185,

		.unprepare = 500,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X24,
	.bus_flags = DRM_BUS_FLAG_DATA_MSB_TO_LSB,
	.connector_type = DRM_MODE_CONNECTOR_eDP,
};

static const struct drm_display_mode boe_nv140fhmn49_modes[] = {
	{
		.clock = 148500,
		.hdisplay = 1920,
		.hsync_start = 1920 + 48,
		.hsync_end = 1920 + 48 + 32,
		.htotal = 2200,
		.vdisplay = 1080,
		.vsync_start = 1080 + 3,
		.vsync_end = 1080 + 3 + 5,
		.vtotal = 1125,
	},
};

static const struct panel_desc boe_nv140fhmn49 = {
	.modes = boe_nv140fhmn49_modes,
	.num_modes = ARRAY_SIZE(boe_nv140fhmn49_modes),
	.bpc = 6,
	.size = {
		.width = 309,
		.height = 174,
	},
	.delay = {
		.prepare = 210,
		.enable = 50,
		.unprepare = 160,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.connector_type = DRM_MODE_CONNECTOR_eDP,
};

static const struct drm_display_mode cdtech_s043wq26h_ct7_mode = {
	.clock = 9000,
	.hdisplay = 480,
	.hsync_start = 480 + 5,
	.hsync_end = 480 + 5 + 5,
	.htotal = 480 + 5 + 5 + 40,
	.vdisplay = 272,
	.vsync_start = 272 + 8,
	.vsync_end = 272 + 8 + 8,
	.vtotal = 272 + 8 + 8 + 8,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static const struct panel_desc cdtech_s043wq26h_ct7 = {
	.modes = &cdtech_s043wq26h_ct7_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 95,
		.height = 54,
	},
	.bus_flags = DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE,
};

/* S070PWS19HP-FC21 2017/04/22 */
static const struct drm_display_mode cdtech_s070pws19hp_fc21_mode = {
	.clock = 51200,
	.hdisplay = 1024,
	.hsync_start = 1024 + 160,
	.hsync_end = 1024 + 160 + 20,
	.htotal = 1024 + 160 + 20 + 140,
	.vdisplay = 600,
	.vsync_start = 600 + 12,
	.vsync_end = 600 + 12 + 3,
	.vtotal = 600 + 12 + 3 + 20,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static const struct panel_desc cdtech_s070pws19hp_fc21 = {
	.modes = &cdtech_s070pws19hp_fc21_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 154,
		.height = 86,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE,
	.connector_type = DRM_MODE_CONNECTOR_DPI,
};

/* S070SWV29HG-DC44 2017/09/21 */
static const struct drm_display_mode cdtech_s070swv29hg_dc44_mode = {
	.clock = 33300,
	.hdisplay = 800,
	.hsync_start = 800 + 210,
	.hsync_end = 800 + 210 + 2,
	.htotal = 800 + 210 + 2 + 44,
	.vdisplay = 480,
	.vsync_start = 480 + 22,
	.vsync_end = 480 + 22 + 2,
	.vtotal = 480 + 22 + 2 + 21,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static const struct panel_desc cdtech_s070swv29hg_dc44 = {
	.modes = &cdtech_s070swv29hg_dc44_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 154,
		.height = 86,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE,
	.connector_type = DRM_MODE_CONNECTOR_DPI,
};

static const struct drm_display_mode cdtech_s070wv95_ct16_mode = {
	.clock = 35000,
	.hdisplay = 800,
	.hsync_start = 800 + 40,
	.hsync_end = 800 + 40 + 40,
	.htotal = 800 + 40 + 40 + 48,
	.vdisplay = 480,
	.vsync_start = 480 + 29,
	.vsync_end = 480 + 29 + 13,
	.vtotal = 480 + 29 + 13 + 3,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static const struct panel_desc cdtech_s070wv95_ct16 = {
	.modes = &cdtech_s070wv95_ct16_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 154,
		.height = 85,
	},
};

static const struct display_timing chefree_ch101olhlwh_002_timing = {
	.pixelclock = { 68900000, 71100000, 73400000 },
	.hactive = { 1280, 1280, 1280 },
	.hfront_porch = { 65, 80, 95 },
	.hback_porch = { 64, 79, 94 },
	.hsync_len = { 1, 1, 1 },
	.vactive = { 800, 800, 800 },
	.vfront_porch = { 7, 11, 14 },
	.vback_porch = { 7, 11, 14 },
	.vsync_len = { 1, 1, 1 },
	.flags = DISPLAY_FLAGS_DE_HIGH,
};

static const struct panel_desc chefree_ch101olhlwh_002 = {
	.timings = &chefree_ch101olhlwh_002_timing,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 217,
		.height = 135,
	},
	.delay = {
		.enable = 200,
		.disable = 200,
	},
	.bus_flags = DRM_BUS_FLAG_DE_HIGH,
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode chunghwa_claa070wp03xg_mode = {
	.clock = 66770,
	.hdisplay = 800,
	.hsync_start = 800 + 49,
	.hsync_end = 800 + 49 + 33,
	.htotal = 800 + 49 + 33 + 17,
	.vdisplay = 1280,
	.vsync_start = 1280 + 1,
	.vsync_end = 1280 + 1 + 7,
	.vtotal = 1280 + 1 + 7 + 15,
	.flags = DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static const struct panel_desc chunghwa_claa070wp03xg = {
	.modes = &chunghwa_claa070wp03xg_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 94,
		.height = 150,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X7X3_SPWG,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode chunghwa_claa101wa01a_mode = {
	.clock = 72070,
	.hdisplay = 1366,
	.hsync_start = 1366 + 58,
	.hsync_end = 1366 + 58 + 58,
	.htotal = 1366 + 58 + 58 + 58,
	.vdisplay = 768,
	.vsync_start = 768 + 4,
	.vsync_end = 768 + 4 + 4,
	.vtotal = 768 + 4 + 4 + 4,
};

static const struct panel_desc chunghwa_claa101wa01a = {
	.modes = &chunghwa_claa101wa01a_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 220,
		.height = 120,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X7X3_SPWG,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode chunghwa_claa101wb01_mode = {
	.clock = 69300,
	.hdisplay = 1366,
	.hsync_start = 1366 + 48,
	.hsync_end = 1366 + 48 + 32,
	.htotal = 1366 + 48 + 32 + 20,
	.vdisplay = 768,
	.vsync_start = 768 + 16,
	.vsync_end = 768 + 16 + 8,
	.vtotal = 768 + 16 + 8 + 16,
};

static const struct panel_desc chunghwa_claa101wb01 = {
	.modes = &chunghwa_claa101wb01_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 223,
		.height = 125,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X7X3_SPWG,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode dataimage_scf0700c48ggu18_mode = {
	.clock = 33260,
	.hdisplay = 800,
	.hsync_start = 800 + 40,
	.hsync_end = 800 + 40 + 128,
	.htotal = 800 + 40 + 128 + 88,
	.vdisplay = 480,
	.vsync_start = 480 + 10,
	.vsync_end = 480 + 10 + 2,
	.vtotal = 480 + 10 + 2 + 33,
	.flags = DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static const struct panel_desc dataimage_scf0700c48ggu18 = {
	.modes = &dataimage_scf0700c48ggu18_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 152,
		.height = 91,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X24,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE,
};

static const struct display_timing dlc_dlc0700yzg_1_timing = {
	.pixelclock = { 45000000, 51200000, 57000000 },
	.hactive = { 1024, 1024, 1024 },
	.hfront_porch = { 100, 106, 113 },
	.hback_porch = { 100, 106, 113 },
	.hsync_len = { 100, 108, 114 },
	.vactive = { 600, 600, 600 },
	.vfront_porch = { 8, 11, 15 },
	.vback_porch = { 8, 11, 15 },
	.vsync_len = { 9, 13, 15 },
	.flags = DISPLAY_FLAGS_DE_HIGH,
};

static const struct panel_desc dlc_dlc0700yzg_1 = {
	.timings = &dlc_dlc0700yzg_1_timing,
	.num_timings = 1,
	.bpc = 6,
	.size = {
		.width = 154,
		.height = 86,
	},
	.delay = {
		.prepare = 30,
		.enable = 200,
		.disable = 200,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X7X3_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct display_timing dlc_dlc1010gig_timing = {
	.pixelclock = { 68900000, 71100000, 73400000 },
	.hactive = { 1280, 1280, 1280 },
	.hfront_porch = { 43, 53, 63 },
	.hback_porch = { 43, 53, 63 },
	.hsync_len = { 44, 54, 64 },
	.vactive = { 800, 800, 800 },
	.vfront_porch = { 5, 8, 11 },
	.vback_porch = { 5, 8, 11 },
	.vsync_len = { 5, 7, 11 },
	.flags = DISPLAY_FLAGS_DE_HIGH,
};

static const struct panel_desc dlc_dlc1010gig = {
	.timings = &dlc_dlc1010gig_timing,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 216,
		.height = 135,
	},
	.delay = {
		.prepare = 60,
		.enable = 150,
		.disable = 100,
		.unprepare = 60,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X7X4_SPWG,
	.connector_type = DRM_MODE_CONNECTOR_LVDS,
};

static const struct drm_display_mode edt_et035012dm6_mode = {
	.clock = 6500,
	.hdisplay = 320,
	.hsync_start = 320 + 20,
	.hsync_end = 320 + 20 + 30,
	.htotal = 320 + 20 + 68,
	.vdisplay = 240,
	.vsync_start = 240 + 4,
	.vsync_end = 240 + 4 + 4,
	.vtotal = 240 + 4 + 4 + 14,
	.flags = DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static const struct panel_desc edt_et035012dm6 = {
	.modes = &edt_et035012dm6_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 70,
		.height = 52,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X24,
	.bus_flags = DRM_BUS_FLAG_DE_LOW | DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE,
};

static const struct drm_display_mode edt_etm043080dh6gp_mode = {
	.clock = 10870,
	.hdisplay = 480,
	.hsync_start = 480 + 8,
	.hsync_end = 480 + 8 + 4,
	.htotal = 480 + 8 + 4 + 41,

	/*
	 * IWG22M: Y resolution changed for "dc_linuxfb" module crashing while
	 * fb_align
	 */

	.vdisplay = 288,
	.vsync_start = 288 + 2,
	.vsync_end = 288 + 2 + 4,
	.vtotal = 288 + 2 + 4 + 10,
};

static const struct panel_desc edt_etm043080dh6gp = {
	.modes = &edt_etm043080dh6gp_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 100,
		.height = 65,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.connector_type = DRM_MODE_CONNECTOR_DPI,
};

static const struct drm_display_mode edt_etm0430g0dh6_mode = {
	.clock = 9000,
	.hdisplay = 480,
	.hsync_start = 480 + 2,
	.hsync_end = 480 + 2 + 41,
	.htotal = 480 + 2 + 41 + 2,
	.vdisplay = 272,
	.vsync_start = 272 + 2,
	.vsync_end = 272 + 2 + 10,
	.vtotal = 272 + 2 + 10 + 2,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static const struct panel_desc edt_etm0430g0dh6 = {
	.modes = &edt_etm0430g0dh6_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 95,
		.height = 54,
	},
};

static const struct drm_display_mode edt_et057090dhu_mode = {
	.clock = 25175,
	.hdisplay = 640,
	.hsync_start = 640 + 16,
	.hsync_end = 640 + 16 + 30,
	.htotal = 640 + 16 + 30 + 114,
	.vdisplay = 480,
	.vsync_start = 480 + 10,
	.vsync_end = 480 + 10 + 3,
	.vtotal = 480 + 10 + 3 + 32,
	.flags = DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static const struct panel_desc edt_et057090dhu = {
	.modes = &edt_et057090dhu_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 115,
		.height = 86,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE,
	.connector_type = DRM_MODE_CONNECTOR_DPI,
};

static const struct drm_display_mode edt_etm0700g0dh6_mode = {
	.clock = 33260,
	.hdisplay = 800,
	.hsync_start = 800 + 40,
	.hsync_end = 800 + 40 + 128,
	.htotal = 800 + 40 + 128 + 88,
	.vdisplay = 480,
	.vsync_start = 480 + 10,
	.vsync_end = 480 + 10 + 2,
	.vtotal = 480 + 10 + 2 + 33,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static const struct panel_desc edt_etm0700g0dh6 = {
	.modes = &edt_etm0700g0dh6_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 152,
		.height = 91,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE,
};

static const struct panel_desc edt_etm0700g0bdh6 = {
	.modes = &edt_etm0700g0dh6_mode,
	.num_modes = 1,
	.bpc = 6,
	.size = {
		.width = 152,
		.height = 91,
	},
	.bus_format = MEDIA_BUS_FMT_RGB666_1X18,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE,
};

static const struct display_timing evervision_vgg804821_timing = {
	.pixelclock = { 27600000, 33300000, 50000000 },
	.hactive = { 800, 800, 800 },
	.hfront_porch = { 40, 66, 70 },
	.hback_porch = { 40, 67, 70 },
	.hsync_len = { 40, 67, 70 },
	.vactive = { 480, 480, 480 },
	.vfront_porch = { 6, 10, 10 },
	.vback_porch = { 7, 11, 11 },
	.vsync_len = { 7, 11, 11 },
	.flags = DISPLAY_FLAGS_HSYNC_HIGH | DISPLAY_FLAGS_VSYNC_HIGH |
		 DISPLAY_FLAGS_DE_HIGH | DISPLAY_FLAGS_PIXDATA_NEGEDGE |
		 DISPLAY_FLAGS_SYNC_NEGEDGE,
};

static const struct panel_desc evervision_vgg804821 = {
	.timings = &evervision_vgg804821_timing,
	.num_timings = 1,
	.bpc = 8,
	.size = {
		.width = 108,
		.height = 64,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X24,
	.bus_flags = DRM_BUS_FLAG_DE_HIGH | DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE,
};

static const struct drm_display_mode foxlink_fl500wvr00_a0t_mode = {
	.clock = 32260,
	.hdisplay = 800,
	.hsync_start = 800 + 168,
	.hsync_end = 800 + 168 + 64,
	.htotal = 800 + 168 + 64 + 88,
	.vdisplay = 480,
	.vsync_start = 480 + 37,
	.vsync_end = 480 + 37 + 2,
	.vtotal = 480 + 37 + 2 + 8,
};

static const struct panel_desc foxlink_fl500wvr00_a0t = {
	.modes = &foxlink_fl500wvr00_a0t_mode,
	.num_modes = 1,
	.bpc = 8,
	.size = {
		.width = 108,
		.height = 65,
	},
	.bus_format = MEDIA_BUS_FMT_RGB888_1X24,
};

static const struct drm_display_mode frida_frd350h54004_modes[] = {
	{ /* 60 Hz */
		.clock = 6000,
		.hdisplay = 320,
		.hsync_start = 320 + 44,
		.hsync_end = 320 + 44 + 16,
		.htotal = 320 + 44 + 16 + 20,
		.vdisplay = 240,
		.vsync_start = 240 + 2,
		.vsync_end = 240 + 2 + 6,
		.vtotal = 240 + 2 + 6 + 2,
		.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
	},
	{ /* 50 Hz */

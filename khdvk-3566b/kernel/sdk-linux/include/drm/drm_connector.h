/*
 * Copyright (c) 2016 Intel Corporation
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#ifndef __DRM_CONNECTOR_H__
#define __DRM_CONNECTOR_H__

#include <linux/list.h>
#include <linux/llist.h>
#include <linux/ctype.h>
#include <linux/hdmi.h>
#include <drm/drm_mode_object.h>
#include <drm/drm_util.h>

#include <uapi/drm/drm_mode.h>

struct drm_connector_helper_funcs;
struct drm_modeset_acquire_ctx;
struct drm_device;
struct drm_crtc;
struct drm_encoder;
struct drm_property;
struct drm_property_blob;
struct drm_printer;
struct edid;
struct i2c_adapter;

enum drm_connector_force {
	DRM_FORCE_UNSPECIFIED,
	DRM_FORCE_OFF,
	DRM_FORCE_ON,         /* force on analog part normally */
	DRM_FORCE_ON_DIGITAL, /* for DVI-I use digital connector */
};

/**
 * enum drm_connector_status - status for a &drm_connector
 *
 * This enum is used to track the connector status. There are no separate
 * #defines for the uapi!
 */
enum drm_connector_status {
	/**
	 * @connector_status_connected: The connector is definitely connected to
	 * a sink device, and can be enabled.
	 */
	connector_status_connected = 1,
	/**
	 * @connector_status_disconnected: The connector isn't connected to a
	 * sink device which can be autodetect. For digital outputs like DP or
	 * HDMI (which can be realiable probed) this means there's really
	 * nothing there. It is driver-dependent whether a connector with this
	 * status can be lit up or not.
	 */
	connector_status_disconnected = 2,
	/**
	 * @connector_status_unknown: The connector's status could not be
	 * reliably detected. This happens when probing would either cause
	 * flicker (like load-detection when the connector is in use), or when a
	 * hardware resource isn't available (like when load-detection needs a
	 * free CRTC). It should be possible to light up the connector with one
	 * of the listed fallback modes. For default configuration userspace
	 * should only try to light up connectors with unknown status when
	 * there's not connector with @connector_status_connected.
	 */
	connector_status_unknown = 3,
};

/**
 * enum drm_connector_registration_status - userspace registration status for
 * a &drm_connector
 *
 * This enum is used to track the status of initializing a connector and
 * registering it with userspace, so that DRM can prevent bogus modesets on
 * connectors that no longer exist.
 */
enum drm_connector_registration_state {
	/**
	 * @DRM_CONNECTOR_INITIALIZING: The connector has just been created,
	 * but has yet to be exposed to userspace. There should be no
	 * additional restrictions to how the state of this connector may be
	 * modified.
	 */
	DRM_CONNECTOR_INITIALIZING = 0,

	/**
	 * @DRM_CONNECTOR_REGISTERED: The connector has been fully initialized
	 * and registered with sysfs, as such it has been exposed to
	 * userspace. There should be no additional restrictions to how the
	 * state of this connector may be modified.
	 */
	DRM_CONNECTOR_REGISTERED = 1,

	/**
	 * @DRM_CONNECTOR_UNREGISTERED: The connector has either been exposed
	 * to userspace and has since been unregistered and removed from
	 * userspace, or the connector was unregistered before it had a chance
	 * to be exposed to userspace (e.g. still in the
	 * @DRM_CONNECTOR_INITIALIZING state). When a connector is
	 * unregistered, there are additional restrictions to how its state
	 * may be modified:
	 *
	 * - An unregistered connector may only have its DPMS changed from
	 *   On->Off. Once DPMS is changed to Off, it may not be switched back
	 *   to On.
	 * - Modesets are not allowed on unregistered connectors, unless they
	 *   would result in disabling its assigned CRTCs. This means
	 *   disabling a CRTC on an unregistered connector is OK, but enabling
	 *   one is not.
	 * - Removing a CRTC from an unregistered connector is OK, but new
	 *   CRTCs may never be assigned to an unregistered connector.
	 */
	DRM_CONNECTOR_UNREGISTERED = 2,
};

enum subpixel_order {
	SubPixelUnknown = 0,
	SubPixelHorizontalRGB,
	SubPixelHorizontalBGR,
	SubPixelVerticalRGB,
	SubPixelVerticalBGR,
	SubPixelNone,

};

/**
 * struct drm_scrambling: sink's scrambling support.
 */
struct drm_scrambling {
	/**
	 * @supported: scrambling supported for rates > 340 Mhz.
	 */
	bool supported;
	/**
	 * @low_rates: scrambling supported for rates <= 340 Mhz.
	 */
	bool low_rates;
};

/*
 * struct drm_scdc - Information about scdc capabilities of a HDMI 2.0 sink
 *
 * Provides SCDC register support and capabilities related information on a
 * HDMI 2.0 sink. In case of a HDMI 1.4 sink, all parameter must be 0.
 */
struct drm_scdc {
	/**
	 * @supported: status control & data channel present.
	 */
	bool supported;
	/**
	 * @read_request: sink is capable of generating scdc read request.
	 */
	bool read_request;
	/**
	 * @scrambling: sink's scrambling capabilities
	 */
	struct drm_scrambling scrambling;
};

#ifdef CONFIG_NO_GKI
/**
 * struct drm_hdmi_dsc_cap - DSC capabilities of HDMI sink
 *
 * Describes the DSC support provided by HDMI 2.1 sink.
 * The information is fetched fom additional HFVSDB blocks defined
 * for HDMI 2.1.
 */
struct drm_hdmi_dsc_cap {
	/** @v_1p2: flag for dsc1.2 version support by sink */
	bool v_1p2;

	/** @native_420: Does sink support DSC with 4:2:0 compression */
	bool native_420;

	/**
	 * @all_bpp: Does sink support all bpp with 4:4:4: or 4:2:2
	 * compressed formats
	 */
	bool all_bpp;

	/**
	 * @bpc_supported: compressed bpc supported by sink : 10, 12 or 16 bpc
	 */
	u8 bpc_supported;

	/** @max_slices: maximum number of Horizontal slices supported by */
	u8 max_slices;

	/** @clk_per_slice : max pixel clock in MHz supported per slice */
	int clk_per_slice;

	/** @max_lanes : dsc max lanes supported for Fixed rate Link training */
	u8 max_lanes;

	/** @max_frl_rate_per_lane : maximum frl rate with DSC per lane */
	u8 max_frl_rate_per_lane;

	/** @total_chunk_kbytes: max size of chunks in KBs supported per line*/
	u8 total_chunk_kbytes;
};
#endif

/**
 * struct drm_hdmi_info - runtime information about the connected HDMI sink
 *
 * Describes if a given display supports advanced HDMI 2.0 features.
 * This information is available in CEA-861-F extension blocks (like HF-VSDB).
 */
struct drm_hdmi_info {
	/** @scdc: sink's scdc support and capabilities */
	struct drm_scdc scdc;

	/**
	 * @y420_vdb_modes: bitmap of modes which can support ycbcr420
	 * output only (not normal RGB/YCBCR444/422 outputs). The max VIC
	 * defined by the CEA-861-G spec is 219, so the size is 256 bits to map
	 * up to 256 VICs.
	 */
	unsigned long y420_vdb_modes[BITS_TO_LONGS(256)];

	/**
	 * @y420_cmdb_modes: bitmap of modes which can support ycbcr420
	 * output also, along with normal HDMI outputs. The max VIC defined by
	 * the CEA-861-G spec is 219, so the size is 256 bits to map up to 256
	 * VICs.
	 */
	unsigned long y420_cmdb_modes[BITS_TO_LONGS(256)];

	/** @y420_cmdb_map: bitmap of SVD index, to extraxt vcb modes */
	u64 y420_cmdb_map;

	/** @y420_dc_modes: bitmap of deep color support index */
	u8 y420_dc_modes;

#ifdef CONFIG_NO_GKI
	/** @max_frl_rate_per_lane: support fixed rate link */
	u8 max_frl_rate_per_lane;

	/** @max_lanes: supported by sink */
	u8 max_lanes;

	/** @dsc_cap: DSC capabilities of the sink */
	struct drm_hdmi_dsc_cap dsc_cap;
#endif
};

/**
 * enum drm_link_status - connector's link_status property value
 *
 * This enum is used as the connector's link status property value.
 * It is set to the values defined in uapi.
 *
 * @DRM_LINK_STATUS_GOOD: DP Link is Good as a result of successful
 *                        link training
 * @DRM_LINK_STATUS_BAD: DP Link is BAD as a result of link training
 *                       failure
 */
enum drm_link_status {
	DRM_LINK_STATUS_GOOD = DRM_MODE_LINK_STATUS_GOOD,
	DRM_LINK_STATUS_BAD = DRM_MODE_LINK_STATUS_BAD,
};

/**
 * enum drm_panel_orientation - panel_orientation info for &drm_display_info
 *
 * This enum is used to track the (LCD) panel orientation. There are no
 * separate #defines for the uapi!
 *
 * @DRM_MODE_PANEL_ORIENTATION_UNKNOWN: The drm driver has not provided any
 *					panel orientation information (normal
 *					for non panels) in this case the "panel
 *					orientation" connector prop will not be
 *					attached.
 * @DRM_MODE_PANEL_ORIENTATION_NORMAL:	The top side of the panel matches the
 *					top side of the device's casing.
 * @DRM_MODE_PANEL_ORIENTATION_BOTTOM_UP: The top side of the panel matches the
 *					bottom side of the device's casing, iow
 *					the panel is mounted upside-down.
 * @DRM_MODE_PANEL_ORIENTATION_LEFT_UP:	The left side of the panel matches the
 *					top side of the device's casing.
 * @DRM_MODE_PANEL_ORIENTATION_RIGHT_UP: The right side of the panel matches the
 *					top side of the device's casing.
 */
enum drm_panel_orientation {
	DRM_MODE_PANEL_ORIENTATION_UNKNOWN = -1,
	DRM_MODE_PANEL_ORIENTATION_NORMAL = 0,
	DRM_MODE_PANEL_ORIENTATION_BOTTOM_UP,
	DRM_MODE_PANEL_ORIENTATION_LEFT_UP,
	DRM_MODE_PANEL_ORIENTATION_RIGHT_UP,
};

/**
 * struct drm_monitor_range_info - Panel's Monitor range in EDID for
 * &drm_display_info
 *
 * This struct is used to store a frequency range supported by panel
 * as parsed from EDID's detailed monitor range descriptor block.
 *
 * @min_vfreq: This is the min supported refresh rate in Hz from
 *             EDID's detailed monitor range.
 * @max_vfreq: This is the max supported refresh rate in Hz from
 *             EDID's detailed monitor range
 */
struct drm_monitor_range_info {
	u8 min_vfreq;
	u8 max_vfreq;
};

/*
 * This is a consolidated colorimetry list supported by HDMI and
 * DP protocol standard. The respective connectors will register
 * a property with the subset of this list (supported by that
 * respective protocol). Userspace will set the colorspace through
 * a colorspace property which will be created and exposed to
 * userspace.
 */

/* For Default case, driver will set the colorspace */
#define DRM_MODE_COLORIMETRY_DEFAULT			0
/* CEA 861 Normal Colorimetry options */
#define DRM_MODE_COLORIMETRY_NO_DATA			0
#define DRM_MODE_COLORIMETRY_SMPTE_170M_YCC		1
#define DRM_MODE_COLORIMETRY_BT709_YCC			2
/* CEA 861 Extended Colorimetry Options */
#define DRM_MODE_COLORIMETRY_XVYCC_601			3
#define DRM_MODE_COLORIMETRY_XVYCC_709			4
#define DRM_MODE_COLORIMETRY_SYCC_601			5
#define DRM_MODE_COLORIMETRY_OPYCC_601			6
#define DRM_MODE_COLORIMETRY_OPRGB			7
#define DRM_MODE_COLORIMETRY_BT2020_CYCC		8
#define DRM_MODE_COLORIMETRY_BT2020_RGB			9
#define DRM_MODE_COLORIMETRY_BT2020_YCC			10
/* Additional Colorimetry extension added as part of CTA 861.G */
#define DRM_MODE_COLORIMETRY_DCI_P3_RGB_D65		11
#define DRM_MODE_COLORIMETRY_DCI_P3_RGB_THEATER		12
/* Additional Colorimetry Options added for DP 1.4a VSC Colorimetry Format */
#define DRM_MODE_COLORIMETRY_RGB_WIDE_FIXED		13
#define DRM_MODE_COLORIMETRY_RGB_WIDE_FLOAT		14
#define DRM_MODE_COLORIMETRY_BT601_YCC			15

/**
 * enum drm_bus_flags - bus_flags info for &drm_display_info
 *
 * This enum defines signal polarities and clock edge information for signals on
 * a bus as bitmask flags.
 *
 * The clock edge information is conveyed by two sets of symbols,
 * DRM_BUS_FLAGS_*_DRIVE_\* and DRM_BUS_FLAGS_*_SAMPLE_\*. When this enum is
 * used to describe a bus from the point of view of the transmitter, the
 * \*_DRIVE_\* flags should be used. When used from the point of view of the
 * receiver, the \*_SAMPLE_\* flags should be used. The \*_DRIVE_\* and
 * \*_SAMPLE_\* flags alias each other, with the \*_SAMPLE_POSEDGE and
 * \*_SAMPLE_NEGEDGE flags being equal to \*_DRIVE_NEGEDGE and \*_DRIVE_POSEDGE
 * respectively. This simplifies code as signals are usually sampled on the
 * opposite edge of the driving edge. Transmitters and receivers may however
 * need to take other signal timings into account to convert between driving
 * and sample edges.
 */
enum drm_bus_flags {
	/**
	 * @DRM_BUS_FLAG_DE_LOW:
	 *
	 * The Data Enable signal is active low
	 */
	DRM_BUS_FLAG_DE_LOW = BIT(0),

	/**
	 * @DRM_BUS_FLAG_DE_HIGH:
	 *
	 * The Data Enable signal is active high
	 */
	DRM_BUS_FLAG_DE_HIGH = BIT(1),

	/**
	 * @DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE:
	 *
	 * Data is driven on the rising edge of the pixel clock
	 */
	DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE = BIT(2),

	/**
	 * @DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE:
	 *
	 * Data is driven on the falling edge of the pixel clock
	 */
	DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE = BIT(3),

	/**
	 * @DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE:
	 *
	 * Data is sampled on the rising edge of the pixel clock
	 */
	DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE = DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE,

	/**
	 * @DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE:
	 *
	 * Data is sampled on the falling edge of the pixel clock
	 */
	DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE = DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE,

	/**
	 * @DRM_BUS_FLAG_DATA_MSB_TO_LSB:
	 *
	 * Data is transmitted MSB to LSB on the bus
	 */
	DRM_BUS_FLAG_DATA_MSB_TO_LSB = BIT(4),

	/**
	 * @DRM_BUS_FLAG_DATA_LSB_TO_MSB:
	 *
	 * Data is transmitted LSB to MSB on the bus
	 */
	DRM_BUS_FLAG_DATA_LSB_TO_MSB = BIT(5),

	/**
	 * @DRM_BUS_FLAG_SYNC_DRIVE_POSEDGE:
	 *
	 * Sync signals are driven on the rising edge of the pixel clock
	 */
	DRM_BUS_FLAG_SYNC_DRIVE_POSEDGE = BIT(6),

	/**
	 * @DRM_BUS_FLAG_SYNC_DRIVE_NEGEDGE:
	 *
	 * Sync signals are driven on the falling edge of the pixel clock
	 */
	DRM_BUS_FLAG_SYNC_DRIVE_NEGEDGE = BIT(7),

	/**
	 * @DRM_BUS_FLAG_SYNC_SAMPLE_POSEDGE:
	 *
	 * Sync signals are sampled on the rising edge of the pixel clock
	 */
	DRM_BUS_FLAG_SYNC_SAMPLE_POSEDGE = DRM_BUS_FLAG_SYNC_DRIVE_NEGEDGE,

	/**
	 * @DRM_BUS_FLAG_SYNC_SAMPLE_NEGEDGE:
	 *
	 * Sync signals are sampled on the falling edge of the pixel clock
	 */
	DRM_BUS_FLAG_SYNC_SAMPLE_NEGEDGE = DRM_BUS_FLAG_SYNC_DRIVE_POSEDGE,

	/**
	 * @DRM_BUS_FLAG_SHARP_SIGNALS:
	 *
	 *  Set if the Sharp-specific signals (SPL, CLS, PS, REV) must be used
	 */
	DRM_BUS_FLAG_SHARP_SIGNALS = BIT(8),
};

/**
 * struct drm_display_info - runtime data about the connected sink
 *
 * Describes a given display (e.g. CRT or flat panel) and its limitations. For
 * fixed display sinks like built-in panels there's not much difference between
 * this and &struct drm_connector. But for sinks with a real cable this
 * structure is meant to describe all the things at the other end of the cable.
 *
 * For sinks which provide an EDID this can be filled out by calling
 * drm_add_edid_modes().
 */
struct drm_display_info {
	/**
	 * @width_mm: Physical width in mm.
	 */
	unsigned int width_mm;

	/**
	 * @height_mm: Physical height in mm.
	 */
	unsigned int height_mm;

	/**
	 * @bpc: Maximum bits per color channel. Used by HDMI and DP outputs.
	 */
	unsigned int bpc;

	/**
	 * @subpixel_order: Subpixel order of LCD panels.
	 */
	enum subpixel_order subpixel_order;

#define DRM_COLOR_FORMAT_RGB444		(1<<0)
#define DRM_COLOR_FORMAT_YCRCB444	(1<<1)
#define DRM_COLOR_FORMAT_YCRCB422	(1<<2)
#define DRM_COLOR_FORMAT_YCRCB420	(1<<3)

	/**
	 * @panel_orientation: Read only connector property for built-in panels,
	 * indicating the orientation of the panel vs the device's casing.
	 * drm_connector_init() sets this to DRM_MODE_PANEL_ORIENTATION_UNKNOWN.
	 * When not UNKNOWN this gets used by the drm_fb_helpers to rotate the
	 * fb to compensate and gets exported as prop to userspace.
	 */
	int panel_orientation;

	/**
	 * @color_formats: HDMI Color formats, selects between RGB and YCrCb
	 * modes. Used DRM_COLOR_FORMAT\_ defines, which are _not_ the same ones
	 * as used to describe the pixel format in framebuffers, and also don't
	 * match the formats in @bus_formats which are shared with v4l.
	 */
	u32 color_formats;

	/**
	 * @bus_formats: Pixel data format on the wire, somewhat redundant with
	 * @color_formats. Array of size @num_bus_formats encoded using
	 * MEDIA_BUS_FMT\_ defines shared with v4l and media drivers.
	 */
	const u32 *bus_formats;
	/**
	 * @num_bus_formats: Size of @bus_formats array.
	 */
	unsigned int num_bus_formats;

	/**
	 * @bus_flags: Additional information (like pixel signal polarity) for
	 * the pixel data on the bus, using &enum drm_bus_flags values
	 * DRM_BUS_FLAGS\_.
	 */
	u32 bus_flags;

	/**
	 * @max_tmds_clock: Maximum TMDS clock rate supported by the
	 * sink in kHz. 0 means undefined.
	 */
	int max_tmds_clock;

	/**
	 * @dvi_dual: Dual-link DVI sink?
	 */
	bool dvi_dual;

	/**
	 * @is_hdmi: True if the sink is an HDMI device.
	 *
	 * This field shall be used instead of calling
	 * drm_detect_hdmi_monitor() when possible.
	 */
	bool is_hdmi;

	/**
	 * @has_hdmi_infoframe: Does the sink support the HDMI infoframe?
	 */
	bool has_hdmi_infoframe;

	/**
	 * @rgb_quant_range_selectable: Does the sink support selecting
	 * the RGB quantization range?
	 */
	bool rgb_quant_range_selectable;

	/**
	 * @edid_hdmi_dc_modes: Mask of supported hdmi deep color modes. Even
	 * more stuff redundant with @bus_formats.
	 */
	u8 edid_hdmi_dc_modes;

	/**
	 * @cea_rev: CEA revision of the HDMI sink.
	 */
	u8 cea_rev;

	/**
	 * @hdmi: advance features of a HDMI sink.
	 */
	struct drm_hdmi_info hdmi;

	/**
	 * @non_desktop: Non desktop display (HMD).
	 */
	bool non_desktop;

	/**
	 * @monitor_range: Frequency range supported by monitor range descriptor
	 */
	struct drm_monitor_range_info monitor_range;
};

int drm_display_info_set_bus_formats(struct drm_display_info *info,
				     const u32 *formats,
				     unsigned int num_formats);

/**
 * struct drm_connector_tv_margins - TV connector related margins
 *
 * Describes the margins in pixels to put around the image on TV
 * connectors to deal with overscan.
 */
struct drm_connector_tv_margins {
	/**
	 * @bottom: Bottom margin in pixels.
	 */
	unsigned int bottom;

	/**
	 * @left: Left margin in pixels.
	 */
	unsigned int left;

	/**
	 * @right: Right margin in pixels.
	 */
	unsigned int right;

	/**
	 * @top: Top margin in pixels.
	 */
	unsigned int top;
};

/**
 * struct drm_tv_connector_state - TV connector related states
 * @subconnector: selected subconnector
 * @margins: TV margins
 * @mode: TV mode
 * @brightness: brightness in percent
 * @contrast: contrast in percent
 * @flicker_reduction: flicker reduction in percent
 * @overscan: overscan in percent
 * @saturation: saturation in percent
 * @hue: hue in percent
 */
struct drm_tv_connector_state {
	enum drm_mode_subconnector subconnector;
	struct drm_connector_tv_margins margins;
	unsigned int mode;
	unsigned int brightness;
	unsigned int contrast;
	unsigned int flicker_reduction;
	unsigned int overscan;
	unsigned int saturation;
	unsigned int hue;
};

/**
 * struct drm_connector_state - mutable connector state
 */
struct drm_connector_state {
	/** @connector: backpointer to the connector */
	struct drm_connector *connector;

	/**
	 * @crtc: CRTC to connect connector to, NULL if disabled.
	 *
	 * Do not change this directly, use drm_atomic_set_crtc_for_connector()
	 * instead.
	 */
	struct drm_crtc *crtc;

	/**
	 * @best_encoder:
	 *
	 * Used by the atomic helpers to select the encoder, through the
	 * &drm_connector_helper_funcs.atomic_best_encoder or
	 * &drm_connector_helper_funcs.best_encoder callbacks.
	 *
	 * This is also used in the atomic helpers to map encoders to their
	 * current and previous connectors, see
	 * drm_atomic_get_old_connector_for_encoder() and
	 * drm_atomic_get_new_connector_for_encoder().
	 *
	 * NOTE: Atomic drivers must fill this out (either themselves or through
	 * helpers), for otherwise the GETCONNECTOR and GETENCODER IOCTLs will
	 * not return correct data to userspace.
	 */
	struct drm_encoder *best_encoder;

	/**
	 * @link_status: Connector link_status to keep track of whether link is
	 * GOOD or BAD to notify userspace if retraining is necessary.
	 */
	enum drm_link_status link_status;

	/** @state: backpointer to global drm_atomic_state */
	struct drm_atomic_state *state;

	/**
	 * @commit: Tracks the pending commit to prevent use-after-free conditions.
	 *
	 * Is only set when @crtc is NULL.
	 */
	struct drm_crtc_commit *commit;

	/** @tv: TV connector state */
	struct drm_tv_connector_state tv;

	/**
	 * @self_refresh_aware:
	 *
	 * This tracks whether a connector is aware of the self refresh state.
	 * It should be set to true for those connector implementations which
	 * understand the self refresh state. This is needed since the crtc
	 * registers the self refresh helpers and it doesn't know if the
	 * connectors downstream have implemented self refresh entry/exit.
	 *
	 * Drivers should set this to true in atomic_check if they know how to
	 * handle self_refresh requests.
	 */
	bool self_refresh_aware;

	/**
	 * @picture_aspect_ratio: Connector property to control the
	 * HDMI infoframe aspect ratio setting.
	 *
	 * The %DRM_MODE_PICTURE_ASPECT_\* values much match the
	 * values for &enum hdmi_picture_aspect
	 */
	enum hdmi_picture_aspect picture_aspect_ratio;

	/**
	 * @content_type: Connector property to control the
	 * HDMI infoframe content type setting.
	 * The %DRM_MODE_CONTENT_TYPE_\* values much
	 * match the values.
	 */
	unsigned int content_type;

	/**
	 * @hdcp_content_type: Connector property to pass the type of
	 * protected content. This is most commonly used for HDCP.
	 */
	unsigned int hdcp_content_type;

	/**
	 * @scaling_mode: Connector property to control the
	 * upscaling, mostly used for built-in panels.
	 */
	unsigned int scaling_mode;

	/**
	 * @content_protection: Connector property to request content
	 * protection. This is most commonly used for HDCP.
	 */
	unsigned int content_protection;

	/**
	 * @colorspace: State variable for Connector property to request
	 * colorspace change on Sink. This is most commonly used to switch
	 * to wider color gamuts like BT2020.
	 */
	u32 colorspace;

	/**
	 * @writeback_job: Writeback job for writeback connectors
	 *
	 * Holds the framebuffer and out-fence for a writeback connector. As
	 * the writeback completion may be asynchronous to the normal commit
	 * cycle, the writeback job lifetime is managed separately from the
	 * normal atomic state by this object.
	 *
	 * See also: drm_writeback_queue_job() and
	 * drm_writeback_signal_completion()
	 */
	struct drm_writeback_job *writeback_job;

	/**
	 * @max_requested_bpc: Connector property to limit the maximum bit
	 * depth of the pixels.
	 */
	u8 max_requested_bpc;

	/**
	 * @max_bpc: Connector max_bpc based on the requested max_bpc property
	 * and the connector bpc limitations obtained from edid.
	 */
	u8 max_bpc;

	/**
	 * @hdr_output_metadata:
	 * DRM blob property for HDR output metadata
	 */
	struct drm_property_blob *hdr_output_metadata;
};

/**
 * struct drm_connector_funcs - control connectors on a given device
 *
 * Each CRTC may have one or more connectors attached to it.  The functions
 * below allow the core DRM code to control connectors, enumerate available modes,
 * etc.
 */
struct drm_connector_funcs {
	/**
	 * @dpms:
	 *
	 * Legacy entry point to set the per-connector DPMS state. Legacy DPMS
	 * is exposed as a standard property on the connector, but diverted to
	 * this callback in the drm core. Note that atomic drivers don't
	 * implement the 4 level DPMS support on the connector any more, but
	 * instead only have an on/off "ACTIVE" property on the CRTC object.
	 *
	 * This hook is not used by atomic drivers, remapping of the legacy DPMS
	 * property is entirely handled in the DRM core.
	 *
	 * RETURNS:
	 *
	 * 0 on success or a negative error code on failure.
	 */
	int (*dpms)(struct drm_connector *connector, int mode);

	/**
	 * @reset:
	 *
	 * Reset connector hardware and software state to off. This function isn't
	 * called by the core directly, only through drm_mode_config_reset().
	 * It's not a helper hook only for historical reasons.
	 *
	 * Atomic drivers can use drm_atomic_helper_connector_reset() to reset
	 * atomic state using this hook.
	 */
	void (*reset)(struct drm_connector *connector);

	/**
	 * @detect:
	 *
	 * Check to see if anything is attached to the connector. The parameter
	 * force is set to false whilst polling, true when checking the
	 * connector due to a user request. force can be used by the driver to
	 * avoid expensive, destructive operations during automated probing.
	 *
	 * This callback is optional, if not implemented the connector will be
	 * considered as always being attached.
	 *
	 * FIXME:
	 *
	 * Note that this hook is only called by the probe helper. It's not in
	 * the helper library vtable purely for historical reasons. The only DRM
	 * core	entry point to probe connector state is @fill_modes.
	 *
	 * Note that the helper library will already hold
	 * &drm_mode_config.connection_mutex. Drivers which need to grab additional
	 * locks to avoid races with concurrent modeset changes need to use
	 * &drm_connector_helper_funcs.detect_ctx instead.
	 *
	 * RETURNS:
	 *
	 * drm_connector_status indicating the connector's status.
	 */
	enum drm_connector_status (*detect)(struct drm_connector *connector,
					    bool force);

	/**
	 * @force:
	 *
	 * This function is called to update internal encoder state when the
	 * connector is forced to a certain state by userspace, either through
	 * the sysfs interfaces or on the kernel cmdline. In that case the
	 * @detect callback isn't called.
	 *
	 * FIXME:
	 *
	 * Note that this hook is only called by the probe helper. It's not in
	 * the helper library vtable purely for historical reasons. The only DRM
	 * core	entry point to probe connector state is @fill_modes.
	 */
	void (*force)(struct drm_connector *connector);

	/**
	 * @fill_modes:
	 *
	 * Entry point for output detection and basic mode validation. The
	 * driver should reprobe the output if needed (e.g. when hotplug
	 * handling is unreliable), add all detected modes to &drm_connector.modes
	 * and filter out any the device can't support in any configuration. It
	 * also needs to filter out any modes wider or higher than the
	 * parameters max_width and max_height indicate.
	 *
	 * The drivers must also prune any modes no longer valid from
	 * &drm_connector.modes. Furthermore it must update
	 * &drm_connector.status and &drm_connector.edid.  If no EDID has been
	 * received for this output connector->edid must be NULL.
	 *
	 * Drivers using the probe helpers should use
	 * drm_helper_probe_single_connector_modes() to implement this
	 * function.
	 *
	 * RETURNS:
	 *
	 * The number of modes detected and filled into &drm_connector.modes.
	 */
	int (*fill_modes)(struct drm_connector *connector, uint32_t max_width, uint32_t max_height);

	/**
	 * @set_property:
	 *
	 * This is the legacy entry point to update a property attached to the
	 * connector.
	 *
	 * This callback is optional if the driver does not support any legacy
	 * driver-private properties. For atomic drivers it is not used because
	 * property handling is done entirely in the DRM core.
	 *
	 * RETURNS:
	 *
	 * 0 on success or a negative error code on failure.
	 */
	int (*set_property)(struct drm_connector *connector, struct drm_property *property,
			     uint64_t val);

	/**
	 * @late_register:
	 *
	 * This optional hook can be used to register additional userspace
	 * interfaces attached to the connector, light backlight control, i2c,
	 * DP aux or similar interfaces. It is called late in the driver load
	 * sequence from drm_connector_register() when registering all the
	 * core drm connector interfaces. Everything added from this callback
	 * should be unregistered in the early_unregister callback.
	 *
	 * This is called while holding &drm_connector.mutex.
	 *
	 * Returns:
	 *
	 * 0 on success, or a negative error code on failure.
	 */
	int (*late_register)(struct drm_connector *connector);

	/**
	 * @early_unregister:
	 *
	 * This optional hook should be used to unregister the additional
	 * userspace interfaces attached to the connector from
	 * late_register(). It is called from drm_connector_unregister(),
	 * early in the driver unload sequence to disable userspace access
	 * before data structures are torndown.
	 *
	 * This is called while holding &drm_connector.mutex.
	 */
	void (*early_unregister)(struct drm_connector *connector);

	/**
	 * @destroy:
	 *
	 * Clean up connector resources. This is called at driver unload time
	 * through drm_mode_config_cleanup(). It can also be called at runtime
	 * when a connector is being hot-unplugged for drivers that support
	 * connector hotplugging (e.g. DisplayPort MST).
	 */
	void (*destroy)(struct drm_connector *connector);

	/**
	 * @atomic_duplicate_state:
	 *
	 * Duplicate the current atomic state for this connector and return it.
	 * The core and helpers guarantee that any atomic state duplicated with
	 * this hook and still owned by the caller (i.e. not transferred to the
	 * driver by calling &drm_mode_config_funcs.atomic_commit) will be
	 * cleaned up by calling the @atomic_destroy_state hook in this
	 * structure.
	 *
	 * This callback is mandatory for atomic drivers.
	 *
	 * Atomic drivers which don't subclass &struct drm_connector_state should use
	 * drm_atomic_helper_connector_duplicate_state(). Drivers that subclass the
	 * state structure to extend it with driver-private state should use
	 * __drm_atomic_helper_connector_duplicate_state() to make sure shared state is
	 * duplicated in a consistent fashion across drivers.
	 *
	 * It is an error to call this hook before &drm_connector.state has been
	 * initialized correctly.
	 *
	 * NOTE:
	 *
	 * If the duplicate state references refcounted resources this hook must
	 * acquire a reference for each of them. The driver must release these
	 * references again in @atomic_destroy_state.
	 *
	 * RETURNS:
	 *
	 * Duplicated atomic state or NULL when the allocation failed.
	 */
	struct drm_connector_state *(*atomic_duplicate_state)(struct drm_connector *connector);

	/**
	 * @atomic_destroy_state:
	 *
	 * Destroy a state duplicated with @atomic_duplicate_state and release
	 * or unreference all resources it references
	 *
	 * This callback is mandatory for atomic drivers.
	 */
	void (*atomic_destroy_state)(struct drm_connector *connector,
				     struct drm_connector_state *state);

	/**
	 * @atomic_set_property:
	 *
	 * Decode a driver-private property value and store the decoded value
	 * into the passed-in state structure. Since the atomic core decodes all
	 * standardized properties (even for extensions beyond the core set of
	 * properties which might not be implemented by all drivers) this
	 * requires drivers to subclass the state structure.
	 *
	 * Such driver-private properties should really only be implemented for
	 * truly hardware/vendor specific state. Instead it is preferred to
	 * standardize atomic extension and decode the properties used to expose
	 * such an extension in the core.
	 *
	 * Do not call this function directly, use
	 * drm_atomic_connector_set_property() instead.
	 *
	 * This callback is optional if the driver does not support any
	 * driver-private atomic properties.
	 *
	 * NOTE:
	 *
	 * This function is called in the state assembly phase of atomic
	 * modesets, which can be aborted for any reason (including on
	 * userspace's request to just check whether a configuration would be
	 * possible). Drivers MUST NOT touch any persistent state (hardware or
	 * software) or data structures except the passed in @state parameter.
	 *
	 * Also since userspace controls in which order properties are set this
	 * function must not do any input validation (since the state update is
	 * incomplete and hence likely inconsistent). Instead any such input
	 * validation must be done in the various atomic_check callbacks.
	 *
	 * RETURNS:
	 *
	 * 0 if the property has been found, -EINVAL if the property isn't
	 * implemented by the driver (which shouldn't ever happen, the core only
	 * asks for properties attached to this connector). No other validation
	 * is allowed by the driver. The core already checks that the property
	 * value is within the range (integer, valid enum value, ...) the driver
	 * set when registering the property.
	 */
	int (*atomic_set_property)(struct drm_connector *connector,
				   struct drm_connector_state *state,
				   struct drm_property *property,
				   uint64_t val);

	/**
	 * @atomic_get_property:
	 *
	 * Reads out the decoded driver-private property. This is used to
	 * implement the GETCONNECTOR IOCTL.
	 *
	 * Do not call this function directly, use
	 * drm_atomic_connector_get_property() instead.
	 *
	 * This callback is optional if the driver does not support any
	 * driver-private atomic properties.
	 *
	 * RETURNS:
	 *
	 * 0 on success, -EINVAL if the property isn't implemented by the
	 * driver (which shouldn't ever happen, the core only asks for
	 * properties attached to this connector).
	 */
	int (*atomic_get_property)(struct drm_connector *connector,
				   const struct drm_connector_state *state,
				   struct drm_property *property,
				   uint64_t *val);

	/**
	 * @atomic_print_state:
	 *
	 * If driver subclasses &struct drm_connector_state, it should implement
	 * this optional hook for printing additional driver specific state.
	 *
	 * Do not call this directly, use drm_atomic_connector_print_state()
	 * instead.
	 */
	void (*atomic_print_state)(struct drm_printer *p,
				   const struct drm_connector_state *state);
};

/**
 * struct drm_cmdline_mode - DRM Mode passed through the kernel command-line
 *
 * Each connector can have an initial mode with additional options
 * passed through the kernel command line. This structure allows to
 * express those parameters and will be filled by the command-line
 * parser.
 */
struct drm_cmdline_mode {
	/**
	 * @name:
	 *
	 * Name of the mode.
	 */
	char name[DRM_DISPLAY_MODE_LEN];

	/**
	 * @specified:
	 *
	 * Has a mode been read from the command-line?
	 */
	bool specified;

	/**
	 * @refresh_specified:
	 *
	 * Did the mode have a preferred refresh rate?
	 */
	bool refresh_specified;

	/**
	 * @bpp_specified:
	 *
	 * Did the mode have a preferred BPP?
	 */
	bool bpp_specified;

	/**
	 * @xres:
	 *
	 * Active resolution on the X axis, in pixels.
	 */
	int xres;

	/**
	 * @yres:
	 *
	 * Active resolution on the Y axis, in pixels.
	 */
	int yres;

	/**
	 * @bpp:
	 *
	 * Bits per pixels for the mode.
	 */
	int bpp;

	/**
	 * @refresh:
	 *
	 * Refresh rate, in Hertz.
	 */
	int refresh;

	/**
	 * @rb:
	 *
	 * Do we need to use reduced blanking?
	 */
	bool rb;

	/**
	 * @interlace:
	 *
	 * The mode is interlaced.
	 */
	bool interlace;

	/**
	 * @cvt:
	 *
	 * The timings will be calculated using the VESA Coordinated
	 * Video Timings instead of looking up the mode from a table.
	 */
	bool cvt;

	/**
	 * @margins:
	 *
	 * Add margins to the mode calculation (1.8% of xres rounded
	 * down to 8 pixels and 1.8% of yres).
	 */
	bool margins;

	/**
	 * @force:
	 *
	 * Ignore the hotplug state of the connector, and force its
	 * state to one of the DRM_FORCE_* values.
	 */
	enum drm_connector_force force;

	/**
	 * @rotation_reflection:
	 *
	 * Initial rotation and reflection of the mode setup from the
	 * command line. See DRM_MODE_ROTATE_* and
	 * DRM_MODE_REFLECT_*. The only rotations supported are
	 * DRM_MODE_ROTATE_0 and DRM_MODE_ROTATE_180.
	 */
	unsigned int rotation_reflection;

	/**
	 * @panel_orientation:
	 *
	 * drm-connector "panel orientation" property override value,
	 * DRM_MODE_PANEL_ORIENTATION_UNKNOWN if not set.
	 */
	enum drm_panel_orientation panel_orientation;

	/**

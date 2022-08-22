// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Rockchip USB2.0 PHY with Innosilicon IP block driver
 *
 * Copyright (C) 2016 Fuzhou Rockchip Electronics Co., Ltd
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/extcon-provider.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/gpio/consumer.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/power_supply.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/mfd/syscon.h>
#include <linux/usb/of.h>
#include <linux/usb/otg.h>
#include <linux/wakelock.h>

#define BIT_WRITEABLE_SHIFT	16
#define SCHEDULE_DELAY		(60 * HZ)
#define OTG_SCHEDULE_DELAY	(1 * HZ)
#define BYPASS_SCHEDULE_DELAY	(2 * HZ)
#define FILTER_COUNTER		0xF4240

struct rockchip_usb2phy;

enum rockchip_usb2phy_port_id {
	USB2PHY_PORT_OTG,
	USB2PHY_PORT_HOST,
	USB2PHY_NUM_PORTS,
};

enum rockchip_usb2phy_host_state {
	PHY_STATE_HS_ONLINE	= 0,
	PHY_STATE_DISCONNECT	= 1,
	PHY_STATE_CONNECT	= 2,
	PHY_STATE_FS_LS_ONLINE	= 4,
};

/**
 * enum usb_chg_state - Different states involved in USB charger detection.
 * @USB_CHG_STATE_UNDEFINED:	USB charger is not connected or detection
 *				process is not yet started.
 * @USB_CHG_STATE_WAIT_FOR_DCD:	Waiting for Data pins contact.
 * @USB_CHG_STATE_DCD_DONE:	Data pin contact is detected.
 * @USB_CHG_STATE_PRIMARY_DONE:	Primary detection is completed (Detects
 *				between SDP and DCP/CDP).
 * @USB_CHG_STATE_SECONDARY_DONE: Secondary detection is completed (Detects
 *				  between DCP and CDP).
 * @USB_CHG_STATE_DETECTED:	USB charger type is determined.
 */
enum usb_chg_state {
	USB_CHG_STATE_UNDEFINED = 0,
	USB_CHG_STATE_WAIT_FOR_DCD,
	USB_CHG_STATE_DCD_DONE,
	USB_CHG_STATE_PRIMARY_DONE,
	USB_CHG_STATE_SECONDARY_DONE,
	USB_CHG_STATE_DETECTED,
};

static const unsigned int rockchip_usb2phy_extcon_cable[] = {
	EXTCON_USB,
	EXTCON_USB_HOST,
	EXTCON_USB_VBUS_EN,
	EXTCON_CHG_USB_SDP,
	EXTCON_CHG_USB_CDP,
	EXTCON_CHG_USB_DCP,
	EXTCON_CHG_USB_SLOW,
	EXTCON_NONE,
};

struct usb2phy_reg {
	unsigned int	offset;
	unsigned int	bitend;
	unsigned int	bitstart;
	unsigned int	disable;
	unsigned int	enable;
};

/**
 * struct rockchip_chg_det_reg - usb charger detect registers
 * @cp_det: charging port detected successfully.
 * @dcp_det: dedicated charging port detected successfully.
 * @dp_det: assert data pin connect successfully.
 * @idm_sink_en: open dm sink curren.
 * @idp_sink_en: open dp sink current.
 * @idp_src_en: open dm source current.
 * @rdm_pdwn_en: open dm pull down resistor.
 * @vdm_src_en: open dm voltage source.
 * @vdp_src_en: open dp voltage source.
 * @chg_mode: set phy in charge detection mode.
 */
struct rockchip_chg_det_reg {
	struct usb2phy_reg	cp_det;
	struct usb2phy_reg	dcp_det;
	struct usb2phy_reg	dp_det;
	struct usb2phy_reg	idm_sink_en;
	struct usb2phy_reg	idp_sink_en;
	struct usb2phy_reg	idp_src_en;
	struct usb2phy_reg	rdm_pdwn_en;
	struct usb2phy_reg	vdm_src_en;
	struct usb2phy_reg	vdp_src_en;
	struct usb2phy_reg	chg_mode;
};

/**
 * struct rockchip_usb2phy_port_cfg - usb-phy port configuration.
 * @phy_sus: phy suspend register.
 * @bvalid_det_en: vbus valid rise detection enable register.
 * @bvalid_det_st: vbus valid rise detection status register.
 * @bvalid_det_clr: vbus valid rise detection clear register.
 * @bvalid_grf_con: vbus valid software control.
 * @bypass_dm_en: usb bypass uart DM enable register.
 * @bypass_sel: usb bypass uart select register.
 * @bypass_iomux: usb bypass uart GRF iomux register.
 * @bypass_bc: bypass battery charging module.
 * @bypass_otg: bypass otg module.
 * @bypass_host: bypass host module.
 * @disfall_en: host disconnect fall edge detection enable.
 * @disfall_st: host disconnect fall edge detection state.
 * @disfall_clr: host disconnect fall edge detection clear.
 * @disrise_en: host disconnect rise edge detection enable.
 * @disrise_st: host disconnect rise edge detection state.
 * @disrise_clr: host disconnect rise edge detection clear.
 * @ls_det_en: linestate detection enable register.
 * @ls_det_st: linestate detection state register.
 * @ls_det_clr: linestate detection clear register.
 * @iddig_output: iddig output from grf.
 * @iddig_en: utmi iddig select between grf and phy,
 *	      0: from phy; 1: from grf
 * @idfall_det_en: id fall detection enable register.
 * @idfall_det_st: id fall detection state register.
 * @idfall_det_clr: id fall detection clear register.
 * @idrise_det_en: id rise detection enable register.
 * @idrise_det_st: id rise detection state register.
 * @idrise_det_clr: id rise detection clear register.
 * @utmi_avalid: utmi vbus avalid status register.
 * @utmi_bvalid: utmi vbus bvalid status register.
 * @utmi_iddig: otg port id pin status register.
 * @utmi_ls: utmi linestate state register.
 * @utmi_hstdet: utmi host disconnect register.
 * @vbus_det_en: vbus detect function power down register.
 */
struct rockchip_usb2phy_port_cfg {
	struct usb2phy_reg	phy_sus;
	struct usb2phy_reg	bvalid_det_en;
	struct usb2phy_reg	bvalid_det_st;
	struct usb2phy_reg	bvalid_det_clr;
	struct usb2phy_reg	bvalid_grf_con;
	struct usb2phy_reg	bypass_dm_en;
	struct usb2phy_reg	bypass_sel;
	struct usb2phy_reg	bypass_iomux;
	struct usb2phy_reg	bypass_bc;
	struct usb2phy_reg	bypass_otg;
	struct usb2phy_reg	bypass_host;
	struct usb2phy_reg	disfall_en;
	struct usb2phy_reg	disfall_st;
	struct usb2phy_reg	disfall_clr;
	struct usb2phy_reg	disrise_en;
	struct usb2phy_reg	disrise_st;
	struct usb2phy_reg	disrise_clr;
	struct usb2phy_reg	ls_det_en;
	struct usb2phy_reg	ls_det_st;
	struct usb2phy_reg	ls_det_clr;
	struct usb2phy_reg	iddig_output;
	struct usb2phy_reg	iddig_en;
	struct usb2phy_reg	idfall_det_en;
	struct usb2phy_reg	idfall_det_st;
	struct usb2phy_reg	idfall_det_clr;
	struct usb2phy_reg	idrise_det_en;
	struct usb2phy_reg	idrise_det_st;
	struct usb2phy_reg	idrise_det_clr;
	struct usb2phy_reg	utmi_avalid;
	struct usb2phy_reg	utmi_bvalid;
	struct usb2phy_reg	utmi_iddig;
	struct usb2phy_reg	utmi_ls;
	struct usb2phy_reg	utmi_hstdet;
	struct usb2phy_reg	vbus_det_en;
};

/**
 * struct rockchip_usb2phy_cfg - usb-phy configuration.
 * @reg: the address offset of grf for usb-phy config.
 * @num_ports: specify how many ports that the phy has.
 * @phy_tuning: phy default parameters tuning.
 * @vbus_detect: vbus voltage level detection function.
 * @clkout_ctl: keep on/turn off output clk of phy.
 * @port_cfgs: usb-phy port configurations.
 * @chg_det: charger detection registers.
 */
struct rockchip_usb2phy_cfg {
	unsigned int	reg;
	unsigned int	num_ports;
	int (*phy_tuning)(struct rockchip_usb2phy *rphy);
	int (*vbus_detect)(struct rockchip_usb2phy *rphy, bool en);
	struct usb2phy_reg	clkout_ctl;
	const struct rockchip_usb2phy_port_cfg	port_cfgs[USB2PHY_NUM_PORTS];
	const struct rockchip_chg_det_reg	chg_det;
};

/**
 * struct rockchip_usb2phy_port - usb-phy port data.
 * @phy: generic phy.
 * @port_id: flag for otg port or host port.
 * @low_power_en: enable enter low power when suspend.
 * @perip_connected: flag for periphyeral connect status.
 * @prev_iddig: previous otg port id pin status.
 * @suspended: phy suspended flag.
 * @typec_vbus_det: Type-C otg vbus detect.
 * @utmi_avalid: utmi avalid status usage flag.
 *	true	- use avalid to get vbus status
 *	false	- use bvalid to get vbus status
 * @vbus_attached: otg device vbus status.
 * @vbus_always_on: otg vbus is always powered on.
 * @vbus_enabled: vbus regulator status.
 * @bypass_uart_en: usb bypass uart enable, passed from DT.
 * @host_disconnect: usb host disconnect status.
 * @bvalid_irq: IRQ number assigned for vbus valid rise detection.
 * @ls_irq: IRQ number assigned for linestate detection.
 * @id_irq: IRQ number assigned for id fall or rise detection.
 * @otg_mux_irq: IRQ number which multiplex otg-id/otg-bvalid/linestate
 *		 irqs to one irq in otg-port.
 * @mutex: for register updating in sm_work.
 * @chg_work: charge detect work.
 * @bypass_uart_work: usb bypass uart work.
 * @otg_sm_work: OTG state machine work.
 * @sm_work: HOST state machine work.
 * @vbus: vbus regulator supply on few rockchip boards.
 * @port_cfg: port register configuration, assigned by driver data.
 * @event_nb: hold event notification callback.
 * @state: define OTG enumeration states before device reset.
 * @mode: the dr_mode of the controller.
 */
struct rockchip_usb2phy_port {
	struct phy	*phy;
	unsigned int	port_id;
	bool		low_power_en;
	bool		perip_connected;
	bool		prev_iddig;
	bool		suspended;
	bool		typec_vbus_det;
	bool		utmi_avalid;
	bool		vbus_attached;
	bool		vbus_always_on;
	bool		vbus_enabled;
	bool		bypass_uart_en;
	bool		host_disconnect;
	int		bvalid_irq;
	int		ls_irq;
	int             id_irq;
	int		otg_mux_irq;
	struct mutex	mutex;
	struct		delayed_work bypass_uart_work;
	struct		delayed_work chg_work;
	struct		delayed_work otg_sm_work;
	struct		delayed_work sm_work;
	struct		regulator *vbus;
	const struct	rockchip_usb2phy_port_cfg *port_cfg;
	struct notifier_block	event_nb;
	struct wake_lock	wakelock;
	enum usb_otg_state	state;
	enum usb_dr_mode	mode;
};

/**
 * struct rockchip_usb2phy - usb2.0 phy driver data.
 * @dev: pointer to device.
 * @grf: General Register Files regmap.
 * @usbgrf: USB General Register Files regmap.
 * *phy_base: the base address of USB PHY.
 * @phy_reset: phy reset control.
 * @clk: clock struct of phy input clk.
 * @clk480m: clock struct of phy output clk.
 * @clk480m_hw: clock struct of phy output clk management.
 * @chg_state: states involved in USB charger detection.
 * @chg_type: USB charger types.
 * @dcd_retries: The retry count used to track Data contact
 *		 detection process.
 * @primary_retries: The retry count used for charger
 *		     detection primary phase.
 * @phy_sus_cfg: Store the phy current suspend configuration.
 * @edev_self: represent the source of extcon.
 * @irq: IRQ number assigned for phy which combined irqs of
 *	 otg port and host port.
 * @edev: extcon device for notification registration
 * @phy_cfg: phy register configuration, assigned by driver data.
 * @ports: phy port instance.
 */
struct rockchip_usb2phy {
	struct device	*dev;
	struct regmap	*grf;
	struct regmap	*usbgrf;
	void __iomem	*phy_base;
	struct reset_control	*phy_reset;
	struct clk	*clk;
	struct clk	*clk480m;
	struct clk_hw	clk480m_hw;
	enum usb_chg_state	chg_state;
	enum power_supply_type	chg_type;
	u8			dcd_retries;
	u8			primary_retries;
	unsigned int		phy_sus_cfg;
	bool			edev_self;
	int			irq;
	struct extcon_dev	*edev;
	const struct rockchip_usb2phy_cfg	*phy_cfg;
	struct rockchip_usb2phy_port	ports[USB2PHY_NUM_PORTS];
};

static inline struct regmap *get_reg_base(struct rockchip_usb2phy *rphy)
{
	return rphy->usbgrf == NULL ? rphy->grf : rphy->usbgrf;
}

static inline int property_enable(struct regmap *base,
				  const struct usb2phy_reg *reg, bool en)
{
	unsigned int val, mask, tmp;

	tmp = en ? reg->enable : reg->disable;
	mask = GENMASK(reg->bitend, reg->bitstart);
	val = (tmp << reg->bitstart) | (mask << BIT_WRITEABLE_SHIFT);

	return regmap_write(base, reg->offset, val);
}

static inline bool property_enabled(struct regmap *base,
				    const struct usb2phy_reg *reg)
{
	int ret;
	unsigned int tmp, orig;
	unsigned int mask = GENMASK(reg->bitend, reg->bitstart);

	ret = regmap_read(base, reg->offset, &orig);
	if (ret)
		return false;

	tmp = (orig & mask) >> reg->bitstart;
	return tmp == reg->enable;
}

static int rockchip_usb2phy_reset(struct rockchip_usb2phy *rphy)
{
	int ret;

	ret = reset_control_assert(rphy->phy_reset);
	if (ret)
		return ret;

	udelay(10);

	ret = reset_control_deassert(rphy->phy_reset);
	if (ret)
		return ret;

	usleep_range(100, 200);

	return 0;
}

static int rockchip_usb2phy_clk480m_prepare(struct clk_hw *hw)
{
	struct rockchip_usb2phy *rphy =
		container_of(hw, struct rockchip_usb2phy, clk480m_hw);
	struct regmap *base = get_reg_base(rphy);
	int ret;

	/* turn on 480m clk output if it is off */
	if (!property_enabled(base, &rphy->phy_cfg->clkout_ctl)) {
		ret = property_enable(base, &rphy->phy_cfg->clkout_ctl, true);
		if (ret)
			return ret;

		/* waiting for the clk become stable */
		usleep_range(1200, 1300);
	}

	return 0;
}

static void rockchip_usb2phy_clk480m_unprepare(struct clk_hw *hw)
{
	struct rockchip_usb2phy *rphy =
		container_of(hw, struct rockchip_usb2phy, clk480m_hw);
	struct regmap *base = get_reg_base(rphy);

	/* turn off 480m clk output */
	property_enable(base, &rphy->phy_cfg->clkout_ctl, false);
}

static int rockchip_usb2phy_clk480m_prepared(struct clk_hw *hw)
{
	struct rockchip_usb2phy *rphy =
		container_of(hw, struct rockchip_usb2phy, clk480m_hw);
	struct regmap *base = get_reg_base(rphy);

	return property_enabled(base, &rphy->phy_cfg->clkout_ctl);
}

static unsigned long
rockchip_usb2phy_clk480m_recalc_rate(struct clk_hw *hw,
				     unsigned long parent_rate)
{
	return 480000000;
}

static const struct clk_ops rockchip_usb2phy_clkout_ops = {
	.prepare = rockchip_usb2phy_clk480m_prepare,
	.unprepare = rockchip_usb2phy_clk480m_unprepare,
	.is_prepared = rockchip_usb2phy_clk480m_prepared,
	.recalc_rate = rockchip_usb2phy_clk480m_recalc_rate,
};

static void rockchip_usb2phy_clk480m_unregister(void *data)
{
	struct rockchip_usb2phy *rphy = data;

	of_clk_del_provider(rphy->dev->of_node);
	clk_unregister(rphy->clk480m);
}

static int
rockchip_usb2phy_clk480m_register(struct rockchip_usb2phy *rphy)
{
	struct device_node *node = rphy->dev->of_node;
	struct clk_init_data init = {};
	const char *clk_name;
	int ret;

	init.flags = 0;
	init.name = "clk_usbphy_480m";
	init.ops = &rockchip_usb2phy_clkout_ops;

	/* optional override of the clockname */
	of_property_read_string(node, "clock-output-names", &init.name);

	if (rphy->clk) {
		clk_name = __clk_get_name(rphy->clk);
		init.parent_names = &clk_name;
		init.num_parents = 1;
	} else {
		init.parent_names = NULL;
		init.num_parents = 0;
	}

	rphy->clk480m_hw.init = &init;

	/* register the clock */
	rphy->clk480m = clk_register(rphy->dev, &rphy->clk480m_hw);
	if (IS_ERR(rphy->clk480m)) {
		ret = PTR_ERR(rphy->clk480m);
		goto err_ret;
	}

	ret = of_clk_add_provider(node, of_clk_src_simple_get, rphy->clk480m);
	if (ret < 0)
		goto err_clk_provider;

	ret = devm_add_action(rphy->dev, rockchip_usb2phy_clk480m_unregister,
			      rphy);
	if (ret < 0)
		goto err_unreg_action;

	return 0;

err_unreg_action:
	of_clk_del_provider(node);
err_clk_provider:
	clk_unregister(rphy->clk480m);
err_ret:
	return ret;
}

static int rockchip_usb2phy_extcon_register(struct rockchip_usb2phy *rphy)
{
	int ret;
	struct device_node *node = rphy->dev->of_node;
	struct extcon_dev *edev;

	if (of_property_read_bool(node, "extcon")) {
		edev = extcon_get_edev_by_phandle(rphy->dev, 0);
		if (IS_ERR(edev)) {
			if (PTR_ERR(edev) != -EPROBE_DEFER)
				dev_err(rphy->dev, "Invalid or missing extcon\n");
			return PTR_ERR(edev);
		}
	} else {
		/* Initialize extcon device */
		edev = devm_extcon_dev_allocate(rphy->dev,
						rockchip_usb2phy_extcon_cable);

		if (IS_ERR(edev))
			return -ENOMEM;

		ret = devm_extcon_dev_register(rphy->dev, edev);
		if (ret) {
			dev_err(rphy->dev, "failed to register extcon device\n");
			return ret;
		}

		rphy->edev_self = true;
	}

	rphy->edev = edev;

	return 0;
}

/* The caller must hold rport->mutex lock */
static int rockchip_usb2phy_enable_id_irq(struct rockchip_usb2phy *rphy,
					  struct rockchip_usb2phy_port *rport,
					  bool en)
{
	int ret;

	ret = property_enable(rphy->grf, &rport->port_cfg->idfall_det_clr, true);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->idfall_det_en, en);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->idrise_det_clr, true);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->idrise_det_en, en);
out:
	return ret;
}

/* The caller must hold rport->mutex lock */
static int rockchip_usb2phy_enable_vbus_irq(struct rockchip_usb2phy *rphy,
					    struct rockchip_usb2phy_port *rport,
					    bool en)
{
	int ret;

	ret = property_enable(rphy->grf, &rport->port_cfg->bvalid_det_clr, true);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->bvalid_det_en, en);
out:
	return ret;
}

static int rockchip_usb2phy_enable_line_irq(struct rockchip_usb2phy *rphy,
					    struct rockchip_usb2phy_port *rport,
					    bool en)
{
	int ret;

	ret = property_enable(rphy->grf, &rport->port_cfg->ls_det_clr, true);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->ls_det_en, en);
out:
	return ret;
}

static int rockchip_usb2phy_enable_host_disc_irq(struct rockchip_usb2phy *rphy,
						 struct rockchip_usb2phy_port *rport,
						 bool en)
{
	int ret;

	ret = property_enable(rphy->grf, &rport->port_cfg->disfall_clr, true);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->disfall_en, en);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->disrise_clr, true);
	if (ret)
		goto out;

	ret = property_enable(rphy->grf, &rport->port_cfg->disrise_en, en);
out:
	return ret;
}

static int rockchip_usb_bypass_uart(struct rockchip_usb2phy_port *rport,
				    bool en)
{
	struct rockchip_usb2phy *rphy = dev_get_drvdata(rport->phy->dev.parent);
	const struct usb2phy_reg *iomux = &rport->port_cfg->bypass_iomux;
	struct regmap *base = get_reg_base(rphy);
	int ret = 0;

	mutex_lock(&rport->mutex);

	if (en == property_enabled(base, &rport->port_cfg->bypass_sel)) {
		dev_info(&rport->phy->dev,
			 "bypass uart %s is already set\n", en ? "on" : "off");
		goto unlock;
	}

	dev_info(&rport->phy->dev, "bypass uart %s\n", en ? "on" : "off");

	if (en) {
		/*
		 * To use UART function:
		 * 1. Put the USB PHY in suspend mode and opmode is normal;
		 * 2. Set bypasssel to 1'b1 and bypassdmen to 1'b1;
		 *
		 * Note: Although the datasheet requires that put USB PHY
		 * in non-driving mode to disable resistance when use USB
		 * bypass UART function, but actually we find that if we
		 * set phy in non-driving mode, it will cause UART to print
		 * random codes. So just put USB PHY in normal mode.
		 */
		ret |= property_enable(base, &rport->port_cfg->bypass_sel,
				       true);
		ret |= property_enable(base, &rport->port_cfg->bypass_dm_en,
				       true);

		/* Some platforms required to set iomux of bypass uart */
		if (iomux->offset)
			ret |= property_enable(rphy->grf, iomux, true);
	} else {
		/* just disable bypass, and resume phy in phy power_on later */
		ret |= property_enable(base, &rport->port_cfg->bypass_sel,
				       false);
		ret |= property_enable(base, &rport->port_cfg->bypass_dm_en,
				       false);

		/* Some platforms required to set iomux of bypass uart */
		if (iomux->offset)
			ret |= property_enable(rphy->grf, iomux, false);
	}

unlock:
	mutex_unlock(&rport->mutex);

	return ret;
}

static void rockchip_usb_bypass_uart_work(struct work_struct *work)
{
	struct rockchip_usb2phy_port *rport =
		container_of(work, struct rockchip_usb2phy_port,
			     bypass_uart_work.work);
	struct rockchip_usb2phy *rphy = dev_get_drvdata(rport->phy->dev.parent);
	bool vbus, iddig;
	int ret;

	mutex_lock(&rport->mutex);

	iddig = property_enabled(rphy->grf, &rport->port_cfg->utmi_iddig);

	if (rport->utmi_avalid)
		vbus = property_enabled(rphy->grf, &rport->port_cfg->utmi_avalid);
	else
		vbus = property_enabled(rphy->grf, &rport->port_cfg->utmi_bvalid);

	mutex_unlock(&rport->mutex);

	/*
	 * If the vbus is low and iddig is high, it indicates that usb
	 * otg is not working, then we can enable usb to bypass uart,
	 * otherwise schedule the work until the conditions (vbus is low
	 * and iddig is high) are matched.
	 */
	if (!vbus && iddig) {
		ret = rockchip_usb_bypass_uart(rport, true);
		if (ret)
			dev_warn(&rport->phy->dev,
				 "failed to enable bypass uart\n");
	} else {
		schedule_delayed_work(&rport->bypass_uart_work,
				      BYPASS_SCHEDULE_DELAY);
	}
}

static int rockchip_usb2phy_init(struct phy *phy)
{
	struct rockchip_usb2phy_port *rport = phy_get_drvdata(phy);
	struct rockchip_usb2phy *rphy = dev_get_drvdata(phy->dev.parent);
	int ret = 0;

	mutex_lock(&rport->mutex);

	if (rport->port_id == USB2PHY_PORT_OTG &&
	    (rport->mode == USB_DR_MODE_PERIPHERAL ||
	     rport->mode == USB_DR_MODE_OTG)) {
		/* clear id status and enable id detect irq */
		if (rport->id_irq > 0 || rport->otg_mux_irq > 0 ||
		    rphy->irq > 0) {
			ret = rockchip_usb2phy_enable_id_irq(rphy, rport,
							     true);
			if (ret) {
				dev_err(rphy->dev,
					"failed to enable id irq\n");
				goto out;
			}
		}

		/* clear bvalid status and enable bvalid detect irq */
		if ((rport->bvalid_irq > 0 || rport->otg_mux_irq > 0 ||
		    rphy->irq > 0) && !rport->vbus_always_on) {
			ret = rockchip_usb2phy_enable_vbus_irq(rphy, rport,
							       true);
			if (ret) {
				dev_err(rphy->dev,
					"failed to enable bvalid irq\n");
				goto out;
			}

			schedule_delayed_work(&rport->otg_sm_work, 0);
		}
	} else if (rport->port_id == USB2PHY_PORT_HOST) {
		if (rport->port_cfg->disfall_en.offset) {
			rport->host_disconnect = true;
			ret = rockchip_usb2phy_enable_host_disc_irq(rphy, rport, true);
			if (ret) {
				dev_err(rphy->dev, "failed to enable disconnect irq\n");
				goto out;
			}
		}

		/* clear linestate and enable linestate detect irq */
		ret = rockchip_usb2phy_enable_line_irq(rphy, rport, true);
		if (ret) {
			dev_err(rphy->dev, "failed to enable linestate irq\n");
			goto out;
		}

		schedule_delayed_work(&rport->sm_work, SCHEDULE_DELAY);
	}

out:
	mutex_unlock(&rport->mutex);
	return ret;
}

static int rockchip_usb2phy_power_on(struct phy *phy)
{
	struct rockchip_usb2phy_port *rport = phy_get_drvdata(phy);
	struct rockchip_usb2phy *rphy = dev_get_drvdata(phy->dev.parent);
	struct regmap *base = get_reg_base(rphy);
	int ret;

	dev_dbg(&rport->phy->dev, "port power on\n");

	if (rport->bypass_uart_en) {
		ret = rockchip_usb_bypass_uart(rport, false);
		if (ret) {
			dev_warn(&rport->phy->dev,
				 "failed to disable bypass uart\n");
			goto exit;
		}
	}

	mutex_lock(&rport->mutex);

	if (!rport->suspended) {
		ret = 0;
		goto unlock;
	}

	ret = clk_prepare_enable(rphy->clk480m);
	if (ret)
		goto unlock;

	ret = property_enable(base, &rport->port_cfg->phy_sus, false);
	if (ret)
		goto unlock;

	/*
	 * For rk3588, it needs to reset phy when exit from
	 * suspend mode with common_on_n 1'b1(aka REFCLK_LOGIC,
	 * Bias, and PLL blocks are powered down) for lower
	 * power consumption. If you don't want to reset phy,
	 * please keep the common_on_n 1'b0 to set these blocks
	 * remain powered.
	 */
	ret = rockchip_usb2phy_reset(rphy);
	if (ret)
		goto unlock;

	/* waiting for the utmi_clk to become stable */
	usleep_range(1500, 2000);

	rport->suspended = false;

unlock:
	mutex_unlock(&rport->mutex);

	/* Enable bypass uart in the bypass_uart_work. */
	if (rport->bypass_uart_en)
		schedule_delayed_work(&rport->bypass_uart_work, 0);

exit:
	return ret;
}

static int rockchip_usb2phy_power_off(struct phy *phy)
{
	struct rockchip_usb2phy_port *rport = phy_get_drvdata(phy);
	struct rockchip_usb2phy *rphy = dev_get_drvdata(phy->dev.parent);
	struct regmap *base = get_reg_base(rphy);
	int ret;

	dev_dbg(&rport->phy->dev, "port power off\n");

	mutex_lock(&rport->mutex);

	if (rport->suspended) {
		ret = 0;
		goto unlock;
	}

	ret = property_enable(base, &rport->port_cfg->phy_sus, true);
	if (ret)
		goto unlock;

	rport->suspended = true;
	clk_disable_unprepare(rphy->clk480m);

unlock:
	mutex_unlock(&rport->mutex);

	/* Enable bypass uart in the bypass_uart_work. */
	if (rport->bypass_uart_en)
		schedule_delayed_work(&rport->bypass_uart_work, 0);

	return ret;
}

static int rockchip_usb2phy_exit(struct phy *phy)
{
	struct rockchip_usb2phy_port *rport = phy_get_drvdata(phy);

	if (rport->port_id == USB2PHY_PORT_HOST)
		cancel_delayed_work_sync(&rport->sm_work);
	else if (rport->port_id == USB2PHY_PORT_OTG &&
		 rport->bvalid_irq > 0)
		flush_delayed_work(&rport->otg_sm_work);

	return 0;
}

static int rockchip_set_vbus_power(struct rockchip_usb2phy_port *rport,
				   bool en)
{
	int ret = 0;

	if (!rport->vbus)
		return 0;

	if (en && !rport->vbus_enabled) {
		ret = regulator_enable(rport->vbus);
		if (ret)
			dev_err(&rport->phy->dev,
				"Failed to enable VBUS supply\n");
	} else if (!en && rport->vbus_enabled) {
		ret = regulator_disable(rport->vbus);
	}

	if (ret == 0)
		rport->vbus_enabled = en;

	return ret;
}

static int rockchip_usb2phy_set_mode(struct phy *phy,
				     enum phy_mode mode, int submode)
{
	struct rockchip_usb2phy_port *rport = phy_get_drvdata(phy);
	struct rockchip_usb2phy *rphy = dev_get_drvdata(phy->dev.parent);
	bool vbus_det_en;
	int ret = 0;

	if (rport->port_id != USB2PHY_PORT_OTG)
		return ret;

	switch (mode) {
	case PHY_MODE_USB_OTG:
		/*
		 * In case of using vbus to detect connect state by u2phy,
		 * enable vbus detect on otg mode.
		 */
		fallthrough;
	case PHY_MODE_USB_DEVICE:
		/* Disable VBUS supply */
		rockchip_set_vbus_power(rport, false);
		extcon_set_state_sync(rphy->edev, EXTCON_USB_VBUS_EN, false);
		/* For vbus always on, set EXTCON_USB to true. */
		extcon_set_state(rphy->edev, EXTCON_USB, true);
		rport->perip_connected = true;
		vbus_det_en = true;
		break;
	case PHY_MODE_USB_HOST:
		/* Enable VBUS supply */
		ret = rockchip_set_vbus_power(rport, true);
		if (ret) {
			dev_err(&rport->phy->dev,
				"Failed to set host mode\n");
			return ret;
		}

		extcon_set_state_sync(rphy->edev, EXTCON_USB_VBUS_EN, true);
		/* For vbus always on, deinit EXTCON_USB to false. */
		extcon_set_state(rphy->edev, EXTCON_USB, false);
		rport->perip_connected = false;
		fallthrough;
	case PHY_MODE_INVALID:
		vbus_det_en = false;
		break;
	default:
		dev_info(&rport->phy->dev, "illegal mode\n");
		return ret;
	}

	if (rphy->phy_cfg->vbus_detect)
		rphy->phy_cfg->vbus_detect(rphy, vbus_det_en);
	else
		ret = property_enable(rphy->grf, &rport->port_cfg->vbus_det_en,
				      vbus_det_en);

	return ret;
}

static const struct phy_ops rockchip_usb2phy_ops = {
	.init		= rockchip_usb2phy_init,
	.exit		= rockchip_usb2phy_exit,
	.power_on	= rockchip_usb2phy_power_on,
	.power_off	= rockchip_usb2phy_power_off,
	.set_mode	= rockchip_usb2phy_set_mode,
	.owner		= THIS_MODULE,
};

/* Show & store the current value of otg mode for otg port */
static ssize_t otg_mode_show(struct device *device,
			     struct device_attribute *attr,
			     char *buf)
{
	struct rockchip_usb2phy *rphy = dev_get_drvdata(device);
	struct rockchip_usb2phy_port *rport = NULL;
	unsigned int index;

	for (index = 0; index < rphy->phy_cfg->num_ports; index++) {
		rport = &rphy->ports[index];
		if (rport->port_id == USB2PHY_PORT_OTG)
			break;
	}

	if (!rport) {
		dev_err(rphy->dev, "Fail to get otg port\n");
		return -EINVAL;
	} else if (rport->port_id != USB2PHY_PORT_OTG) {
		dev_err(rphy->dev, "No support otg\n");
		return -EINVAL;
	}

	switch (rport->mode) {
	case USB_DR_MODE_HOST:
		return sprintf(buf, "host\n");
	case USB_DR_MODE_PERIPHERAL:
		return sprintf(buf, "peripheral\n");
	case USB_DR_MODE_OTG:
		return sprintf(buf, "otg\n");
	case USB_DR_MODE_UNKNOWN:
		return sprintf(buf, "UNKNOWN\n");
	}

	return -EINVAL;
}

static ssize_t otg_mode_store(struct device *device,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct rockchip_usb2phy *rphy = dev_get_drvdata(device);
	struct rockchip_usb2phy_port *rport = NULL;
	struct regmap *base = get_reg_base(rphy);
	enum usb_dr_mode new_dr_mode;
	unsigned int index;
	int rc = count;

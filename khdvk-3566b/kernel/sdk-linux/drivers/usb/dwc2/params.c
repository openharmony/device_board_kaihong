// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * Copyright (C) 2004-2016 Synopsys, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the above-listed copyright holders may not be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_device.h>

#include "core.h"

static void dwc2_set_bcm_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->host_rx_fifo_size = 774;
	p->max_transfer_size = 65535;
	p->max_packet_count = 511;
	p->ahbcfg = 0x10;
}

static void dwc2_set_his_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->otg_cap = DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE;
	p->speed = DWC2_SPEED_PARAM_HIGH;
	p->host_rx_fifo_size = 512;
	p->host_nperio_tx_fifo_size = 512;
	p->host_perio_tx_fifo_size = 512;
	p->max_transfer_size = 65535;
	p->max_packet_count = 511;
	p->host_channels = 16;
	p->phy_type = DWC2_PHY_TYPE_PARAM_UTMI;
	p->phy_utmi_width = 8;
	p->i2c_enable = false;
	p->reload_ctl = false;
	p->ahbcfg = GAHBCFG_HBSTLEN_INCR16 <<
		GAHBCFG_HBSTLEN_SHIFT;
	p->change_speed_quirk = true;
	p->power_down = DWC2_POWER_DOWN_PARAM_NONE;
}

static void dwc2_set_s3c6400_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->power_down = DWC2_POWER_DOWN_PARAM_NONE;
	p->phy_utmi_width = 8;
}

static void dwc2_set_rk_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->otg_cap = DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE;
	p->host_rx_fifo_size = 525;
	p->host_nperio_tx_fifo_size = 128;
	p->host_perio_tx_fifo_size = 256;
	p->ahbcfg = GAHBCFG_HBSTLEN_INCR16 <<
		GAHBCFG_HBSTLEN_SHIFT;
	p->power_down = DWC2_POWER_DOWN_PARAM_NONE;
	p->lpm = false;
	p->g_dma_desc = false;
}

static void dwc2_set_ltq_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->otg_cap = 2;
	p->host_rx_fifo_size = 288;
	p->host_nperio_tx_fifo_size = 128;
	p->host_perio_tx_fifo_size = 96;
	p->max_transfer_size = 65535;
	p->max_packet_count = 511;
	p->ahbcfg = GAHBCFG_HBSTLEN_INCR16 <<
		GAHBCFG_HBSTLEN_SHIFT;
}

static void dwc2_set_amlogic_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->otg_cap = DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE;
	p->speed = DWC2_SPEED_PARAM_HIGH;
	p->host_rx_fifo_size = 512;
	p->host_nperio_tx_fifo_size = 500;
	p->host_perio_tx_fifo_size = 500;
	p->host_channels = 16;
	p->phy_type = DWC2_PHY_TYPE_PARAM_UTMI;
	p->ahbcfg = GAHBCFG_HBSTLEN_INCR8 <<
		GAHBCFG_HBSTLEN_SHIFT;
	p->power_down = DWC2_POWER_DOWN_PARAM_NONE;
}

static void dwc2_set_amlogic_g12a_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->lpm = false;
	p->lpm_clock_gating = false;
	p->besl = false;
	p->hird_threshold_en = false;
}

static void dwc2_set_amcc_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->ahbcfg = GAHBCFG_HBSTLEN_INCR16 << GAHBCFG_HBSTLEN_SHIFT;
}

static void dwc2_set_stm32f4x9_fsotg_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->otg_cap = DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE;
	p->speed = DWC2_SPEED_PARAM_FULL;
	p->host_rx_fifo_size = 128;
	p->host_nperio_tx_fifo_size = 96;
	p->host_perio_tx_fifo_size = 96;
	p->max_packet_count = 256;
	p->phy_type = DWC2_PHY_TYPE_PARAM_FS;
	p->i2c_enable = false;
	p->activate_stm_fs_transceiver = true;
}

static void dwc2_set_stm32f7_hsotg_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->host_rx_fifo_size = 622;
	p->host_nperio_tx_fifo_size = 128;
	p->host_perio_tx_fifo_size = 256;
}

static void dwc2_set_stm32mp15_fsotg_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->otg_cap = DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE;
	p->speed = DWC2_SPEED_PARAM_FULL;
	p->host_rx_fifo_size = 128;
	p->host_nperio_tx_fifo_size = 96;
	p->host_perio_tx_fifo_size = 96;
	p->max_packet_count = 256;
	p->phy_type = DWC2_PHY_TYPE_PARAM_FS;
	p->i2c_enable = false;
	p->activate_stm_fs_transceiver = true;
	p->activate_stm_id_vb_detection = true;
	p->ahbcfg = GAHBCFG_HBSTLEN_INCR16 << GAHBCFG_HBSTLEN_SHIFT;
	p->power_down = DWC2_POWER_DOWN_PARAM_NONE;
	p->host_support_fs_ls_low_power = true;
	p->host_ls_low_power_phy_clk = true;
}

static void dwc2_set_stm32mp15_hsotg_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->otg_cap = DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE;
	p->activate_stm_id_vb_detection = !device_property_read_bool(hsotg->dev, "usb-role-switch");
	p->host_rx_fifo_size = 440;
	p->host_nperio_tx_fifo_size = 256;
	p->host_perio_tx_fifo_size = 256;
	p->ahbcfg = GAHBCFG_HBSTLEN_INCR16 << GAHBCFG_HBSTLEN_SHIFT;
	p->power_down = DWC2_POWER_DOWN_PARAM_NONE;
	p->lpm = false;
	p->lpm_clock_gating = false;
	p->besl = false;
	p->hird_threshold_en = false;
}

const struct of_device_id dwc2_of_match_table[] = {
	{ .compatible = "brcm,bcm2835-usb", .data = dwc2_set_bcm_params },
	{ .compatible = "hisilicon,hi6220-usb", .data = dwc2_set_his_params  },
	{ .compatible = "rockchip,rk3066-usb", .data = dwc2_set_rk_params },
	{ .compatible = "lantiq,arx100-usb", .data = dwc2_set_ltq_params },
	{ .compatible = "lantiq,xrx200-usb", .data = dwc2_set_ltq_params },
	{ .compatible = "snps,dwc2" },
	{ .compatible = "samsung,s3c6400-hsotg",
	  .data = dwc2_set_s3c6400_params },
	{ .compatible = "amlogic,meson8-usb",
	  .data = dwc2_set_amlogic_params },
	{ .compatible = "amlogic,meson8b-usb",
	  .data = dwc2_set_amlogic_params },
	{ .compatible = "amlogic,meson-gxbb-usb",
	  .data = dwc2_set_amlogic_params },
	{ .compatible = "amlogic,meson-g12a-usb",
	  .data = dwc2_set_amlogic_g12a_params },
	{ .compatible = "amcc,dwc-otg", .data = dwc2_set_amcc_params },
	{ .compatible = "apm,apm82181-dwc-otg", .data = dwc2_set_amcc_params },
	{ .compatible = "st,stm32f4x9-fsotg",
	  .data = dwc2_set_stm32f4x9_fsotg_params },
	{ .compatible = "st,stm32f4x9-hsotg" },
	{ .compatible = "st,stm32f7-hsotg",
	  .data = dwc2_set_stm32f7_hsotg_params },
	{ .compatible = "st,stm32mp15-fsotg",
	  .data = dwc2_set_stm32mp15_fsotg_params },
	{ .compatible = "st,stm32mp15-hsotg",
	  .data = dwc2_set_stm32mp15_hsotg_params },
	{},
};
MODULE_DEVICE_TABLE(of, dwc2_of_match_table);

static void dwc2_set_param_otg_cap(struct dwc2_hsotg *hsotg)
{
	u8 val;

	switch (hsotg->hw_params.op_mode) {
	case GHWCFG2_OP_MODE_HNP_SRP_CAPABLE:
		val = DWC2_CAP_PARAM_HNP_SRP_CAPABLE;
		break;
	case GHWCFG2_OP_MODE_SRP_ONLY_CAPABLE:
	case GHWCFG2_OP_MODE_SRP_CAPABLE_DEVICE:
	case GHWCFG2_OP_MODE_SRP_CAPABLE_HOST:
		val = DWC2_CAP_PARAM_SRP_ONLY_CAPABLE;
		break;
	default:
		val = DWC2_CAP_PARAM_NO_HNP_SRP_CAPABLE;
		break;
	}

	hsotg->params.otg_cap = val;
}

static void dwc2_set_param_phy_type(struct dwc2_hsotg *hsotg)
{
	int val;
	u32 hs_phy_type = hsotg->hw_params.hs_phy_type;

	val = DWC2_PHY_TYPE_PARAM_FS;
	if (hs_phy_type != GHWCFG2_HS_PHY_TYPE_NOT_SUPPORTED) {
		if (hs_phy_type == GHWCFG2_HS_PHY_TYPE_UTMI ||
		    hs_phy_type == GHWCFG2_HS_PHY_TYPE_UTMI_ULPI)
			val = DWC2_PHY_TYPE_PARAM_UTMI;
		else
			val = DWC2_PHY_TYPE_PARAM_ULPI;
	}

	if (dwc2_is_fs_iot(hsotg))
		hsotg->params.phy_type = DWC2_PHY_TYPE_PARAM_FS;

	hsotg->params.phy_type = val;
}

static void dwc2_set_param_speed(struct dwc2_hsotg *hsotg)
{
	int val;

	val = hsotg->params.phy_type == DWC2_PHY_TYPE_PARAM_FS ?
		DWC2_SPEED_PARAM_FULL : DWC2_SPEED_PARAM_HIGH;

	if (dwc2_is_fs_iot(hsotg))
		val = DWC2_SPEED_PARAM_FULL;

	if (dwc2_is_hs_iot(hsotg))
		val = DWC2_SPEED_PARAM_HIGH;

	hsotg->params.speed = val;
}

static void dwc2_set_param_phy_utmi_width(struct dwc2_hsotg *hsotg)
{
	int val;

	val = (hsotg->hw_params.utmi_phy_data_width ==
	       GHWCFG4_UTMI_PHY_DATA_WIDTH_8) ? 8 : 16;

	if (hsotg->phy) {
		/*
		 * If using the generic PHY framework, check if the PHY bus
		 * width is 8-bit and set the phyif appropriately.
		 */
		if (phy_get_bus_width(hsotg->phy) == 8)
			val = 8;
	}

	hsotg->params.phy_utmi_width = val;
}

static void dwc2_set_param_tx_fifo_sizes(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;
	int depth_average;
	int fifo_count;
	int i;

	fifo_count = dwc2_hsotg_tx_fifo_count(hsotg);

	memset(p->g_tx_fifo_size, 0, sizeof(p->g_tx_fifo_size));
	depth_average = dwc2_hsotg_tx_fifo_average_depth(hsotg);
	for (i = 1; i <= fifo_count; i++)
		p->g_tx_fifo_size[i] = depth_average;
}

static void dwc2_set_param_power_down(struct dwc2_hsotg *hsotg)
{
	int val;

	if (hsotg->hw_params.hibernation)
		val = DWC2_POWER_DOWN_PARAM_HIBERNATION;
	else if (hsotg->hw_params.power_optimized)
		val = DWC2_POWER_DOWN_PARAM_PARTIAL;
	else
		val = DWC2_POWER_DOWN_PARAM_NONE;

	hsotg->params.power_down = val;
}

static void dwc2_set_param_lpm(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;

	p->lpm = hsotg->hw_params.lpm_mode;
	if (p->lpm) {
		p->lpm_clock_gating = true;
		p->besl = true;
		p->hird_threshold_en = true;
		p->hird_threshold = 4;
	} else {
		p->lpm_clock_gating = false;
		p->besl = false;
		p->hird_threshold_en = false;
	}
}

/**
 * dwc2_set_default_params() - Set all core parameters to their
 * auto-detected default values.
 *
 * @hsotg: Programming view of the DWC_otg controller
 *
 */
static void dwc2_set_default_params(struct dwc2_hsotg *hsotg)
{
	struct dwc2_hw_params *hw = &hsotg->hw_params;
	struct dwc2_core_params *p = &hsotg->params;
	bool dma_capable = !(hw->arch == GHWCFG2_SLAVE_ONLY_ARCH);

	dwc2_set_param_otg_cap(hsotg);
	dwc2_set_param_phy_type(hsotg);
	dwc2_set_param_speed(hsotg);
	dwc2_set_param_phy_utmi_width(hsotg);
	dwc2_set_param_power_down(hsotg);
	dwc2_set_param_lpm(hsotg);
	p->phy_ulpi_ddr = false;
	p->phy_ulpi_ext_vbus = false;

	p->enable_dynamic_fifo = hw->enable_dynamic_fifo;
	p->en_multiple_tx_fifo = hw->en_multiple_tx_fifo;
	p->i2c_enable = hw->i2c_enable;
	p->acg_enable = hw->acg_enable;
	p->ulpi_fs_ls = false;
	p->ts_dline = false;
	p->reload_ctl = (hw->snpsid >= DWC2_CORE_REV_2_92a);
	p->uframe_sched = true;
	p->external_id_pin_ctl = false;
	p->ipg_isoc_en = false;
	p->service_interval = false;
	p->max_packet_count = hw->max_packet_count;
	p->max_transfer_size = hw->max_transfer_size;
	p->ahbcfg = GAHBCFG_HBSTLEN_INCR << GAHBCFG_HBSTLEN_SHIFT;
	p->ref_clk_per = 33333;
	p->sof_cnt_wkup_alert = 100;

	if ((hsotg->dr_mode == USB_DR_MODE_HOST) ||
	    (hsotg->dr_mode == USB_DR_MODE_OTG)) {
		p->host_dma = dma_capable;
		p->dma_desc_enable = false;
		p->dma_desc_fs_enable = false;
		p->host_support_fs_ls_low_power = false;
		p->host_ls_low_power_phy_clk = false;
		p->host_channels = hw->host_channels;
		p->host_rx_fifo_size = hw->rx_fifo_size;
		p->host_nperio_tx_fifo_size = hw->host_nperio_tx_fifo_size;
		p->host_perio_tx_fifo_size = hw->host_perio_tx_fifo_size;
	}

	if ((hsotg->dr_mode == USB_DR_MODE_PERIPHERAL) ||
	    (hsotg->dr_mode == USB_DR_MODE_OTG)) {
		p->g_dma = dma_capable;
		p->g_dma_desc = hw->dma_desc_enable;

		/*
		 * The values for g_rx_fifo_size (2048) and
		 * g_np_tx_fifo_size (1024) come from the legacy s3c
		 * gadget driver. These defaults have been hard-coded
		 * for some time so many platforms depend on these
		 * values. Leave them as defaults for now and only
		 * auto-detect if the hardware does not support the
		 * default.
		 */
		p->g_rx_fifo_size = 2048;
		p->g_np_tx_fifo_size = 1024;
		dwc2_set_param_tx_fifo_sizes(hsotg);
	}
}

/**
 * dwc2_get_device_properties() - Read in device properties.
 *
 * @hsotg: Programming view of the DWC_otg controller
 *
 * Read in the device properties and adjust core parameters if needed.
 */
static void dwc2_get_device_properties(struct dwc2_hsotg *hsotg)
{
	struct dwc2_core_params *p = &hsotg->params;
	int num;

	if ((hsotg->dr_mode == USB_DR_MODE_PERIPHERAL) ||
	    (hsotg->dr_mode == USB_DR_MODE_OTG)) {
		device_property_read_u32(hsotg->dev, "g-rx-fifo-size",
					 &p->g_rx_fifo_size);

		device_property_read_u32(hsotg->dev, "g-np-tx-fifo-size",
					 &p->g_np_tx_fifo_size);

		num = device_property_count_u32(hsotg->dev, "g-tx-fifo-size");
		if (num > 0) {
			num = min(num, 15);
			memset(p->g_tx_fifo_size, 0,
			       sizeof(p->g_tx_fifo_size));
			device_property_read_u32_array(hsotg->dev,
						       "g-tx-fifo-size",
						       &p->g_tx_fifo_size[1],
						       num);
		}
	}

	if (of_find_property(hsotg->dev->of_node, "disable-over-current", NULL))
		p->oc_disable = true;
}


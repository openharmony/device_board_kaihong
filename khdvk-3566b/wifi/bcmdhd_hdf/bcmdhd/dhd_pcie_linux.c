/*
 * Linux DHD Bus Module for PCIE
 *
 * Copyright (C) 2022 Broadcom.
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id: dhd_pcie_linux.c 821650 2019-05-24 10:41:54Z $
 */

/* include files */
#include <typedefs.h>
#include <bcmutils.h>
#include <bcmdevs.h>
#include <siutils.h>
#include <hndsoc.h>
#include <hndpmu.h>
#include <sbchipc.h>
#if defined(DHD_DEBUG)
#include <hnd_armtrap.h>
#include <hnd_cons.h>
#endif /* defined(DHD_DEBUG) */
#include <dngl_stats.h>
#include <pcie_core.h>
#include <dhd.h>
#include <dhd_bus.h>
#include <dhd_proto.h>
#include <dhd_dbg.h>
#include <dhdioctl.h>
#include <bcmmsgbuf.h>
#include <pcicfg.h>
#include <dhd_pcie.h>
#include <dhd_linux.h>
#ifdef CONFIG_ARCH_MSM
#if defined(CONFIG_PCI_MSM) || defined(CONFIG_ARCH_MSM8996)
#include <linux/msm_pcie.h>
#else
#include <mach/msm_pcie.h>
#endif /* CONFIG_PCI_MSM */
#endif /* CONFIG_ARCH_MSM */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#include <linux/pm_runtime.h>
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#ifndef AUTO_SUSPEND_TIMEOUT
#define AUTO_SUSPEND_TIMEOUT 1000
#endif /* AUTO_SUSPEND_TIMEOUT */
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#include <linux/irq.h>
#ifdef USE_SMMU_ARCH_MSM
#include <asm/dma-iommu.h>
#include <linux/iommu.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#endif /* USE_SMMU_ARCH_MSM */
#include <dhd_config.h>

#define PCI_CFG_RETRY 		10
#define OS_HANDLE_MAGIC		0x1234abcd	/* Magic # to recognize osh */
#define BCM_MEM_FILENAME_LEN 	24		/* Mem. filename length */

#ifdef FORCE_TPOWERON
extern uint32 tpoweron_scale;
#endif /* FORCE_TPOWERON */
/* user defined data structures  */

typedef bool (*dhdpcie_cb_fn_t)(void *);

typedef struct dhdpcie_info
{
	dhd_bus_t	*bus;
	osl_t		*osh;
	struct pci_dev  *dev;		/* pci device handle */
	volatile char	*regs;		/* pci device memory va */
	volatile char	*tcm;		/* pci device memory va */
	uint32		bar1_size;	/* pci device memory size */
	uint32		curr_bar1_win;	/* current PCIEBar1Window setting */
	struct pcos_info *pcos_info;
	uint16		last_intrstatus;	/* to cache intrstatus */
	int	irq;
	char pciname[32];
	struct pci_saved_state* default_state;
	struct pci_saved_state* state;
#ifdef BCMPCIE_OOB_HOST_WAKE
	void *os_cxt;			/* Pointer to per-OS private data */
#endif /* BCMPCIE_OOB_HOST_WAKE */
#ifdef DHD_WAKE_STATUS
	spinlock_t	pcie_lock;
	unsigned int	total_wake_count;
	int		pkt_wake;
	int		wake_irq;
#endif /* DHD_WAKE_STATUS */
#ifdef USE_SMMU_ARCH_MSM
	void *smmu_cxt;
#endif /* USE_SMMU_ARCH_MSM */
} dhdpcie_info_t;

struct pcos_info {
	dhdpcie_info_t *pc;
	spinlock_t lock;
	wait_queue_head_t intr_wait_queue;
	struct timer_list tuning_timer;
	int tuning_timer_exp;
	atomic_t timer_enab;
	struct tasklet_struct tuning_tasklet;
};

#ifdef BCMPCIE_OOB_HOST_WAKE
typedef struct dhdpcie_os_info {
	int			oob_irq_num;	/* valid when hardware or software oob in use */
	unsigned long		oob_irq_flags;	/* valid when hardware or software oob in use */
	bool			oob_irq_registered;
	bool			oob_irq_enabled;
	bool			oob_irq_wake_enabled;
	spinlock_t		oob_irq_spinlock;
	void			*dev;		/* handle to the underlying device */
} dhdpcie_os_info_t;
static irqreturn_t wlan_oob_irq(int irq, void *data);
#ifdef CUSTOMER_HW2
extern struct brcm_pcie_wake brcm_pcie_wake;
#endif /* CUSTOMER_HW2 */
#endif /* BCMPCIE_OOB_HOST_WAKE */

#ifdef USE_SMMU_ARCH_MSM
typedef struct dhdpcie_smmu_info {
	struct dma_iommu_mapping *smmu_mapping;
	dma_addr_t smmu_iova_start;
	size_t smmu_iova_len;
} dhdpcie_smmu_info_t;
#endif /* USE_SMMU_ARCH_MSM */

/* function declarations */
static int __devinit
dhdpcie_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void __devexit
dhdpcie_pci_remove(struct pci_dev *pdev);
static int dhdpcie_init(struct pci_dev *pdev);
static irqreturn_t dhdpcie_isr(int irq, void *arg);
/* OS Routine functions for PCI suspend/resume */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
static int dhdpcie_set_suspend_resume(struct pci_dev *dev, bool state, bool byint);
#else
static int dhdpcie_set_suspend_resume(dhd_bus_t *bus, bool state);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
static int dhdpcie_resume_host_dev(dhd_bus_t *bus);
static int dhdpcie_suspend_host_dev(dhd_bus_t *bus);
static int dhdpcie_resume_dev(struct pci_dev *dev);
static int dhdpcie_suspend_dev(struct pci_dev *dev);
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
static int dhdpcie_pm_system_suspend_noirq(struct device * dev);
static int dhdpcie_pm_system_resume_noirq(struct device * dev);
#else
static int dhdpcie_pci_suspend(struct pci_dev *dev, pm_message_t state);
static int dhdpcie_pci_resume(struct pci_dev *dev);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
static int dhdpcie_pm_runtime_suspend(struct device * dev);
static int dhdpcie_pm_runtime_resume(struct device * dev);
static int dhdpcie_pm_system_suspend_noirq(struct device * dev);
static int dhdpcie_pm_system_resume_noirq(struct device * dev);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

static void dhdpcie_config_save_restore_coherent(dhd_bus_t *bus, bool state);

uint32
dhdpcie_access_cap(struct pci_dev *pdev, int cap, uint offset, bool is_ext, bool is_write,
	uint32 writeval);

static struct pci_device_id dhdpcie_pci_devid[] __devinitdata = {
	{ vendor: 0x14e4,
	device: PCI_ANY_ID,
	subvendor: PCI_ANY_ID,
	subdevice: PCI_ANY_ID,
	class: PCI_CLASS_NETWORK_OTHER << 8,
	class_mask: 0xffff00,
	driver_data: 0,
	},
	{ 0, 0, 0, 0, 0, 0, 0}
};
MODULE_DEVICE_TABLE(pci, dhdpcie_pci_devid);

/* Power Management Hooks */
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
static const struct dev_pm_ops dhdpcie_pm_ops = {
	SET_RUNTIME_PM_OPS(dhdpcie_pm_runtime_suspend, dhdpcie_pm_runtime_resume, NULL)
	.suspend_noirq = dhdpcie_pm_system_suspend_noirq,
	.resume_noirq = dhdpcie_pm_system_resume_noirq
};
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

static struct pci_driver dhdpcie_driver = {
	node:		{&dhdpcie_driver.node, &dhdpcie_driver.node},
	name:		"pcieh",
	id_table:	dhdpcie_pci_devid,
	probe:		dhdpcie_pci_probe,
	remove:		dhdpcie_pci_remove,
#if defined(DHD_PCIE_NATIVE_RUNTIMEPM)
	.driver.pm = &dhd_pcie_pm_ops,
#else
	suspend:	dhdpcie_pci_suspend,
	resume:		dhdpcie_pci_resume,
#endif // endif
};

int dhdpcie_init_succeeded = FALSE;

#ifdef USE_SMMU_ARCH_MSM
static int dhdpcie_smmu_init(struct pci_dev *pdev, void *smmu_cxt)
{
	struct dma_iommu_mapping *mapping;
	struct device_node *root_node = NULL;
	dhdpcie_smmu_info_t *smmu_info = (dhdpcie_smmu_info_t *)smmu_cxt;
	int smmu_iova_address[2];
	char *wlan_node = "android,bcmdhd_wlan";
	char *wlan_smmu_node = "wlan-smmu-iova-address";
	int atomic_ctx = 1;
	int s1_bypass = 1;
	int ret = 0;

	DHD_ERROR(("%s: SMMU initialize\n", __FUNCTION__));

	root_node = of_find_compatible_node(NULL, NULL, wlan_node);
	if (!root_node) {
		WARN(1, "failed to get device node of BRCM WLAN\n");
		return -ENODEV;
	}

	if (of_property_read_u32_array(root_node, wlan_smmu_node,
		smmu_iova_address, 2) == 0) {
		DHD_ERROR(("%s : get SMMU start address 0x%x, size 0x%x\n",
			__FUNCTION__, smmu_iova_address[0], smmu_iova_address[1]));
		smmu_info->smmu_iova_start = smmu_iova_address[0];
		smmu_info->smmu_iova_len = smmu_iova_address[1];
	} else {
		printf("%s : can't get smmu iova address property\n",
			__FUNCTION__);
		return -ENODEV;
	}

	if (smmu_info->smmu_iova_len <= 0) {
		DHD_ERROR(("%s: Invalid smmu iova len %d\n",
			__FUNCTION__, (int)smmu_info->smmu_iova_len));
		return -EINVAL;
	}

	DHD_ERROR(("%s : SMMU init start\n", __FUNCTION__));

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(64)) ||
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64))) {
		DHD_ERROR(("%s: DMA set 64bit mask failed.\n", __FUNCTION__));
		return -EINVAL;
	}

	mapping = arm_iommu_create_mapping(&platform_bus_type,
		smmu_info->smmu_iova_start, smmu_info->smmu_iova_len);
	if (IS_ERR(mapping)) {
		DHD_ERROR(("%s: create mapping failed, err = %d\n",
			__FUNCTION__, ret));
		ret = PTR_ERR(mapping);
		goto map_fail;
	}

	ret = iommu_domain_set_attr(mapping->domain,
		DOMAIN_ATTR_ATOMIC, &atomic_ctx);
	if (ret) {
		DHD_ERROR(("%s: set atomic_ctx attribute failed, err = %d\n",
			__FUNCTION__, ret));
		goto set_attr_fail;
	}

	ret = iommu_domain_set_attr(mapping->domain,
		DOMAIN_ATTR_S1_BYPASS, &s1_bypass);
	if (ret < 0) {
		DHD_ERROR(("%s: set s1_bypass attribute failed, err = %d\n",
			__FUNCTION__, ret));
		goto set_attr_fail;
	}

	ret = arm_iommu_attach_device(&pdev->dev, mapping);
	if (ret) {
		DHD_ERROR(("%s: attach device failed, err = %d\n",
			__FUNCTION__, ret));
		goto attach_fail;
	}

	smmu_info->smmu_mapping = mapping;

	return ret;

attach_fail:
set_attr_fail:
	arm_iommu_release_mapping(mapping);
map_fail:
	return ret;
}

static void dhdpcie_smmu_remove(struct pci_dev *pdev, void *smmu_cxt)
{
	dhdpcie_smmu_info_t *smmu_info;

	if (!smmu_cxt) {
		return;
	}

	smmu_info = (dhdpcie_smmu_info_t *)smmu_cxt;
	if (smmu_info->smmu_mapping) {
		arm_iommu_detach_device(&pdev->dev);
		arm_iommu_release_mapping(smmu_info->smmu_mapping);
		smmu_info->smmu_mapping = NULL;
	}
}
#endif /* USE_SMMU_ARCH_MSM */

#ifdef FORCE_TPOWERON
static void
dhd_bus_get_tpoweron(dhd_bus_t *bus)
{

	uint32 tpoweron_rc;
	uint32 tpoweron_ep;

	tpoweron_rc = dhdpcie_rc_access_cap(bus, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL2_OFFSET, TRUE, FALSE, 0);
	tpoweron_ep = dhdpcie_ep_access_cap(bus, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL2_OFFSET, TRUE, FALSE, 0);
	DHD_ERROR(("%s: tpoweron_rc:0x%x tpoweron_ep:0x%x\n",
		__FUNCTION__, tpoweron_rc, tpoweron_ep));
}

static void
dhd_bus_set_tpoweron(dhd_bus_t *bus, uint16 tpoweron)
{

	dhd_bus_get_tpoweron(bus);
	/* Set the tpoweron */
	DHD_ERROR(("%s tpoweron: 0x%x\n", __FUNCTION__, tpoweron));
	dhdpcie_rc_access_cap(bus, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL2_OFFSET, TRUE, TRUE, tpoweron);
	dhdpcie_ep_access_cap(bus, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL2_OFFSET, TRUE, TRUE, tpoweron);

	dhd_bus_get_tpoweron(bus);

}

static bool
dhdpcie_chip_req_forced_tpoweron(dhd_bus_t *bus)
{
	/*
	 * On Fire's reference platform, coming out of L1.2,
	 * there is a constant delay of 45us between CLKREQ# and stable REFCLK
	 * Due to this delay, with tPowerOn < 50
	 * there is a chance of the refclk sense to trigger on noise.
	 *
	 * Which ever chip needs forced tPowerOn of 50us should be listed below.
	 */
	if (si_chipid(bus->sih) == BCM4377_CHIP_ID) {
		return TRUE;
	}
	return FALSE;
}
#endif /* FORCE_TPOWERON */

static bool
dhd_bus_aspm_enable_dev(dhd_bus_t *bus, struct pci_dev *dev, bool enable)
{
	uint32 linkctrl_before;
	uint32 linkctrl_after = 0;
	uint8 linkctrl_asm;
	char *device;

	device = (dev == bus->dev) ? "EP" : "RC";

	linkctrl_before = dhdpcie_access_cap(dev, PCIE_CAP_ID_EXP, PCIE_CAP_LINKCTRL_OFFSET,
		FALSE, FALSE, 0);
	linkctrl_asm = (linkctrl_before & PCIE_ASPM_CTRL_MASK);

	if (enable) {
		if (linkctrl_asm == PCIE_ASPM_L1_ENAB) {
			DHD_ERROR(("%s: %s already enabled  linkctrl: 0x%x\n",
				__FUNCTION__, device, linkctrl_before));
			return FALSE;
		}
		/* Enable only L1 ASPM (bit 1) */
		dhdpcie_access_cap(dev, PCIE_CAP_ID_EXP, PCIE_CAP_LINKCTRL_OFFSET, FALSE,
			TRUE, (linkctrl_before | PCIE_ASPM_L1_ENAB));
	} else {
		if (linkctrl_asm == 0) {
			DHD_ERROR(("%s: %s already disabled linkctrl: 0x%x\n",
				__FUNCTION__, device, linkctrl_before));
			return FALSE;
		}
		/* Disable complete ASPM (bit 1 and bit 0) */
		dhdpcie_access_cap(dev, PCIE_CAP_ID_EXP, PCIE_CAP_LINKCTRL_OFFSET, FALSE,
			TRUE, (linkctrl_before & (~PCIE_ASPM_ENAB)));
	}

	linkctrl_after = dhdpcie_access_cap(dev, PCIE_CAP_ID_EXP, PCIE_CAP_LINKCTRL_OFFSET,
		FALSE, FALSE, 0);
	DHD_ERROR(("%s: %s %s, linkctrl_before: 0x%x linkctrl_after: 0x%x\n",
		__FUNCTION__, device, (enable ? "ENABLE " : "DISABLE"),
		linkctrl_before, linkctrl_after));

	return TRUE;
}

static bool
dhd_bus_is_rc_ep_aspm_capable(dhd_bus_t *bus)
{
	uint32 rc_aspm_cap;
	uint32 ep_aspm_cap;

	/* RC ASPM capability */
	rc_aspm_cap = dhdpcie_access_cap(bus->rc_dev, PCIE_CAP_ID_EXP, PCIE_CAP_LINKCTRL_OFFSET,
		FALSE, FALSE, 0);
	if (rc_aspm_cap == BCME_ERROR) {
		DHD_ERROR(("%s RC is not ASPM capable\n", __FUNCTION__));
		return FALSE;
	}

	/* EP ASPM capability */
	ep_aspm_cap = dhdpcie_access_cap(bus->dev, PCIE_CAP_ID_EXP, PCIE_CAP_LINKCTRL_OFFSET,
		FALSE, FALSE, 0);
	if (ep_aspm_cap == BCME_ERROR) {
		DHD_ERROR(("%s EP is not ASPM capable\n", __FUNCTION__));
		return FALSE;
	}

	return TRUE;
}

bool
dhd_bus_aspm_enable_rc_ep(dhd_bus_t *bus, bool enable)
{
	bool ret;

	if (!bus->rc_ep_aspm_cap) {
		DHD_ERROR(("%s: NOT ASPM  CAPABLE rc_ep_aspm_cap: %d\n",
			__FUNCTION__, bus->rc_ep_aspm_cap));
		return FALSE;
	}

	if (enable) {
		/* Enable only L1 ASPM first RC then EP */
		ret = dhd_bus_aspm_enable_dev(bus, bus->rc_dev, enable);
		ret = dhd_bus_aspm_enable_dev(bus, bus->dev, enable);
	} else {
		/* Disable complete ASPM first EP then RC */
		ret = dhd_bus_aspm_enable_dev(bus, bus->dev, enable);
		ret = dhd_bus_aspm_enable_dev(bus, bus->rc_dev, enable);
	}

	return ret;
}

static void
dhd_bus_l1ss_enable_dev(dhd_bus_t *bus, struct pci_dev *dev, bool enable)
{
	uint32 l1ssctrl_before;
	uint32 l1ssctrl_after = 0;
	uint8 l1ss_ep;
	char *device;

	device = (dev == bus->dev) ? "EP" : "RC";

	/* Extendend Capacility Reg */
	l1ssctrl_before = dhdpcie_access_cap(dev, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL_OFFSET, TRUE, FALSE, 0);
	l1ss_ep = (l1ssctrl_before & PCIE_EXT_L1SS_MASK);

	if (enable) {
		if (l1ss_ep == PCIE_EXT_L1SS_ENAB) {
			DHD_ERROR(("%s: %s already enabled,  l1ssctrl: 0x%x\n",
				__FUNCTION__, device, l1ssctrl_before));
			return;
		}
		dhdpcie_access_cap(dev, PCIE_EXTCAP_ID_L1SS, PCIE_EXTCAP_L1SS_CONTROL_OFFSET,
			TRUE, TRUE, (l1ssctrl_before | PCIE_EXT_L1SS_ENAB));
	} else {
		if (l1ss_ep == 0) {
			DHD_ERROR(("%s: %s already disabled, l1ssctrl: 0x%x\n",
				__FUNCTION__, device, l1ssctrl_before));
			return;
		}
		dhdpcie_access_cap(dev, PCIE_EXTCAP_ID_L1SS, PCIE_EXTCAP_L1SS_CONTROL_OFFSET,
			TRUE, TRUE, (l1ssctrl_before & (~PCIE_EXT_L1SS_ENAB)));
	}
	l1ssctrl_after = dhdpcie_access_cap(dev, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL_OFFSET, TRUE, FALSE, 0);
	DHD_ERROR(("%s: %s %s, l1ssctrl_before: 0x%x l1ssctrl_after: 0x%x\n",
		__FUNCTION__, device, (enable ? "ENABLE " : "DISABLE"),
		l1ssctrl_before, l1ssctrl_after));

}

static bool
dhd_bus_is_rc_ep_l1ss_capable(dhd_bus_t *bus)
{
	uint32 rc_l1ss_cap;
	uint32 ep_l1ss_cap;

	/* RC Extendend Capacility */
	rc_l1ss_cap = dhdpcie_access_cap(bus->rc_dev, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL_OFFSET, TRUE, FALSE, 0);
	if (rc_l1ss_cap == BCME_ERROR) {
		DHD_ERROR(("%s RC is not l1ss capable\n", __FUNCTION__));
		return FALSE;
	}

	/* EP Extendend Capacility */
	ep_l1ss_cap = dhdpcie_access_cap(bus->dev, PCIE_EXTCAP_ID_L1SS,
		PCIE_EXTCAP_L1SS_CONTROL_OFFSET, TRUE, FALSE, 0);
	if (ep_l1ss_cap == BCME_ERROR) {
		DHD_ERROR(("%s EP is not l1ss capable\n", __FUNCTION__));
		return FALSE;
	}

	return TRUE;
}

void
dhd_bus_l1ss_enable_rc_ep(dhd_bus_t *bus, bool enable)
{
	bool ret;

	if ((!bus->rc_ep_aspm_cap) || (!bus->rc_ep_l1ss_cap)) {
		DHD_ERROR(("%s: NOT L1SS CAPABLE rc_ep_aspm_cap: %d rc_ep_l1ss_cap: %d\n",
			__FUNCTION__, bus->rc_ep_aspm_cap, bus->rc_ep_l1ss_cap));
		return;
	}

	/* Disable ASPM of RC and EP */
	ret = dhd_bus_aspm_enable_rc_ep(bus, FALSE);

	if (enable) {
		/* Enable RC then EP */
		dhd_bus_l1ss_enable_dev(bus, bus->rc_dev, enable);
		dhd_bus_l1ss_enable_dev(bus, bus->dev, enable);
	} else {
		/* Disable EP then RC */
		dhd_bus_l1ss_enable_dev(bus, bus->dev, enable);
		dhd_bus_l1ss_enable_dev(bus, bus->rc_dev, enable);
	}

	/* Enable ASPM of RC and EP only if this API disabled */
	if (ret == TRUE) {
		dhd_bus_aspm_enable_rc_ep(bus, TRUE);
	}
}

void
dhd_bus_aer_config(dhd_bus_t *bus)
{
	uint32 val;

	DHD_ERROR(("%s: Configure AER registers for EP\n", __FUNCTION__));
	val = dhdpcie_ep_access_cap(bus, PCIE_ADVERRREP_CAPID,
		PCIE_ADV_CORR_ERR_MASK_OFFSET, TRUE, FALSE, 0);
	if (val != (uint32)-1) {
		val &= ~CORR_ERR_AE;
		dhdpcie_ep_access_cap(bus, PCIE_ADVERRREP_CAPID,
			PCIE_ADV_CORR_ERR_MASK_OFFSET, TRUE, TRUE, val);
	} else {
		DHD_ERROR(("%s: Invalid EP's PCIE_ADV_CORR_ERR_MASK: 0x%x\n",
			__FUNCTION__, val));
	}

	DHD_ERROR(("%s: Configure AER registers for RC\n", __FUNCTION__));
	val = dhdpcie_rc_access_cap(bus, PCIE_ADVERRREP_CAPID,
		PCIE_ADV_CORR_ERR_MASK_OFFSET, TRUE, FALSE, 0);
	if (val != (uint32)-1) {
		val &= ~CORR_ERR_AE;
		dhdpcie_rc_access_cap(bus, PCIE_ADVERRREP_CAPID,
			PCIE_ADV_CORR_ERR_MASK_OFFSET, TRUE, TRUE, val);
	} else {
		DHD_ERROR(("%s: Invalid RC's PCIE_ADV_CORR_ERR_MASK: 0x%x\n",
			__FUNCTION__, val));
	}
}

static int dhdpcie_pci_suspend(struct pci_dev * pdev, pm_message_t state)
{
	int ret = 0;
	dhdpcie_info_t *pch = pci_get_drvdata(pdev);
	dhd_bus_t *bus = NULL;
	unsigned long flags;
	uint32 i = 0;

	if (pch) {
		bus = pch->bus;
	}
	if (!bus) {
		return ret;
	}

	BCM_REFERENCE(state);

	if (!DHD_BUS_BUSY_CHECK_IDLE(bus->dhd)) {
		DHD_ERROR(("%s: Bus not IDLE!! dhd_bus_busy_state = 0x%x\n",
			__FUNCTION__, bus->dhd->dhd_bus_busy_state));

		OSL_DELAY(1000);
		/* retry till the transaction is complete */
		while (i < 100) {
			OSL_DELAY(1000);
			i++;
			if (DHD_BUS_BUSY_CHECK_IDLE(bus->dhd)) {
				DHD_ERROR(("%s: Bus enter IDLE!! after %d ms\n",
					__FUNCTION__, i));
				break;
			}
		}
		if (!DHD_BUS_BUSY_CHECK_IDLE(bus->dhd)) {
			DHD_ERROR(("%s: Bus not IDLE!! Failed after %d ms, "
				"dhd_bus_busy_state = 0x%x\n",
				__FUNCTION__, i, bus->dhd->dhd_bus_busy_state));
			return -EBUSY;
		}
	}
	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_BUS_BUSY_SET_SUSPEND_IN_PROGRESS(bus->dhd);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);

	if (!bus->dhd->dongle_reset)
		ret = dhdpcie_set_suspend_resume(bus, TRUE);

	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_BUS_BUSY_CLEAR_SUSPEND_IN_PROGRESS(bus->dhd);
	dhd_os_busbusy_wake(bus->dhd);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);

	return ret;
}

static int dhdpcie_pci_resume(struct pci_dev *pdev)
{
	int ret = 0;
	dhdpcie_info_t *pch = pci_get_drvdata(pdev);
	dhd_bus_t *bus = NULL;
	unsigned long flags;

	if (pch) {
		bus = pch->bus;
	}
	if (!bus) {
		return ret;
	}

	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_BUS_BUSY_SET_RESUME_IN_PROGRESS(bus->dhd);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);

	if (!bus->dhd->dongle_reset)
		ret = dhdpcie_set_suspend_resume(bus, FALSE);

	DHD_GENERAL_LOCK(bus->dhd, flags);
	DHD_BUS_BUSY_CLEAR_RESUME_IN_PROGRESS(bus->dhd);
	dhd_os_busbusy_wake(bus->dhd);
	DHD_GENERAL_UNLOCK(bus->dhd, flags);

	return ret;
}

static int
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
dhdpcie_set_suspend_resume(dhd_bus_t *bus, bool state, bool byint)
#else
dhdpcie_set_suspend_resume(dhd_bus_t *bus, bool state)
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */
{
	int ret = 0;

	ASSERT(bus && !bus->dhd->dongle_reset);

	/* When firmware is not loaded do the PCI bus */
	/* suspend/resume only */
	if (bus->dhd->busstate == DHD_BUS_DOWN) {
		ret = dhdpcie_pci_suspend_resume(bus, state);
		return ret;
	}
#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
		ret = dhdpcie_bus_suspend(bus, state, byint);
#else
		ret = dhdpcie_bus_suspend(bus, state);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

	return ret;
}

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
static int dhdpcie_pm_runtime_suspend(struct device * dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	dhdpcie_info_t *pch = pci_get_drvdata(pdev);
	dhd_bus_t *bus = NULL;
	int ret = 0;

	if (!pch)
		return -EBUSY;

	bus = pch->bus;

	DHD_RPM(("%s Enter\n", __FUNCTION__));

	if (atomic_read(&bus->dhd->block_bus))
		return -EHOSTDOWN;

	dhd_netif_stop_queue(bus);
	atomic_set(&bus->dhd->block_bus, TRUE);

	if (dhdpcie_set_suspend_resume(pdev, TRUE, TRUE)) {
		pm_runtime_mark_last_busy(dev);
		ret = -EAGAIN;
	}

	atomic_set(&bus->dhd->block_bus, FALSE);
	dhd_bus_start_queue(bus);

	return ret;
}

static int dhdpcie_pm_runtime_resume(struct device * dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	dhdpcie_info_t *pch = pci_get_drvdata(pdev);
	dhd_bus_t *bus = pch->bus;

	DHD_RPM(("%s Enter\n", __FUNCTION__));

	if (atomic_read(&bus->dhd->block_bus))
		return -EHOSTDOWN;

	if (dhdpcie_set_suspend_resume(pdev, FALSE, TRUE))
		return -EAGAIN;

	return 0;
}

static int dhdpcie_pm_system_suspend_noirq(struct device * dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	dhdpcie_info_t *pch = pci_get_drvdata(pdev);
	dhd_bus_t *bus = NULL;
	int ret;

	DHD_RPM(("%s Enter\n", __FUNCTION__));

	if (!pch)
		return -EBUSY;

	bus = pch->bus;

	if (atomic_read(&bus->dhd->block_bus))
		return -EHOSTDOWN;

	dhd_netif_stop_queue(bus);
	atomic_set(&bus->dhd->block_bus, TRUE);

	ret = dhdpcie_set_suspend_resume(pdev, TRUE, FALSE);

	if (ret) {
		dhd_bus_start_queue(bus);
		atomic_set(&bus->dhd->block_bus, FALSE);
	}

	return ret;
}

static int dhdpcie_pm_system_resume_noirq(struct device * dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	dhdpcie_info_t *pch = pci_get_drvdata(pdev);
	dhd_bus_t *bus = NULL;
	int ret;

	if (!pch)
		return -EBUSY;

	bus = pch->bus;

	DHD_RPM(("%s Enter\n", __FUNCTION__));

	ret = dhdpcie_set_suspend_resume(pdev, FALSE, FALSE);

	atomic_set(&bus->dhd->block_bus, FALSE);
	dhd_bus_start_queue(bus);
	pm_runtime_mark_last_busy(dhd_bus_to_dev(bus));

	return ret;
}
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
extern void dhd_dpc_tasklet_kill(dhd_pub_t *dhdp);
#endif /* OEM_ANDROID && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */

static void
dhdpcie_suspend_dump_cfgregs(struct dhd_bus *bus, char *suspend_state)
{
	DHD_ERROR(("%s: BaseAddress0(0x%x)=0x%x, "
		"BaseAddress1(0x%x)=0x%x PCIE_CFG_PMCSR(0x%x)=0x%x\n",
		suspend_state,
		PCIECFGREG_BASEADDR0,
		dhd_pcie_config_read(bus->osh,
			PCIECFGREG_BASEADDR0, sizeof(uint32)),
		PCIECFGREG_BASEADDR1,
		dhd_pcie_config_read(bus->osh,
			PCIECFGREG_BASEADDR1, sizeof(uint32)),
		PCIE_CFG_PMCSR,
		dhd_pcie_config_read(bus->osh,
			PCIE_CFG_PMCSR, sizeof(uint32))));
}

static int dhdpcie_suspend_dev(struct pci_dev *dev)
{
	int ret;
	dhdpcie_info_t *pch = pci_get_drvdata(dev);
	dhd_bus_t *bus = pch->bus;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	if (bus->is_linkdown) {
		DHD_ERROR(("%s: PCIe link is down\n", __FUNCTION__));
		return BCME_ERROR;
	}
#endif /* OEM_ANDROID && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */
	DHD_ERROR(("%s: Enter\n", __FUNCTION__));
	dhdpcie_suspend_dump_cfgregs(bus, "BEFORE_EP_SUSPEND");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	dhd_dpc_tasklet_kill(bus->dhd);
#endif /* OEM_ANDROID && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */
	pci_save_state(dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	pch->state = pci_store_saved_state(dev);
#endif /* OEM_ANDROID && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */
	pci_enable_wake(dev, PCI_D0, TRUE);
	if (pci_is_enabled(dev))
		pci_disable_device(dev);

	ret = pci_set_power_state(dev, PCI_D3hot);
	if (ret) {
		DHD_ERROR(("%s: pci_set_power_state error %d\n",
			__FUNCTION__, ret));
	}
//	dev->state_saved = FALSE;
	dhdpcie_suspend_dump_cfgregs(bus, "AFTER_EP_SUSPEND");
	return ret;
}

#ifdef DHD_WAKE_STATUS
int bcmpcie_get_total_wake(struct dhd_bus *bus)
{
	dhdpcie_info_t *pch = pci_get_drvdata(bus->dev);

	return pch->total_wake_count;
}

int bcmpcie_set_get_wake(struct dhd_bus *bus, int flag)
{
	dhdpcie_info_t *pch = pci_get_drvdata(bus->dev);
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&pch->pcie_lock, flags);

	ret = pch->pkt_wake;
	pch->total_wake_count += flag;
	pch->pkt_wake = flag;

	spin_unlock_irqrestore(&pch->pcie_lock, flags);
	return ret;
}
#endif /* DHD_WAKE_STATUS */

static int dhdpcie_resume_dev(struct pci_dev *dev)
{
	int err = 0;
	dhdpcie_info_t *pch = pci_get_drvdata(dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
	pci_load_and_free_saved_state(dev, &pch->state);
#endif /* OEM_ANDROID && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0) */
	DHD_ERROR(("%s: Enter\n", __FUNCTION__));
//	dev->state_saved = TRUE;
	pci_restore_state(dev);
#ifdef FORCE_TPOWERON
	if (dhdpcie_chip_req_forced_tpoweron(pch->bus)) {
		dhd_bus_set_tpoweron(pch->bus, tpoweron_scale);
	}
#endif /* FORCE_TPOWERON */
	err = pci_enable_device(dev);
	if (err) {
		printf("%s:pci_enable_device error %d \n", __FUNCTION__, err);
		goto out;
	}
	pci_set_master(dev);
	err = pci_set_power_state(dev, PCI_D0);
	if (err) {
		printf("%s:pci_set_power_state error %d \n", __FUNCTION__, err);
		goto out;
	}
	BCM_REFERENCE(pch);
	dhdpcie_suspend_dump_cfgregs(pch->bus, "AFTER_EP_RESUME");
out:
	return err;
}

static int dhdpcie_resume_host_dev(dhd_bus_t *bus)
{
	int bcmerror = 0;
#ifdef USE_EXYNOS_PCIE_RC_PMPATCH
	bcmerror = exynos_pcie_pm_resume(SAMSUNG_PCIE_CH_NUM);
#endif /* USE_EXYNOS_PCIE_RC_PMPATCH */
#ifdef CONFIG_ARCH_MSM
	bcmerror = dhdpcie_start_host_pcieclock(bus);
#endif /* CONFIG_ARCH_MSM */
#ifdef CONFIG_ARCH_TEGRA
	bcmerror = tegra_pcie_pm_resume();
#endif /* CONFIG_ARCH_TEGRA */
	if (bcmerror < 0) {
		DHD_ERROR(("%s: PCIe RC resume failed!!! (%d)\n",
			__FUNCTION__, bcmerror));
		bus->is_linkdown = 1;
	}

	return bcmerror;
}

static int dhdpcie_suspend_host_dev(dhd_bus_t *bus)
{
	int bcmerror = 0;
#ifdef USE_EXYNOS_PCIE_RC_PMPATCH
	if (bus->rc_dev) {
		pci_save_state(bus->rc_dev);
	} else {
		DHD_ERROR(("%s: RC %x:%x handle is NULL\n",
			__FUNCTION__, PCIE_RC_VENDOR_ID, PCIE_RC_DEVICE_ID));
	}
	exynos_pcie_pm_suspend(SAMSUNG_PCIE_CH_NUM);
#endif	/* USE_EXYNOS_PCIE_RC_PMPATCH */
#ifdef CONFIG_ARCH_MSM
	bcmerror = dhdpcie_stop_host_pcieclock(bus);
#endif	/* CONFIG_ARCH_MSM */
#ifdef CONFIG_ARCH_TEGRA
	bcmerror = tegra_pcie_pm_suspend();
#endif /* CONFIG_ARCH_TEGRA */
	return bcmerror;
}

/**
 * dhdpcie_os_setbar1win
 *
 * Interface function for setting bar1 window in order to allow
 * os layer to be aware of current window positon.
 *
 * @bus: dhd bus context
 * @addr: new backplane windows address for BAR1
 */
void
dhdpcie_os_setbar1win(dhd_bus_t *bus, uint32 addr)
{
	dhdpcie_info_t *pch = pci_get_drvdata(bus->dev);

	osl_pci_write_config(bus->osh, PCI_BAR1_WIN, 4, addr);
	pch->curr_bar1_win = addr;
}

/**
 * dhdpcie_os_chkbpoffset
 *
 * Check the provided address is within the current BAR1 window,
 * if not, shift the window
 *
 * @bus: dhd bus context
 * @offset: back plane address that the caller wants to access
 *
 * Return: new offset for access
 */
static ulong
dhdpcie_os_chkbpoffset(dhdpcie_info_t *pch, ulong offset)
{
	/* Determine BAR1 backplane window using window size
	 * Window address mask should be ~(size - 1)
	 */
	uint32 bpwin = (uint32)(offset & ~(pch->bar1_size - 1));

	if (bpwin != pch->curr_bar1_win) {
		/* Move BAR1 window */
		dhdpcie_os_setbar1win(pch->bus, bpwin);
	}

	return offset - bpwin;
}

/**
 * dhdpcie os layer tcm read/write interface
 */
void
dhdpcie_os_wtcm8(dhd_bus_t *bus, ulong offset, uint8 data)
{
	dhdpcie_info_t *pch = pci_get_drvdata(bus->dev);

	offset = dhdpcie_os_chkbpoffset(pch, offset);
	W_REG(bus->dhd->osh, (volatile uint8 *)(bus->tcm + offset), data);
}

uint8
dhdpcie_os_rtcm8(dhd_bus_t *bus, ulong offset)
{
	volatile uint8 data;
	dhdpcie_info_t *pch = pci_get_drvdata(bus->dev);

	offset = dhdpcie_os_chkbpoffset(pch, offset);
	data = R_REG(bus->dhd->osh, (volatile uint8 *)(bus->tcm + offset));
	return data;
}

void
dhdpcie_os_wtcm16(dhd_bus_t *bus, ulong offset, uint16 data)
{
	dhdpcie_info_t *pch = pci_get_drvdata(bus->dev);

	offset = dhdpcie_os_chkbpoffset(pch, offset);
	W_REG(bus->dhd->osh, (volatile uint16 *)(bus->tcm + offset), data);
}

uint16
dhdpcie_os_rtcm16(dhd_bus_t *bus, ulong offset)
{
	volatile uint16 data;
	dhdpcie_info_t *pch = pci_get_drvdata(bus->dev);

	offset = dhdpcie_os_chkbpoffset(pch, offset);
	data = R_REG(bus->dhd->osh, (volatile uint16 *)(bus->tcm + offset));
	return data;
}

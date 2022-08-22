/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <typedefs.h>
#include <osl.h>

#include <bcmendian.h>
#include <bcmutils.h>
#include <hndsoc.h>
#include <bcmsdbus.h>
#if defined(HW_OOB) || defined(FORCE_WOWLAN)
#include <bcmdefs.h>
#include <bcmsdh.h>
#include <sdio.h>
#include <sbchipc.h>
#endif
#ifdef DHDTCPACK_SUPPRESS
#include <dhd_ip.h>
#endif /* DHDTCPACK_SUPPRESS */
#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#endif

#include <dhd_config.h>
#include <dhd_dbg.h>
#include <wl_android.h>
#ifdef BCMPCIE
#include <dhd_flowring.h>
#endif

#if defined(BCMSDIO) || defined(BCMPCIE)
#include <dhd_linux.h>
#include <dhd_bus.h>
#ifdef BCMSDIO
#include <linux/mmc/core.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio_func.h>
#endif /* defined(BCMSDIO) */
#endif

/* message levels */
#define CONFIG_ERROR_LEVEL	(1 << 0)
#define CONFIG_TRACE_LEVEL	(1 << 1)
#define CONFIG_MSG_LEVEL	(1 << 0)

uint config_msg_level = CONFIG_ERROR_LEVEL | CONFIG_MSG_LEVEL;
uint dump_msg_level = 0;

#define CONFIG_MSG(x, args...) \
	do { \
		if (config_msg_level & CONFIG_MSG_LEVEL) { \
			printk(KERN_ERR DHD_LOG_PREFIXS "%s : " x, __func__, ## args); \
		} \
	} while (0)
#define CONFIG_ERROR(x, args...) \
	do { \
		if (config_msg_level & CONFIG_ERROR_LEVEL) { \
			printk(KERN_ERR DHD_LOG_PREFIXS "CONFIG-ERROR) %s : " x, __func__, ## args); \
		} \
	} while (0)
#define CONFIG_TRACE(x, args...) \
	do { \
		if (config_msg_level & CONFIG_TRACE_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIXS "CONFIG-TRACE) %s : " x, __func__, ## args); \
		} \
	} while (0)

#define MAXSZ_BUF		4096
#define MAXSZ_CONFIG	8192

#if defined(BCMSDIO) && defined(DYNAMIC_MAX_HDR_READ)
extern uint firstread;
#endif

#if defined(PROP_TXSTATUS)
#include <dhd_wlfc.h>
#endif /* PROP_TXSTATUS */

#define MAX_EVENT_BUF_NUM 16
typedef struct eventmsg_buf {
	u16 num;
	struct {
		u16 type;
		bool set;
	} event [MAX_EVENT_BUF_NUM];
} eventmsg_buf_t;

typedef struct chip_name_map_t {
	uint chip;
	uint chiprev;
	uint ag_type;
	char *chip_name;
	char *module_name;
} chip_name_map_t;

/* Map of WLC_E events to connection failure strings */
#define DONT_CARE	9999
const chip_name_map_t chip_name_map[] = {
	/* ChipID			Chiprev	AG	 	ChipName	ModuleName  */
#ifdef BCMSDIO
	{BCM43362_CHIP_ID,	0,	DONT_CARE,	"bcm40181a0",		""},
	{BCM43362_CHIP_ID,	1,	DONT_CARE,	"bcm40181a2",		""},
	{BCM4330_CHIP_ID,	4,	FW_TYPE_G,	"bcm40183b2",		""},
	{BCM4330_CHIP_ID,	4,	FW_TYPE_AG,	"bcm40183b2_ag",	""},
	{BCM43430_CHIP_ID,	0,	DONT_CARE,	"bcm43438a0",		""},
	{BCM43430_CHIP_ID,	1,	DONT_CARE,	"bcm43438a1",		"ap6212a"},
	{BCM43430_CHIP_ID,	2,	DONT_CARE,	"bcm43436b0",		""},
	{BCM43012_CHIP_ID,	1,	FW_TYPE_G,	"bcm43013b0",		""},
	{BCM43012_CHIP_ID,	1,	FW_TYPE_AG,	"bcm43013c0_ag",	""},
	{BCM43012_CHIP_ID,	2,	DONT_CARE,	"bcm43013c1_ag",	""},
	{BCM4334_CHIP_ID,	3,	DONT_CARE,	"bcm4334b1_ag",		""},
	{BCM43340_CHIP_ID,	2,	DONT_CARE,	"bcm43341b0_ag",	""},
	{BCM43341_CHIP_ID,	2,	DONT_CARE,	"bcm43341b0_ag",	""},
	{BCM4324_CHIP_ID,	5,	DONT_CARE,	"bcm43241b4_ag",	""},
	{BCM4335_CHIP_ID,	2,	DONT_CARE,	"bcm4339a0_ag",		""},
	{BCM4339_CHIP_ID,	1,	DONT_CARE,	"bcm4339a0_ag",		""},
	{BCM4345_CHIP_ID,	6,	DONT_CARE,	"bcm43455c0_ag",	""},
	{BCM43454_CHIP_ID,	6,	DONT_CARE,	"bcm43455c0_ag",	""},
	{BCM4345_CHIP_ID,	9,	DONT_CARE,	"bcm43456c5_ag",	"ap6256"},
	{BCM43454_CHIP_ID,	9,	DONT_CARE,	"bcm43456c5_ag",	""},
	{BCM4354_CHIP_ID,	1,	DONT_CARE,	"bcm4354a1_ag",		""},
	{BCM4354_CHIP_ID,	2,	DONT_CARE,	"bcm4356a2_ag",		""},
	{BCM4356_CHIP_ID,	2,	DONT_CARE,	"bcm4356a2_ag",		""},
	{BCM4371_CHIP_ID,	2,	DONT_CARE,	"bcm4356a2_ag",		""},
	{BCM43569_CHIP_ID,	3,	DONT_CARE,	"bcm4358a3_ag",		""},
	{BCM4359_CHIP_ID,	5,	DONT_CARE,	"bcm4359b1_ag",		""},
	{BCM4359_CHIP_ID,	9,	DONT_CARE,	"bcm4359c0_ag",		""},
	{BCM43751_CHIP_ID,	1,	DONT_CARE,	"bcm43751a1_ag",	""},
	{BCM43751_CHIP_ID,	2,	DONT_CARE,	"bcm43751a2_ag",	""},
	{BCM43752_CHIP_ID,	1,	DONT_CARE,	"bcm43752a1_ag",	""},
	{BCM43752_CHIP_ID,	2,	DONT_CARE,	"bcm43752a2_ag",	""},
#endif
#ifdef BCMPCIE
	{BCM4354_CHIP_ID,	2,	DONT_CARE,	"bcm4356a2_pcie_ag",	""},
	{BCM4356_CHIP_ID,	2,	DONT_CARE,	"bcm4356a2_pcie_ag",	""},
	{BCM4359_CHIP_ID,	9,	DONT_CARE,	"bcm4359c0_pcie_ag",	""},
	{BCM43751_CHIP_ID,	1,	DONT_CARE,	"bcm43751a1_pcie_ag",	""},
	{BCM43751_CHIP_ID,	2,	DONT_CARE,	"bcm43751a2_pcie_ag",	""},
	{BCM43752_CHIP_ID,	1,	DONT_CARE,	"bcm43752a1_pcie_ag",	""},
	{BCM43752_CHIP_ID,	2,	DONT_CARE,	"bcm43752a2_pcie_ag",	""},
	{BCM4375_CHIP_ID,	5,	DONT_CARE,	"bcm4375b4_pcie_ag",	""},
#endif
#ifdef BCMDBUS
	{BCM43143_CHIP_ID,	2,	DONT_CARE,	"bcm43143b0",		""},
	{BCM43242_CHIP_ID,	1,	DONT_CARE,	"bcm43242a1_ag",	""},
	{BCM43569_CHIP_ID,	2,	DONT_CARE,	"bcm4358u_ag",		""},
#endif
};

#ifdef UPDATE_MODULE_NAME
typedef void (compat_func_t)(dhd_pub_t *dhd);
typedef struct module_name_map_t {
	uint devid;
	uint chip;
	uint chiprev;
	uint svid;
	uint ssid;
	char *module_name;
	char *chip_name;
	compat_func_t *compat_func;
} module_name_map_t;

#if defined(BCMSDIO) || defined(BCMPCIE)
static void dhd_conf_compat_vht(dhd_pub_t *dhd);
#endif

const module_name_map_t module_name_map[] = {
	/* Devce ID			Chip ID			Chiprev	SVID	SSID
	 *  ModuleName		ChipName			Compat function
	 */
#ifdef BCMSDIO
	{BCM43751_CHIP_ID,	BCM43752_CHIP_ID,	2,	0, 0,
		"ap6398s2",		"bcm4359c51a2_ag",	dhd_conf_compat_vht},
	{BCM43751_CHIP_ID,	BCM43752_CHIP_ID,	2,	0, 0,
		"ap6398sr32",	"bcm4359c51a2_ag",	dhd_conf_compat_vht},
	{BCM43751_CHIP_ID,	BCM43752_CHIP_ID,	2,	0, 0,
		"ap6398sv",		"bcm4359c51a2_ag",	dhd_conf_compat_vht},
	{BCM43751_CHIP_ID,	BCM43752_CHIP_ID,	2,	0, 0,
		"ap6398sv3",	"bcm4359c51a2_ag",	dhd_conf_compat_vht},
#endif
#ifdef BCMPCIE
	{BCM43751_D11AX_ID,	BCM43752_CHIP_ID,	2,	0x179F, 0x003C,
		"ap6398p2",		"bcm4359c51a2_pcie_ag",	dhd_conf_compat_vht},
	{BCM43751_D11AX_ID,	BCM43752_CHIP_ID,	2,	0x17F9, 0x003C,
		"ap6398p2",		"bcm4359c51a2_pcie_ag",	dhd_conf_compat_vht},
	{BCM43751_D11AX_ID,	BCM43752_CHIP_ID,	2,	0x17F9, 0x003D,
		"ap6398pr32",	"bcm4359c51a2_pcie_ag",	dhd_conf_compat_vht},
	{BCM43751_D11AX_ID,	BCM43752_CHIP_ID,	2,	0x17F9, 0x003E,
		"ap6398pv",		"bcm4359c51a2_pcie_ag",	dhd_conf_compat_vht},
	{BCM43751_D11AX_ID,	BCM43752_CHIP_ID,	2,	0x17F9, 0x003F,
		"ap6398pv3",	"bcm4359c51a2_pcie_ag",	dhd_conf_compat_vht},
#endif
};
#endif

#ifdef BCMPCIE
typedef struct chip_cisaddr_map_t {
	uint chip;
	uint chiprev;
	uint start_addr;
	uint end_addr;
} chip_cisaddr_map_t;
const chip_cisaddr_map_t chip_cisaddr_map[] = {
	/* ChipID			Chiprev	Start	 	End  */
	{BCM4354_CHIP_ID,	2,		0x0,		0x0},
	{BCM4356_CHIP_ID,	2,		0x0,		0x0},
	{BCM4359_CHIP_ID,	9,		0x0,		0x0},
//	{BCM43752_CHIP_ID,	2,		0x18011120,	0x18011177},
//	{BCM4375_CHIP_ID,	5,		0x18011120,	0x18011177},
};
#endif

#ifdef DHD_TPUT_PATCH
extern int dhd_change_mtu(dhd_pub_t *dhd, int new_mtu, int ifidx);
#endif

void
dhd_conf_free_chip_nv_path_list(wl_chip_nv_path_list_ctrl_t *chip_nv_list)
{
	CONFIG_TRACE("called\n");

	if (chip_nv_list->m_chip_nv_path_head) {
		CONFIG_TRACE("Free %p\n", chip_nv_list->m_chip_nv_path_head);
		kfree(chip_nv_list->m_chip_nv_path_head);
		chip_nv_list->m_chip_nv_path_head = NULL;
	}
	chip_nv_list->count = 0;
}

#if defined(BCMSDIO) || defined(BCMPCIE)
typedef struct cis_tuple_format {
	uint8	id;
	uint8	len;	/* total length of tag and data */
	uint8	tag;
	uint8	data[1];
} cis_tuple_format_t;
#define SBSDIO_CIS_SIZE_LIMIT		0x200
#define SBSDIO_TUPLE_SIZE_LIMIT		0xff
#define CIS_TUPLE_ID_BRCM			0x80
#define CIS_TUPLE_TAG_MACADDR		0x19
#define CIS_TUPLE_ID_AMPAK			0x8e
#define CIS_TUPLE_TAG_MODULE		0x41
#define CIS_TUPLE_LENGTH		1
#define CIS_TUPLE_HDR_LEN		2
#endif

#ifdef BCMSDIO
#if defined(HW_OOB) || defined(FORCE_WOWLAN)
void
dhd_conf_set_hw_oob_intr(bcmsdh_info_t *sdh, struct si_pub *sih)
{
	uint32 gpiocontrol, addr;

	if (CHIPID(sih->chip) == BCM43362_CHIP_ID) {
		CONFIG_MSG("Enable HW OOB for 43362\n");
		addr = SI_ENUM_BASE(sih) + OFFSETOF(chipcregs_t, gpiocontrol);
		gpiocontrol = bcmsdh_reg_read(sdh, addr, 4);
		gpiocontrol |= 0x2;
		bcmsdh_reg_write(sdh, addr, 4, gpiocontrol);
		bcmsdh_cfg_write(sdh, SDIO_FUNC_1, 0x10005, 0xf, NULL);
		bcmsdh_cfg_write(sdh, SDIO_FUNC_1, 0x10006, 0x0, NULL);
		bcmsdh_cfg_write(sdh, SDIO_FUNC_1, 0x10007, 0x2, NULL);
	}
}
#endif

void
dhd_conf_get_otp(dhd_pub_t *dhd, bcmsdh_info_t *sdh, si_t *sih)
{
	int i, err = -1;
	uint8 *cis, *ptr = 0;
	uint8 mac_header[3] = {0x80, 0x07, 0x19};
	cis_tuple_format_t *tuple;
	int totlen, len;

	if (!(cis = MALLOC(dhd->osh, SBSDIO_CIS_SIZE_LIMIT))) {
		CONFIG_ERROR("cis malloc failed\n");
	}
	bzero(cis, SBSDIO_CIS_SIZE_LIMIT);

	if ((err = bcmsdh_cis_read(sdh, 0, cis, SBSDIO_CIS_SIZE_LIMIT))) {
		CONFIG_ERROR("cis read err %d\n", err);
		MFREE(dhd->osh, cis, SBSDIO_CIS_SIZE_LIMIT);
		return;
	}
	tuple = (cis_tuple_format_t *)cis;
	totlen = SBSDIO_CIS_SIZE_LIMIT;
	if (config_msg_level & CONFIG_TRACE_LEVEL) {
		prhex("CIS", &tuple->id, totlen);
	}
	while (totlen >= (tuple->len + CIS_TUPLE_HDR_LEN)) {
		len = tuple->len;
		if ((config_msg_level & CONFIG_TRACE_LEVEL) && tuple->id) {
			prhex("TPL", &tuple->id, tuple->len + CIS_TUPLE_HDR_LEN);
		}
		if (tuple->id == 0xff || tuple->len == 0xff)
			break;
		if ((tuple->id == CIS_TUPLE_ID_BRCM) &&
				(tuple->tag == CIS_TUPLE_TAG_MACADDR) &&
				(totlen >= (int)(len + CIS_TUPLE_HDR_LEN))) {
			memcpy(&dhd->conf->otp_mac, tuple->data, ETHER_ADDR_LEN);
		}
#ifdef GET_OTP_MODULE_NAME
		else if (tuple->id == CIS_TUPLE_ID_AMPAK && (tuple->len) &&
				tuple->tag == CIS_TUPLE_TAG_MODULE) {
			int len = tuple->len - 1;
			if (len <= sizeof(dhd->conf->module_name) - 1) {
				strncpy(dhd->conf->module_name, tuple->data, len);
				CONFIG_MSG("module_name=%s\n", dhd->conf->module_name);
			} else {
				CONFIG_ERROR("len is too long %d >= %d\n",
					len, (int)sizeof(dhd->conf->module_name) - 1);
			}
		}
#endif
		tuple = (cis_tuple_format_t*)((uint8*)tuple + (len + CIS_TUPLE_HDR_LEN));
		totlen -= (len + CIS_TUPLE_HDR_LEN);
	}

	if (!memcmp(&ether_null, &dhd->conf->otp_mac, ETHER_ADDR_LEN)) {
		ptr = cis;
		/* Special OTP */
		if (bcmsdh_reg_read(sdh, SI_ENUM_BASE(sih), 4) == 0x16044330) {
			for (i=0; i<SBSDIO_CIS_SIZE_LIMIT; i++) {
				if (!memcmp(mac_header, ptr, 3)) {
					memcpy(&dhd->conf->otp_mac, ptr+3, ETHER_ADDR_LEN);
					break;
				}
				ptr++;
			}
		}
	}

	ASSERT(cis);
	MFREE(dhd->osh, cis, SBSDIO_CIS_SIZE_LIMIT);
}

#ifdef SET_FWNV_BY_MAC
void
dhd_conf_free_mac_list(wl_mac_list_ctrl_t *mac_list)
{
	int i;

	CONFIG_TRACE("called\n");
	if (mac_list->m_mac_list_head) {
		for (i=0; i<mac_list->count; i++) {
			if (mac_list->m_mac_list_head[i].mac) {
				CONFIG_TRACE("Free mac %p\n", mac_list->m_mac_list_head[i].mac);
				kfree(mac_list->m_mac_list_head[i].mac);
			}
		}
		CONFIG_TRACE("Free m_mac_list_head %p\n", mac_list->m_mac_list_head);
		kfree(mac_list->m_mac_list_head);
	}
	mac_list->count = 0;
}

void
dhd_conf_set_fw_name_by_mac(dhd_pub_t *dhd, char *fw_path)
{
	int i, j;
	uint8 *mac = (uint8 *)&dhd->conf->otp_mac;
	int fw_num=0, mac_num=0;
	uint32 oui, nic;
	wl_mac_list_t *mac_list;
	wl_mac_range_t *mac_range;
	int fw_type, fw_type_new;
	char *name_ptr;

	mac_list = dhd->conf->fw_by_mac.m_mac_list_head;
	fw_num = dhd->conf->fw_by_mac.count;
	if (!mac_list || !fw_num)
		return;

	oui = (mac[0] << 16) | (mac[1] << 8) | (mac[2]);
	nic = (mac[3] << 16) | (mac[4] << 8) | (mac[5]);

	/* find out the last '/' */
	i = strlen(fw_path);
	while (i > 0) {
		if (fw_path[i] == '/') {
			i++;
			break;
		}
		i--;
	}
	name_ptr = &fw_path[i];

	if (strstr(name_ptr, "_apsta"))
		fw_type = FW_TYPE_APSTA;
	else if (strstr(name_ptr, "_p2p"))
		fw_type = FW_TYPE_P2P;
	else if (strstr(name_ptr, "_mesh"))
		fw_type = FW_TYPE_MESH;
	else if (strstr(name_ptr, "_ezmesh"))
		fw_type = FW_TYPE_EZMESH;
	else if (strstr(name_ptr, "_es"))
		fw_type = FW_TYPE_ES;
	else if (strstr(name_ptr, "_mfg"))
		fw_type = FW_TYPE_MFG;
	else
		fw_type = FW_TYPE_STA;

	for (i=0; i<fw_num; i++) {
		mac_num = mac_list[i].count;
		mac_range = mac_list[i].mac;
		if (strstr(mac_list[i].name, "_apsta"))
			fw_type_new = FW_TYPE_APSTA;
		else if (strstr(mac_list[i].name, "_p2p"))
			fw_type_new = FW_TYPE_P2P;
		else if (strstr(mac_list[i].name, "_mesh"))
			fw_type_new = FW_TYPE_MESH;
		else if (strstr(mac_list[i].name, "_ezmesh"))
			fw_type_new = FW_TYPE_EZMESH;
		else if (strstr(mac_list[i].name, "_es"))
			fw_type_new = FW_TYPE_ES;
		else if (strstr(mac_list[i].name, "_mfg"))
			fw_type_new = FW_TYPE_MFG;
		else
			fw_type_new = FW_TYPE_STA;
		if (fw_type != fw_type_new) {
			CONFIG_MSG("fw_typ=%d != fw_type_new=%d\n", fw_type, fw_type_new);
			continue;
		}
		for (j=0; j<mac_num; j++) {
			if (oui == mac_range[j].oui) {
				if (nic >= mac_range[j].nic_start && nic <= mac_range[j].nic_end) {
					strcpy(name_ptr, mac_list[i].name);
					CONFIG_MSG("matched oui=0x%06X, nic=0x%06X\n", oui, nic);
					CONFIG_MSG("fw_path=%s\n", fw_path);
					return;
				}
			}
		}
	}
}

void
dhd_conf_set_nv_name_by_mac(dhd_pub_t *dhd, char *nv_path)
{
	int i, j;
	uint8 *mac = (uint8 *)&dhd->conf->otp_mac;
	int nv_num=0, mac_num=0;
	uint32 oui, nic;
	wl_mac_list_t *mac_list;
	wl_mac_range_t *mac_range;
	char *pnv_name;

	mac_list = dhd->conf->nv_by_mac.m_mac_list_head;
	nv_num = dhd->conf->nv_by_mac.count;
	if (!mac_list || !nv_num)
		return;

	oui = (mac[0] << 16) | (mac[1] << 8) | (mac[2]);
	nic = (mac[3] << 16) | (mac[4] << 8) | (mac[5]);

	/* find out the last '/' */
	i = strlen(nv_path);
	while (i > 0) {
		if (nv_path[i] == '/') break;
		i--;
	}
	pnv_name = &nv_path[i+1];

	for (i=0; i<nv_num; i++) {
		mac_num = mac_list[i].count;
		mac_range = mac_list[i].mac;
		for (j=0; j<mac_num; j++) {
			if (oui == mac_range[j].oui) {
				if (nic >= mac_range[j].nic_start && nic <= mac_range[j].nic_end) {
					strcpy(pnv_name, mac_list[i].name);
					CONFIG_MSG("matched oui=0x%06X, nic=0x%06X\n", oui, nic);
					CONFIG_MSG("nv_path=%s\n", nv_path);
					return;
				}
			}
		}
	}
}
#endif
#endif

#ifdef BCMPCIE
static int
dhd_conf_read_otp_from_bp(si_t *sih, uint32 *data_buf,
	uint32 cis_start_addr, uint32 cis_max_cnt)
{
	int int_val = 0, i = 0, bp_idx = 0;
	int boardtype_backplane_addr[] = {
		0x18010324, /* OTP Control 1 */
		0x18012618, /* PMU min resource mask */
	};
	int boardtype_backplane_data[] = {
		0x00fa0000,
		0x0e4fffff /* Keep on ARMHTAVAIL */
	};
	uint32 org_boardtype_backplane_data[] = {
		0,
		0
	};

	for (bp_idx=0; bp_idx<ARRAYSIZE(boardtype_backplane_addr); bp_idx++) {
		/* Read OTP Control 1 and PMU min_rsrc_mask before writing */
		if (si_backplane_access(sih, boardtype_backplane_addr[bp_idx], sizeof(int),
				&org_boardtype_backplane_data[bp_idx], TRUE) != BCME_OK) {
			CONFIG_ERROR("invalid size/addr combination\n");
			return BCME_ERROR;
		}

		/* Write new OTP and PMU configuration */
		if (si_backplane_access(sih, boardtype_backplane_addr[bp_idx], sizeof(int),
				&boardtype_backplane_data[bp_idx], FALSE) != BCME_OK) {
			CONFIG_ERROR("invalid size/addr combination\n");
			return BCME_ERROR;
		}

		if (si_backplane_access(sih, boardtype_backplane_addr[bp_idx], sizeof(int),
				&int_val, TRUE) != BCME_OK) {
			CONFIG_ERROR("invalid size/addr combination\n");
			return BCME_ERROR;
		}

		CONFIG_TRACE("boardtype_backplane_addr 0x%08x rdata 0x%04x\n",
			boardtype_backplane_addr[bp_idx], int_val);
	}

	/* read tuple raw data */
	for (i=0; i<cis_max_cnt; i++) {
		if (si_backplane_access(sih, cis_start_addr + i * sizeof(uint32),
				sizeof(uint32),	&data_buf[i], TRUE) != BCME_OK) {
			break;
		}
		CONFIG_TRACE("tuple index %d, raw data 0x%08x\n", i,  data_buf[i]);
	}

	for (bp_idx=0; bp_idx<ARRAYSIZE(boardtype_backplane_addr); bp_idx++) {
		/* Write original OTP and PMU configuration */
		if (si_backplane_access(sih, boardtype_backplane_addr[bp_idx], sizeof(int),
				&org_boardtype_backplane_data[bp_idx], FALSE) != BCME_OK) {
			CONFIG_ERROR("invalid size/addr combination\n");
			return BCME_ERROR;
		}

		if (si_backplane_access(sih, boardtype_backplane_addr[bp_idx], sizeof(int),
				&int_val, TRUE) != BCME_OK) {
			CONFIG_ERROR("invalid size/addr combination\n");
			return BCME_ERROR;
		}

		CONFIG_TRACE("boardtype_backplane_addr 0x%08x rdata 0x%04x\n",
			boardtype_backplane_addr[bp_idx], int_val);
	}

	return i * sizeof(uint32);
}

int
dhd_conf_get_otp(dhd_pub_t *dhd, si_t *sih)
{
	int totlen, len;
	uint32 *raw_data = NULL;
	cis_tuple_format_t *tuple;
	uint32 cis_start_addr = 0, cis_end_addr = 0, cis_max_cnt;
	uint chip, chiprev;
	int i, ret = BCME_OK;

	chip = dhd->conf->chip;
	chiprev = dhd->conf->chiprev;

	for (i=0; i<sizeof(chip_cisaddr_map)/sizeof(chip_cisaddr_map[0]); i++) {
		const chip_cisaddr_map_t* row = &chip_cisaddr_map[i];
		if (row->chip == chip && row->chiprev == chiprev) {
			cis_start_addr = row->start_addr;
			cis_end_addr = row->end_addr;
		}
	}

	if (!cis_start_addr || !cis_end_addr) {
		CONFIG_TRACE("no matched chip\n");
		goto exit;
	}
	cis_max_cnt = (cis_end_addr - cis_start_addr + 1) / sizeof(uint32);

	raw_data = kmalloc(cis_max_cnt, GFP_KERNEL);
	if (raw_data == NULL) {
		CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", cis_max_cnt);
		goto exit;
	}

	totlen = dhd_conf_read_otp_from_bp(sih, raw_data, cis_start_addr, cis_max_cnt);
	if (totlen == BCME_ERROR || totlen == 0) {
		CONFIG_ERROR("Can't read the OTP\n");
		ret = BCME_ERROR;
		goto exit;
	}

	tuple = (cis_tuple_format_t *)raw_data;

	if (config_msg_level & CONFIG_TRACE_LEVEL) {
		CONFIG_TRACE("start: 0x%x, end: 0x%x, totlen: %d\n",
			cis_start_addr, cis_end_addr, totlen);
		prhex("CIS", &tuple->id, totlen);
	}

	/* check the first tuple has tag 'start' */
	if (tuple->id != CIS_TUPLE_ID_BRCM) {
		CONFIG_ERROR("Can not find the TAG\n");
		ret = BCME_ERROR;
		goto exit;
	}

	/* find tagged parameter */
	while (totlen >= (tuple->len + CIS_TUPLE_HDR_LEN)) {
		len = tuple->len;
		if ((config_msg_level & CONFIG_TRACE_LEVEL) && tuple->id) {
			prhex("TPL", &tuple->id, tuple->len+CIS_TUPLE_HDR_LEN);
		}
		if ((tuple->id == CIS_TUPLE_ID_BRCM) &&
				(tuple->tag == CIS_TUPLE_TAG_MACADDR) &&
				(totlen >= (int)(len + CIS_TUPLE_HDR_LEN))) {
			memcpy(&dhd->conf->otp_mac, tuple->data, ETHER_ADDR_LEN);
		}
		tuple = (cis_tuple_format_t*)((uint8*)tuple + (len + CIS_TUPLE_HDR_LEN));
		totlen -= (len + CIS_TUPLE_HDR_LEN);
	}

exit:
	if(raw_data)
		kfree(raw_data);
	return ret;
}

bool
dhd_conf_legacy_msi_chip(dhd_pub_t *dhd)
{
	uint chip;

	chip = dhd->conf->chip;

	if (chip == BCM4354_CHIP_ID || chip == BCM4356_CHIP_ID ||
		chip == BCM4371_CHIP_ID ||
		chip == BCM4359_CHIP_ID) {
		return true;
	}

	return false;
}
#endif

void
dhd_conf_free_country_list(struct dhd_conf *conf)
{
	country_list_t *country = conf->country_head;
	int count = 0;

	CONFIG_TRACE("called\n");
	while (country) {
		CONFIG_TRACE("Free cspec %s\n", country->cspec.country_abbrev);
		conf->country_head = country->next;
		kfree(country);
		country = conf->country_head;
		count++;
	}
	CONFIG_TRACE("%d country released\n", count);
}

void
dhd_conf_free_mchan_list(struct dhd_conf *conf)
{
	mchan_params_t *mchan = conf->mchan;
	int count = 0;

	CONFIG_TRACE("called\n");
	while (mchan) {
		CONFIG_TRACE("Free cspec %p\n", mchan);
		conf->mchan = mchan->next;
		kfree(mchan);
		mchan = conf->mchan;
		count++;
	}
	CONFIG_TRACE("%d mchan released\n", count);
}

const chip_name_map_t*
dhd_conf_match_chip(dhd_pub_t *dhd, uint ag_type)
{
	uint chip, chiprev;
	int i;

	chip = dhd->conf->chip;
	chiprev = dhd->conf->chiprev;

	for (i=0; i<sizeof(chip_name_map)/sizeof(chip_name_map[0]); i++) {
		const chip_name_map_t* row = &chip_name_map[i];
		if (row->chip == chip && row->chiprev == chiprev &&
				(row->ag_type == ag_type ||
					ag_type == DONT_CARE || row->ag_type == DONT_CARE)) {
			return row;
		}
	}

	return NULL;
}

#ifdef UPDATE_MODULE_NAME
const module_name_map_t*
dhd_conf_match_module(dhd_pub_t *dhd)
{
	uint devid, chip, chiprev;
#ifdef BCMPCIE
	uint svid, ssid;
#endif
#if defined(BCMSDIO) || defined(BCMPCIE)
	int i;
#endif

	devid = dhd->conf->devid;
	chip = dhd->conf->chip;
	chiprev = dhd->conf->chiprev;
#ifdef BCMPCIE
	svid = dhd->conf->svid;
	ssid = dhd->conf->ssid;
#endif

#ifdef BCMSDIO
	for (i=0; i<sizeof(module_name_map)/sizeof(module_name_map[0]); i++) {
		const module_name_map_t* row = &module_name_map[i];
		if (row->devid == devid && row->chip == chip && row->chiprev == chiprev &&
				!strcmp(row->module_name, dhd->conf->module_name)) {
			return row;
		}
	}
#endif

#ifdef BCMPCIE
	for (i=0; i<sizeof(module_name_map)/sizeof(module_name_map[0]); i++) {
		const module_name_map_t* row = &module_name_map[i];
		if (row->devid == devid && row->chip == chip && row->chiprev == chiprev &&
				row->svid == svid && row->ssid == ssid) {
			return row;
		}
	}
#endif

	return NULL;
}
#endif

int
dhd_conf_set_fw_name_by_chip(dhd_pub_t *dhd, char *fw_path)
{
#ifdef UPDATE_MODULE_NAME
	const module_name_map_t* row_module = NULL;
#endif
	const chip_name_map_t* row_chip = NULL;
	int fw_type, ag_type;
	uint chip, chiprev;
	char *name_ptr;
	int i;

	chip = dhd->conf->chip;
	chiprev = dhd->conf->chiprev;

	if (fw_path[0] == '\0') {
#ifdef CONFIG_BCMDHD_FW_PATH
		bcm_strncpy_s(fw_path, MOD_PARAM_PATHLEN-1, CONFIG_BCMDHD_FW_PATH, MOD_PARAM_PATHLEN-1);
		if (fw_path[0] == '\0')
#endif
		{
			CONFIG_MSG("firmware path is null\n");
			return 0;
		}
	}
#ifndef FW_PATH_AUTO_SELECT
	return DONT_CARE;
#endif

	/* find out the last '/' */
	i = strlen(fw_path);
	while (i > 0) {
		if (fw_path[i] == '/') {
			i++;
			break;
		}
		i--;
	}
	name_ptr = &fw_path[i];
#ifdef BAND_AG
	ag_type = FW_TYPE_AG;
#else
	ag_type = strstr(name_ptr, "_ag") ? FW_TYPE_AG : FW_TYPE_G;
#endif
	if (strstr(name_ptr, "_apsta"))
		fw_type = FW_TYPE_APSTA;
	else if (strstr(name_ptr, "_p2p"))
		fw_type = FW_TYPE_P2P;
	else if (strstr(name_ptr, "_mesh"))
		fw_type = FW_TYPE_MESH;
	else if (strstr(name_ptr, "_ezmesh"))
		fw_type = FW_TYPE_EZMESH;
	else if (strstr(name_ptr, "_es"))
		fw_type = FW_TYPE_ES;
	else if (strstr(name_ptr, "_mfg"))
		fw_type = FW_TYPE_MFG;
	else if (strstr(name_ptr, "_minime"))
		fw_type = FW_TYPE_MINIME;
	else
		fw_type = FW_TYPE_STA;
#ifdef WLEASYMESH
	if (dhd->conf->fw_type == FW_TYPE_EZMESH)
		fw_type = FW_TYPE_EZMESH;
#endif /* WLEASYMESH */

	row_chip = dhd_conf_match_chip(dhd, ag_type);
	if (row_chip && strlen(row_chip->chip_name)) {
		strcpy(name_ptr, "fw_");
		strcat(name_ptr, row_chip->chip_name);
#ifdef BCMUSBDEV_COMPOSITE
		strcat(name_ptr, "_cusb");
#endif
		if (fw_type == FW_TYPE_APSTA)
			strcat(name_ptr, "_apsta.bin");
		else if (fw_type == FW_TYPE_P2P)
			strcat(name_ptr, "_p2p.bin");
		else if (fw_type == FW_TYPE_MESH)
			strcat(name_ptr, "_mesh.bin");
		else if (fw_type == FW_TYPE_EZMESH)
			strcat(name_ptr, "_ezmesh.bin");
		else if (fw_type == FW_TYPE_ES)
			strcat(name_ptr, "_es.bin");
		else if (fw_type == FW_TYPE_MFG)
			strcat(name_ptr, "_mfg.bin");
		else if (fw_type == FW_TYPE_MINIME)
			strcat(name_ptr, "_minime.bin");
		else
			strcat(name_ptr, ".bin");
	}

#ifdef UPDATE_MODULE_NAME
	row_module = dhd_conf_match_module(dhd);
	if (row_module && strlen(row_module->chip_name)) {
		strcpy(name_ptr, "fw_");
		strcat(name_ptr, row_module->chip_name);
#ifdef BCMUSBDEV_COMPOSITE
		strcat(name_ptr, "_cusb");
#endif
		if (fw_type == FW_TYPE_APSTA)
			strcat(name_ptr, "_apsta.bin");
		else if (fw_type == FW_TYPE_P2P)
			strcat(name_ptr, "_p2p.bin");
		else if (fw_type == FW_TYPE_MESH)
			strcat(name_ptr, "_mesh.bin");
		else if (fw_type == FW_TYPE_EZMESH)
			strcat(name_ptr, "_ezmesh.bin");
		else if (fw_type == FW_TYPE_ES)
			strcat(name_ptr, "_es.bin");
		else if (fw_type == FW_TYPE_MFG)
			strcat(name_ptr, "_mfg.bin");
		else if (fw_type == FW_TYPE_MINIME)
			strcat(name_ptr, "_minime.bin");
		else
			strcat(name_ptr, ".bin");
	}
#endif

	dhd->conf->fw_type = fw_type;

#ifndef MINIME
	if (fw_type == FW_TYPE_MINIME)
		CONFIG_ERROR("***** Please enable MINIME in Makefile *****\n");
#endif

	CONFIG_TRACE("firmware_path=%s\n", fw_path);
	return ag_type;
}

void
dhd_conf_set_clm_name_by_chip(dhd_pub_t *dhd, char *clm_path, int ag_type)
{
#ifdef UPDATE_MODULE_NAME
	const module_name_map_t* row_module = NULL;
#endif
	const chip_name_map_t* row_chip = NULL;
	uint chip, chiprev;
	char *name_ptr;
	int i;

	chip = dhd->conf->chip;
	chiprev = dhd->conf->chiprev;

	if (clm_path[0] == '\0') {
		CONFIG_MSG("clm path is null\n");
		return;
	}

	/* find out the last '/' */
	i = strlen(clm_path);
	while (i > 0) {
		if (clm_path[i] == '/') {
			i++;
			break;
		}
		i--;
	}
	name_ptr = &clm_path[i];

	row_chip = dhd_conf_match_chip(dhd, ag_type);
	if (row_chip && strlen(row_chip->chip_name)) {
		strcpy(name_ptr, "clm_");
		strcat(name_ptr, row_chip->chip_name);
		strcat(name_ptr, ".blob");
	}

#ifdef UPDATE_MODULE_NAME
	row_module = dhd_conf_match_module(dhd);
	if (row_module && strlen(row_module->chip_name)) {
		strcpy(name_ptr, "clm_");
		strcat(name_ptr, row_module->chip_name);
		strcat(name_ptr, ".blob");
	}
#endif

	CONFIG_TRACE("clm_path=%s\n", clm_path);
}

void
dhd_conf_set_nv_name_by_chip(dhd_pub_t *dhd, char *nv_path, int ag_type)
{
#if defined(BCMPCIE) && defined(UPDATE_MODULE_NAME)
	const module_name_map_t* row_module = NULL;
#endif
	const chip_name_map_t* row_chip = NULL;
	uint chip, chiprev;
	char *name_ptr, nv_name[32];
	int i;

	chip = dhd->conf->chip;
	chiprev = dhd->conf->chiprev;

	if (nv_path[0] == '\0') {
#ifdef CONFIG_BCMDHD_NVRAM_PATH
		bcm_strncpy_s(nv_path, MOD_PARAM_PATHLEN-1, CONFIG_BCMDHD_NVRAM_PATH, MOD_PARAM_PATHLEN-1);
		if (nv_path[0] == '\0')
#endif
		{
			CONFIG_MSG("nvram path is null\n");
			return;
		}
	}

	/* find out the last '/' */
	i = strlen(nv_path);
	while (i > 0) {
		if (nv_path[i] == '/') {
			i++;
			break;
		}
		i--;
	}
	name_ptr = &nv_path[i];

	row_chip = dhd_conf_match_chip(dhd, ag_type);
	if (row_chip && strlen(row_chip->module_name)) {
		strcpy(name_ptr, "nvram_");
		strcat(name_ptr, row_chip->module_name);
#ifdef BCMUSBDEV_COMPOSITE
		strcat(name_ptr, "_cusb");
#endif
		strcat(name_ptr, ".txt");
	}
	strcpy(nv_name, name_ptr);

#if defined(BCMSDIO) && defined(GET_OTP_MODULE_NAME)
	if (strlen(dhd->conf->module_name)) {
		strcpy(name_ptr, "nvram_");
		strcat(name_ptr, dhd->conf->module_name);
		strcat(name_ptr, ".txt");
#ifdef COMPAT_OLD_MODULE
		if (dhd->conf->chip == BCM4359_CHIP_ID) {
			struct file *fp;
			// compatible for AP6398S and AP6398SA
			fp = filp_open(nv_path, O_RDONLY, 0);
			if (IS_ERR(fp)) {
				strcpy(name_ptr, nv_name);
			} else {
				filp_close((struct file *)fp, NULL);
			}
		}
#endif
	}
#endif

#if defined(BCMPCIE) && defined(UPDATE_MODULE_NAME)
	row_module = dhd_conf_match_module(dhd);
	if (row_module && strlen(row_module->module_name)) {
		strcpy(name_ptr, "nvram_");
		strcat(name_ptr, row_module->module_name);
		strcat(name_ptr, ".txt");
	}
#endif

	for (i=0; i<dhd->conf->nv_by_chip.count; i++) {
		if (chip==dhd->conf->nv_by_chip.m_chip_nv_path_head[i].chip &&
				chiprev==dhd->conf->nv_by_chip.m_chip_nv_path_head[i].chiprev) {
			strcpy(name_ptr, dhd->conf->nv_by_chip.m_chip_nv_path_head[i].name);
			break;
		}
	}

	CONFIG_TRACE("nvram_path=%s\n", nv_path);
}

void
dhd_conf_copy_path(dhd_pub_t *dhd, char *dst_name, char *dst_path, char *src_path)
{
	int i;

	if (src_path[0] == '\0') {
		CONFIG_MSG("src_path is null\n");
		return;
	} else
		strcpy(dst_path, src_path);

	/* find out the last '/' */
	i = strlen(dst_path);
	while (i > 0) {
		if (dst_path[i] == '/') {
			i++;
			break;
		}
		i--;
	}
	strcpy(&dst_path[i], dst_name);

	CONFIG_TRACE("dst_path=%s\n", dst_path);
}

#ifdef CONFIG_PATH_AUTO_SELECT
void
dhd_conf_set_conf_name_by_chip(dhd_pub_t *dhd, char *conf_path)
{
#ifdef UPDATE_MODULE_NAME
	const module_name_map_t* row_module = NULL;
#endif
	const chip_name_map_t* row_chip = NULL;
	uint chip, chiprev;
	char *name_ptr;
	int i;

	chip = dhd->conf->chip;
	chiprev = dhd->conf->chiprev;

	if (conf_path[0] == '\0') {
		CONFIG_MSG("config path is null\n");
		return;
	}

	/* find out the last '/' */
	i = strlen(conf_path);
	while (i > 0) {
		if (conf_path[i] == '/') {
			i++;
			break;
		}
		i--;
	}
	name_ptr = &conf_path[i];

	row_chip = dhd_conf_match_chip(dhd, DONT_CARE);
	if (row_chip && strlen(row_chip->chip_name)) {
		strcpy(name_ptr, "config_");
		strcat(name_ptr, row_chip->chip_name);
		strcat(name_ptr, ".txt");
	}

#ifdef UPDATE_MODULE_NAME
	row_module = dhd_conf_match_module(dhd);
	if (row_module && strlen(row_module->chip_name)) {
		strcpy(name_ptr, "config_");
		strcat(name_ptr, row_module->chip_name);
		strcat(name_ptr, ".txt");
	}
#endif

	CONFIG_TRACE("config_path=%s\n", conf_path);
}
#endif

#ifdef TPUT_MONITOR
void
dhd_conf_tput_monitor(dhd_pub_t *dhd)
{
	struct dhd_conf *conf = dhd->conf;

	if (conf->tput_monitor_ms && conf->data_drop_mode >= FW_DROP) {
		if (conf->tput_ts.tv_sec == 0 && conf->tput_ts.tv_nsec == 0) {
			osl_do_gettimeofday(&conf->tput_ts);
		} else {
			struct osl_timespec cur_ts;
			int32 tput_tx = 0, tput_rx = 0, tput_tx_kb = 0,
				tput_rx_kb = 0, tput_net = 0, tput_net_kb = 0;
			uint32 diff_ms;
			unsigned long diff_bytes;
			osl_do_gettimeofday(&cur_ts);
			diff_ms = osl_do_gettimediff(&cur_ts, &conf->tput_ts)/1000;
			if (diff_ms >= conf->tput_monitor_ms) {
				diff_bytes = dhd->dstats.tx_bytes - conf->last_tx;
				tput_tx = (int32)((diff_bytes/1024/1024)*8)*1000/diff_ms;
				if (tput_tx == 0) {
					tput_tx = (int32)(diff_bytes*8/1024/1024)*1000/diff_ms;
					tput_tx_kb = (int32)(diff_bytes*8*1000/1024)/diff_ms;
					tput_tx_kb = tput_tx_kb % 1000;
				}
				diff_bytes = dhd->dstats.rx_bytes - conf->last_rx;
				tput_rx = (int32)((diff_bytes/1024/1024)*8)*1000/diff_ms;
				if (tput_rx == 0) {
					tput_rx = (int32)(diff_bytes*8/1024/1024)*1000/diff_ms;
					tput_rx_kb = (int32)(diff_bytes*8*1000/1024)/diff_ms;
					tput_rx_kb = tput_tx_kb % 1000;
				}
				diff_bytes = conf->net_len - conf->last_net_tx;
				tput_net = (int32)((diff_bytes/1024/1024)*8)*1000/diff_ms;
				if (tput_net == 0) {
					tput_net = (int32)(diff_bytes*8/1024/1024)*1000/diff_ms;
					tput_net_kb = (int32)(diff_bytes*8*1000/1024)/diff_ms;
					tput_net_kb = tput_net_kb % 1000;
				}
				conf->last_tx = dhd->dstats.tx_bytes;
				conf->last_rx = dhd->dstats.rx_bytes;
				conf->last_net_tx = conf->net_len;
				memcpy(&conf->tput_ts, &cur_ts, sizeof(struct osl_timespec));
				CONFIG_TRACE("xmit=%3d.%d%d%d Mbps, tx=%3d.%d%d%d Mbps, rx=%3d.%d%d%d Mbps\n",
					tput_net, (tput_net_kb/100)%10, (tput_net_kb/10)%10, (tput_net_kb)%10,
					tput_tx, (tput_tx_kb/100)%10, (tput_tx_kb/10)%10, (tput_tx_kb)%10,
					tput_rx, (tput_rx_kb/100)%10, (tput_rx_kb/10)%10, (tput_rx_kb)%10);
			}
		}
	}
}
#endif

#ifdef DHD_TPUT_PATCH
void
dhd_conf_set_tput_patch(dhd_pub_t *dhd)
{
	struct dhd_conf *conf = dhd->conf;

	if (conf->tput_patch) {
		conf->mtu = 1500;
		conf->pktsetsum = TRUE;
#ifdef BCMSDIO
		conf->dhd_dpc_prio = 98;
/* need to check if CPU can support multi-core first,
 * so don't enable it by default.
 */
//		conf->dpc_cpucore = 2;
//		conf->rxf_cpucore = 3;
//		conf->disable_proptx = 1;
		conf->frameburst = 1;
#ifdef DYNAMIC_MAX_HDR_READ
		conf->max_hdr_read = 256;
		firstread = 256;
#endif /* DYNAMIC_MAX_HDR_READ */
		dhd_rxbound = 512;
#endif /* BCMSDIO */
#ifdef BCMPCIE
#if defined(SET_XPS_CPUS)
		conf->xps_cpus = TRUE;
#endif /* SET_XPS_CPUS */
#if defined(SET_RPS_CPUS)
		conf->rps_cpus = TRUE;
#endif /* SET_RPS_CPUS */
		conf->orphan_move = 3;
		conf->flow_ring_queue_threshold = 2048;
#endif /* BCMPCIE */
#ifdef DHDTCPACK_SUPPRESS
		conf->tcpack_sup_ratio = 15;
		conf->tcpack_sup_delay = 10;
#endif /* DHDTCPACK_SUPPRESS */
	}
	else {
		conf->mtu = 0;
		conf->pktsetsum = FALSE;
#ifdef BCMSDIO
		conf->dhd_dpc_prio = -1;
		conf->disable_proptx = -1;
		conf->frameburst = 1;
#ifdef DYNAMIC_MAX_HDR_READ
		conf->max_hdr_read = 0;
		firstread = 32;
#endif /* DYNAMIC_MAX_HDR_READ */
		dhd_rxbound = 128;
#endif /* BCMSDIO */
#ifdef BCMPCIE
#if defined(SET_XPS_CPUS)
		conf->xps_cpus = FALSE;
#endif /* SET_XPS_CPUS */
#if defined(SET_RPS_CPUS)
		conf->rps_cpus = FALSE;
#endif /* SET_RPS_CPUS */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
		conf->orphan_move = 1;
#else
		conf->orphan_move = 0;
#endif
		conf->flow_ring_queue_threshold = 2048;
#endif /* BCMPCIE */
#ifdef DHDTCPACK_SUPPRESS
		conf->tcpack_sup_ratio = CUSTOM_TCPACK_SUPP_RATIO;
		conf->tcpack_sup_delay = CUSTOM_TCPACK_DELAY_TIME;
#endif /* DHDTCPACK_SUPPRESS */
	}
}

void
dhd_conf_dump_tput_patch(dhd_pub_t *dhd)
{
	struct dhd_conf *conf = dhd->conf;

	CONFIG_TRACE("tput_patch=%d\n", conf->tput_patch);
	CONFIG_TRACE("mtu=%d\n", conf->mtu);
	CONFIG_TRACE("pktsetsum=%d\n", conf->pktsetsum);
	CONFIG_TRACE("orphan_move=%d\n", conf->orphan_move);
#ifdef DHDTCPACK_SUPPRESS
	CONFIG_TRACE("tcpack_sup_ratio=%d\n", conf->tcpack_sup_ratio);
	CONFIG_TRACE("tcpack_sup_delay=%d\n", conf->tcpack_sup_delay);
#endif

#ifdef BCMSDIO
	CONFIG_TRACE("dhd_dpc_prio=%d\n", conf->dhd_dpc_prio);
	CONFIG_TRACE("dhd_poll=%d\n", conf->dhd_poll);
	CONFIG_TRACE("disable_proptx=%d\n", conf->disable_proptx);
	CONFIG_TRACE("frameburst=%d\n", conf->frameburst);
#ifdef DYNAMIC_MAX_HDR_READ
	CONFIG_TRACE("max_hdr_read=%d\n", conf->max_hdr_read);
	CONFIG_TRACE("firstread=%d\n", firstread);
#endif
	CONFIG_TRACE("dhd_rxbound=%d\n", dhd_rxbound);
#endif

#ifdef BCMPCIE
	CONFIG_TRACE("flow_ring_queue_threshold=%d\n", conf->flow_ring_queue_threshold);
#endif

#if defined(SET_XPS_CPUS)
	CONFIG_TRACE("xps_cpus=%d\n", conf->xps_cpus);
#endif
#if defined(SET_RPS_CPUS)
	CONFIG_TRACE("rps_cpus=%d\n", conf->rps_cpus);
#endif

}
#endif /* DHD_TPUT_PATCH */

void
dhd_conf_set_path_params(dhd_pub_t *dhd, char *fw_path, char *nv_path)
{
	int ag_type;

	/* External conf takes precedence if specified */
	dhd_conf_preinit(dhd);

	if (dhd->conf_path[0] == '\0') {
		dhd_conf_copy_path(dhd, "config.txt", dhd->conf_path, nv_path);
	}
	if (dhd->clm_path[0] == '\0') {
		dhd_conf_copy_path(dhd, "clm.blob", dhd->clm_path, fw_path);
	}
#ifdef CONFIG_PATH_AUTO_SELECT
	dhd_conf_set_conf_name_by_chip(dhd, dhd->conf_path);
#endif

	dhd_conf_read_config(dhd, dhd->conf_path);
#ifdef DHD_TPUT_PATCH
	dhd_conf_dump_tput_patch(dhd);
#endif

	ag_type = dhd_conf_set_fw_name_by_chip(dhd, fw_path);
	dhd_conf_set_nv_name_by_chip(dhd, nv_path, ag_type);
	dhd_conf_set_clm_name_by_chip(dhd, dhd->clm_path, ag_type);
#ifdef SET_FWNV_BY_MAC
	dhd_conf_set_fw_name_by_mac(dhd, fw_path);
	dhd_conf_set_nv_name_by_mac(dhd, nv_path);
#endif

	CONFIG_MSG("Final fw_path=%s\n", fw_path);
	CONFIG_MSG("Final nv_path=%s\n", nv_path);
	CONFIG_MSG("Final clm_path=%s\n", dhd->clm_path);
	CONFIG_MSG("Final conf_path=%s\n", dhd->conf_path);
}

int
dhd_conf_set_intiovar(dhd_pub_t *dhd, int ifidx, uint cmd, char *name, int val,
	int def, bool down)
{
	int ret = -1;
	char iovbuf[WL_EVENTING_MASK_LEN + 12];	/*  Room for "event_msgs" + '\0' + bitvec  */

	if (val >= def) {
		if (down) {
			if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_DOWN, NULL, 0, TRUE, 0)) < 0)
				CONFIG_ERROR("WLC_DOWN setting failed %d\n", ret);
		}
		if (cmd == WLC_SET_VAR) {
			CONFIG_TRACE("set %s %d\n", name, val);
			bcm_mkiovar(name, (char *)&val, sizeof(val), iovbuf, sizeof(iovbuf));
			if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_VAR, iovbuf, sizeof(iovbuf), TRUE, 0)) < 0)
				CONFIG_ERROR("%s setting failed %d\n", name, ret);
		} else {
			CONFIG_TRACE("set %s %d %d\n", name, cmd, val);
			if ((ret = dhd_wl_ioctl_cmd(dhd, cmd, &val, sizeof(val), TRUE, 0)) < 0)
				CONFIG_ERROR("%s setting failed %d\n", name, ret);
		}
	}

	return ret;
}

static int
dhd_conf_set_bufiovar(dhd_pub_t *dhd, int ifidx, uint cmd, char *name,
	char *buf, int len, bool down)
{
	char iovbuf[WLC_IOCTL_SMLEN];
	s32 iovar_len;
	int ret = -1;

	if (down) {
		if ((ret = dhd_wl_ioctl_cmd(dhd, WLC_DOWN, NULL, 0, TRUE, ifidx)) < 0)
			CONFIG_ERROR("WLC_DOWN setting failed %d\n", ret);
	}

	if (cmd == WLC_SET_VAR) {
		iovar_len = bcm_mkiovar(name, buf, len, iovbuf, sizeof(iovbuf));
		if (iovar_len > 0)
			ret = dhd_wl_ioctl_cmd(dhd, cmd, iovbuf, iovar_len, TRUE, ifidx);
		else
			ret = BCME_BUFTOOSHORT;
		if (ret < 0)
			CONFIG_ERROR("%s setting failed %d, len=%d\n", name, ret, len);
	} else {
		if ((ret = dhd_wl_ioctl_cmd(dhd, cmd, buf, len, TRUE, ifidx)) < 0)
			CONFIG_ERROR("%s setting failed %d\n", name, ret);
	}

	return ret;
}

static int
dhd_conf_iovar_buf(dhd_pub_t *dhd, int ifidx, int cmd, char *name,
	char *buf, int len)
{
	char *iovbuf = NULL;
	int ret = -1, iovbuf_len = WLC_IOCTL_MEDLEN;
	s32 iovar_len;

	iovbuf = kmalloc(iovbuf_len, GFP_KERNEL);
	if (iovbuf == NULL) {
		CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", iovbuf_len);
		goto exit;
	}

	if (cmd == WLC_GET_VAR) {
		if (bcm_mkiovar(name, buf, len, iovbuf, iovbuf_len)) {
			ret = dhd_wl_ioctl_cmd(dhd, cmd, iovbuf, iovbuf_len, FALSE, ifidx);
			if (!ret) {
				memcpy(buf, iovbuf, len);
			} else {
				CONFIG_ERROR("get iovar %s failed %d\n", name, ret);
			}
		} else {
			CONFIG_ERROR("mkiovar %s failed\n", name);
		}
	} else if (cmd == WLC_SET_VAR) {
		iovar_len = bcm_mkiovar(name, buf, len, iovbuf, iovbuf_len);
		if (iovar_len > 0)
			ret = dhd_wl_ioctl_cmd(dhd, cmd, iovbuf, iovar_len, TRUE, ifidx);
		else
			ret = BCME_BUFTOOSHORT;
		if (ret < 0)
			CONFIG_ERROR("%s setting failed %d, len=%d\n", name, ret, len);
	}

exit:
	if (iovbuf)
		kfree(iovbuf);
	return ret;
}

static int
dhd_conf_get_iovar(dhd_pub_t *dhd, int ifidx, int cmd, char *name,
	char *buf, int len)
{
	char iovbuf[WLC_IOCTL_SMLEN];
	int ret = -1;

	if (cmd == WLC_GET_VAR) {
		if (bcm_mkiovar(name, NULL, 0, iovbuf, sizeof(iovbuf))) {
			ret = dhd_wl_ioctl_cmd(dhd, cmd, iovbuf, sizeof(iovbuf), FALSE, ifidx);
			if (!ret) {
				memcpy(buf, iovbuf, len);
			} else {
				CONFIG_ERROR("get iovar %s failed %d\n", name, ret);
			}
		} else {
			CONFIG_ERROR("mkiovar %s failed\n", name);
		}
	} else {
		ret = dhd_wl_ioctl_cmd(dhd, cmd, buf, len, FALSE, 0);
		if (ret < 0)
			CONFIG_ERROR("get iovar %s failed %d\n", name, ret);
	}

	return ret;
}

static int
dhd_conf_rsdb_mode(dhd_pub_t *dhd, char *cmd, char *buf)
{
	wl_config_t rsdb_mode_cfg = {1, 0};

	if (buf) {
		rsdb_mode_cfg.config = (int)simple_strtol(buf, NULL, 0);
		CONFIG_MSG("rsdb_mode %d\n", rsdb_mode_cfg.config);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, cmd, (char *)&rsdb_mode_cfg,
			sizeof(rsdb_mode_cfg), TRUE);
	}

	return 0;
}

int
dhd_conf_reg2args(dhd_pub_t *dhd, char *cmd, bool set, uint32 index, uint32 *val)
{
	char var[WLC_IOCTL_SMLEN];
	uint32 int_val, len;
	void *ptr = NULL;
	int ret = 0;

	len = sizeof(int_val);
	int_val = htod32(index);
	memset(var, 0, sizeof(var));
	memcpy(var, (char *)&int_val, sizeof(int_val));

	if (set) {
		int_val = htod32(*val);
		memcpy(&var[len], (char *)&int_val, sizeof(int_val));
		len += sizeof(int_val);
		dhd_conf_iovar_buf(dhd, 0, WLC_SET_VAR, cmd, var, sizeof(var));
	} else {
		ret = dhd_conf_iovar_buf(dhd, 0, WLC_GET_VAR, cmd, var, sizeof(var));
		if (ret < 0)
			return ret;
		ptr = var;
		*val = dtoh32(*(int *)ptr);
	}

	return ret;
}

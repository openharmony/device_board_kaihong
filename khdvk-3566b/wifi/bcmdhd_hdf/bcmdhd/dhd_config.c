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

static int
dhd_conf_btc_params(dhd_pub_t *dhd, char *cmd, char *buf)
{
	int ret = BCME_OK;
	uint32 cur_val;
	int index = 0, mask = 0, value = 0;
	// btc_params=[index] [mask] [value]
	// Ex: btc_params=82 0x0021 0x0001

	if (buf) {
		sscanf(buf, "%d %x %x", &index, &mask, &value);
	}

	CONFIG_TRACE("%s%d mask=0x%04x value=0x%04x\n", cmd, index, mask, value);

	ret = dhd_conf_reg2args(dhd, cmd, FALSE, index, &cur_val);
	CONFIG_TRACE("%s%d = 0x%04x\n", cmd, index, cur_val);
	cur_val &= (~mask);
	cur_val |= value;

	// need to WLC_UP before btc_params
	dhd_conf_set_intiovar(dhd, 0, WLC_UP, "WLC_UP", 0, 0, FALSE);

	CONFIG_TRACE("wl %s%d 0x%04x\n", cmd, index, cur_val);
	ret = dhd_conf_reg2args(dhd, cmd, TRUE, index, &cur_val);

	ret = dhd_conf_reg2args(dhd, cmd, FALSE, index, &cur_val);
	CONFIG_MSG("%s%d = 0x%04x\n", cmd, index, cur_val);

	return ret;
}

typedef struct sub_cmd_t {
	char *name;
	uint16 id;		/* id for the dongle f/w switch/case  */
	uint16 type;		/* base type of argument IOVT_XXXX */
} sub_cmd_t;

/* wl he sub cmd list */
static const sub_cmd_t he_cmd_list[] = {
	{"enab", WL_HE_CMD_ENAB, IOVT_UINT8},
	{"features", WL_HE_CMD_FEATURES, IOVT_UINT32},
	{"bsscolor", WL_HE_CMD_BSSCOLOR, IOVT_UINT8},
	{"partialbsscolor", WL_HE_CMD_PARTIAL_BSSCOLOR, IOVT_UINT8},
	{"cap", WL_HE_CMD_CAP, IOVT_UINT8},
	{"staid", WL_HE_CMD_STAID, IOVT_UINT16},
	{"rtsdurthresh", WL_HE_CMD_RTSDURTHRESH, IOVT_UINT16},
	{"peduration", WL_HE_CMD_PEDURATION, IOVT_UINT8},
	{"testbed_mode", WL_HE_CMD_TESTBED_MODE, IOVT_UINT32},
	{"omi_ulmu_throttle", WL_HE_CMD_OMI_ULMU_THROTTLE, IOVT_UINT16},
	{"omi_dlmu_rr_mpf_map", WL_HE_CMD_OMI_DLMU_RSD_RCM_MPF_MAP, IOVT_UINT32},
	{"ulmu_disable_policy", WL_HE_CMD_ULMU_DISABLE_POLICY, IOVT_UINT8},
	{"sr_prohibit", WL_HE_CMD_SR_PROHIBIT, IOVT_UINT8},
};

static uint
wl_he_iovt2len(uint iovt)
{
	switch (iovt) {
	case IOVT_BOOL:
	case IOVT_INT8:
	case IOVT_UINT8:
		return sizeof(uint8);
	case IOVT_INT16:
	case IOVT_UINT16:
		return sizeof(uint16);
	case IOVT_INT32:
	case IOVT_UINT32:
		return sizeof(uint32);
	default:
		/* ASSERT(0); */
		return 0;
	}
}

static int
dhd_conf_he_cmd(dhd_pub_t * dhd, char *cmd, char *buf)
{
	int ret = BCME_OK, i;
	bcm_xtlv_t *pxtlv = NULL;
	uint8 mybuf[128];
	uint16 he_id = -1, he_len = 0, mybuf_len = sizeof(mybuf);
	uint32 he_val;
	const sub_cmd_t *tpl = he_cmd_list;
	char sub_cmd[32], he_val_str[10];

	if (buf) {
		sscanf(buf, "%s %s", sub_cmd, he_val_str);
	}

	for (i=0; i<ARRAY_SIZE(he_cmd_list); i++, tpl++) {
		if (!strcmp(tpl->name, sub_cmd)) {
			he_id = tpl->id;
			he_len = wl_he_iovt2len(tpl->type);
			break;
		}
	}
	if (he_id < 0) {
		CONFIG_ERROR("No he id found for %s\n", sub_cmd);
		return 0;
	}

	pxtlv = (bcm_xtlv_t *)mybuf;

	if (strlen(he_val_str)) {
		he_val = simple_strtol(he_val_str, NULL, 0);
		ret = bcm_pack_xtlv_entry((uint8**)&pxtlv, &mybuf_len, he_id,
			he_len, (uint8 *)&he_val, BCM_XTLV_OPTION_ALIGN32);
		if (ret != BCME_OK) {
			CONFIG_ERROR("failed to pack he enab, err: %s\n", bcmerrorstr(ret));
			return 0;
		}
		CONFIG_TRACE("he %s 0x%x\n", sub_cmd, he_val);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, cmd, (char *)&mybuf,
			sizeof(mybuf), TRUE);
	}

	return 0;
}

#ifndef SUPPORT_RANDOM_MAC_SCAN
int
dhd_conf_scan_mac(dhd_pub_t * dhd, char *cmd, char *buf)
{
	uint8 buffer[WLC_IOCTL_SMLEN] = {0, };
	wl_scanmac_t *sm = NULL;
	wl_scanmac_enable_t *sm_enable = NULL;
	int enable = 0, len = 0, ret = -1;
	char sub_cmd[32], iovbuf[WLC_IOCTL_SMLEN];
	s32 iovar_len;

	memset(sub_cmd, 0, sizeof(sub_cmd));
	if (buf) {
		sscanf(buf, "%s %d", sub_cmd, &enable);
	}

	if (!strcmp(sub_cmd, "enable")) {
		sm = (wl_scanmac_t *)buffer;
		sm_enable = (wl_scanmac_enable_t *)sm->data;
		sm->len = sizeof(*sm_enable);
		sm_enable->enable = enable;
		len = OFFSETOF(wl_scanmac_t, data) + sm->len;
		sm->subcmd_id = WL_SCANMAC_SUBCMD_ENABLE;
		CONFIG_TRACE("scanmac enable %d\n", sm_enable->enable);

		iovar_len = bcm_mkiovar("scanmac", buffer, len, iovbuf, sizeof(iovbuf));
		if (iovar_len > 0)
			ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_VAR, iovbuf, iovar_len, TRUE, 0);
		else
			ret = BCME_BUFTOOSHORT;
		if (ret == BCME_UNSUPPORTED)
			CONFIG_TRACE("scanmac, UNSUPPORTED\n");
		else if (ret != BCME_OK)
			CONFIG_ERROR("%s setting failed %d, len=%d\n", "scanmac", ret, len);
	}
	else {
		CONFIG_ERROR("wrong cmd \"%s %d\"\n", sub_cmd, enable);
	}

	return 0;
}
#endif

typedef int (tpl_parse_t)(dhd_pub_t *dhd, char *name, char *buf);

typedef struct iovar_tpl_t {
	int cmd;
	char *name;
	tpl_parse_t *parse;
} iovar_tpl_t;

const iovar_tpl_t iovar_tpl_list[] = {
	{WLC_SET_VAR,	"rsdb_mode",	dhd_conf_rsdb_mode},
	{WLC_SET_VAR,	"he",		dhd_conf_he_cmd},
	{WLC_SET_VAR,	"btc_params",	dhd_conf_btc_params},
#ifndef SUPPORT_RANDOM_MAC_SCAN
	{WLC_SET_VAR,	"scanmac",		dhd_conf_scan_mac},
#endif
};

static int iovar_tpl_parse(const iovar_tpl_t *tpl, int tpl_count,
	dhd_pub_t *dhd, int cmd, char *name, char *buf)
{
	int i, ret = 0;

	/* look for a matching code in the table */
	for (i = 0; i < tpl_count; i++, tpl++) {
		if (tpl->cmd == cmd && !strcmp(tpl->name, name))
			break;
	}
	if (i < tpl_count && tpl->parse) {
		ret = tpl->parse(dhd, name, buf);
	} else {
		ret = -1;
	}

	return ret;
}

static bool
dhd_conf_set_wl_cmd(dhd_pub_t *dhd, char *data, bool down)
{
	int cmd, val, ret = 0, len;
	char name[32], *pch, *pick_tmp, *pick_tmp2, *pdata = NULL;

	/* Process wl_preinit:
	 * wl_preinit=[cmd]=[val], [cmd]=[val]
	 * Ex: wl_preinit=86=0, mpc=0
	 */

	if (data == NULL)
		return FALSE;

	len = strlen(data);
	pdata = kmalloc(len+1, GFP_KERNEL);
	if (pdata == NULL) {
		CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", len+1);
		goto exit;
	}
	memset(pdata, 0, len+1);
	strcpy(pdata, data);

	pick_tmp = pdata;
	while (pick_tmp && (pick_tmp2 = bcmstrtok(&pick_tmp, ",", 0)) != NULL) {
		pch = bcmstrtok(&pick_tmp2, "=", 0);
		if (!pch)
			break;
		if (*pch == ' ') {
			pch++;
		}
		memset(name, 0 , sizeof (name));
		cmd = (int)simple_strtol(pch, NULL, 0);
		if (cmd == 0) {
			cmd = WLC_SET_VAR;
			strcpy(name, pch);
		}
		pch = bcmstrtok(&pick_tmp2, ",", 0);
		if (!pch) {
			break;
		}
		ret = iovar_tpl_parse(iovar_tpl_list, ARRAY_SIZE(iovar_tpl_list),
			dhd, cmd, name, pch);
		if (ret) {
			val = (int)simple_strtol(pch, NULL, 0);
			dhd_conf_set_intiovar(dhd, 0, cmd, name, val, -1, down);
		}
	}

exit:
	if (pdata)
		kfree(pdata);
	return true;
}

int
dhd_conf_get_band(dhd_pub_t *dhd)
{
	int band = -1;

	if (dhd && dhd->conf)
		band = dhd->conf->band;
	else
		CONFIG_ERROR("dhd or conf is NULL\n");

	return band;
}

int
dhd_conf_get_country(dhd_pub_t *dhd, wl_country_t *cspec)
{
	int bcmerror = -1;

	memset(cspec, 0, sizeof(wl_country_t));
	bcm_mkiovar("country", NULL, 0, (char*)cspec, sizeof(wl_country_t));
	if ((bcmerror = dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, cspec, sizeof(wl_country_t),
			FALSE, 0)) < 0)
		CONFIG_ERROR("country code getting failed %d\n", bcmerror);

	return bcmerror;
}

int
dhd_conf_map_country_list(dhd_pub_t *dhd, wl_country_t *cspec)
{
	int bcmerror = -1;
	struct dhd_conf *conf = dhd->conf;
	country_list_t *country = conf->country_head;

#ifdef CCODE_LIST
	bcmerror = dhd_ccode_map_country_list(dhd, cspec);
#endif
	// **:XZ/11 => return XZ/11 if not found
	// **:**/0 => return user specified ccode if not found, but set regrev 0
	while (country != NULL) {
		if (!strncmp("**", country->cspec.country_abbrev, 2)) {
			if (!strncmp("**", country->cspec.ccode, 2)) {
				cspec->rev = 0;
				bcmerror = 0;
				break;
			}
			memcpy(cspec->ccode, country->cspec.ccode, WLC_CNTRY_BUF_SZ);
			cspec->rev = country->cspec.rev;
			bcmerror = 0;
			break;
		} else if (!strncmp(cspec->country_abbrev,
				country->cspec.country_abbrev, 2)) {
			memcpy(cspec->ccode, country->cspec.ccode, WLC_CNTRY_BUF_SZ);
			cspec->rev = country->cspec.rev;
			bcmerror = 0;
			break;
		}
		country = country->next;
	}

	if (!bcmerror)
		CONFIG_MSG("%s/%d\n", cspec->ccode, cspec->rev);

	return bcmerror;
}

int
dhd_conf_set_country(dhd_pub_t *dhd, wl_country_t *cspec)
{
	int bcmerror = -1;

	memset(&dhd->dhd_cspec, 0, sizeof(wl_country_t));

	CONFIG_MSG("set country %s, revision %d\n", cspec->ccode, cspec->rev);
	bcmerror = dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, "country", (char *)cspec,
		sizeof(wl_country_t), FALSE);
	dhd_conf_get_country(dhd, cspec);
	CONFIG_MSG("Country code: %s (%s/%d)\n",
		cspec->country_abbrev, cspec->ccode, cspec->rev);

	return bcmerror;
}

int
dhd_conf_fix_country(dhd_pub_t *dhd)
{
	int bcmerror = -1;
	int band;
	wl_uint32_list_t *list;
	u8 valid_chan_list[sizeof(u32)*(WL_NUMCHANNELS + 1)];
	wl_country_t cspec;

	if (!(dhd && dhd->conf)) {
		return bcmerror;
	}

	memset(valid_chan_list, 0, sizeof(valid_chan_list));
	list = (wl_uint32_list_t *)(void *) valid_chan_list;
	list->count = htod32(WL_NUMCHANNELS);
	if ((bcmerror = dhd_wl_ioctl_cmd(dhd, WLC_GET_VALID_CHANNELS, valid_chan_list,
			sizeof(valid_chan_list), FALSE, 0)) < 0) {
		CONFIG_ERROR("get channels failed with %d\n", bcmerror);
	}

	band = dhd_conf_get_band(dhd);

	if (bcmerror || ((band==WLC_BAND_AUTO || band==WLC_BAND_2G || band==-1) &&
			dtoh32(list->count)<11)) {
		CONFIG_ERROR("bcmerror=%d, # of channels %d\n",
			bcmerror, dtoh32(list->count));
		dhd_conf_map_country_list(dhd, &dhd->conf->cspec);
		if ((bcmerror = dhd_conf_set_country(dhd, &dhd->conf->cspec)) < 0) {
			strcpy(cspec.country_abbrev, "US");
			cspec.rev = 0;
			strcpy(cspec.ccode, "US");
			dhd_conf_map_country_list(dhd, &cspec);
			dhd_conf_set_country(dhd, &cspec);
		}
	}

	return bcmerror;
}

bool
dhd_conf_match_channel(dhd_pub_t *dhd, uint32 channel)
{
	int i;
	bool match = false;

	if (dhd && dhd->conf) {
		if (dhd->conf->channels.count == 0)
			return true;
		for (i=0; i<dhd->conf->channels.count; i++) {
			if (channel == dhd->conf->channels.channel[i])
				match = true;
		}
	} else {
		match = true;
		CONFIG_ERROR("dhd or conf is NULL\n");
	}

	return match;
}

int
dhd_conf_set_roam(dhd_pub_t *dhd)
{
	int bcmerror = -1;
	struct dhd_conf *conf = dhd->conf;

	dhd_roam_disable = conf->roam_off;
	dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "roam_off", dhd->conf->roam_off, 0, FALSE);

	if (!conf->roam_off || !conf->roam_off_suspend) {
		CONFIG_MSG("set roam_trigger %d\n", conf->roam_trigger[0]);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_ROAM_TRIGGER, "WLC_SET_ROAM_TRIGGER",
			(char *)conf->roam_trigger, sizeof(conf->roam_trigger), FALSE);

		CONFIG_MSG("set roam_scan_period %d\n", conf->roam_scan_period[0]);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_ROAM_SCAN_PERIOD, "WLC_SET_ROAM_SCAN_PERIOD",
			(char *)conf->roam_scan_period, sizeof(conf->roam_scan_period), FALSE);

		CONFIG_MSG("set roam_delta %d\n", conf->roam_delta[0]);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_ROAM_DELTA, "WLC_SET_ROAM_DELTA",
			(char *)conf->roam_delta, sizeof(conf->roam_delta), FALSE);

		dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "fullroamperiod",
			dhd->conf->fullroamperiod, 1, FALSE);
	}

	return bcmerror;
}

void
dhd_conf_add_to_eventbuffer(struct eventmsg_buf *ev, u16 event, bool set)
{
	if (!ev || (event > WLC_E_LAST))
		return;

	if (ev->num < MAX_EVENT_BUF_NUM) {
		ev->event[ev->num].type = event;
		ev->event[ev->num].set = set;
		ev->num++;
	} else {
		CONFIG_ERROR("evenbuffer doesn't support > %u events. Update"
			" the define MAX_EVENT_BUF_NUM \n", MAX_EVENT_BUF_NUM);
		ASSERT(0);
	}
}

s32
dhd_conf_apply_eventbuffer(dhd_pub_t *dhd, eventmsg_buf_t *ev)
{
	char eventmask[WL_EVENTING_MASK_LEN];
	int i, ret = 0;

	if (!ev || (!ev->num))
		return -EINVAL;

	/* Read event_msgs mask */
	ret = dhd_conf_get_iovar(dhd, 0, WLC_GET_VAR, "event_msgs", eventmask,
		sizeof(eventmask));
	if (unlikely(ret)) {
		CONFIG_ERROR("Get event_msgs error (%d)\n", ret);
		goto exit;
	}

	/* apply the set bits */
	for (i = 0; i < ev->num; i++) {
		if (ev->event[i].set)
			setbit(eventmask, ev->event[i].type);
		else
			clrbit(eventmask, ev->event[i].type);
	}

	/* Write updated Event mask */
	ret = dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, "event_msgs", eventmask,
		sizeof(eventmask), FALSE);
	if (unlikely(ret)) {
		CONFIG_ERROR("Set event_msgs error (%d)\n", ret);
	}

exit:
	return ret;
}

static int
dhd_conf_enable_roam_offload(dhd_pub_t *dhd, int enable)
{
	int err;
	eventmsg_buf_t ev_buf;

	if (dhd->conf->roam_off_suspend)
		return 0;

	err = dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "roam_offload", enable, 0, FALSE);
	if (err)
		return err;

	bzero(&ev_buf, sizeof(eventmsg_buf_t));
	dhd_conf_add_to_eventbuffer(&ev_buf, WLC_E_PSK_SUP, !enable);
	dhd_conf_add_to_eventbuffer(&ev_buf, WLC_E_ASSOC_REQ_IE, !enable);
	dhd_conf_add_to_eventbuffer(&ev_buf, WLC_E_ASSOC_RESP_IE, !enable);
	dhd_conf_add_to_eventbuffer(&ev_buf, WLC_E_REASSOC, !enable);
	dhd_conf_add_to_eventbuffer(&ev_buf, WLC_E_JOIN, !enable);
	dhd_conf_add_to_eventbuffer(&ev_buf, WLC_E_ROAM, !enable);
	err = dhd_conf_apply_eventbuffer(dhd, &ev_buf);

	CONFIG_TRACE("roam_offload %d\n", enable);

	return err;
}

void
dhd_conf_set_bw_cap(dhd_pub_t *dhd)
{
	struct {
		u32 band;
		u32 bw_cap;
	} param = {0, 0};

	if (dhd->conf->bw_cap[0] >= 0) {
		memset(&param, 0, sizeof(param));
		param.band = WLC_BAND_2G;
		param.bw_cap = (uint)dhd->conf->bw_cap[0];
		CONFIG_MSG("set bw_cap 2g 0x%x\n", param.bw_cap);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, "bw_cap", (char *)&param,
			sizeof(param), TRUE);
	}

	if (dhd->conf->bw_cap[1] >= 0) {
		memset(&param, 0, sizeof(param));
		param.band = WLC_BAND_5G;
		param.bw_cap = (uint)dhd->conf->bw_cap[1];
		CONFIG_MSG("set bw_cap 5g 0x%x\n", param.bw_cap);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, "bw_cap", (char *)&param,
			sizeof(param), TRUE);
	}
}

void
dhd_conf_get_wme(dhd_pub_t *dhd, int ifidx, int mode, edcf_acparam_t *acp)
{
	int bcmerror = -1;
	char iovbuf[WLC_IOCTL_SMLEN];
	edcf_acparam_t *acparam;

	bzero(iovbuf, sizeof(iovbuf));

	/*
	 * Get current acparams, using buf as an input buffer.
	 * Return data is array of 4 ACs of wme params.
	 */
	if (mode == 0)
		bcm_mkiovar("wme_ac_sta", NULL, 0, iovbuf, sizeof(iovbuf));
	else
		bcm_mkiovar("wme_ac_ap", NULL, 0, iovbuf, sizeof(iovbuf));
	if ((bcmerror = dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, iovbuf, sizeof(iovbuf),
			FALSE, ifidx)) < 0) {
		CONFIG_ERROR("wme_ac_sta getting failed %d\n", bcmerror);
		return;
	}
	memcpy((char*)acp, iovbuf, sizeof(edcf_acparam_t)*AC_COUNT);

	acparam = &acp[AC_BK];
	CONFIG_TRACE("BK: aci %d aifsn %d ecwmin %d ecwmax %d txop 0x%x\n",
		acparam->ACI, acparam->ACI&EDCF_AIFSN_MASK,
		acparam->ECW&EDCF_ECWMIN_MASK, (acparam->ECW&EDCF_ECWMAX_MASK)>>EDCF_ECWMAX_SHIFT,
		acparam->TXOP);
	acparam = &acp[AC_BE];
	CONFIG_TRACE("BE: aci %d aifsn %d ecwmin %d ecwmax %d txop 0x%x\n",
		acparam->ACI, acparam->ACI&EDCF_AIFSN_MASK,
		acparam->ECW&EDCF_ECWMIN_MASK, (acparam->ECW&EDCF_ECWMAX_MASK)>>EDCF_ECWMAX_SHIFT,
		acparam->TXOP);
	acparam = &acp[AC_VI];
	CONFIG_TRACE("VI: aci %d aifsn %d ecwmin %d ecwmax %d txop 0x%x\n",
		acparam->ACI, acparam->ACI&EDCF_AIFSN_MASK,
		acparam->ECW&EDCF_ECWMIN_MASK, (acparam->ECW&EDCF_ECWMAX_MASK)>>EDCF_ECWMAX_SHIFT,
		acparam->TXOP);
	acparam = &acp[AC_VO];
	CONFIG_TRACE("VO: aci %d aifsn %d ecwmin %d ecwmax %d txop 0x%x\n",
		acparam->ACI, acparam->ACI&EDCF_AIFSN_MASK,
		acparam->ECW&EDCF_ECWMIN_MASK, (acparam->ECW&EDCF_ECWMAX_MASK)>>EDCF_ECWMAX_SHIFT,
		acparam->TXOP);

	return;
}

void
dhd_conf_update_wme(dhd_pub_t *dhd, int ifidx, int mode,
	edcf_acparam_t *acparam_cur, int aci)
{
	int aifsn, ecwmin, ecwmax, txop;
	edcf_acparam_t *acp;
	struct dhd_conf *conf = dhd->conf;
	wme_param_t *wme;

	if (mode == 0)
		wme = &conf->wme_sta;
	else
		wme = &conf->wme_ap;

	/* Default value */
	aifsn = acparam_cur->ACI&EDCF_AIFSN_MASK;
	ecwmin = acparam_cur->ECW&EDCF_ECWMIN_MASK;
	ecwmax = (acparam_cur->ECW&EDCF_ECWMAX_MASK)>>EDCF_ECWMAX_SHIFT;
	txop = acparam_cur->TXOP;

	/* Modified value */
	if (wme->aifsn[aci] > 0)
		aifsn = wme->aifsn[aci];
	if (wme->ecwmin[aci] > 0)
		ecwmin = wme->ecwmin[aci];
	if (wme->ecwmax[aci] > 0)
		ecwmax = wme->ecwmax[aci];
	if (wme->txop[aci] > 0)
		txop = wme->txop[aci];

	if (!(wme->aifsn[aci] || wme->ecwmin[aci] ||
			wme->ecwmax[aci] || wme->txop[aci]))
		return;

	/* Update */
	acp = acparam_cur;
	acp->ACI = (acp->ACI & ~EDCF_AIFSN_MASK) | (aifsn & EDCF_AIFSN_MASK);
	acp->ECW = ((ecwmax << EDCF_ECWMAX_SHIFT) & EDCF_ECWMAX_MASK) | (acp->ECW & EDCF_ECWMIN_MASK);
	acp->ECW = ((acp->ECW & EDCF_ECWMAX_MASK) | (ecwmin & EDCF_ECWMIN_MASK));
	acp->TXOP = txop;

	CONFIG_MSG("wme_ac %s aci %d aifsn %d ecwmin %d ecwmax %d txop 0x%x\n",
		mode?"ap":"sta", acp->ACI, acp->ACI&EDCF_AIFSN_MASK,
		acp->ECW&EDCF_ECWMIN_MASK, (acp->ECW&EDCF_ECWMAX_MASK)>>EDCF_ECWMAX_SHIFT,
		acp->TXOP);

	/*
	* Now use buf as an output buffer.
	* Put WME acparams after "wme_ac\0" in buf.
	* NOTE: only one of the four ACs can be set at a time.
	*/
	if (mode == 0)
		dhd_conf_set_bufiovar(dhd, ifidx, WLC_SET_VAR, "wme_ac_sta", (char *)acp,
			sizeof(edcf_acparam_t), FALSE);
	else
		dhd_conf_set_bufiovar(dhd, ifidx, WLC_SET_VAR, "wme_ac_ap", (char *)acp,
			sizeof(edcf_acparam_t), FALSE);

}

void
dhd_conf_set_wme(dhd_pub_t *dhd, int ifidx, int mode)
{
	edcf_acparam_t acparam_cur[AC_COUNT];

	if (dhd && dhd->conf) {
		if (!dhd->conf->force_wme_ac) {
			CONFIG_TRACE("force_wme_ac is not enabled %d\n",
				dhd->conf->force_wme_ac);
			return;
		}

		CONFIG_TRACE("Before change:\n");
		dhd_conf_get_wme(dhd, ifidx, mode, acparam_cur);

		dhd_conf_update_wme(dhd, ifidx, mode, &acparam_cur[AC_BK], AC_BK);
		dhd_conf_update_wme(dhd, ifidx, mode, &acparam_cur[AC_BE], AC_BE);
		dhd_conf_update_wme(dhd, ifidx, mode, &acparam_cur[AC_VI], AC_VI);
		dhd_conf_update_wme(dhd, ifidx, mode, &acparam_cur[AC_VO], AC_VO);

		CONFIG_TRACE("After change:\n");
		dhd_conf_get_wme(dhd, ifidx, mode, acparam_cur);
	} else {
		CONFIG_ERROR("dhd or conf is NULL\n");
	}

	return;
}

void
dhd_conf_set_mchan_bw(dhd_pub_t *dhd, int p2p_mode, int miracast_mode)
{
	struct dhd_conf *conf = dhd->conf;
	mchan_params_t *mchan = conf->mchan;
	bool set = true;

	while (mchan != NULL) {
		set = true;
		set &= (mchan->bw >= 0);
		set &= ((mchan->p2p_mode == -1) | (mchan->p2p_mode == p2p_mode));
		set &= ((mchan->miracast_mode == -1) | (mchan->miracast_mode == miracast_mode));
		if (set) {
			dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "mchan_bw", mchan->bw, 0, FALSE);
		}
		mchan = mchan->next;
	}

	return;
}

#ifdef PKT_FILTER_SUPPORT
void
dhd_conf_add_pkt_filter(dhd_pub_t *dhd)
{
	int i, j;
	char str[16];
#define MACS "%02x%02x%02x%02x%02x%02x"

	/*  0) suspend_mode=1
	 * Case 1: no connection in suspend
	 *   1) wl_suspend=3=0
	 *   2) wl_resume=2=0
	 *   3) insuspend=0x7
	 * Case 2: keep connection in suspend, but no pkt and event wake up
	 *   1) dhd_master_mode=1
	 *   2) pkt_filter_delete=100, 102, 103, 104, 105, 106, 107
	 *   3) pkt_filter_add=141 0 0 0 0xFFFFFFFFFFFF 0x000000000000
	 *   4) insuspend=0x7
	 *   5) rekey_offload=1
	 * Case 3: magic pkt and event wake up
	 *   1) dhd_master_mode=1
	 *   2) pkt_filter_delete=100, 102, 103, 104, 105, 106, 107
	 *   3) pkt_filter_add=141 0 0 0 0xFFFFFFFFFFFF 0x000000000000
	 *   4) magic_pkt_filter_add=141 0 1 12
	 *   5) rekey_offload=1
	 */
	for(i=0; i<dhd->conf->pkt_filter_add.count; i++) {
		dhd->pktfilter[i+dhd->pktfilter_count] = dhd->conf->pkt_filter_add.filter[i];
		CONFIG_MSG("%s\n", dhd->pktfilter[i+dhd->pktfilter_count]);
	}
	dhd->pktfilter_count += i;

	if (dhd->conf->magic_pkt_filter_add) {
		strcat(dhd->conf->magic_pkt_filter_add, " 0x");
		strcat(dhd->conf->magic_pkt_filter_add, "FFFFFFFFFFFF");
		for (j=0; j<16; j++)
			strcat(dhd->conf->magic_pkt_filter_add, "FFFFFFFFFFFF");
		strcat(dhd->conf->magic_pkt_filter_add, " 0x");
		strcat(dhd->conf->magic_pkt_filter_add, "FFFFFFFFFFFF");
		sprintf(str, MACS, MAC2STRDBG(dhd->mac.octet));
		for (j=0; j<16; j++)
			strncat(dhd->conf->magic_pkt_filter_add, str, 12);
		dhd->pktfilter[dhd->pktfilter_count] = dhd->conf->magic_pkt_filter_add;
		dhd->pktfilter_count += 1;
	}
}

bool
dhd_conf_del_pkt_filter(dhd_pub_t *dhd, uint32 id)
{
	int i;

	if (dhd && dhd->conf) {
		for (i=0; i<dhd->conf->pkt_filter_del.count; i++) {
			if (id == dhd->conf->pkt_filter_del.id[i]) {
				CONFIG_MSG("%d\n", dhd->conf->pkt_filter_del.id[i]);
				return true;
			}
		}
		return false;
	}
	return false;
}

void
dhd_conf_discard_pkt_filter(dhd_pub_t *dhd)
{
	dhd->pktfilter_count = 6;
	dhd->pktfilter[DHD_UNICAST_FILTER_NUM] = NULL;
	dhd->pktfilter[DHD_BROADCAST_FILTER_NUM] = "101 0 0 0 0xFFFFFFFFFFFF 0xFFFFFFFFFFFF";
	dhd->pktfilter[DHD_MULTICAST4_FILTER_NUM] = "102 0 0 0 0xFFFFFF 0x01005E";
	dhd->pktfilter[DHD_MULTICAST6_FILTER_NUM] = "103 0 0 0 0xFFFF 0x3333";
	dhd->pktfilter[DHD_MDNS_FILTER_NUM] = NULL;
	/* Do not enable ARP to pkt filter if dhd_master_mode is false.*/
	dhd->pktfilter[DHD_ARP_FILTER_NUM] = NULL;

	/* IPv4 broadcast address XXX.XXX.XXX.255 */
	dhd->pktfilter[dhd->pktfilter_count] = "110 0 0 12 0xFFFF00000000000000000000000000000000000000FF 0x080000000000000000000000000000000000000000FF";
	dhd->pktfilter_count++;
	/* discard IPv4 multicast address 224.0.0.0/4 */
	dhd->pktfilter[dhd->pktfilter_count] = "111 0 0 12 0xFFFF00000000000000000000000000000000F0 0x080000000000000000000000000000000000E0";
	dhd->pktfilter_count++;
	/* discard IPv6 multicast address FF00::/8 */
	dhd->pktfilter[dhd->pktfilter_count] = "112 0 0 12 0xFFFF000000000000000000000000000000000000000000000000FF 0x86DD000000000000000000000000000000000000000000000000FF";
	dhd->pktfilter_count++;
	/* discard Netbios pkt */
	dhd->pktfilter[dhd->pktfilter_count] = "121 0 0 12 0xFFFF000000000000000000FF000000000000000000000000FFFF 0x0800000000000000000000110000000000000000000000000089";
	dhd->pktfilter_count++;

}
#endif /* PKT_FILTER_SUPPORT */

int
dhd_conf_get_pm(dhd_pub_t *dhd)
{
	if (dhd && dhd->conf) {
		return dhd->conf->pm;
	}
	return -1;
}

int
dhd_conf_check_hostsleep(dhd_pub_t *dhd, int cmd, void *buf, int len,
	int *hostsleep_set, int *hostsleep_val, int *ret)
{
	if (dhd->conf->insuspend & (NO_TXCTL_IN_SUSPEND | WOWL_IN_SUSPEND)) {
		if (cmd == WLC_SET_VAR) {
			char *psleep = NULL;
			psleep = strstr(buf, "hostsleep");
			if (psleep) {
				*hostsleep_set = 1;
				memcpy(hostsleep_val, psleep+strlen("hostsleep")+1, sizeof(int));
			}
		}
		if (dhd->hostsleep && (!*hostsleep_set || *hostsleep_val)) {
			CONFIG_TRACE("block all none hostsleep clr cmd\n");
			*ret = BCME_EPERM;
			goto exit;
		} else if (*hostsleep_set && *hostsleep_val) {
			CONFIG_TRACE("hostsleep %d => %d\n", dhd->hostsleep, *hostsleep_val);
			dhd->hostsleep = *hostsleep_val;
			if (dhd->conf->insuspend & NO_TXDATA_IN_SUSPEND) {
				dhd_txflowcontrol(dhd, ALL_INTERFACES, ON);
			}
			if (dhd->hostsleep == 2) {
				*ret = 0;
				goto exit;
			}
		} else if (dhd->hostsleep == 2 && !*hostsleep_val) {
			CONFIG_TRACE("hostsleep %d => %d\n", dhd->hostsleep, *hostsleep_val);
			dhd->hostsleep = *hostsleep_val;
			if (dhd->conf->insuspend & NO_TXDATA_IN_SUSPEND) {
				dhd_txflowcontrol(dhd, ALL_INTERFACES, OFF);
			}
			*ret = 0;
			goto exit;
		}
	}
#ifdef NO_POWER_SAVE
	if (cmd == WLC_SET_PM) {
		if (*(const u32*)buf != 0) {
			CONFIG_TRACE("skip PM\n");
			*ret = BCME_OK;
			goto exit;
		}
	} else if (cmd == WLC_SET_VAR) {
		int cmd_len = strlen("mpc");
		if (!strncmp(buf, "mpc", cmd_len)) {
			if (*((u32 *)((u8*)buf+cmd_len+1)) != 0) {
				CONFIG_TRACE("skip mpc\n");
				*ret = BCME_OK;
				goto exit;
			}
		}
	}
#endif

	return 0;
exit:
	return -1;
}

void
dhd_conf_get_hostsleep(dhd_pub_t *dhd,
	int hostsleep_set, int hostsleep_val, int ret)
{
	if (dhd->conf->insuspend & (NO_TXCTL_IN_SUSPEND | WOWL_IN_SUSPEND)) {
		if (hostsleep_set) {
			if (hostsleep_val && ret) {
				CONFIG_TRACE("reset hostsleep %d => 0\n", dhd->hostsleep);
				dhd->hostsleep = 0;
				if (dhd->conf->insuspend & NO_TXDATA_IN_SUSPEND) {
					dhd_txflowcontrol(dhd, ALL_INTERFACES, OFF);
				}
			} else if (!hostsleep_val && !ret) {
				CONFIG_TRACE("set hostsleep %d => 0\n", dhd->hostsleep);
				dhd->hostsleep = 0;
				if (dhd->conf->insuspend & NO_TXDATA_IN_SUSPEND) {
					dhd_txflowcontrol(dhd, ALL_INTERFACES, OFF);
				}
			}
		}
	}
}

#ifdef WL_EXT_WOWL
#define WL_WOWL_TCPFIN	(1 << 26)
typedef struct wl_wowl_pattern2 {
	char cmd[4];
	wl_wowl_pattern_t wowl_pattern;
} wl_wowl_pattern2_t;
static int
dhd_conf_wowl_pattern(dhd_pub_t *dhd, int ifidx, bool add, char *data)
{
	uint buf_len = 0;
	int	id, type, polarity, offset;
	char cmd[4]="\0", mask[128]="\0", pattern[128]="\0", mask_tmp[128]="\0", *pmask_tmp;
	uint32 masksize, patternsize, pad_len = 0;
	wl_wowl_pattern2_t *wowl_pattern2 = NULL;
	char *mask_and_pattern;
	int ret = 0, i, j, v;

	if (data) {
		if (add)
			strcpy(cmd, "add");
		else
			strcpy(cmd, "clr");
		if (!strcmp(cmd, "clr")) {
			CONFIG_TRACE("wowl_pattern clr\n");
			ret = dhd_conf_set_bufiovar(dhd, ifidx, WLC_SET_VAR, "wowl_pattern", cmd,
				sizeof(cmd), FALSE);
			goto exit;
		}
		sscanf(data, "%d %d %d %d %s %s", &id, &type, &polarity, &offset,
			mask_tmp, pattern);
		masksize = strlen(mask_tmp) -2;
		CONFIG_TRACE("0 mask_tmp=%s, masksize=%d\n", mask_tmp, masksize);

		// add pading
		if (masksize % 16)
			pad_len = (16 - masksize % 16);
		for (i=0; i<pad_len; i++)
			strcat(mask_tmp, "0");
		masksize += pad_len;
		CONFIG_TRACE("1 mask_tmp=%s, masksize=%d\n", mask_tmp, masksize);

		// translate 0x00 to 0, others to 1
		j = 0;
		pmask_tmp = &mask_tmp[2];
		for (i=0; i<masksize/2; i++) {
			if(strncmp(&pmask_tmp[i*2], "00", 2))
				pmask_tmp[j] = '1';
			else
				pmask_tmp[j] = '0';
			j++;
		}
		pmask_tmp[j] = '\0';
		masksize = masksize / 2;
		CONFIG_TRACE("2 mask_tmp=%s, masksize=%d\n", mask_tmp, masksize);

		// reorder per 8bits
		pmask_tmp = &mask_tmp[2];
		for (i=0; i<masksize/8; i++) {
			char c;
			for (j=0; j<4; j++) {
				c = pmask_tmp[i*8+j];
				pmask_tmp[i*8+j] = pmask_tmp[(i+1)*8-j-1];
				pmask_tmp[(i+1)*8-j-1] = c;
			}
		}
		CONFIG_TRACE("3 mask_tmp=%s, masksize=%d\n", mask_tmp, masksize);

		// translate 8bits to 1byte
		j = 0; v = 0;
		pmask_tmp = &mask_tmp[2];
		strcpy(mask, "0x");
		for (i=0; i<masksize; i++) {
			v = (v<<1) | (pmask_tmp[i]=='1');
			if (((i+1)%4) == 0) {
				if (v < 10)
					mask[j+2] = v + '0';
				else
					mask[j+2] = (v-10) + 'a';
				j++;
				v = 0;
			}
		}
		mask[j+2] = '\0';
		masksize = j/2;
		CONFIG_TRACE("4 mask=%s, masksize=%d\n", mask, masksize);

		patternsize = (strlen(pattern)-2)/2;
		buf_len = sizeof(wl_wowl_pattern2_t) + patternsize + masksize;
		wowl_pattern2 = kmalloc(buf_len, GFP_KERNEL);
		if (wowl_pattern2 == NULL) {
			CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", buf_len);
			goto exit;
		}
		memset(wowl_pattern2, 0, sizeof(wl_wowl_pattern2_t));

		strncpy(wowl_pattern2->cmd, cmd, sizeof(cmd));
		wowl_pattern2->wowl_pattern.id = id;
		wowl_pattern2->wowl_pattern.type = 0;
		wowl_pattern2->wowl_pattern.offset = offset;
		mask_and_pattern = (char*)wowl_pattern2 + sizeof(wl_wowl_pattern2_t);

		wowl_pattern2->wowl_pattern.masksize = masksize;
		ret = wl_pattern_atoh(mask, mask_and_pattern);
		if (ret == -1) {
			CONFIG_ERROR("rejecting mask=%s\n", mask);
			goto exit;
		}

		mask_and_pattern += wowl_pattern2->wowl_pattern.masksize;
		wowl_pattern2->wowl_pattern.patternoffset = sizeof(wl_wowl_pattern_t) +
			wowl_pattern2->wowl_pattern.masksize;

		wowl_pattern2->wowl_pattern.patternsize = patternsize;
		ret = wl_pattern_atoh(pattern, mask_and_pattern);
		if (ret == -1) {
			CONFIG_ERROR("rejecting pattern=%s\n", pattern);
			goto exit;
		}

		CONFIG_TRACE("%s %d %s %s\n", cmd, offset, mask, pattern);

		ret = dhd_conf_set_bufiovar(dhd, ifidx, WLC_SET_VAR, "wowl_pattern",
			(char *)wowl_pattern2, buf_len, FALSE);
	}

exit:
	if (wowl_pattern2)
		kfree(wowl_pattern2);
	return ret;
}

static int
dhd_conf_wowl_wakeind(dhd_pub_t *dhd, int ifidx, bool clear)
{
	s8 iovar_buf[WLC_IOCTL_SMLEN];
	wl_wowl_wakeind_t *wake = NULL;
	int ret = -1;
	char clr[6]="clear", wakeind_str[32]="\0";

	if (clear) {
		CONFIG_TRACE("wowl_wakeind clear\n");
		ret = dhd_conf_set_bufiovar(dhd, ifidx, WLC_SET_VAR, "wowl_wakeind",
			clr, sizeof(clr), 0);
	} else {
		ret = dhd_conf_get_iovar(dhd, ifidx, WLC_GET_VAR, "wowl_wakeind",
			iovar_buf, sizeof(iovar_buf));
		if (!ret) {
			wake = (wl_wowl_wakeind_t *) iovar_buf;
			if (wake->ucode_wakeind & WL_WOWL_MAGIC)
				strcpy(wakeind_str, "(MAGIC packet)");
			if (wake->ucode_wakeind & WL_WOWL_NET)
				strcpy(wakeind_str, "(Netpattern)");
			if (wake->ucode_wakeind & WL_WOWL_DIS)
				strcpy(wakeind_str, "(Disassoc/Deauth)");
			if (wake->ucode_wakeind & WL_WOWL_BCN)
				strcpy(wakeind_str, "(Loss of beacon)");
			if (wake->ucode_wakeind & WL_WOWL_TCPKEEP_TIME)
				strcpy(wakeind_str, "(TCPKA timeout)");
			if (wake->ucode_wakeind & WL_WOWL_TCPKEEP_DATA)
				strcpy(wakeind_str, "(TCPKA data)");
			if (wake->ucode_wakeind & WL_WOWL_TCPFIN)
				strcpy(wakeind_str, "(TCP FIN)");
			CONFIG_MSG("wakeind=0x%x %s\n", wake->ucode_wakeind, wakeind_str);
		}
	}

	return ret;
}
#endif

int
dhd_conf_mkeep_alive(dhd_pub_t *dhd, int ifidx, int id, int period,
	char *packet, bool bcast)
{
	wl_mkeep_alive_pkt_t *mkeep_alive_pktp;
	int ret = 0, len_bytes=0, buf_len=0;
	char *buf = NULL, *iovar_buf = NULL;
	uint8 *pdata;

	CONFIG_TRACE("id=%d, period=%d, packet=%s\n", id, period, packet);
	if (period >= 0) {
		buf = kmalloc(WLC_IOCTL_SMLEN, GFP_KERNEL);
		if (buf == NULL) {
			CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", WLC_IOCTL_SMLEN);
			goto exit;
		}
		iovar_buf = kmalloc(WLC_IOCTL_SMLEN, GFP_KERNEL);
		if (iovar_buf == NULL) {
			CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", WLC_IOCTL_SMLEN);
			goto exit;
		}
		mkeep_alive_pktp = (wl_mkeep_alive_pkt_t *)buf;
		mkeep_alive_pktp->version = htod16(WL_MKEEP_ALIVE_VERSION);
		mkeep_alive_pktp->length = htod16(WL_MKEEP_ALIVE_FIXED_LEN);
		mkeep_alive_pktp->keep_alive_id = id;
		buf_len += WL_MKEEP_ALIVE_FIXED_LEN;
		mkeep_alive_pktp->period_msec = period;
		if (packet && strlen(packet)) {
			len_bytes = wl_pattern_atoh(packet, (char *)mkeep_alive_pktp->data);
			buf_len += len_bytes;
			if (bcast) {
				memcpy(mkeep_alive_pktp->data, &ether_bcast, ETHER_ADDR_LEN);
			}
			ret = dhd_conf_get_iovar(dhd, ifidx, WLC_GET_VAR, "cur_etheraddr",
				iovar_buf, WLC_IOCTL_SMLEN);
			if (!ret) {
				pdata = mkeep_alive_pktp->data;
				memcpy(pdata+6, iovar_buf, ETHER_ADDR_LEN);
			}
		}
		mkeep_alive_pktp->len_bytes = htod16(len_bytes);
		ret = dhd_conf_set_bufiovar(dhd, ifidx, WLC_SET_VAR, "mkeep_alive",
			buf, buf_len, FALSE);
	}

exit:
	if (buf)
		kfree(buf);
	if (iovar_buf)
		kfree(iovar_buf);
	return ret;
}

#ifdef ARP_OFFLOAD_SUPPORT
void
dhd_conf_set_garp(dhd_pub_t *dhd, int ifidx, uint32 ipa, bool enable)
{
	int i, len = 0, total_len = WLC_IOCTL_SMLEN;
	char *iovar_buf = NULL, *packet = NULL;

	if (!dhd->conf->garp || ifidx != 0 || !(dhd->op_mode & DHD_FLAG_STA_MODE))
		return;

	CONFIG_TRACE("enable=%d\n", enable);

	if (enable) {
		iovar_buf = kmalloc(total_len, GFP_KERNEL);
		if (iovar_buf == NULL) {
			CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", total_len);
			goto exit;
		}
		packet = kmalloc(total_len, GFP_KERNEL);
		if (packet == NULL) {
			CONFIG_ERROR("Failed to allocate buffer of %d bytes\n", total_len);
			goto exit;
		}
		dhd_conf_get_iovar(dhd, ifidx, WLC_GET_VAR, "cur_etheraddr", iovar_buf, total_len);

		len += snprintf(packet+len, total_len, "0xffffffffffff");
		for (i=0; i<ETHER_ADDR_LEN; i++)
			len += snprintf(packet+len, total_len, "%02x", iovar_buf[i]);
		len += snprintf(packet+len, total_len, "08060001080006040001");
		 // Sender Hardware Addr.
		for (i=0; i<ETHER_ADDR_LEN; i++)
			len += snprintf(packet+len, total_len, "%02x", iovar_buf[i]);
		 // Sender IP Addr.
		len += snprintf(packet+len, total_len, "%02x%02x%02x%02x",
			ipa&0xff, (ipa>>8)&0xff, (ipa>>16)&0xff, (ipa>>24)&0xff);
		 // Target Hardware Addr.
		len += snprintf(packet+len, total_len, "ffffffffffff");
		 // Target IP Addr.
		len += snprintf(packet+len, total_len, "%02x%02x%02x%02x",
			ipa&0xff, (ipa>>8)&0xff, (ipa>>16)&0xff, (ipa>>24)&0xff);
		len += snprintf(packet+len, total_len, "000000000000000000000000000000000000");
	}

	dhd_conf_mkeep_alive(dhd, ifidx, 0, dhd->conf->keep_alive_period, packet, TRUE);

exit:
	if (iovar_buf)
		kfree(iovar_buf);
	if (packet)
		kfree(packet);
	return;
}
#endif

uint
dhd_conf_get_insuspend(dhd_pub_t *dhd, uint mask)
{
	uint insuspend = 0;

	if (dhd->op_mode & DHD_FLAG_STA_MODE) {
		insuspend = dhd->conf->insuspend &
			(NO_EVENT_IN_SUSPEND | NO_TXDATA_IN_SUSPEND | NO_TXCTL_IN_SUSPEND |
			ROAM_OFFLOAD_IN_SUSPEND | WOWL_IN_SUSPEND);
	} else if (dhd->op_mode & DHD_FLAG_HOSTAP_MODE) {
		insuspend = dhd->conf->insuspend &
			(NO_EVENT_IN_SUSPEND | NO_TXDATA_IN_SUSPEND | NO_TXCTL_IN_SUSPEND |
			AP_DOWN_IN_SUSPEND | AP_FILTER_IN_SUSPEND);
	}

	return (insuspend & mask);
}

static void
dhd_conf_check_connection(dhd_pub_t *dhd, int ifidx, int suspend)
{
	struct dhd_conf *conf = dhd->conf;
	struct ether_addr bssid;
	wl_event_msg_t msg;
	int pm;
#ifdef WL_CFG80211
	struct net_device *net;
	unsigned long flags = 0;
#endif /* defined(WL_CFG80211) */

	if (suspend) {
		memset(&bssid, 0, ETHER_ADDR_LEN);
		dhd_wl_ioctl_cmd(dhd, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN, FALSE, ifidx);
		if (memcmp(&ether_null, &bssid, ETHER_ADDR_LEN))
			memcpy(&conf->bssid_insuspend, &bssid, ETHER_ADDR_LEN);
		else
			memset(&conf->bssid_insuspend, 0, ETHER_ADDR_LEN);
	}
	else {
		if (memcmp(&ether_null, &conf->bssid_insuspend, ETHER_ADDR_LEN)) {
			memset(&bssid, 0, ETHER_ADDR_LEN);
			dhd_wl_ioctl_cmd(dhd, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN, FALSE, ifidx);
			if (memcmp(&ether_null, &bssid, ETHER_ADDR_LEN)) {
				dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_PM, "WLC_SET_PM", 0, 0, FALSE);
				dhd_conf_set_bufiovar(dhd, ifidx, WLC_SET_VAR, "send_nulldata",
					(char *)&bssid, ETHER_ADDR_LEN, FALSE);
				OSL_SLEEP(100);
				if (conf->pm >= 0)
					pm = conf->pm;
				else
					pm = PM_FAST;
				dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_PM, "WLC_SET_PM", pm, 0, FALSE);
			} else {
				CONFIG_TRACE("send WLC_E_DEAUTH_IND event\n");
				bzero(&msg, sizeof(wl_event_msg_t));
				msg.ifidx = ifidx;
				memcpy(&msg.addr, &conf->bssid_insuspend, ETHER_ADDR_LEN);
				msg.event_type = hton32(WLC_E_DEAUTH_IND);
				msg.status = 0;
				msg.reason = hton32(DOT11_RC_DEAUTH_LEAVING);
#ifdef WL_EVENT
				wl_ext_event_send(dhd->event_params, &msg, NULL);
#endif
#ifdef WL_CFG80211
				spin_lock_irqsave(&dhd->up_lock, flags);
				net = dhd_idx2net(dhd, ifidx);
				if (net && dhd->up) {
					wl_cfg80211_event(net, &msg, NULL);
				}
				spin_unlock_irqrestore(&dhd->up_lock, flags);
#endif /* defined(WL_CFG80211) */
			}
		}
	}
}

#ifdef SUSPEND_EVENT
static void
dhd_conf_set_suspend_event(dhd_pub_t *dhd, int suspend)
{
	struct dhd_conf *conf = dhd->conf;
	char suspend_eventmask[WL_EVENTING_MASK_LEN];

	CONFIG_TRACE("Enter\n");
	if (suspend) {
#ifdef PROP_TXSTATUS
#if defined(BCMSDIO) || defined(BCMDBUS)
		if (dhd->wlfc_enabled) {
			dhd_wlfc_deinit(dhd);
			conf->wlfc = TRUE;
		} else {
			conf->wlfc = FALSE;
		}
#endif /* BCMSDIO || BCMDBUS */
#endif /* PROP_TXSTATUS */
		dhd_conf_get_iovar(dhd, 0, WLC_GET_VAR, "event_msgs",
			conf->resume_eventmask, sizeof(conf->resume_eventmask));
		memset(suspend_eventmask, 0, sizeof(suspend_eventmask));
		setbit(suspend_eventmask, WLC_E_ESCAN_RESULT);
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, "event_msgs",
			suspend_eventmask, sizeof(suspend_eventmask), FALSE);
	}
	else {
		dhd_conf_set_bufiovar(dhd, 0, WLC_SET_VAR, "event_msgs",
			conf->resume_eventmask, sizeof(conf->resume_eventmask), FALSE);
#ifdef PROP_TXSTATUS
#if defined(BCMSDIO) || defined(BCMDBUS)
		if (conf->wlfc) {
			dhd_wlfc_init(dhd);
			dhd_conf_set_intiovar(dhd, 0, WLC_UP, "WLC_UP", 0, 0, FALSE);
		}
#endif
#endif /* PROP_TXSTATUS */
	}

}
#endif

int
dhd_conf_suspend_resume_sta(dhd_pub_t *dhd, int ifidx, int suspend)
{
	struct dhd_conf *conf = dhd->conf;
	uint insuspend = 0;
	int pm;
#ifdef WL_EXT_WOWL
	int i;
#endif

	insuspend = dhd_conf_get_insuspend(dhd, ALL_IN_SUSPEND);
	if (insuspend)
		WL_MSG(dhd_ifname(dhd, ifidx), "suspend %d\n", suspend);

	if (suspend) {
		dhd_conf_check_connection(dhd, ifidx, suspend);
		dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "roam_off",
			conf->roam_off_suspend, 0, FALSE);
		dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "bcn_li_dtim",
			conf->suspend_bcn_li_dtim, 0, FALSE);
		if (conf->pm_in_suspend >= 0)
			pm = conf->pm_in_suspend;
		else if (conf->pm >= 0)
			pm = conf->pm;
		else
			pm = PM_FAST;
		dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_PM, "WLC_SET_PM", pm, 0, FALSE);
#ifdef WL_EXT_WOWL
		if ((insuspend & WOWL_IN_SUSPEND) && dhd_master_mode) {
			dhd_conf_wowl_pattern(dhd, ifidx, FALSE, "clr");
			for(i=0; i<conf->pkt_filter_add.count; i++) {
				dhd_conf_wowl_pattern(dhd, ifidx, TRUE, conf->pkt_filter_add.filter[i]);
			}
			dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "wowl", conf->wowl, 0, FALSE);
			dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "wowl_activate", 1, 0, FALSE);
			dhd_conf_wowl_wakeind(dhd, ifidx, TRUE);
		}
#endif
	}
	else {
		dhd_conf_get_iovar(dhd, 0, WLC_GET_PM, "WLC_GET_PM", (char *)&pm, sizeof(pm));
		CONFIG_TRACE("PM in suspend = %d\n", pm);
		if (conf->pm >= 0)
			pm = conf->pm;
		else
			pm = PM_FAST;
		dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_PM, "WLC_SET_PM", pm, 0, FALSE);
#ifdef WL_EXT_WOWL
		if (insuspend & WOWL_IN_SUSPEND) {
			dhd_conf_wowl_wakeind(dhd, ifidx, FALSE);
			dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "wowl_activate", 0, 0, FALSE);
			dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "wowl", 0, 0, FALSE);
			dhd_conf_wowl_pattern(dhd, ifidx, FALSE, "clr");
		}
#endif
		dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "bcn_li_dtim", 0, 0, FALSE);
		dhd_conf_set_intiovar(dhd, ifidx, WLC_SET_VAR, "roam_off",
			conf->roam_off, 0, FALSE);
		dhd_conf_check_connection(dhd, ifidx, suspend);
	}

	return 0;
}

#ifndef WL_EXT_IAPSTA
static int
dhd_conf_suspend_resume_ap(dhd_pub_t *dhd, int ifidx, int suspend)
{
	struct dhd_conf *conf = dhd->conf;
	uint insuspend = 0;

	insuspend = dhd_conf_get_insuspend(dhd, ALL_IN_SUSPEND);
	if (insuspend)
		WL_MSG(dhd_ifname(dhd, ifidx), "suspend %d\n", suspend);

	if (suspend) {
		if (insuspend & AP_DOWN_IN_SUSPEND) {
			dhd_conf_set_intiovar(dhd, ifidx, WLC_DOWN, "WLC_DOWN", 1, 0, FALSE);
		}
	} else {
		if (insuspend & AP_DOWN_IN_SUSPEND) {
			dhd_conf_set_intiovar(dhd, ifidx, WLC_UP, "WLC_UP", 0, 0, FALSE);
		}
	}

	return 0;
}
#endif /* !WL_EXT_IAPSTA */

static int
dhd_conf_suspend_resume_bus(dhd_pub_t *dhd, int suspend)
{
	uint insuspend = 0;

	insuspend = dhd_conf_get_insuspend(dhd, ALL_IN_SUSPEND);
	if (insuspend)
		CONFIG_MSG("suspend %d\n", suspend);

	if (suspend) {
		if (insuspend & (WOWL_IN_SUSPEND | NO_TXCTL_IN_SUSPEND)) {
#ifdef BCMSDIO
			uint32 intstatus = 0;
			int ret = 0;
#endif
			int hostsleep = 2;
#ifdef WL_EXT_WOWL
			hostsleep = 1;
#endif
			dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "hostsleep", hostsleep, 0, FALSE);
#ifdef BCMSDIO
			ret = dhd_bus_sleep(dhd, TRUE, &intstatus);
			CONFIG_TRACE("ret = %d, intstatus = 0x%x\n", ret, intstatus);
#endif
		}
	} else {
		if (insuspend & (WOWL_IN_SUSPEND | NO_TXCTL_IN_SUSPEND)) {
			dhd_conf_set_intiovar(dhd, 0, WLC_SET_VAR, "hostsleep", 0, 0, FALSE);
		}
	}

	return 0;
}

int
dhd_conf_set_suspend_resume(dhd_pub_t *dhd, int suspend)
{
	struct dhd_conf *conf = dhd->conf;
	uint insuspend = 0;

	insuspend = dhd_conf_get_insuspend(dhd, ALL_IN_SUSPEND);
	if (insuspend)
		CONFIG_MSG("op_mode %d, suspend %d, suspended %d, insuspend 0x%x, suspend_mode=%d\n",
			dhd->op_mode, suspend, conf->suspended, insuspend, conf->suspend_mode);

	if (conf->suspended == suspend || !dhd->up) {
		return 0;
	}

	if (suspend) {
		if (insuspend & (NO_EVENT_IN_SUSPEND|NO_TXCTL_IN_SUSPEND|WOWL_IN_SUSPEND)) {
			if (conf->suspend_mode == PM_NOTIFIER)
#ifdef WL_EXT_IAPSTA
				wl_iapsta_wait_event_complete(dhd);
#else
				wl_ext_wait_event_complete(dhd, 0);
#endif /* WL_EXT_IAPSTA */
		}
		if (insuspend & NO_TXDATA_IN_SUSPEND) {
			dhd_txflowcontrol(dhd, ALL_INTERFACES, ON);
		}
#if defined(WL_CFG80211) || defined(WL_ESCAN)
		if (insuspend & (NO_EVENT_IN_SUSPEND|NO_TXCTL_IN_SUSPEND|WOWL_IN_SUSPEND)) {
			if (conf->suspend_mode == PM_NOTIFIER)
				wl_ext_user_sync(dhd, 0, TRUE);
		}
#endif
		if (insuspend & ROAM_OFFLOAD_IN_SUSPEND)
			dhd_conf_enable_roam_offload(dhd, 2);
#ifdef SUSPEND_EVENT
		if (insuspend & NO_EVENT_IN_SUSPEND) {
			dhd_conf_set_suspend_event(dhd, suspend);
		}
#endif
#ifdef WL_EXT_IAPSTA
		wl_iapsta_suspend_resume(dhd, suspend);
#else
		if (dhd->op_mode & DHD_FLAG_STA_MODE) {
			dhd_conf_suspend_resume_sta(dhd, 0, suspend);
		} else if (dhd->op_mode & DHD_FLAG_HOSTAP_MODE) {
			dhd_conf_suspend_resume_ap(dhd, 0, suspend);
		}
#endif /* WL_EXT_IAPSTA */
		dhd_conf_set_wl_cmd(dhd, conf->wl_suspend, FALSE);
		dhd_conf_suspend_resume_bus(dhd, suspend);
		conf->suspended = TRUE;
	}
	else {
		dhd_conf_suspend_resume_bus(dhd, suspend);
#ifdef SUSPEND_EVENT
		if (insuspend & NO_EVENT_IN_SUSPEND) {
			dhd_conf_set_suspend_event(dhd, suspend);
		}
#endif
		if (insuspend & ROAM_OFFLOAD_IN_SUSPEND)
			dhd_conf_enable_roam_offload(dhd, 0);
		dhd_conf_set_wl_cmd(dhd, conf->wl_resume, FALSE);
#ifdef WL_EXT_IAPSTA
		wl_iapsta_suspend_resume(dhd, suspend);
#else
		if (dhd->op_mode & DHD_FLAG_STA_MODE) {
			dhd_conf_suspend_resume_sta(dhd, 0, suspend);
		} else if (dhd->op_mode & DHD_FLAG_HOSTAP_MODE) {
			dhd_conf_suspend_resume_ap(dhd, 0, suspend);
		}
#endif /* WL_EXT_IAPSTA */
#if defined(WL_CFG80211) || defined(WL_ESCAN)
		if (insuspend & (NO_EVENT_IN_SUSPEND|NO_TXCTL_IN_SUSPEND|WOWL_IN_SUSPEND)) {
			if (conf->suspend_mode == PM_NOTIFIER)
				wl_ext_user_sync(dhd, 0, FALSE);
		}
#endif
		if (insuspend & NO_TXDATA_IN_SUSPEND) {
			dhd_txflowcontrol(dhd, ALL_INTERFACES, OFF);
		}
		conf->suspended = FALSE;
	}

	return 0;
}

#ifdef PROP_TXSTATUS
int
dhd_conf_get_disable_proptx(dhd_pub_t *dhd)
{
	struct dhd_conf *conf = dhd->conf;
	int disable_proptx = -1;
	int fw_proptx = 0;

	/* check fw proptx priority:
	  * 1st: check fw support by wl cap
	  * 2nd: 4334/43340/43341/43241 support proptx but not show in wl cap, so enable it by default
	  * 	   if you would like to disable it, please set disable_proptx=1 in config.txt
	  * 3th: disable when proptxstatus not support in wl cap
	  */
	if (FW_SUPPORTED(dhd, proptxstatus)) {
		fw_proptx = 1;
	} else if (conf->chip == BCM4334_CHIP_ID || conf->chip == BCM43340_CHIP_ID ||
			dhd->conf->chip == BCM43340_CHIP_ID || conf->chip == BCM4324_CHIP_ID) {
		fw_proptx = 1;
	} else {
		fw_proptx = 0;
	}

	/* returned disable_proptx value:
	  * -1: disable in STA and enable in P2P(follow original dhd settings when PROP_TXSTATUS_VSDB enabled)
	  * 0: depend on fw support
	  * 1: always disable proptx
	  */
	if (conf->disable_proptx == 0) {
		// check fw support as well
		if (fw_proptx)
			disable_proptx = 0;
		else
			disable_proptx = 1;
	} else if (conf->disable_proptx >= 1) {
		disable_proptx = 1;
	} else {
		// check fw support as well
		if (fw_proptx)
			disable_proptx = -1;
		else
			disable_proptx = 1;
	}

	CONFIG_MSG("fw_proptx=%d, disable_proptx=%d\n", fw_proptx, disable_proptx);

	return disable_proptx;
}
#endif

uint
pick_config_vars(char *varbuf, uint len, uint start_pos, char *pickbuf, int picklen)
{
	bool findNewline, changenewline=FALSE, pick=FALSE;
	int column;
	uint n, pick_column=0;

	findNewline = FALSE;
	column = 0;

	if (start_pos >= len) {
		CONFIG_ERROR("wrong start pos\n");
		return 0;
	}

	for (n = start_pos; n < len; n++) {
		if (varbuf[n] == '\r')
			continue;
		if ((findNewline || changenewline) && varbuf[n] != '\n')
			continue;
		findNewline = FALSE;
		if (varbuf[n] == '#') {
			findNewline = TRUE;
			continue;
		}
		if (varbuf[n] == '\\') {
			changenewline = TRUE;
			continue;
		}
		if (!changenewline && varbuf[n] == '\n') {
			if (column == 0)
				continue;
			column = 0;
			continue;
		}
		if (changenewline && varbuf[n] == '\n') {
			changenewline = FALSE;
			continue;
		}

		if (column==0 && !pick) { // start to pick
			pick = TRUE;
			column++;
			pick_column = 0;
		} else {
			if (pick && column==0) { // stop to pick
				pick = FALSE;
				break;
			} else
				column++;
		}
		if (pick) {
			if (varbuf[n] == 0x9)
				continue;
			if (pick_column >= picklen)
				break;
			pickbuf[pick_column] = varbuf[n];
			pick_column++;
		}
	}

	return n; // return current position
}

bool
dhd_conf_read_chiprev(dhd_pub_t *dhd, int *chip_match,
	char *full_param, uint len_param)
{
	char *data = full_param+len_param, *pick_tmp, *pch;
	uint chip = 0, rev = 0;

	/* Process chip, regrev:
	 * chip=[chipid], rev==[rev]
	 * Ex: chip=0x4359, rev=9
	 */
	if (!strncmp("chip=", full_param, len_param)) {
		chip = (int)simple_strtol(data, NULL, 0);
		pick_tmp = data;
		pch = bcmstrstr(pick_tmp, "rev=");
		if (pch) {
			rev = (int)simple_strtol(pch+strlen("rev="), NULL, 0);
		}
		if (chip == dhd->conf->chip && rev == dhd->conf->chiprev)
			*chip_match = 1;
		else
			*chip_match = 0;
		CONFIG_MSG("chip=0x%x, rev=%d, chip_match=%d\n", chip, rev, *chip_match);
	}

	return TRUE;
}

bool
dhd_conf_read_log_level(dhd_pub_t *dhd, char *full_param, uint len_param)
{
	char *data = full_param+len_param;

	if (!strncmp("dhd_msg_level=", full_param, len_param)) {
		dhd_msg_level = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("dhd_msg_level = 0x%X\n", dhd_msg_level);
	}
	else if (!strncmp("dump_msg_level=", full_param, len_param)) {
		dump_msg_level = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("dump_msg_level = 0x%X\n", dump_msg_level);
	}
#ifdef BCMSDIO
	else if (!strncmp("sd_msglevel=", full_param, len_param)) {
		sd_msglevel = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("sd_msglevel = 0x%X\n", sd_msglevel);
	}
#endif
#ifdef BCMDBUS
	else if (!strncmp("dbus_msglevel=", full_param, len_param)) {
		dbus_msglevel = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("dbus_msglevel = 0x%X\n", dbus_msglevel);
	}
#endif
	else if (!strncmp("android_msg_level=", full_param, len_param)) {
		android_msg_level = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("android_msg_level = 0x%X\n", android_msg_level);
	}
	else if (!strncmp("config_msg_level=", full_param, len_param)) {
		config_msg_level = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("config_msg_level = 0x%X\n", config_msg_level);
	}
#ifdef WL_CFG80211
	else if (!strncmp("wl_dbg_level=", full_param, len_param)) {
		wl_dbg_level = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("wl_dbg_level = 0x%X\n", wl_dbg_level);
	}
#endif
#if defined(WL_WIRELESS_EXT)
	else if (!strncmp("iw_msg_level=", full_param, len_param)) {
		iw_msg_level = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("iw_msg_level = 0x%X\n", iw_msg_level);
	}
#endif
#if defined(DHD_DEBUG)
	else if (!strncmp("dhd_console_ms=", full_param, len_param)) {
		dhd->dhd_console_ms = (int)simple_strtol(data, NULL, 0);
		CONFIG_MSG("dhd_console_ms = %d\n", dhd->dhd_console_ms);
	}
#endif
	else
		return false;

	return true;
}

void
dhd_conf_read_wme_ac_value(wme_param_t *wme, char *pick, int ac_val)
{
	char *pick_tmp, *pch;

	pick_tmp = pick;
	pch = bcmstrstr(pick_tmp, "aifsn ");
	if (pch) {
		wme->aifsn[ac_val] = (int)simple_strtol(pch+strlen("aifsn "), NULL, 0);
		CONFIG_MSG("ac_val=%d, aifsn=%d\n", ac_val, wme->aifsn[ac_val]);
	}
	pick_tmp = pick;
	pch = bcmstrstr(pick_tmp, "ecwmin ");
	if (pch) {
		wme->ecwmin[ac_val] = (int)simple_strtol(pch+strlen("ecwmin "), NULL, 0);
		CONFIG_MSG("ac_val=%d, ecwmin=%d\n", ac_val, wme->ecwmin[ac_val]);
	}
	pick_tmp = pick;
	pch = bcmstrstr(pick_tmp, "ecwmax ");
	if (pch) {
		wme->ecwmax[ac_val] = (int)simple_strtol(pch+strlen("ecwmax "), NULL, 0);
		CONFIG_MSG("ac_val=%d, ecwmax=%d\n", ac_val, wme->ecwmax[ac_val]);
	}
	pick_tmp = pick;
	pch = bcmstrstr(pick_tmp, "txop ");
	if (pch) {
		wme->txop[ac_val] = (int)simple_strtol(pch+strlen("txop "), NULL, 0);
		CONFIG_MSG("ac_val=%d, txop=0x%x\n", ac_val, wme->txop[ac_val]);
	}

}

bool
dhd_conf_read_wme_ac_params(dhd_pub_t *dhd, char *full_param, uint len_param)
{
	struct dhd_conf *conf = dhd->conf;
	char *data = full_param+len_param;

	// wme_ac_sta_be=aifsn 1 ecwmin 2 ecwmax 3 txop 0x5e
	// wme_ac_sta_vo=aifsn 1 ecwmin 1 ecwmax 1 txop 0x5e

	if (!strncmp("force_wme_ac=", full_param, len_param)) {
		conf->force_wme_ac = (int)simple_strtol(data, NULL, 10);
		CONFIG_MSG("force_wme_ac = %d\n", conf->force_wme_ac);
	}
	else if (!strncmp("wme_ac_sta_be=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_sta, data, AC_BE);
	}
	else if (!strncmp("wme_ac_sta_bk=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_sta, data, AC_BK);
	}
	else if (!strncmp("wme_ac_sta_vi=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_sta, data, AC_VI);
	}
	else if (!strncmp("wme_ac_sta_vo=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_sta, data, AC_VO);
	}
	else if (!strncmp("wme_ac_ap_be=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_ap, data, AC_BE);
	}
	else if (!strncmp("wme_ac_ap_bk=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_ap, data, AC_BK);
	}
	else if (!strncmp("wme_ac_ap_vi=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_ap, data, AC_VI);
	}
	else if (!strncmp("wme_ac_ap_vo=", full_param, len_param)) {
		dhd_conf_read_wme_ac_value(&conf->wme_ap, data, AC_VO);
	}
	else
		return false;

	return true;
}

#ifdef SET_FWNV_BY_MAC
bool
dhd_conf_read_fw_by_mac(dhd_pub_t *dhd, char *full_param, uint len_param)
{
	int i, j;
	char *pch, *pick_tmp;
	wl_mac_list_t *mac_list;
	wl_mac_range_t *mac_range;
	struct dhd_conf *conf = dhd->conf;
	char *data = full_param+len_param;

	/* Process fw_by_mac:
	 * fw_by_mac=[fw_mac_num] \
	 *  [fw_name1] [mac_num1] [oui1-1] [nic_start1-1] [nic_end1-1] \
	 *                                    [oui1-1] [nic_start1-1] [nic_end1-1]... \
	 *                                    [oui1-n] [nic_start1-n] [nic_end1-n] \
	 *  [fw_name2] [mac_num2] [oui2-1] [nic_start2-1] [nic_end2-1] \
	 *                                    [oui2-1] [nic_start2-1] [nic_end2-1]... \
	 *                                    [oui2-n] [nic_start2-n] [nic_end2-n] \
	 * Ex: fw_by_mac=2 \
	 *  fw_bcmdhd1.bin 2 0x0022F4 0xE85408 0xE8549D 0x983B16 0x3557A9 0x35582A \
	 *  fw_bcmdhd2.bin 3 0x0022F4 0xE85408 0xE8549D 0x983B16 0x3557A9 0x35582A \
	 *                           0x983B16 0x916157 0x916487
	 */

	if (!strncmp("fw_by_mac=", full_param, len_param)) {
		dhd_conf_free_mac_list(&conf->fw_by_mac);
		pick_tmp = data;
		pch = bcmstrtok(&pick_tmp, " ", 0);
		conf->fw_by_mac.count = (uint32)simple_strtol(pch, NULL, 0);
		if (!(mac_list = kmalloc(sizeof(wl_mac_list_t)*conf->fw_by_mac.count,
				GFP_KERNEL))) {
			conf->fw_by_mac.count = 0;
			CONFIG_ERROR("kmalloc failed\n");
		}
		CONFIG_MSG("fw_count=%d\n", conf->fw_by_mac.count);
		conf->fw_by_mac.m_mac_list_head = mac_list;
		for (i=0; i<conf->fw_by_mac.count; i++) {
			pch = bcmstrtok(&pick_tmp, " ", 0);
			strcpy(mac_list[i].name, pch);
			pch = bcmstrtok(&pick_tmp, " ", 0);
			mac_list[i].count = (uint32)simple_strtol(pch, NULL, 0);
			CONFIG_MSG("name=%s, mac_count=%d\n",
				mac_list[i].name, mac_list[i].count);
			if (!(mac_range = kmalloc(sizeof(wl_mac_range_t)*mac_list[i].count,
					GFP_KERNEL))) {
				mac_list[i].count = 0;
				CONFIG_ERROR("kmalloc failed\n");
				break;
			}
			mac_list[i].mac = mac_range;
			for (j=0; j<mac_list[i].count; j++) {
				pch = bcmstrtok(&pick_tmp, " ", 0);
				mac_range[j].oui = (uint32)simple_strtol(pch, NULL, 0);
				pch = bcmstrtok(&pick_tmp, " ", 0);
				mac_range[j].nic_start = (uint32)simple_strtol(pch, NULL, 0);
				pch = bcmstrtok(&pick_tmp, " ", 0);
				mac_range[j].nic_end = (uint32)simple_strtol(pch, NULL, 0);
				CONFIG_MSG("oui=0x%06X, nic_start=0x%06X, nic_end=0x%06X\n",
					mac_range[j].oui, mac_range[j].nic_start, mac_range[j].nic_end);
			}
		}
	}
	else
		return false;

	return true;
}

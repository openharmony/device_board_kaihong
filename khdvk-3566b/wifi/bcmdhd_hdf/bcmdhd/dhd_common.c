/*
 * Broadcom Dongle Host Driver (DHD), common DHD core.
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
 * $Id: dhd_common.c 826445 2019-06-20 04:47:47Z $
 */
#include <typedefs.h>
#include <osl.h>

#include <epivers.h>
#include <bcmutils.h>
#include <bcmstdlib_s.h>

#include <bcmendian.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_ip.h>
#include <bcmevent.h>
#include <dhdioctl.h>

#ifdef PCIE_FULL_DONGLE
#include <bcmmsgbuf.h>
#endif /* PCIE_FULL_DONGLE */

#ifdef SHOW_LOGTRACE
#include <event_log.h>
#endif /* SHOW_LOGTRACE */

#ifdef BCMPCIE
#include <dhd_flowring.h>
#endif // endif

#include <dhd_bus.h>
#include <dhd_proto.h>
#include <bcmsdbus.h>
#include <dhd_dbg.h>
#include <802.1d.h>
#include <dhd_debug.h>
#include <dhd_dbg_ring.h>
#include <dhd_mschdbg.h>
#include <msgtrace.h>
#include <dhd_config.h>
#include <wl_android.h>

#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#endif // endif
#if defined(PNO_SUPPORT)
#include <dhd_pno.h>
#endif /* OEM_ANDROID && PNO_SUPPORT */
#ifdef RTT_SUPPORT
#include <dhd_rtt.h>
#endif // endif

#ifdef DNGL_EVENT_SUPPORT
#include <dnglevent.h>
#endif // endif

#define htod32(i) (i)
#define htod16(i) (i)
#define dtoh32(i) (i)
#define dtoh16(i) (i)
#define htodchanspec(i) (i)
#define dtohchanspec(i) (i)

#ifdef PROP_TXSTATUS
#include <wlfc_proto.h>
#include <dhd_wlfc.h>
#endif // endif

#if defined(DHD_POST_EAPOL_M1_AFTER_ROAM_EVT)
#include <dhd_linux.h>
#endif // endif

#ifdef DHD_L2_FILTER
#include <dhd_l2_filter.h>
#endif /* DHD_L2_FILTER */

#ifdef DHD_PSTA
#include <dhd_psta.h>
#endif /* DHD_PSTA */

#ifdef DHD_WET
#include <dhd_wet.h>
#endif /* DHD_WET */

#ifdef DHD_LOG_DUMP
#include <dhd_dbg.h>
#endif /* DHD_LOG_DUMP */

#ifdef DHD_LOG_PRINT_RATE_LIMIT
int log_print_threshold = 0;
#endif /* DHD_LOG_PRINT_RATE_LIMIT */
int dhd_msg_level = DHD_ERROR_VAL | DHD_FWLOG_VAL;// | DHD_EVENT_VAL
	/* For CUSTOMER_HW4 do not enable DHD_IOVAR_MEM_VAL by default */
//	| DHD_PKT_MON_VAL;

#if defined(WL_WIRELESS_EXT)
#include <wl_iw.h>
#endif // endif

#ifdef DHD_ULP
#include <dhd_ulp.h>
#endif /* DHD_ULP */

#ifdef DHD_DEBUG
#include <sdiovar.h>
#endif /* DHD_DEBUG */

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
#include <linux/pm_runtime.h>
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifdef CSI_SUPPORT
#include <dhd_csi.h>
#endif /* CSI_SUPPORT */

#ifdef SOFTAP
char fw_path2[MOD_PARAM_PATHLEN];
extern bool softap_enabled;
#endif // endif
#ifdef PROP_TXSTATUS
extern int disable_proptx;
#endif /* PROP_TXSTATUS */

#ifdef SHOW_LOGTRACE
#define BYTES_AHEAD_NUM		10	/* address in map file is before these many bytes */
#define READ_NUM_BYTES		1000 /* read map file each time this No. of bytes */
#define GO_BACK_FILE_POS_NUM_BYTES	100 /* set file pos back to cur pos */
static char *ramstart_str = " text_start"; /* string in mapfile has addr ramstart */
static char *rodata_start_str = " rodata_start"; /* string in mapfile has addr rodata start */
static char *rodata_end_str = " rodata_end"; /* string in mapfile has addr rodata end */
#define RAMSTART_BIT	0x01
#define RDSTART_BIT		0x02
#define RDEND_BIT		0x04
#define ALL_MAP_VAL		(RAMSTART_BIT | RDSTART_BIT | RDEND_BIT)
#endif /* SHOW_LOGTRACE */

#ifdef SHOW_LOGTRACE
/* the fw file path is taken from either the module parameter at
 * insmod time or is defined as a constant of different values
 * for different platforms
 */
extern char *st_str_file_path;
#endif /* SHOW_LOGTRACE */

#define DHD_TPUT_MAX_TX_PKTS_BATCH	1000

#ifdef EWP_EDL
typedef struct msg_hdr_edl {
	uint32 infobuf_ver;
	info_buf_payload_hdr_t pyld_hdr;
	msgtrace_hdr_t trace_hdr;
} msg_hdr_edl_t;
#endif /* EWP_EDL */

/* Last connection success/failure status */
uint32 dhd_conn_event;
uint32 dhd_conn_status;
uint32 dhd_conn_reason;

extern int dhd_iscan_request(void * dhdp, uint16 action);
extern void dhd_ind_scan_confirm(void *h, bool status);
extern int dhd_iscan_in_progress(void *h);
void dhd_iscan_lock(void);
void dhd_iscan_unlock(void);
extern int dhd_change_mtu(dhd_pub_t *dhd, int new_mtu, int ifidx);
#if !defined(AP) && defined(WLP2P)
extern int dhd_get_concurrent_capabilites(dhd_pub_t *dhd);
#endif // endif

extern int dhd_socram_dump(struct dhd_bus *bus);
extern void dhd_set_packet_filter(dhd_pub_t *dhd);

#ifdef DNGL_EVENT_SUPPORT
static void dngl_host_event_process(dhd_pub_t *dhdp, bcm_dngl_event_t *event,
	bcm_dngl_event_msg_t *dngl_event, size_t pktlen);
static int dngl_host_event(dhd_pub_t *dhdp, void *pktdata, bcm_dngl_event_msg_t *dngl_event,
	size_t pktlen);
#endif /* DNGL_EVENT_SUPPORT */

#define MAX_CHUNK_LEN 1408 /* 8 * 8 * 22 */

bool ap_cfg_running = FALSE;
bool ap_fw_loaded = FALSE;

#ifdef WLEASYMESH
extern int dhd_set_1905_almac(dhd_pub_t *dhdp, uint8 ifidx, uint8* ea, bool mcast);
extern int dhd_get_1905_almac(dhd_pub_t *dhdp, uint8 ifidx, uint8* ea, bool mcast);
#endif /* WLEASYMESH */

#define CHIPID_MISMATCH	8

#define DHD_VERSION "Dongle Host Driver, version " EPI_VERSION_STR "\n"

#if defined(DHD_DEBUG) && defined(DHD_COMPILED)
const char dhd_version[] = DHD_VERSION DHD_COMPILED " compiled on "
			__DATE__ " at " __TIME__ "\n\0<TIMESTAMP>";
#else
const char dhd_version[] = DHD_VERSION;
#endif /* DHD_DEBUG && DHD_COMPILED */

char fw_version[FW_VER_STR_LEN] = "\0";
char clm_version[CLM_VER_STR_LEN] = "\0";

char bus_api_revision[BUS_API_REV_STR_LEN] = "\0";

void dhd_set_timer(void *bus, uint wdtick);

static char* ioctl2str(uint32 ioctl);

/* IOVar table */
enum {
	IOV_VERSION = 1,
	IOV_WLMSGLEVEL,
	IOV_MSGLEVEL,
	IOV_BCMERRORSTR,
	IOV_BCMERROR,
	IOV_WDTICK,
	IOV_DUMP,
	IOV_CLEARCOUNTS,
	IOV_LOGDUMP,
	IOV_LOGCAL,
	IOV_LOGSTAMP,
	IOV_GPIOOB,
	IOV_IOCTLTIMEOUT,
	IOV_CONS,
	IOV_DCONSOLE_POLL,
#if defined(DHD_DEBUG)
	IOV_DHD_JOIN_TIMEOUT_DBG,
	IOV_SCAN_TIMEOUT,
	IOV_MEM_DEBUG,
#ifdef BCMPCIE
	IOV_FLOW_RING_DEBUG,
#endif /* BCMPCIE */
#endif /* defined(DHD_DEBUG) */
#ifdef PROP_TXSTATUS
	IOV_PROPTXSTATUS_ENABLE,
	IOV_PROPTXSTATUS_MODE,
	IOV_PROPTXSTATUS_OPT,
	IOV_PROPTXSTATUS_MODULE_IGNORE,
	IOV_PROPTXSTATUS_CREDIT_IGNORE,
	IOV_PROPTXSTATUS_TXSTATUS_IGNORE,
	IOV_PROPTXSTATUS_RXPKT_CHK,
#endif /* PROP_TXSTATUS */
	IOV_BUS_TYPE,
	IOV_CHANGEMTU,
	IOV_HOSTREORDER_FLOWS,
#ifdef DHDTCPACK_SUPPRESS
	IOV_TCPACK_SUPPRESS,
#endif /* DHDTCPACK_SUPPRESS */
	IOV_AP_ISOLATE,
#ifdef DHD_L2_FILTER
	IOV_DHCP_UNICAST,
	IOV_BLOCK_PING,
	IOV_PROXY_ARP,
	IOV_GRAT_ARP,
	IOV_BLOCK_TDLS,
#endif /* DHD_L2_FILTER */
	IOV_DHD_IE,
#ifdef DHD_PSTA
	IOV_PSTA,
#endif /* DHD_PSTA */
#ifdef DHD_WET
	IOV_WET,
	IOV_WET_HOST_IPV4,
	IOV_WET_HOST_MAC,
#endif /* DHD_WET */
	IOV_CFG80211_OPMODE,
	IOV_ASSERT_TYPE,
	IOV_LMTEST,
#ifdef DHD_MCAST_REGEN
	IOV_MCAST_REGEN_BSS_ENABLE,
#endif // endif
#ifdef SHOW_LOGTRACE
	IOV_DUMP_TRACE_LOG,
#endif /* SHOW_LOGTRACE */
	IOV_DONGLE_TRAP_TYPE,
	IOV_DONGLE_TRAP_INFO,
	IOV_BPADDR,
	IOV_DUMP_DONGLE, /**< dumps core registers and d11 memories */
#if defined(DHD_LOG_DUMP)
	IOV_LOG_DUMP,
#endif /* DHD_LOG_DUMP */
	IOV_TPUT_TEST,
	IOV_FIS_TRIGGER,
	IOV_DEBUG_BUF_DEST_STAT,
#ifdef DHD_DEBUG
	IOV_INDUCE_ERROR,
#endif /* DHD_DEBUG */
#ifdef WL_IFACE_MGMT_CONF
#ifdef WL_CFG80211
#ifdef WL_NANP2P
	IOV_CONC_DISC,
#endif /* WL_NANP2P */
#ifdef WL_IFACE_MGMT
	IOV_IFACE_POLICY,
#endif /* WL_IFACE_MGMT */
#endif /* WL_CFG80211 */
#endif /* WL_IFACE_MGMT_CONF */
#ifdef RTT_GEOFENCE_CONT
#if defined(RTT_SUPPORT) && defined(WL_NAN)
	IOV_RTT_GEOFENCE_TYPE_OVRD,
#endif /* RTT_SUPPORT && WL_NAN */
#endif /* RTT_GEOFENCE_CONT */
#ifdef WLEASYMESH
	IOV_1905_AL_UCAST,
	IOV_1905_AL_MCAST,
#endif /* WLEASYMESH */
	IOV_LAST
};

const bcm_iovar_t dhd_iovars[] = {
	/* name         varid                   flags   flags2 type     minlen */
	{"version",	IOV_VERSION,		0,	0, IOVT_BUFFER,	sizeof(dhd_version)},
	{"wlmsglevel",	IOV_WLMSGLEVEL,	0,	0,	IOVT_UINT32,	0 },
#ifdef DHD_DEBUG
	{"msglevel",	IOV_MSGLEVEL,		0,	0, IOVT_UINT32,	0},
	{"mem_debug",   IOV_MEM_DEBUG,  0,      0,      IOVT_BUFFER,    0 },
#ifdef BCMPCIE
	{"flow_ring_debug", IOV_FLOW_RING_DEBUG, 0, 0, IOVT_BUFFER, 0 },
#endif /* BCMPCIE */
#endif /* DHD_DEBUG */
	{"bcmerrorstr", IOV_BCMERRORSTR,	0,	0, IOVT_BUFFER,	BCME_STRLEN},
	{"bcmerror",	IOV_BCMERROR,		0,	0, IOVT_INT8,	0},
	{"wdtick",	IOV_WDTICK,		0,	0, IOVT_UINT32,	0},
	{"dump",	IOV_DUMP,		0,	0, IOVT_BUFFER,	DHD_IOCTL_MAXLEN},
	{"cons",	IOV_CONS,		0,	0, IOVT_BUFFER,	0},
	{"dconpoll",	IOV_DCONSOLE_POLL,	0,	0, IOVT_UINT32,	0},
	{"clearcounts", IOV_CLEARCOUNTS,	0,	0, IOVT_VOID,	0},
	{"gpioob",	IOV_GPIOOB,		0,	0, IOVT_UINT32,	0},
	{"ioctl_timeout", IOV_IOCTLTIMEOUT,	0,	0, IOVT_UINT32,	0},
#ifdef PROP_TXSTATUS
	{"proptx",	IOV_PROPTXSTATUS_ENABLE,	0,	0, IOVT_BOOL,	0 },
	/*
	set the proptxtstatus operation mode:
	0 - Do not do any proptxtstatus flow control
	1 - Use implied credit from a packet status
	2 - Use explicit credit
	*/
	{"ptxmode",	IOV_PROPTXSTATUS_MODE,	0,	0, IOVT_UINT32,	0 },
	{"proptx_opt", IOV_PROPTXSTATUS_OPT,	0,	0, IOVT_UINT32,	0 },
	{"pmodule_ignore", IOV_PROPTXSTATUS_MODULE_IGNORE, 0, 0, IOVT_BOOL, 0 },
	{"pcredit_ignore", IOV_PROPTXSTATUS_CREDIT_IGNORE, 0, 0, IOVT_BOOL, 0 },
	{"ptxstatus_ignore", IOV_PROPTXSTATUS_TXSTATUS_IGNORE, 0, 0,  IOVT_BOOL, 0 },
	{"rxpkt_chk", IOV_PROPTXSTATUS_RXPKT_CHK, 0, 0, IOVT_BOOL, 0 },
#endif /* PROP_TXSTATUS */
	{"bustype", IOV_BUS_TYPE, 0, 0, IOVT_UINT32, 0},
	{"changemtu", IOV_CHANGEMTU, 0, 0, IOVT_UINT32, 0 },
	{"host_reorder_flows", IOV_HOSTREORDER_FLOWS, 0, 0, IOVT_BUFFER,
	(WLHOST_REORDERDATA_MAXFLOWS + 1) },
#ifdef DHDTCPACK_SUPPRESS
	{"tcpack_suppress",	IOV_TCPACK_SUPPRESS,	0,	0, IOVT_UINT8,	0 },
#endif /* DHDTCPACK_SUPPRESS */
#ifdef DHD_L2_FILTER
	{"dhcp_unicast", IOV_DHCP_UNICAST, (0), 0, IOVT_BOOL, 0 },
#endif /* DHD_L2_FILTER */
	{"ap_isolate", IOV_AP_ISOLATE, (0), 0, IOVT_BOOL, 0},
#ifdef DHD_L2_FILTER
	{"block_ping", IOV_BLOCK_PING, (0), 0, IOVT_BOOL, 0},
	{"proxy_arp", IOV_PROXY_ARP, (0), 0, IOVT_BOOL, 0},
	{"grat_arp", IOV_GRAT_ARP, (0), 0, IOVT_BOOL, 0},
	{"block_tdls", IOV_BLOCK_TDLS, (0), IOVT_BOOL, 0},
#endif /* DHD_L2_FILTER */
	{"dhd_ie", IOV_DHD_IE, (0), 0, IOVT_BUFFER, 0},
#ifdef DHD_PSTA
	/* PSTA/PSR Mode configuration. 0: DIABLED 1: PSTA 2: PSR */
	{"psta", IOV_PSTA, 0, 0, IOVT_UINT32, 0},
#endif /* DHD PSTA */
#ifdef DHD_WET
	/* WET Mode configuration. 0: DIABLED 1: WET */
	{"wet", IOV_WET, 0, 0, IOVT_UINT32, 0},
	{"wet_host_ipv4", IOV_WET_HOST_IPV4, 0, 0, IOVT_UINT32, 0},
	{"wet_host_mac", IOV_WET_HOST_MAC, 0, 0, IOVT_BUFFER, 0},
#endif /* DHD WET */
	{"op_mode",	IOV_CFG80211_OPMODE,	0,	0, IOVT_UINT32,	0 },
	{"assert_type", IOV_ASSERT_TYPE, (0), 0, IOVT_UINT32, 0},
	{"lmtest", IOV_LMTEST,	0,	0, IOVT_UINT32,	0 },
#ifdef DHD_MCAST_REGEN
	{"mcast_regen_bss_enable", IOV_MCAST_REGEN_BSS_ENABLE, 0, 0, IOVT_BOOL, 0},
#endif // endif
#ifdef SHOW_LOGTRACE
	{"dump_trace_buf", IOV_DUMP_TRACE_LOG,	0, 0, IOVT_BUFFER,	sizeof(trace_buf_info_t) },
#endif /* SHOW_LOGTRACE */
	{"trap_type", IOV_DONGLE_TRAP_TYPE, 0, 0, IOVT_UINT32, 0 },
	{"trap_info", IOV_DONGLE_TRAP_INFO, 0, 0, IOVT_BUFFER, sizeof(trap_t) },
#ifdef DHD_DEBUG
	{"bpaddr", IOV_BPADDR,	0, 0, IOVT_BUFFER,	sizeof(sdreg_t) },
#endif /* DHD_DEBUG */
	{"dump_dongle", IOV_DUMP_DONGLE, 0, 0, IOVT_BUFFER,
	MAX(sizeof(dump_dongle_in_t), sizeof(dump_dongle_out_t)) },
#if defined(DHD_LOG_DUMP)
	{"log_dump", IOV_LOG_DUMP,	0, 0, IOVT_UINT8, 0},
#endif /* DHD_LOG_DUMP */
	{"debug_buf_dest_stat", IOV_DEBUG_BUF_DEST_STAT, 0, 0, IOVT_UINT32, 0 },
#ifdef DHD_DEBUG
	{"induce_error", IOV_INDUCE_ERROR, (0), 0, IOVT_UINT16, 0 },
#endif /* DHD_DEBUG */
#ifdef WL_IFACE_MGMT_CONF
#ifdef WL_CFG80211
#ifdef WL_NANP2P
	{"conc_disc", IOV_CONC_DISC, (0), 0, IOVT_UINT16, 0 },
#endif /* WL_NANP2P */
#ifdef WL_IFACE_MGMT
	{"if_policy", IOV_IFACE_POLICY, (0), 0, IOVT_BUFFER, sizeof(iface_mgmt_data_t)},
#endif /* WL_IFACE_MGMT */
#endif /* WL_CFG80211 */
#endif /* WL_IFACE_MGMT_CONF */
#ifdef RTT_GEOFENCE_CONT
#if defined(RTT_SUPPORT) && defined(WL_NAN)
	{"rtt_geofence_type_ovrd", IOV_RTT_GEOFENCE_TYPE_OVRD, (0), 0, IOVT_BOOL, 0},
#endif /* RTT_SUPPORT && WL_NAN */
#endif /* RTT_GEOFENCE_CONT */
#ifdef WLEASYMESH
	{"1905_al_ucast", IOV_1905_AL_UCAST, 0, 0, IOVT_BUFFER, ETHER_ADDR_LEN},
	{"1905_al_mcast", IOV_1905_AL_MCAST, 0, 0, IOVT_BUFFER, ETHER_ADDR_LEN},
#endif /* WLEASYMESH */
	{NULL, 0, 0, 0, 0, 0 }
};

#define DHD_IOVAR_BUF_SIZE	128

bool
dhd_query_bus_erros(dhd_pub_t *dhdp)
{
	bool ret = FALSE;

	if (dhdp->dongle_reset) {
		DHD_ERROR_RLMT(("%s: Dongle Reset occurred, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

	if (dhdp->dongle_trap_occured) {
		DHD_ERROR_RLMT(("%s: FW TRAP has occurred, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
		dhdp->hang_reason = HANG_REASON_DONGLE_TRAP;
		dhd_os_send_hang_message(dhdp);
	}

	if (dhdp->iovar_timeout_occured) {
		DHD_ERROR_RLMT(("%s: Resumed on timeout for previous IOVAR, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

#ifdef PCIE_FULL_DONGLE
	if (dhdp->d3ack_timeout_occured) {
		DHD_ERROR_RLMT(("%s: Resumed on timeout for previous D3ACK, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}
	if (dhdp->livelock_occured) {
		DHD_ERROR_RLMT(("%s: LIVELOCK occurred for previous msg, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

	if (dhdp->pktid_audit_failed) {
		DHD_ERROR_RLMT(("%s: pktid_audit_failed, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}
#endif /* PCIE_FULL_DONGLE */

	if (dhdp->iface_op_failed) {
		DHD_ERROR_RLMT(("%s: iface_op_failed, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

	if (dhdp->scan_timeout_occurred) {
		DHD_ERROR_RLMT(("%s: scan_timeout_occurred, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

	if (dhdp->scan_busy_occurred) {
		DHD_ERROR_RLMT(("%s: scan_busy_occurred, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

#ifdef DNGL_AXI_ERROR_LOGGING
	if (dhdp->axi_error) {
		DHD_ERROR_RLMT(("%s: AXI error occurred, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}
#endif /* DNGL_AXI_ERROR_LOGGING */

	if (dhd_bus_get_linkdown(dhdp)) {
		DHD_ERROR_RLMT(("%s : PCIE Link down occurred, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

	if (dhd_bus_get_cto(dhdp)) {
		DHD_ERROR_RLMT(("%s : CTO Recovery reported, cannot proceed\n",
			__FUNCTION__));
		ret = TRUE;
	}

	return ret;
}

void
dhd_clear_bus_errors(dhd_pub_t *dhdp)
{
	if (!dhdp)
		return;

	dhdp->dongle_reset = FALSE;
	dhdp->dongle_trap_occured = FALSE;
	dhdp->iovar_timeout_occured = FALSE;
#ifdef PCIE_FULL_DONGLE
	dhdp->d3ack_timeout_occured = FALSE;
	dhdp->livelock_occured = FALSE;
	dhdp->pktid_audit_failed = FALSE;
#endif // endif
	dhdp->iface_op_failed = FALSE;
	dhdp->scan_timeout_occurred = FALSE;
	dhdp->scan_busy_occurred = FALSE;
}

#ifdef DHD_SSSR_DUMP

/* This can be overwritten by module parameter defined in dhd_linux.c */
uint support_sssr_dump = TRUE;

int
dhd_sssr_mempool_init(dhd_pub_t *dhd)
{
	dhd->sssr_mempool = (uint8 *) MALLOCZ(dhd->osh, DHD_SSSR_MEMPOOL_SIZE);
	if (dhd->sssr_mempool == NULL) {
		DHD_ERROR(("%s: MALLOC of sssr_mempool failed\n",
			__FUNCTION__));
		return BCME_ERROR;
	}
	return BCME_OK;
}

void
dhd_sssr_mempool_deinit(dhd_pub_t *dhd)
{
	if (dhd->sssr_mempool) {
		MFREE(dhd->osh, dhd->sssr_mempool, DHD_SSSR_MEMPOOL_SIZE);
		dhd->sssr_mempool = NULL;
	}
}

void
dhd_dump_sssr_reg_info(sssr_reg_info_v1_t *sssr_reg_info)
{
}

int
dhd_get_sssr_reg_info(dhd_pub_t *dhd)
{
	int ret;
	/* get sssr_reg_info from firmware */
	memset((void *)&dhd->sssr_reg_info, 0, sizeof(dhd->sssr_reg_info));
	ret = dhd_iovar(dhd, 0, "sssr_reg_info", NULL, 0,  (char *)&dhd->sssr_reg_info,
		sizeof(dhd->sssr_reg_info), FALSE);
	if (ret < 0) {
		DHD_ERROR(("%s: sssr_reg_info failed (error=%d)\n",
			__FUNCTION__, ret));
		return BCME_ERROR;
	}

	dhd_dump_sssr_reg_info(&dhd->sssr_reg_info);
	return BCME_OK;
}

uint32
dhd_get_sssr_bufsize(dhd_pub_t *dhd)
{
	int i;
	uint32 sssr_bufsize = 0;
	/* Init all pointers to NULL */
	for (i = 0; i < MAX_NUM_D11CORES; i++) {
		sssr_bufsize += dhd->sssr_reg_info.mac_regs[i].sr_size;
	}
	sssr_bufsize += dhd->sssr_reg_info.vasip_regs.vasip_sr_size;

	/* Double the size as different dumps will be saved before and after SR */
	sssr_bufsize = 2 * sssr_bufsize;

	return sssr_bufsize;
}

int
dhd_sssr_dump_init(dhd_pub_t *dhd)
{
	int i;
	uint32 sssr_bufsize;
	uint32 mempool_used = 0;

	dhd->sssr_inited = FALSE;

	if (!support_sssr_dump) {
		DHD_ERROR(("%s: sssr dump not inited as instructed by mod param\n", __FUNCTION__));
		return BCME_OK;
	}

	/* check if sssr mempool is allocated */
	if (dhd->sssr_mempool == NULL) {
		DHD_ERROR(("%s: sssr_mempool is not allocated\n",
			__FUNCTION__));
		return BCME_ERROR;
	}

	/* Get SSSR reg info */
	if (dhd_get_sssr_reg_info(dhd) != BCME_OK) {
		DHD_ERROR(("%s: dhd_get_sssr_reg_info failed\n", __FUNCTION__));
		return BCME_ERROR;
	}

	/* Validate structure version */
	if (dhd->sssr_reg_info.version > SSSR_REG_INFO_VER_1) {
		DHD_ERROR(("%s: dhd->sssr_reg_info.version (%d : %d) mismatch\n",
			__FUNCTION__, (int)dhd->sssr_reg_info.version, SSSR_REG_INFO_VER));
		return BCME_ERROR;
	}

	/* Validate structure length */
	if (dhd->sssr_reg_info.length < sizeof(sssr_reg_info_v0_t)) {
		DHD_ERROR(("%s: dhd->sssr_reg_info.length (%d : %d) mismatch\n",
			__FUNCTION__, (int)dhd->sssr_reg_info.length,
			(int)sizeof(dhd->sssr_reg_info)));
		return BCME_ERROR;
	}

	/* validate fifo size */
	sssr_bufsize = dhd_get_sssr_bufsize(dhd);
	if (sssr_bufsize > DHD_SSSR_MEMPOOL_SIZE) {
		DHD_ERROR(("%s: sssr_bufsize(%d) is greater than sssr_mempool(%d)\n",
			__FUNCTION__, (int)sssr_bufsize, DHD_SSSR_MEMPOOL_SIZE));
		return BCME_ERROR;
	}

	/* init all pointers to NULL */
	for (i = 0; i < MAX_NUM_D11CORES; i++) {
		dhd->sssr_d11_before[i] = NULL;
		dhd->sssr_d11_after[i] = NULL;
	}
	dhd->sssr_dig_buf_before = NULL;
	dhd->sssr_dig_buf_after = NULL;

	/* Allocate memory */
	for (i = 0; i < MAX_NUM_D11CORES; i++) {
		if (dhd->sssr_reg_info.mac_regs[i].sr_size) {
			dhd->sssr_d11_before[i] = (uint32 *)(dhd->sssr_mempool + mempool_used);
			mempool_used += dhd->sssr_reg_info.mac_regs[i].sr_size;

			dhd->sssr_d11_after[i] = (uint32 *)(dhd->sssr_mempool + mempool_used);
			mempool_used += dhd->sssr_reg_info.mac_regs[i].sr_size;
		}
	}

	if (dhd->sssr_reg_info.vasip_regs.vasip_sr_size) {
		dhd->sssr_dig_buf_before = (uint32 *)(dhd->sssr_mempool + mempool_used);
		mempool_used += dhd->sssr_reg_info.vasip_regs.vasip_sr_size;

		dhd->sssr_dig_buf_after = (uint32 *)(dhd->sssr_mempool + mempool_used);
		mempool_used += dhd->sssr_reg_info.vasip_regs.vasip_sr_size;
	} else if ((dhd->sssr_reg_info.length > OFFSETOF(sssr_reg_info_v1_t, dig_mem_info)) &&
		dhd->sssr_reg_info.dig_mem_info.dig_sr_addr) {
		dhd->sssr_dig_buf_before = (uint32 *)(dhd->sssr_mempool + mempool_used);
		mempool_used += dhd->sssr_reg_info.dig_mem_info.dig_sr_size;

		dhd->sssr_dig_buf_after = (uint32 *)(dhd->sssr_mempool + mempool_used);
		mempool_used += dhd->sssr_reg_info.dig_mem_info.dig_sr_size;
	}

	dhd->sssr_inited = TRUE;

	return BCME_OK;

}

void
dhd_sssr_dump_deinit(dhd_pub_t *dhd)
{
	int i;

	dhd->sssr_inited = FALSE;
	/* init all pointers to NULL */
	for (i = 0; i < MAX_NUM_D11CORES; i++) {
		dhd->sssr_d11_before[i] = NULL;
		dhd->sssr_d11_after[i] = NULL;
	}
	dhd->sssr_dig_buf_before = NULL;
	dhd->sssr_dig_buf_after = NULL;

	return;
}

void
dhd_sssr_print_filepath(dhd_pub_t *dhd, char *path)
{
	bool print_info = FALSE;
	int dump_mode;

	if (!dhd || !path) {
		DHD_ERROR(("%s: dhd or memdump_path is NULL\n",
			__FUNCTION__));
		return;
	}

	if (!dhd->sssr_dump_collected) {
		/* SSSR dump is not collected */
		return;
	}

	dump_mode = dhd->sssr_dump_mode;

	if (bcmstrstr(path, "core_0_before")) {
		if (dhd->sssr_d11_outofreset[0] &&
			dump_mode == SSSR_DUMP_MODE_SSSR) {
			print_info = TRUE;
		}
	} else if (bcmstrstr(path, "core_0_after")) {
		if (dhd->sssr_d11_outofreset[0]) {
			print_info = TRUE;
		}
	} else if (bcmstrstr(path, "core_1_before")) {
		if (dhd->sssr_d11_outofreset[1] &&
			dump_mode == SSSR_DUMP_MODE_SSSR) {
			print_info = TRUE;
		}
	} else if (bcmstrstr(path, "core_1_after")) {
		if (dhd->sssr_d11_outofreset[1]) {
			print_info = TRUE;
		}
	} else {
		print_info = TRUE;
	}

	if (print_info) {
		DHD_ERROR(("%s: file_path = %s%s\n", __FUNCTION__,
			path, FILE_NAME_HAL_TAG));
	}
}
#endif /* DHD_SSSR_DUMP */

#ifdef DHD_FW_COREDUMP
void* dhd_get_fwdump_buf(dhd_pub_t *dhd_pub, uint32 length)
{
	if (!dhd_pub->soc_ram) {
#if defined(CONFIG_DHD_USE_STATIC_BUF) && defined(DHD_USE_STATIC_MEMDUMP)
		dhd_pub->soc_ram = (uint8*)DHD_OS_PREALLOC(dhd_pub,
			DHD_PREALLOC_MEMDUMP_RAM, length);
#else
		dhd_pub->soc_ram = (uint8*) MALLOC(dhd_pub->osh, length);
#endif /* CONFIG_DHD_USE_STATIC_BUF && DHD_USE_STATIC_MEMDUMP */
	}

	if (dhd_pub->soc_ram == NULL) {
		DHD_ERROR(("%s: Failed to allocate memory for fw crash snap shot.\n",
			__FUNCTION__));
		dhd_pub->soc_ram_length = 0;
	} else {
		memset(dhd_pub->soc_ram, 0, length);
		dhd_pub->soc_ram_length = length;
	}

	/* soc_ram free handled in dhd_{free,clear} */
	return dhd_pub->soc_ram;
}
#endif /* DHD_FW_COREDUMP */

/* to NDIS developer, the structure dhd_common is redundant,
 * please do NOT merge it back from other branches !!!
 */

int
dhd_common_socram_dump(dhd_pub_t *dhdp)
{
#ifdef BCMDBUS
	return 0;
#else
	return dhd_socram_dump(dhdp->bus);
#endif /* BCMDBUS */
}

int
dhd_dump(dhd_pub_t *dhdp, char *buf, int buflen)
{
	struct bcmstrbuf b;
	struct bcmstrbuf *strbuf = &b;

	if (!dhdp || !dhdp->prot || !buf) {
		return BCME_ERROR;
	}

	bcm_binit(strbuf, buf, buflen);

	/* Base DHD info */
	bcm_bprintf(strbuf, "%s\n", dhd_version);
	bcm_bprintf(strbuf, "\n");
	bcm_bprintf(strbuf, "pub.up %d pub.txoff %d pub.busstate %d\n",
	            dhdp->up, dhdp->txoff, dhdp->busstate);
	bcm_bprintf(strbuf, "pub.hdrlen %u pub.maxctl %u pub.rxsz %u\n",
	            dhdp->hdrlen, dhdp->maxctl, dhdp->rxsz);
	bcm_bprintf(strbuf, "pub.iswl %d pub.drv_version %ld pub.mac "MACDBG"\n",
	            dhdp->iswl, dhdp->drv_version, MAC2STRDBG(&dhdp->mac));
	bcm_bprintf(strbuf, "pub.bcmerror %d tickcnt %u\n", dhdp->bcmerror, dhdp->tickcnt);

	bcm_bprintf(strbuf, "dongle stats:\n");
	bcm_bprintf(strbuf, "tx_packets %lu tx_bytes %lu tx_errors %lu tx_dropped %lu\n",
	            dhdp->dstats.tx_packets, dhdp->dstats.tx_bytes,
	            dhdp->dstats.tx_errors, dhdp->dstats.tx_dropped);
	bcm_bprintf(strbuf, "rx_packets %lu rx_bytes %lu rx_errors %lu rx_dropped %lu\n",
	            dhdp->dstats.rx_packets, dhdp->dstats.rx_bytes,
	            dhdp->dstats.rx_errors, dhdp->dstats.rx_dropped);
	bcm_bprintf(strbuf, "multicast %lu\n", dhdp->dstats.multicast);

	bcm_bprintf(strbuf, "bus stats:\n");
	bcm_bprintf(strbuf, "tx_packets %lu  tx_dropped %lu tx_multicast %lu tx_errors %lu\n",
	            dhdp->tx_packets, dhdp->tx_dropped, dhdp->tx_multicast, dhdp->tx_errors);
	bcm_bprintf(strbuf, "tx_ctlpkts %lu tx_ctlerrs %lu\n",
	            dhdp->tx_ctlpkts, dhdp->tx_ctlerrs);
	bcm_bprintf(strbuf, "rx_packets %lu rx_multicast %lu rx_errors %lu \n",
	            dhdp->rx_packets, dhdp->rx_multicast, dhdp->rx_errors);
	bcm_bprintf(strbuf, "rx_ctlpkts %lu rx_ctlerrs %lu rx_dropped %lu\n",
	            dhdp->rx_ctlpkts, dhdp->rx_ctlerrs, dhdp->rx_dropped);
	bcm_bprintf(strbuf, "rx_readahead_cnt %lu tx_realloc %lu\n",
	            dhdp->rx_readahead_cnt, dhdp->tx_realloc);
	bcm_bprintf(strbuf, "tx_pktgetfail %lu rx_pktgetfail %lu\n",
	            dhdp->tx_pktgetfail, dhdp->rx_pktgetfail);
	bcm_bprintf(strbuf, "tx_big_packets %lu\n",
	            dhdp->tx_big_packets);
	bcm_bprintf(strbuf, "\n");
#ifdef DMAMAP_STATS
	/* Add DMA MAP info */
	bcm_bprintf(strbuf, "DMA MAP stats: \n");
	bcm_bprintf(strbuf, "txdata: %lu size: %luK, rxdata: %lu size: %luK\n",
			dhdp->dma_stats.txdata, KB(dhdp->dma_stats.txdata_sz),
			dhdp->dma_stats.rxdata, KB(dhdp->dma_stats.rxdata_sz));
#ifndef IOCTLRESP_USE_CONSTMEM
	bcm_bprintf(strbuf, "IOCTL RX: %lu size: %luK ,",
			dhdp->dma_stats.ioctl_rx, KB(dhdp->dma_stats.ioctl_rx_sz));
#endif /* !IOCTLRESP_USE_CONSTMEM */
	bcm_bprintf(strbuf, "EVENT RX: %lu size: %luK, INFO RX: %lu size: %luK, "
			"TSBUF RX: %lu size %luK\n",
			dhdp->dma_stats.event_rx, KB(dhdp->dma_stats.event_rx_sz),
			dhdp->dma_stats.info_rx, KB(dhdp->dma_stats.info_rx_sz),
			dhdp->dma_stats.tsbuf_rx, KB(dhdp->dma_stats.tsbuf_rx_sz));
	bcm_bprintf(strbuf, "Total : %luK \n",
			KB(dhdp->dma_stats.txdata_sz + dhdp->dma_stats.rxdata_sz +
			dhdp->dma_stats.ioctl_rx_sz + dhdp->dma_stats.event_rx_sz +
			dhdp->dma_stats.tsbuf_rx_sz));
#endif /* DMAMAP_STATS */
	bcm_bprintf(strbuf, "dhd_induce_error : %u\n", dhdp->dhd_induce_error);
	/* Add any prot info */
	dhd_prot_dump(dhdp, strbuf);
	bcm_bprintf(strbuf, "\n");

	/* Add any bus info */
	dhd_bus_dump(dhdp, strbuf);

#if defined(DHD_LB_STATS)
	dhd_lb_stats_dump(dhdp, strbuf);
#endif /* DHD_LB_STATS */
#ifdef DHD_WET
	if (dhd_get_wet_mode(dhdp)) {
		bcm_bprintf(strbuf, "Wet Dump:\n");
		dhd_wet_dump(dhdp, strbuf);
		}
#endif /* DHD_WET */

	/* return remaining buffer length */
	return (!strbuf->size ? BCME_BUFTOOSHORT : strbuf->size);
}

void
dhd_dump_to_kernelog(dhd_pub_t *dhdp)
{
	char buf[512];

	DHD_ERROR(("F/W version: %s\n", fw_version));
	bcm_bprintf_bypass = TRUE;
	dhd_dump(dhdp, buf, sizeof(buf));
	bcm_bprintf_bypass = FALSE;
}

int
dhd_wl_ioctl_cmd(dhd_pub_t *dhd_pub, int cmd, void *arg, int len, uint8 set, int ifidx)
{
	wl_ioctl_t ioc;

	ioc.cmd = cmd;
	ioc.buf = arg;
	ioc.len = len;
	ioc.set = set;

	return dhd_wl_ioctl(dhd_pub, ifidx, &ioc, arg, len);
}

int
dhd_wl_ioctl_get_intiovar(dhd_pub_t *dhd_pub, char *name, uint *pval,
	int cmd, uint8 set, int ifidx)
{
	char iovbuf[WLC_IOCTL_SMLEN];
	int ret = -1;

	memset(iovbuf, 0, sizeof(iovbuf));
	if (bcm_mkiovar(name, NULL, 0, iovbuf, sizeof(iovbuf))) {
		ret = dhd_wl_ioctl_cmd(dhd_pub, cmd, iovbuf, sizeof(iovbuf), set, ifidx);
		if (!ret) {
			*pval = ltoh32(*((uint*)iovbuf));
		} else {
			DHD_ERROR(("%s: get int iovar %s failed, ERR %d\n",
				__FUNCTION__, name, ret));
		}
	} else {
		DHD_ERROR(("%s: mkiovar %s failed\n",
			__FUNCTION__, name));
	}

	return ret;
}

int
dhd_wl_ioctl_set_intiovar(dhd_pub_t *dhd_pub, char *name, uint val,
	int cmd, uint8 set, int ifidx)
{
	char iovbuf[WLC_IOCTL_SMLEN];
	int ret = -1;
	int lval = htol32(val);
	uint len;

	len = bcm_mkiovar(name, (char*)&lval, sizeof(lval), iovbuf, sizeof(iovbuf));

	if (len) {
		ret = dhd_wl_ioctl_cmd(dhd_pub, cmd, iovbuf, len, set, ifidx);
		if (ret) {
			DHD_ERROR(("%s: set int iovar %s failed, ERR %d\n",
				__FUNCTION__, name, ret));
		}
	} else {
		DHD_ERROR(("%s: mkiovar %s failed\n",
			__FUNCTION__, name));
	}

	return ret;
}

static struct ioctl2str_s {
	uint32 ioctl;
	char *name;
} ioctl2str_array[] = {
	{WLC_UP, "UP"},
	{WLC_DOWN, "DOWN"},
	{WLC_SET_PROMISC, "SET_PROMISC"},
	{WLC_SET_INFRA, "SET_INFRA"},
	{WLC_SET_AUTH, "SET_AUTH"},
	{WLC_SET_SSID, "SET_SSID"},
	{WLC_RESTART, "RESTART"},
	{WLC_SET_CHANNEL, "SET_CHANNEL"},
	{WLC_SET_RATE_PARAMS, "SET_RATE_PARAMS"},
	{WLC_SET_KEY, "SET_KEY"},
	{WLC_SCAN, "SCAN"},
	{WLC_DISASSOC, "DISASSOC"},
	{WLC_REASSOC, "REASSOC"},
	{WLC_SET_COUNTRY, "SET_COUNTRY"},
	{WLC_SET_WAKE, "SET_WAKE"},
	{WLC_SET_SCANSUPPRESS, "SET_SCANSUPPRESS"},
	{WLC_SCB_DEAUTHORIZE, "SCB_DEAUTHORIZE"},
	{WLC_SET_WSEC, "SET_WSEC"},
	{WLC_SET_INTERFERENCE_MODE, "SET_INTERFERENCE_MODE"},
	{WLC_SET_RADAR, "SET_RADAR"},
	{0, NULL}
};

static char *
ioctl2str(uint32 ioctl)
{
	struct ioctl2str_s *p = ioctl2str_array;

	while (p->name != NULL) {
		if (p->ioctl == ioctl) {
			return p->name;
		}
		p++;
	}

	return "";
}

/**
 * @param ioc          IO control struct, members are partially used by this function.
 * @param buf [inout]  Contains parameters to send to dongle, contains dongle response on return.
 * @param len          Maximum number of bytes that dongle is allowed to write into 'buf'.
 */
int
dhd_wl_ioctl(dhd_pub_t *dhd_pub, int ifidx, wl_ioctl_t *ioc, void *buf, int len)
{
	int ret = BCME_ERROR;
	unsigned long flags;
#ifdef DUMP_IOCTL_IOV_LIST
	dhd_iov_li_t *iov_li;
#endif /* DUMP_IOCTL_IOV_LIST */
	int hostsleep_set = 0;
	int hostsleep_val = 0;

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	DHD_OS_WAKE_LOCK(dhd_pub);
	if (pm_runtime_get_sync(dhd_bus_to_dev(dhd_pub->bus)) < 0) {
		DHD_RPM(("%s: pm_runtime_get_sync error. \n", __FUNCTION__));
		DHD_OS_WAKE_UNLOCK(dhd_pub);
		return BCME_ERROR;
	}
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifdef KEEPIF_ON_DEVICE_RESET
		if (ioc->cmd == WLC_GET_VAR) {
			dbus_config_t config;
			config.general_param = 0;
			if (buf) {
				if (!strcmp(buf, "wowl_activate")) {
					 /* 1 (TRUE) after decreased by 1 */
					config.general_param = 2;
				} else if (!strcmp(buf, "wowl_clear")) {
					 /* 0 (FALSE) after decreased by 1 */
					config.general_param = 1;
				}
			}
			if (config.general_param) {
				config.config_id = DBUS_CONFIG_ID_KEEPIF_ON_DEVRESET;
				config.general_param--;
				dbus_set_config(dhd_pub->dbus, &config);
			}
		}
#endif /* KEEPIF_ON_DEVICE_RESET */

	if (dhd_os_proto_block(dhd_pub))
	{
#ifdef DHD_LOG_DUMP
		int slen, val, lval, min_len;
		char *msg, tmp[64];

		/* WLC_GET_VAR */
		if (ioc->cmd == WLC_GET_VAR && buf) {
			min_len = MIN(sizeof(tmp) - 1, strlen(buf));
			memset(tmp, 0, sizeof(tmp));
			bcopy(buf, tmp, min_len);
			tmp[min_len] = '\0';
		}
#endif /* DHD_LOG_DUMP */

#ifdef DHD_DISCONNECT_TRACE
		if ((WLC_DISASSOC == ioc->cmd) || (WLC_DOWN == ioc->cmd) ||
			(WLC_DISASSOC_MYAP == ioc->cmd)) {
			DHD_ERROR(("IOCTL Disconnect WiFi: %d\n", ioc->cmd));
		}
#endif /* HW_DISCONNECT_TRACE */

		/* logging of iovars that are send to the dongle, ./dhd msglevel +iovar */
		if (ioc->set == TRUE) {
			char *pars = (char *)buf; // points at user buffer
			if (ioc->cmd == WLC_SET_VAR && buf) {
				DHD_DNGL_IOVAR_SET(("iovar:%d: set %s", ifidx, pars));
				if (ioc->len > 1 + sizeof(uint32)) {
					// skip iovar name:
					pars += strnlen(pars, ioc->len - 1 - sizeof(uint32));
					pars++;               // skip NULL character
				}
			} else {
				DHD_DNGL_IOVAR_SET(("ioctl:%d: set %d %s",
					ifidx, ioc->cmd, ioctl2str(ioc->cmd)));
			}
			if (pars != NULL) {
				DHD_DNGL_IOVAR_SET((" 0x%x\n", *(uint32*)pars));
			} else {
				DHD_DNGL_IOVAR_SET((" NULL\n"));
			}
		}

		DHD_LINUX_GENERAL_LOCK(dhd_pub, flags);
		if (DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(dhd_pub)) {
			DHD_INFO(("%s: returning as busstate=%d\n",
				__FUNCTION__, dhd_pub->busstate));
			DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);
			dhd_os_proto_unblock(dhd_pub);
			return -ENODEV;
		}
		DHD_BUS_BUSY_SET_IN_IOVAR(dhd_pub);
		DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);

		DHD_LINUX_GENERAL_LOCK(dhd_pub, flags);
		if (DHD_BUS_CHECK_SUSPEND_OR_SUSPEND_IN_PROGRESS(dhd_pub)) {
			DHD_ERROR(("%s: bus is in suspend(%d) or suspending(0x%x) state!!\n",
				__FUNCTION__, dhd_pub->busstate, dhd_pub->dhd_bus_busy_state));
			DHD_BUS_BUSY_CLEAR_IN_IOVAR(dhd_pub);
			dhd_os_busbusy_wake(dhd_pub);
			DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);
			dhd_os_proto_unblock(dhd_pub);
			return -ENODEV;
		}
		DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);

#ifdef DUMP_IOCTL_IOV_LIST
		if (ioc->cmd != WLC_GET_MAGIC && ioc->cmd != WLC_GET_VERSION && buf) {
			if (!(iov_li = MALLOC(dhd_pub->osh, sizeof(*iov_li)))) {
				DHD_ERROR(("iovar dump list item allocation Failed\n"));
			} else {
				iov_li->cmd = ioc->cmd;
				if (buf)
					bcopy((char *)buf, iov_li->buff, strlen((char *)buf)+1);
				dhd_iov_li_append(dhd_pub, &dhd_pub->dump_iovlist_head,
						&iov_li->list);
			}
		}
#endif /* DUMP_IOCTL_IOV_LIST */

		if (dhd_conf_check_hostsleep(dhd_pub, ioc->cmd, ioc->buf, len,
				&hostsleep_set, &hostsleep_val, &ret))
			goto exit;
		ret = dhd_prot_ioctl(dhd_pub, ifidx, ioc, buf, len);
		dhd_conf_get_hostsleep(dhd_pub, hostsleep_set, hostsleep_val, ret);

#ifdef DUMP_IOCTL_IOV_LIST
		if (ret == -ETIMEDOUT) {
			DHD_ERROR(("Last %d issued commands: Latest one is at bottom.\n",
				IOV_LIST_MAX_LEN));
			dhd_iov_li_print(&dhd_pub->dump_iovlist_head);
		}
#endif /* DUMP_IOCTL_IOV_LIST */
#ifdef DHD_LOG_DUMP
		if ((ioc->cmd == WLC_GET_VAR || ioc->cmd == WLC_SET_VAR) &&
				buf != NULL) {
			if (buf) {
				lval = 0;
				slen = strlen(buf) + 1;
				msg = (char*)buf;
				if (len >= slen + sizeof(lval)) {
					if (ioc->cmd == WLC_GET_VAR) {
						msg = tmp;
						lval = *(int*)buf;
					} else {
						min_len = MIN(ioc->len - slen, sizeof(int));
						bcopy((msg + slen), &lval, min_len);
					}
					if (!strncmp(msg, "cur_etheraddr",
						strlen("cur_etheraddr"))) {
						lval = 0;
					}
				}
				DHD_IOVAR_MEM((
					"%s: cmd: %d, msg: %s val: 0x%x,"
					" len: %d, set: %d, txn-id: %d\n",
					ioc->cmd == WLC_GET_VAR ?
					"WLC_GET_VAR" : "WLC_SET_VAR",
					ioc->cmd, msg, lval, ioc->len, ioc->set,
					dhd_prot_get_ioctl_trans_id(dhd_pub)));
			} else {
				DHD_IOVAR_MEM(("%s: cmd: %d, len: %d, set: %d, txn-id: %d\n",
					ioc->cmd == WLC_GET_VAR ? "WLC_GET_VAR" : "WLC_SET_VAR",
					ioc->cmd, ioc->len, ioc->set,
					dhd_prot_get_ioctl_trans_id(dhd_pub)));
			}
		} else {
			slen = ioc->len;
			if (buf != NULL && slen != 0) {
				if (slen >= 4) {
					val = *(int*)buf;
				} else if (slen >= 2) {
					val = *(short*)buf;
				} else {
					val = *(char*)buf;
				}
				/* Do not dump for WLC_GET_MAGIC and WLC_GET_VERSION */
				if (ioc->cmd != WLC_GET_MAGIC && ioc->cmd != WLC_GET_VERSION)
					DHD_IOVAR_MEM(("WLC_IOCTL: cmd: %d, val: %d, len: %d, "
						"set: %d\n", ioc->cmd, val, ioc->len, ioc->set));
			} else {
				DHD_IOVAR_MEM(("WLC_IOCTL: cmd: %d, buf is NULL\n", ioc->cmd));
			}
		}
#endif /* DHD_LOG_DUMP */
		if (ret && dhd_pub->up) {
			/* Send hang event only if dhd_open() was success */
			dhd_os_check_hang(dhd_pub, ifidx, ret);
		}

		if (ret == -ETIMEDOUT && !dhd_pub->up) {
			DHD_ERROR(("%s: 'resumed on timeout' error is "
				"occurred before the interface does not"
				" bring up\n", __FUNCTION__));
		}

exit:
		DHD_LINUX_GENERAL_LOCK(dhd_pub, flags);
		DHD_BUS_BUSY_CLEAR_IN_IOVAR(dhd_pub);
		dhd_os_busbusy_wake(dhd_pub);
		DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);

		dhd_os_proto_unblock(dhd_pub);

	}

#ifdef DHD_PCIE_NATIVE_RUNTIMEPM
	pm_runtime_mark_last_busy(dhd_bus_to_dev(dhd_pub->bus));
	pm_runtime_put_autosuspend(dhd_bus_to_dev(dhd_pub->bus));

	DHD_OS_WAKE_UNLOCK(dhd_pub);
#endif /* DHD_PCIE_NATIVE_RUNTIMEPM */

#ifdef WL_MONITOR
	/* Intercept monitor ioctl here, add/del monitor if */
	if (ret == BCME_OK && ioc->cmd == WLC_SET_MONITOR) {
		int val = 0;
		if (buf != NULL && len != 0) {
			if (len >= 4) {
				val = *(int*)buf;
			} else if (len >= 2) {
				val = *(short*)buf;
			} else {
				val = *(char*)buf;
			}
		}
		dhd_set_monitor(dhd_pub, ifidx, val);
	}
#endif /* WL_MONITOR */

	return ret;
}

uint wl_get_port_num(wl_io_pport_t *io_pport)
{
	return 0;
}

/* Get bssidx from iovar params
 * Input:   dhd_pub - pointer to dhd_pub_t
 *	    params  - IOVAR params
 * Output:  idx	    - BSS index
 *	    val	    - ponter to the IOVAR arguments
 */
static int
dhd_iovar_parse_bssidx(dhd_pub_t *dhd_pub, const char *params, uint32 *idx, const char **val)
{
	char *prefix = "bsscfg:";
	uint32	bssidx;

	if (!(strncmp(params, prefix, strlen(prefix)))) {
		/* per bss setting should be prefixed with 'bsscfg:' */
		const char *p = params + strlen(prefix);

		/* Skip Name */
		while (*p != '\0')
			p++;
		/* consider null */
		p = p + 1;
		bcopy(p, &bssidx, sizeof(uint32));
		/* Get corresponding dhd index */
		bssidx = dhd_bssidx2idx(dhd_pub, htod32(bssidx));

		if (bssidx >= DHD_MAX_IFS) {
			DHD_ERROR(("%s Wrong bssidx provided\n", __FUNCTION__));
			return BCME_ERROR;
		}

		/* skip bss idx */
		p += sizeof(uint32);
		*val = p;
		*idx = bssidx;
	} else {
		DHD_ERROR(("%s: bad parameter for per bss iovar\n", __FUNCTION__));
		return BCME_ERROR;
	}

	return BCME_OK;
}

#if defined(DHD_DEBUG) && defined(BCMDBUS)
/* USB Device console input function */
int dhd_bus_console_in(dhd_pub_t *dhd, uchar *msg, uint msglen)
{
	DHD_TRACE(("%s \n", __FUNCTION__));

	return dhd_iovar(dhd, 0, "cons", msg, msglen, NULL, 0, TRUE);

}
#endif /* DHD_DEBUG && BCMDBUS  */

#ifdef DHD_DEBUG
int
dhd_mem_debug(dhd_pub_t *dhd, uchar *msg, uint msglen)
{
	unsigned long int_arg = 0;
	char *p;
	char *end_ptr = NULL;
	dhd_dbg_mwli_t *mw_li;
	dll_t *item, *next;
	/* check if mwalloc, mwquery or mwfree was supplied arguement with space */
	p = bcmstrstr((char *)msg, " ");
	if (p != NULL) {
		/* space should be converted to null as separation flag for firmware */
		*p = '\0';
		/* store the argument in int_arg */
		int_arg = bcm_strtoul(p+1, &end_ptr, 10);
	}

	if (!p && !strcmp(msg, "query")) {
		/* lets query the list inetrnally */
		if (dll_empty(dll_head_p(&dhd->mw_list_head))) {
			DHD_ERROR(("memwaste list is empty, call mwalloc < size > to allocate\n"));
		} else {
			for (item = dll_head_p(&dhd->mw_list_head);
					!dll_end(&dhd->mw_list_head, item); item = next) {
				next = dll_next_p(item);
				mw_li = (dhd_dbg_mwli_t *)CONTAINEROF(item, dhd_dbg_mwli_t, list);
				DHD_ERROR(("item: <id=%d, size=%d>\n", mw_li->id, mw_li->size));
			}
		}
	} else if (p && end_ptr && (*end_ptr == '\0') && !strcmp(msg, "alloc")) {
		int32 alloc_handle;
		/* convert size into KB and append as integer */
		*((int32 *)(p+1)) = int_arg*1024;
		*(p+1+sizeof(int32)) = '\0';

		/* recalculated length -> 5 bytes for "alloc" + 4 bytes for size +
		 * 1 bytes for null caracter
		 */
		msglen = strlen(msg) + sizeof(int32) + 1;
		if (dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, msg, msglen+1, FALSE, 0) < 0) {
			DHD_ERROR(("IOCTL failed for memdebug alloc\n"));
		}

		/* returned allocated handle from dongle, basically address of the allocated unit */
		alloc_handle = *((int32 *)msg);

		/* add a node in the list with tuple <id, handle, size> */
		if (alloc_handle == 0) {
			DHD_ERROR(("Reuqested size could not be allocated\n"));
		} else if (!(mw_li = MALLOC(dhd->osh, sizeof(*mw_li)))) {
			DHD_ERROR(("mw list item allocation Failed\n"));
		} else {
			mw_li->id = dhd->mw_id++;
			mw_li->handle = alloc_handle;
			mw_li->size = int_arg;
			/* append the node in the list */
			dll_append(&dhd->mw_list_head, &mw_li->list);
		}
	} else if (p && end_ptr && (*end_ptr == '\0') && !strcmp(msg, "free")) {
		/* inform dongle to free wasted chunk */
		int handle = 0;
		int size = 0;
		for (item = dll_head_p(&dhd->mw_list_head);
				!dll_end(&dhd->mw_list_head, item); item = next) {
			next = dll_next_p(item);
			mw_li = (dhd_dbg_mwli_t *)CONTAINEROF(item, dhd_dbg_mwli_t, list);

			if (mw_li->id == (int)int_arg) {
				handle = mw_li->handle;
				size = mw_li->size;
				dll_delete(item);
				MFREE(dhd->osh, mw_li, sizeof(*mw_li));
				if (dll_empty(dll_head_p(&dhd->mw_list_head))) {
					/* reset the id */
					dhd->mw_id = 0;
				}
			}
		}
		if (handle) {
			int len;
			/* append the free handle and the chunk size in first 8 bytes
			 * after the command and null character
			 */
			*((int32 *)(p+1)) = handle;
			*((int32 *)((p+1)+sizeof(int32))) = size;
			/* append null as terminator */
			*(p+1+2*sizeof(int32)) = '\0';
			/* recalculated length -> 4 bytes for "free" + 8 bytes for hadnle and size
			 * + 1 bytes for null caracter
			 */
			len = strlen(msg) + 2*sizeof(int32) + 1;
			/* send iovar to free the chunk */
			if (dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, msg, len, FALSE, 0) < 0) {
				DHD_ERROR(("IOCTL failed for memdebug free\n"));
			}
		} else {
			DHD_ERROR(("specified id does not exist\n"));
		}
	} else {
		/* for all the wrong argument formats */
		return BCME_BADARG;
	}
	return 0;
}
extern void
dhd_mw_list_delete(dhd_pub_t *dhd, dll_t *list_head)
{
	dll_t *item;
	dhd_dbg_mwli_t *mw_li;
	while (!(dll_empty(list_head))) {
		item = dll_head_p(list_head);
		mw_li = (dhd_dbg_mwli_t *)CONTAINEROF(item, dhd_dbg_mwli_t, list);
		dll_delete(item);
		MFREE(dhd->osh, mw_li, sizeof(*mw_li));
	}
}
#ifdef BCMPCIE
int
dhd_flow_ring_debug(dhd_pub_t *dhd, char *msg, uint msglen)
{
	flow_ring_table_t *flow_ring_table;
	char *cmd;
	char *end_ptr = NULL;
	uint8 prio;
	uint16 flowid;
	int i;
	int ret = 0;
	cmd = bcmstrstr(msg, " ");
	BCM_REFERENCE(prio);
	if (cmd != NULL) {
		/* in order to use string operations append null */
		*cmd = '\0';
	} else {
		DHD_ERROR(("missing: create/delete args\n"));
		return BCME_ERROR;
	}
	if (cmd && !strcmp(msg, "create")) {
		/* extract <"source address", "destination address", "priority"> */
		uint8 sa[ETHER_ADDR_LEN], da[ETHER_ADDR_LEN];
		BCM_REFERENCE(sa);
		BCM_REFERENCE(da);
		msg = msg + strlen("create") + 1;
		/* fill ethernet source address */
		for (i = 0; i < ETHER_ADDR_LEN; i++) {
			sa[i] = (uint8)bcm_strtoul(msg, &end_ptr, 16);
			if (*end_ptr == ':') {
				msg = (end_ptr + 1);
			} else if (i != 5) {
				DHD_ERROR(("not a valid source mac addr\n"));
				return BCME_ERROR;
			}
		}
		if (*end_ptr != ' ') {
			DHD_ERROR(("missing: destiantion mac id\n"));
			return BCME_ERROR;
		} else {
			/* skip space */
			msg = end_ptr + 1;
		}
		/* fill ethernet destination address */
		for (i = 0; i < ETHER_ADDR_LEN; i++) {
			da[i] = (uint8)bcm_strtoul(msg, &end_ptr, 16);
			if (*end_ptr == ':') {
				msg = (end_ptr + 1);
			} else if (i != 5) {
				DHD_ERROR(("not a valid destination  mac addr\n"));
				return BCME_ERROR;
			}
		}
		if (*end_ptr != ' ') {
			DHD_ERROR(("missing: priority\n"));
			return BCME_ERROR;
		} else {
			msg = end_ptr + 1;
		}
		/* parse priority */
		prio = (uint8)bcm_strtoul(msg, &end_ptr, 10);
		if (prio > MAXPRIO) {
			DHD_ERROR(("%s: invalid priority. Must be between 0-7 inclusive\n",
				__FUNCTION__));
			return BCME_ERROR;
		}

		if (*end_ptr != '\0') {
			DHD_ERROR(("msg not truncated with NULL character\n"));
			return BCME_ERROR;
		}
		ret = dhd_flowid_debug_create(dhd, 0, prio, (char *)sa, (char *)da, &flowid);
		if (ret != BCME_OK) {
			DHD_ERROR(("%s: flowring creation failed ret: %d\n", __FUNCTION__, ret));
			return BCME_ERROR;
		}
		return BCME_OK;

	} else if (cmd && !strcmp(msg, "delete")) {
		msg = msg + strlen("delete") + 1;
		/* parse flowid */
		flowid = (uint16)bcm_strtoul(msg, &end_ptr, 10);
		if (*end_ptr != '\0') {
			DHD_ERROR(("msg not truncated with NULL character\n"));
			return BCME_ERROR;
		}

		/* Find flowid from ifidx 0 since this IOVAR creating flowring with ifidx 0 */
		if (dhd_flowid_find_by_ifidx(dhd, 0, flowid) != BCME_OK)
		{
			DHD_ERROR(("%s : Deleting not created flowid: %u\n", __FUNCTION__, flowid));
			return BCME_ERROR;
		}

		flow_ring_table = (flow_ring_table_t *)dhd->flow_ring_table;
		ret = dhd_bus_flow_ring_delete_request(dhd->bus, (void *)&flow_ring_table[flowid]);
		if (ret != BCME_OK) {
			DHD_ERROR(("%s: flowring deletion failed ret: %d\n", __FUNCTION__, ret));
			return BCME_ERROR;
		}
		return BCME_OK;
	}
	DHD_ERROR(("%s: neither create nor delete\n", __FUNCTION__));
	return BCME_ERROR;
}
#endif /* BCMPCIE */
#endif /* DHD_DEBUG */

static int
dhd_doiovar(dhd_pub_t *dhd_pub, const bcm_iovar_t *vi, uint32 actionid, const char *name,
            void *params, int plen, void *arg, int len, int val_size)
{
	int bcmerror = 0;
	int32 int_val = 0;
	uint32 dhd_ver_len, bus_api_rev_len;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));
	DHD_TRACE(("%s: actionid = %d; name %s\n", __FUNCTION__, actionid, name));

	if ((bcmerror = bcm_iovar_lencheck(vi, arg, len, IOV_ISSET(actionid))) != 0)
		goto exit;

	if (plen >= (int)sizeof(int_val))
		bcopy(params, &int_val, sizeof(int_val));

	switch (actionid) {
	case IOV_GVAL(IOV_VERSION):
		/* Need to have checked buffer length */
		dhd_ver_len = strlen(dhd_version);
		bus_api_rev_len = strlen(bus_api_revision);
		if (dhd_ver_len)
			bcm_strncpy_s((char*)arg, dhd_ver_len, dhd_version, dhd_ver_len);
		if (bus_api_rev_len)
			bcm_strncat_s((char*)arg + dhd_ver_len, bus_api_rev_len, bus_api_revision,
				bus_api_rev_len);
		break;

	case IOV_GVAL(IOV_WLMSGLEVEL):
		printf("android_msg_level=0x%x\n", android_msg_level);
		printf("config_msg_level=0x%x\n", config_msg_level);
#if defined(WL_WIRELESS_EXT)
		int_val = (int32)iw_msg_level;
		bcopy(&int_val, arg, val_size);
		printf("iw_msg_level=0x%x\n", iw_msg_level);
#endif
#ifdef WL_CFG80211
		int_val = (int32)wl_dbg_level;
		bcopy(&int_val, arg, val_size);
		printf("cfg_msg_level=0x%x\n", wl_dbg_level);
#endif
		break;

	case IOV_SVAL(IOV_WLMSGLEVEL):
		if (int_val & DHD_ANDROID_VAL) {
			android_msg_level = (uint)(int_val & 0xFFFF);
			printf("android_msg_level=0x%x\n", android_msg_level);
		}
		if (int_val & DHD_CONFIG_VAL) {
			config_msg_level = (uint)(int_val & 0xFFFF);
			printf("config_msg_level=0x%x\n", config_msg_level);
		}
#if defined(WL_WIRELESS_EXT)
		if (int_val & DHD_IW_VAL) {
			iw_msg_level = (uint)(int_val & 0xFFFF);
			printf("iw_msg_level=0x%x\n", iw_msg_level);
		}
#endif
#ifdef WL_CFG80211
		if (int_val & DHD_CFG_VAL) {
			wl_cfg80211_enable_trace((u32)(int_val & 0xFFFF));
		}
#endif
		break;

	case IOV_GVAL(IOV_MSGLEVEL):
		int_val = (int32)dhd_msg_level;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_MSGLEVEL):
		dhd_msg_level = int_val;
		break;

	case IOV_GVAL(IOV_BCMERRORSTR):
		bcm_strncpy_s((char *)arg, len, bcmerrorstr(dhd_pub->bcmerror), BCME_STRLEN);
		((char *)arg)[BCME_STRLEN - 1] = 0x00;
		break;

	case IOV_GVAL(IOV_BCMERROR):
		int_val = (int32)dhd_pub->bcmerror;
		bcopy(&int_val, arg, val_size);
		break;

#ifndef BCMDBUS
	case IOV_GVAL(IOV_WDTICK):
		int_val = (int32)dhd_watchdog_ms;
		bcopy(&int_val, arg, val_size);
		break;
#endif /* !BCMDBUS */

	case IOV_SVAL(IOV_WDTICK):
		if (!dhd_pub->up) {
			bcmerror = BCME_NOTUP;
			break;
		}

		dhd_watchdog_ms = (uint)int_val;

		dhd_os_wd_timer(dhd_pub, (uint)int_val);
		break;

	case IOV_GVAL(IOV_DUMP):
		if (dhd_dump(dhd_pub, arg, len) <= 0)
			bcmerror = BCME_ERROR;
		else
			bcmerror = BCME_OK;
		break;

#ifndef BCMDBUS
	case IOV_GVAL(IOV_DCONSOLE_POLL):
		int_val = (int32)dhd_pub->dhd_console_ms;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_DCONSOLE_POLL):
		dhd_pub->dhd_console_ms = (uint)int_val;
		break;

#if defined(DHD_DEBUG)
	case IOV_SVAL(IOV_CONS):
		if (len > 0) {
#ifdef CONSOLE_DPC
			bcmerror = dhd_bus_txcons(dhd_pub, arg, len - 1);
#else
			bcmerror = dhd_bus_console_in(dhd_pub, arg, len - 1);
#endif
		}
		break;
#endif /* DHD_DEBUG */
#endif /* !BCMDBUS */

	case IOV_SVAL(IOV_CLEARCOUNTS):
		dhd_pub->tx_packets = dhd_pub->rx_packets = 0;
		dhd_pub->tx_errors = dhd_pub->rx_errors = 0;
		dhd_pub->tx_ctlpkts = dhd_pub->rx_ctlpkts = 0;
		dhd_pub->tx_ctlerrs = dhd_pub->rx_ctlerrs = 0;
		dhd_pub->tx_dropped = 0;
		dhd_pub->rx_dropped = 0;
		dhd_pub->tx_pktgetfail = 0;
		dhd_pub->rx_pktgetfail = 0;
		dhd_pub->rx_readahead_cnt = 0;
		dhd_pub->tx_realloc = 0;
		dhd_pub->wd_dpc_sched = 0;
		dhd_pub->tx_big_packets = 0;
		memset(&dhd_pub->dstats, 0, sizeof(dhd_pub->dstats));
		dhd_bus_clearcounts(dhd_pub);
#ifdef PROP_TXSTATUS
		/* clear proptxstatus related counters */
		dhd_wlfc_clear_counts(dhd_pub);
#endif /* PROP_TXSTATUS */
#if defined(DHD_LB_STATS)
		DHD_LB_STATS_RESET(dhd_pub);
#endif /* DHD_LB_STATS */
		break;

	case IOV_GVAL(IOV_IOCTLTIMEOUT): {
		int_val = (int32)dhd_os_get_ioctl_resp_timeout();
		bcopy(&int_val, arg, sizeof(int_val));
		break;
	}

	case IOV_SVAL(IOV_IOCTLTIMEOUT): {
		if (int_val <= 0)
			bcmerror = BCME_BADARG;
		else
			dhd_os_set_ioctl_resp_timeout((unsigned int)int_val);
		break;
	}

#ifdef PROP_TXSTATUS
	case IOV_GVAL(IOV_PROPTXSTATUS_ENABLE): {
		bool wlfc_enab = FALSE;
		bcmerror = dhd_wlfc_get_enable(dhd_pub, &wlfc_enab);
		if (bcmerror != BCME_OK)
			goto exit;
		int_val = wlfc_enab ? 1 : 0;
		bcopy(&int_val, arg, val_size);
		break;
	}
	case IOV_SVAL(IOV_PROPTXSTATUS_ENABLE): {
		bool wlfc_enab = FALSE;
		bcmerror = dhd_wlfc_get_enable(dhd_pub, &wlfc_enab);
		if (bcmerror != BCME_OK)
			goto exit;

		/* wlfc is already set as desired */
		if (wlfc_enab == (int_val == 0 ? FALSE : TRUE))
			goto exit;

		if (int_val == TRUE && disable_proptx) {
			disable_proptx = 0;
		}

		if (int_val == TRUE)
			bcmerror = dhd_wlfc_init(dhd_pub);
		else
			bcmerror = dhd_wlfc_deinit(dhd_pub);

		break;
	}
	case IOV_GVAL(IOV_PROPTXSTATUS_MODE):
		bcmerror = dhd_wlfc_get_mode(dhd_pub, &int_val);
		if (bcmerror != BCME_OK)
			goto exit;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_PROPTXSTATUS_MODE):
		dhd_wlfc_set_mode(dhd_pub, int_val);
		break;

	case IOV_GVAL(IOV_PROPTXSTATUS_MODULE_IGNORE):
		bcmerror = dhd_wlfc_get_module_ignore(dhd_pub, &int_val);
		if (bcmerror != BCME_OK)
			goto exit;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_PROPTXSTATUS_MODULE_IGNORE):
		dhd_wlfc_set_module_ignore(dhd_pub, int_val);
		break;

	case IOV_GVAL(IOV_PROPTXSTATUS_CREDIT_IGNORE):
		bcmerror = dhd_wlfc_get_credit_ignore(dhd_pub, &int_val);
		if (bcmerror != BCME_OK)
			goto exit;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_PROPTXSTATUS_CREDIT_IGNORE):
		dhd_wlfc_set_credit_ignore(dhd_pub, int_val);
		break;

	case IOV_GVAL(IOV_PROPTXSTATUS_TXSTATUS_IGNORE):
		bcmerror = dhd_wlfc_get_txstatus_ignore(dhd_pub, &int_val);
		if (bcmerror != BCME_OK)
			goto exit;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_PROPTXSTATUS_TXSTATUS_IGNORE):
		dhd_wlfc_set_txstatus_ignore(dhd_pub, int_val);
		break;

	case IOV_GVAL(IOV_PROPTXSTATUS_RXPKT_CHK):
		bcmerror = dhd_wlfc_get_rxpkt_chk(dhd_pub, &int_val);
		if (bcmerror != BCME_OK)
			goto exit;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_PROPTXSTATUS_RXPKT_CHK):
		dhd_wlfc_set_rxpkt_chk(dhd_pub, int_val);
		break;

#endif /* PROP_TXSTATUS */

	case IOV_GVAL(IOV_BUS_TYPE):
		/* The dhd application queries the driver to check if its usb or sdio.  */
#ifdef BCMDBUS
		int_val = BUS_TYPE_USB;
#endif // endif
#ifdef BCMSDIO
		int_val = BUS_TYPE_SDIO;
#endif // endif
#ifdef PCIE_FULL_DONGLE
		int_val = BUS_TYPE_PCIE;
#endif // endif
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_CHANGEMTU):
		int_val &= 0xffff;
		bcmerror = dhd_change_mtu(dhd_pub, int_val, 0);
		break;

	case IOV_GVAL(IOV_HOSTREORDER_FLOWS):
	{
		uint i = 0;
		uint8 *ptr = (uint8 *)arg;
		uint8 count = 0;

		ptr++;
		for (i = 0; i < WLHOST_REORDERDATA_MAXFLOWS; i++) {
			if (dhd_pub->reorder_bufs[i] != NULL) {
				*ptr = dhd_pub->reorder_bufs[i]->flow_id;
				ptr++;
				count++;
			}
		}
		ptr = (uint8 *)arg;
		*ptr = count;
		break;
	}
#ifdef DHDTCPACK_SUPPRESS
	case IOV_GVAL(IOV_TCPACK_SUPPRESS): {
		int_val = (uint32)dhd_pub->tcpack_sup_mode;
		bcopy(&int_val, arg, val_size);
		break;
	}
	case IOV_SVAL(IOV_TCPACK_SUPPRESS): {
		bcmerror = dhd_tcpack_suppress_set(dhd_pub, (uint8)int_val);
		break;
	}
#endif /* DHDTCPACK_SUPPRESS */

#ifdef DHD_L2_FILTER
	case IOV_GVAL(IOV_DHCP_UNICAST): {
		uint32 bssidx;
		const char *val;
		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_DHCP_UNICAST: bad parameterand name = %s\n",
				__FUNCTION__, name));
			bcmerror = BCME_BADARG;
			break;
		}
		int_val = dhd_get_dhcp_unicast_status(dhd_pub, bssidx);
		memcpy(arg, &int_val, val_size);
		break;
	}
	case IOV_SVAL(IOV_DHCP_UNICAST): {
		uint32	bssidx;
		const char *val;
		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_DHCP_UNICAST: bad parameterand name = %s\n",
				__FUNCTION__, name));
			bcmerror = BCME_BADARG;
			break;
		}
		memcpy(&int_val, val, sizeof(int_val));
		bcmerror = dhd_set_dhcp_unicast_status(dhd_pub, bssidx, int_val ? 1 : 0);
		break;
	}
	case IOV_GVAL(IOV_BLOCK_PING): {
		uint32 bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_BLOCK_PING: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		int_val = dhd_get_block_ping_status(dhd_pub, bssidx);
		memcpy(arg, &int_val, val_size);
		break;
	}
	case IOV_SVAL(IOV_BLOCK_PING): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_BLOCK_PING: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		memcpy(&int_val, val, sizeof(int_val));
		bcmerror = dhd_set_block_ping_status(dhd_pub, bssidx, int_val ? 1 : 0);
		break;
	}
	case IOV_GVAL(IOV_PROXY_ARP): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_PROXY_ARP: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		int_val = dhd_get_parp_status(dhd_pub, bssidx);
		bcopy(&int_val, arg, val_size);
		break;
	}
	case IOV_SVAL(IOV_PROXY_ARP): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_PROXY_ARP: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		bcopy(val, &int_val, sizeof(int_val));

		/* Issue a iovar request to WL to update the proxy arp capability bit
		 * in the Extended Capability IE of beacons/probe responses.
		 */
		bcmerror = dhd_iovar(dhd_pub, bssidx, "proxy_arp_advertise", val, sizeof(int_val),
				NULL, 0, TRUE);
		if (bcmerror == BCME_OK) {
			dhd_set_parp_status(dhd_pub, bssidx, int_val ? 1 : 0);
		}
		break;
	}
	case IOV_GVAL(IOV_GRAT_ARP): {
		uint32 bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_GRAT_ARP: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		int_val = dhd_get_grat_arp_status(dhd_pub, bssidx);
		memcpy(arg, &int_val, val_size);
		break;
	}
	case IOV_SVAL(IOV_GRAT_ARP): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_GRAT_ARP: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		memcpy(&int_val, val, sizeof(int_val));
		bcmerror = dhd_set_grat_arp_status(dhd_pub, bssidx, int_val ? 1 : 0);
		break;
	}
	case IOV_GVAL(IOV_BLOCK_TDLS): {
		uint32 bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_BLOCK_TDLS: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		int_val = dhd_get_block_tdls_status(dhd_pub, bssidx);
		memcpy(arg, &int_val, val_size);
		break;
	}
	case IOV_SVAL(IOV_BLOCK_TDLS): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: IOV_BLOCK_TDLS: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		memcpy(&int_val, val, sizeof(int_val));
		bcmerror = dhd_set_block_tdls_status(dhd_pub, bssidx, int_val ? 1 : 0);
		break;
	}
#endif /* DHD_L2_FILTER */
	case IOV_SVAL(IOV_DHD_IE): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: dhd ie: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}

		break;
	}
	case IOV_GVAL(IOV_AP_ISOLATE): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: ap isoalate: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}

		int_val = dhd_get_ap_isolate(dhd_pub, bssidx);
		bcopy(&int_val, arg, val_size);
		break;
	}
	case IOV_SVAL(IOV_AP_ISOLATE): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: ap isolate: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}

		ASSERT(val);
		bcopy(val, &int_val, sizeof(uint32));
		dhd_set_ap_isolate(dhd_pub, bssidx, int_val);
		break;
	}
#ifdef DHD_PSTA
	case IOV_GVAL(IOV_PSTA): {
		int_val = dhd_get_psta_mode(dhd_pub);
		bcopy(&int_val, arg, val_size);
		break;
		}
	case IOV_SVAL(IOV_PSTA): {
		if (int_val >= DHD_MODE_PSTA_DISABLED && int_val <= DHD_MODE_PSR) {
			dhd_set_psta_mode(dhd_pub, int_val);
		} else {
			bcmerror = BCME_RANGE;
		}
		break;
		}
#endif /* DHD_PSTA */
#ifdef DHD_WET
	case IOV_GVAL(IOV_WET):
		 int_val = dhd_get_wet_mode(dhd_pub);
		 bcopy(&int_val, arg, val_size);
		 break;

	case IOV_SVAL(IOV_WET):
		 if (int_val == 0 || int_val == 1) {
			 dhd_set_wet_mode(dhd_pub, int_val);
			 /* Delete the WET DB when disabled */
			 if (!int_val) {
				 dhd_wet_sta_delete_list(dhd_pub);
			 }
		 } else {
			 bcmerror = BCME_RANGE;
		 }
				 break;
	case IOV_SVAL(IOV_WET_HOST_IPV4):
			dhd_set_wet_host_ipv4(dhd_pub, params, plen);
			break;
	case IOV_SVAL(IOV_WET_HOST_MAC):
			dhd_set_wet_host_mac(dhd_pub, params, plen);
		break;
#endif /* DHD_WET */
#ifdef DHD_MCAST_REGEN
	case IOV_GVAL(IOV_MCAST_REGEN_BSS_ENABLE): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, (char *)name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: mcast_regen_bss_enable: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}

		int_val = dhd_get_mcast_regen_bss_enable(dhd_pub, bssidx);
		bcopy(&int_val, arg, val_size);
		break;
	}

	case IOV_SVAL(IOV_MCAST_REGEN_BSS_ENABLE): {
		uint32	bssidx;
		const char *val;

		if (dhd_iovar_parse_bssidx(dhd_pub, (char *)name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: mcast_regen_bss_enable: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}

		ASSERT(val);
		bcopy(val, &int_val, sizeof(uint32));
		dhd_set_mcast_regen_bss_enable(dhd_pub, bssidx, int_val);
		break;
	}
#endif /* DHD_MCAST_REGEN */

	case IOV_GVAL(IOV_CFG80211_OPMODE): {
		int_val = (int32)dhd_pub->op_mode;
		bcopy(&int_val, arg, sizeof(int_val));
		break;
		}
	case IOV_SVAL(IOV_CFG80211_OPMODE): {
		if (int_val <= 0)
			bcmerror = BCME_BADARG;
		else
			dhd_pub->op_mode = int_val;
		break;
	}

	case IOV_GVAL(IOV_ASSERT_TYPE):
		int_val = g_assert_type;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_SVAL(IOV_ASSERT_TYPE):
		g_assert_type = (uint32)int_val;
		break;

#if !defined(MACOSX_DHD)
	case IOV_GVAL(IOV_LMTEST): {
		*(uint32 *)arg = (uint32)lmtest;
		break;
	}

	case IOV_SVAL(IOV_LMTEST): {
		uint32 val = *(uint32 *)arg;
		if (val > 50)
			bcmerror = BCME_BADARG;
		else {
			lmtest = (uint)val;
			DHD_ERROR(("%s: lmtest %s\n",
				__FUNCTION__, (lmtest == FALSE)? "OFF" : "ON"));
		}
		break;
	}
#endif // endif

#ifdef SHOW_LOGTRACE
	case IOV_GVAL(IOV_DUMP_TRACE_LOG): {
		trace_buf_info_t *trace_buf_info = (trace_buf_info_t *)arg;
		dhd_dbg_ring_t *dbg_verbose_ring = NULL;

		dbg_verbose_ring = dhd_dbg_get_ring_from_ring_id(dhd_pub, FW_VERBOSE_RING_ID);
		if (dbg_verbose_ring == NULL) {
			DHD_ERROR(("dbg_verbose_ring is NULL\n"));
			bcmerror = BCME_UNSUPPORTED;
			break;
		}

		if (trace_buf_info != NULL) {
			bzero(trace_buf_info, sizeof(trace_buf_info_t));
			dhd_dbg_read_ring_into_trace_buf(dbg_verbose_ring, trace_buf_info);
		} else {
			DHD_ERROR(("%s: arg is NULL\n", __FUNCTION__));
			bcmerror = BCME_NOMEM;
		}
		break;
	}
#endif /* SHOW_LOGTRACE */
#ifdef DHD_DEBUG
#if defined(BCMSDIO) || defined(BCMPCIE)
	case IOV_GVAL(IOV_DONGLE_TRAP_TYPE):
		if (dhd_pub->dongle_trap_occured)
			int_val = ltoh32(dhd_pub->last_trap_info.type);
		else
			int_val = 0;
		bcopy(&int_val, arg, val_size);
		break;

	case IOV_GVAL(IOV_DONGLE_TRAP_INFO):
	{
		struct bcmstrbuf strbuf;
		bcm_binit(&strbuf, arg, len);
		if (dhd_pub->dongle_trap_occured == FALSE) {
			bcm_bprintf(&strbuf, "no trap recorded\n");
			break;
		}
		dhd_bus_dump_trap_info(dhd_pub->bus, &strbuf);
		break;
	}

	case IOV_GVAL(IOV_BPADDR):
		{
			sdreg_t sdreg;
			uint32 addr, size;

			memcpy(&sdreg, params, sizeof(sdreg));

			addr = sdreg.offset;
			size = sdreg.func;

			bcmerror = dhd_bus_readwrite_bp_addr(dhd_pub, addr, size,
				(uint *)&int_val, TRUE);

			memcpy(arg, &int_val, sizeof(int32));

			break;
		}

	case IOV_SVAL(IOV_BPADDR):
		{
			sdreg_t sdreg;
			uint32 addr, size;

			memcpy(&sdreg, params, sizeof(sdreg));

			addr = sdreg.offset;
			size = sdreg.func;

			bcmerror = dhd_bus_readwrite_bp_addr(dhd_pub, addr, size,
				(uint *)&sdreg.value,
				FALSE);

			break;
		}
#endif /* BCMSDIO || BCMPCIE */
#ifdef BCMPCIE
	case IOV_SVAL(IOV_FLOW_RING_DEBUG):
		{
			bcmerror = dhd_flow_ring_debug(dhd_pub, arg, len);
			break;
		}
#endif /* BCMPCIE */
	case IOV_SVAL(IOV_MEM_DEBUG):
		if (len > 0) {
			bcmerror = dhd_mem_debug(dhd_pub, arg, len - 1);
		}
		break;
#endif /* DHD_DEBUG */
#if defined(DHD_LOG_DUMP)
	case IOV_GVAL(IOV_LOG_DUMP):
		{
			dhd_prot_debug_info_print(dhd_pub);
			dhd_log_dump_trigger(dhd_pub, CMD_DEFAULT);
			break;
		}
#endif /* DHD_LOG_DUMP */
	case IOV_GVAL(IOV_DEBUG_BUF_DEST_STAT):
		{
			if (dhd_pub->debug_buf_dest_support) {
				debug_buf_dest_stat_t *debug_buf_dest_stat =
					(debug_buf_dest_stat_t *)arg;
				memcpy(debug_buf_dest_stat, dhd_pub->debug_buf_dest_stat,
					sizeof(dhd_pub->debug_buf_dest_stat));
			} else {
				bcmerror = BCME_DISABLED;
			}
			break;
		}

#ifdef DHD_DEBUG
	case IOV_SVAL(IOV_INDUCE_ERROR): {
		if (int_val >= DHD_INDUCE_ERROR_MAX) {
			DHD_ERROR(("%s: Invalid command : %u\n", __FUNCTION__, (uint16)int_val));
		} else {
			dhd_pub->dhd_induce_error = (uint16)int_val;
		}
		break;
	}
#endif /* DHD_DEBUG */

#ifdef WL_IFACE_MGMT_CONF
#ifdef WL_CFG80211
#ifdef WL_NANP2P
	case IOV_GVAL(IOV_CONC_DISC): {
		int_val = wl_cfg80211_get_iface_conc_disc(
			dhd_linux_get_primary_netdev(dhd_pub));
		bcopy(&int_val, arg, sizeof(int_val));
		break;
	}
	case IOV_SVAL(IOV_CONC_DISC): {
		bcmerror = wl_cfg80211_set_iface_conc_disc(
			dhd_linux_get_primary_netdev(dhd_pub), (uint8)int_val);
		break;
	}
#endif /* WL_NANP2P */
#ifdef WL_IFACE_MGMT
	case IOV_GVAL(IOV_IFACE_POLICY): {
		int_val = wl_cfg80211_get_iface_policy(
			dhd_linux_get_primary_netdev(dhd_pub));
		bcopy(&int_val, arg, sizeof(int_val));
		break;
	}
	case IOV_SVAL(IOV_IFACE_POLICY): {
		bcmerror = wl_cfg80211_set_iface_policy(
			dhd_linux_get_primary_netdev(dhd_pub),
			arg, len);
		break;
	}
#endif /* WL_IFACE_MGMT */
#endif /* WL_CFG80211 */
#endif /* WL_IFACE_MGMT_CONF */
#ifdef RTT_GEOFENCE_CONT
#if defined(RTT_SUPPORT) && defined(WL_NAN)
	case IOV_GVAL(IOV_RTT_GEOFENCE_TYPE_OVRD): {
		bool enable = 0;
		dhd_rtt_get_geofence_cont_ind(dhd_pub, &enable);
		int_val = enable ? 1 : 0;
		bcopy(&int_val, arg, val_size);
		break;
	}
	case IOV_SVAL(IOV_RTT_GEOFENCE_TYPE_OVRD): {
		bool enable = *(bool *)arg;
		dhd_rtt_set_geofence_cont_ind(dhd_pub, enable);
		break;
	}
#endif /* RTT_SUPPORT && WL_NAN */
#endif /* RTT_GEOFENCE_CONT */
#ifdef WLEASYMESH
	case IOV_SVAL(IOV_1905_AL_UCAST): {
		uint32  bssidx;
		const char *val;
		uint8 ea[6] = {0};
		if (dhd_iovar_parse_bssidx(dhd_pub, (char *)name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: 1905_al_ucast: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		bcopy(val, ea, ETHER_ADDR_LEN);
		printf("IOV_1905_AL_UCAST:" MACDBG "\n", MAC2STRDBG(ea));
		bcmerror = dhd_set_1905_almac(dhd_pub, bssidx, ea, FALSE);
		break;
	}
	case IOV_GVAL(IOV_1905_AL_UCAST): {
		uint32  bssidx;
		const char *val;
		if (dhd_iovar_parse_bssidx(dhd_pub, (char *)name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: 1905_al_ucast: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}

		bcmerror = dhd_get_1905_almac(dhd_pub, bssidx, arg, FALSE);
		break;
	}
	case IOV_SVAL(IOV_1905_AL_MCAST): {
		uint32  bssidx;
		const char *val;
		uint8 ea[6] = {0};
		if (dhd_iovar_parse_bssidx(dhd_pub, (char *)name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: 1905_al_mcast: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}
		bcopy(val, ea, ETHER_ADDR_LEN);
		printf("IOV_1905_AL_MCAST:" MACDBG "\n", MAC2STRDBG(ea));
		bcmerror = dhd_set_1905_almac(dhd_pub, bssidx, ea, TRUE);
		break;
	}
	case IOV_GVAL(IOV_1905_AL_MCAST): {
		uint32  bssidx;
		const char *val;
		if (dhd_iovar_parse_bssidx(dhd_pub, (char *)name, &bssidx, &val) != BCME_OK) {
			DHD_ERROR(("%s: 1905_al_mcast: bad parameter\n", __FUNCTION__));
			bcmerror = BCME_BADARG;
			break;
		}

		bcmerror = dhd_get_1905_almac(dhd_pub, bssidx, arg, TRUE);
		break;
	}
#endif /* WLEASYMESH */
	default:
		bcmerror = BCME_UNSUPPORTED;
		break;
	}

exit:
	DHD_TRACE(("%s: actionid %d, bcmerror %d\n", __FUNCTION__, actionid, bcmerror));
	return bcmerror;
}

/* Store the status of a connection attempt for later retrieval by an iovar */
void
dhd_store_conn_status(uint32 event, uint32 status, uint32 reason)
{
	/* Do not overwrite a WLC_E_PRUNE with a WLC_E_SET_SSID
	 * because an encryption/rsn mismatch results in both events, and
	 * the important information is in the WLC_E_PRUNE.
	 */
	if (!(event == WLC_E_SET_SSID && status == WLC_E_STATUS_FAIL &&
	      dhd_conn_event == WLC_E_PRUNE)) {
		dhd_conn_event = event;
		dhd_conn_status = status;
		dhd_conn_reason = reason;
	}
}

bool
dhd_prec_enq(dhd_pub_t *dhdp, struct pktq *q, void *pkt, int prec)
{
	void *p;
	int eprec = -1;		/* precedence to evict from */
	bool discard_oldest;

	/* Fast case, precedence queue is not full and we are also not
	 * exceeding total queue length
	 */
	if (!pktqprec_full(q, prec) && !pktq_full(q)) {
		pktq_penq(q, prec, pkt);
		return TRUE;
	}

	/* Determine precedence from which to evict packet, if any */
	if (pktqprec_full(q, prec))
		eprec = prec;
	else if (pktq_full(q)) {
		p = pktq_peek_tail(q, &eprec);
		ASSERT(p);
		if (eprec > prec || eprec < 0)
			return FALSE;
	}

	/* Evict if needed */
	if (eprec >= 0) {
		/* Detect queueing to unconfigured precedence */
		ASSERT(!pktqprec_empty(q, eprec));
		discard_oldest = AC_BITMAP_TST(dhdp->wme_dp, eprec);
		if (eprec == prec && !discard_oldest)
			return FALSE;		/* refuse newer (incoming) packet */
		/* Evict packet according to discard policy */
		p = discard_oldest ? pktq_pdeq(q, eprec) : pktq_pdeq_tail(q, eprec);
		ASSERT(p);
#ifdef DHDTCPACK_SUPPRESS
		if (dhd_tcpack_check_xmit(dhdp, p) == BCME_ERROR) {
			DHD_ERROR(("%s %d: tcpack_suppress ERROR!!! Stop using it\n",
				__FUNCTION__, __LINE__));
			dhd_tcpack_suppress_set(dhdp, TCPACK_SUP_OFF);
		}
#endif /* DHDTCPACK_SUPPRESS */
		PKTFREE(dhdp->osh, p, TRUE);
	}

	/* Enqueue */
	p = pktq_penq(q, prec, pkt);
	ASSERT(p);

	return TRUE;
}

/*
 * Functions to drop proper pkts from queue:
 *	If one pkt in queue is non-fragmented, drop first non-fragmented pkt only
 *	If all pkts in queue are all fragmented, find and drop one whole set fragmented pkts
 *	If can't find pkts matching upper 2 cases, drop first pkt anyway
 */
bool
dhd_prec_drop_pkts(dhd_pub_t *dhdp, struct pktq *pq, int prec, f_droppkt_t fn)
{
	struct pktq_prec *q = NULL;
	void *p, *prev = NULL, *next = NULL, *first = NULL, *last = NULL, *prev_first = NULL;
	pkt_frag_t frag_info;

	ASSERT(dhdp && pq);
	ASSERT(prec >= 0 && prec < pq->num_prec);

	q = &pq->q[prec];
	p = q->head;

	if (p == NULL)
		return FALSE;

	while (p) {
		frag_info = pkt_frag_info(dhdp->osh, p);
		if (frag_info == DHD_PKT_FRAG_NONE) {
			break;
		} else if (frag_info == DHD_PKT_FRAG_FIRST) {
			if (first) {
				/* No last frag pkt, use prev as last */
				last = prev;
				break;
			} else {
				first = p;
				prev_first = prev;
			}
		} else if (frag_info == DHD_PKT_FRAG_LAST) {
			if (first) {
				last = p;
				break;
			}
		}

		prev = p;
		p = PKTLINK(p);
	}

	if ((p == NULL) || ((frag_info != DHD_PKT_FRAG_NONE) && !(first && last))) {
		/* Not found matching pkts, use oldest */
		prev = NULL;
		p = q->head;
		frag_info = 0;
	}

	if (frag_info == DHD_PKT_FRAG_NONE) {
		first = last = p;
		prev_first = prev;
	}

	p = first;
	while (p) {
		next = PKTLINK(p);
		q->n_pkts--;
		pq->n_pkts_tot--;

#ifdef WL_TXQ_STALL
		q->dequeue_count++;
#endif // endif

		PKTSETLINK(p, NULL);

		if (fn)
			fn(dhdp, prec, p, TRUE);

		if (p == last)
			break;

		p = next;
	}

	if (prev_first == NULL) {
		if ((q->head = next) == NULL)
			q->tail = NULL;
	} else {
		PKTSETLINK(prev_first, next);
		if (!next)
			q->tail = prev_first;
	}

	return TRUE;
}

static int
dhd_iovar_op(dhd_pub_t *dhd_pub, const char *name,
	void *params, int plen, void *arg, int len, bool set)
{
	int bcmerror = 0;
	int val_size;
	const bcm_iovar_t *vi = NULL;
	uint32 actionid;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	ASSERT(name);
	ASSERT(len >= 0);

	/* Get MUST have return space */
	ASSERT(set || (arg && len));

	/* Set does NOT take qualifiers */
	ASSERT(!set || (!params && !plen));

	if ((vi = bcm_iovar_lookup(dhd_iovars, name)) == NULL) {
		bcmerror = BCME_UNSUPPORTED;
		goto exit;
	}

	DHD_CTL(("%s: %s %s, len %d plen %d\n", __FUNCTION__,
		name, (set ? "set" : "get"), len, plen));

	/* set up 'params' pointer in case this is a set command so that
	 * the convenience int and bool code can be common to set and get
	 */
	if (params == NULL) {
		params = arg;
		plen = len;
	}

	if (vi->type == IOVT_VOID)
		val_size = 0;
	else if (vi->type == IOVT_BUFFER)
		val_size = len;
	else
		/* all other types are integer sized */
		val_size = sizeof(int);

	actionid = set ? IOV_SVAL(vi->varid) : IOV_GVAL(vi->varid);

	bcmerror = dhd_doiovar(dhd_pub, vi, actionid, name, params, plen, arg, len, val_size);

exit:
	return bcmerror;
}

int
dhd_ioctl(dhd_pub_t * dhd_pub, dhd_ioctl_t *ioc, void *buf, uint buflen)
{
	int bcmerror = 0;
	unsigned long flags;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

	if (!buf) {
		return BCME_BADARG;
	}

	dhd_os_dhdiovar_lock(dhd_pub);
	switch (ioc->cmd) {
		case DHD_GET_MAGIC:
			if (buflen < sizeof(int))
				bcmerror = BCME_BUFTOOSHORT;
			else
				*(int*)buf = DHD_IOCTL_MAGIC;
			break;

		case DHD_GET_VERSION:
			if (buflen < sizeof(int))
				bcmerror = BCME_BUFTOOSHORT;
			else
				*(int*)buf = DHD_IOCTL_VERSION;
			break;

		case DHD_GET_VAR:
		case DHD_SET_VAR:
			{
				char *arg;
				uint arglen;

				DHD_LINUX_GENERAL_LOCK(dhd_pub, flags);
				if (DHD_BUS_CHECK_DOWN_OR_DOWN_IN_PROGRESS(dhd_pub) &&
					bcmstricmp((char *)buf, "devreset")) {
					/* In platforms like FC19, the FW download is done via IOCTL
					 * and should not return error for IOCTLs fired before FW
					 * Download is done
					 */
					if (dhd_fw_download_status(dhd_pub) == FW_DOWNLOAD_DONE) {
						DHD_ERROR(("%s: returning as busstate=%d\n",
								__FUNCTION__, dhd_pub->busstate));
						DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);
						dhd_os_dhdiovar_unlock(dhd_pub);
						return -ENODEV;
					}
				}
				DHD_BUS_BUSY_SET_IN_DHD_IOVAR(dhd_pub);
				DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);

				DHD_LINUX_GENERAL_LOCK(dhd_pub, flags);
				if (DHD_BUS_CHECK_SUSPEND_OR_SUSPEND_IN_PROGRESS(dhd_pub)) {
					/* If Suspend/Resume is tested via pcie_suspend IOVAR
					 * then continue to execute the IOVAR, return from here for
					 * other IOVARs, also include pciecfgreg and devreset to go
					 * through.
					 */
					if (bcmstricmp((char *)buf, "pcie_suspend") &&
					    bcmstricmp((char *)buf, "pciecfgreg") &&
					    bcmstricmp((char *)buf, "devreset") &&
					    bcmstricmp((char *)buf, "sdio_suspend")) {
						DHD_ERROR(("%s: bus is in suspend(%d)"
							"or suspending(0x%x) state\n",
							__FUNCTION__, dhd_pub->busstate,
							dhd_pub->dhd_bus_busy_state));
						DHD_BUS_BUSY_CLEAR_IN_DHD_IOVAR(dhd_pub);
						dhd_os_busbusy_wake(dhd_pub);
						DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);
						dhd_os_dhdiovar_unlock(dhd_pub);
						return -ENODEV;
					}
				}
				/* During devreset ioctl, we call dhdpcie_advertise_bus_cleanup,
				 * which will wait for all the busy contexts to get over for
				 * particular time and call ASSERT if timeout happens. As during
				 * devreset ioctal, we made DHD_BUS_BUSY_SET_IN_DHD_IOVAR,
				 * to avoid ASSERT, clear the IOCTL busy state. "devreset" ioctl is
				 * not used in Production platforms but only used in FC19 setups.
				 */
				if (!bcmstricmp((char *)buf, "devreset") ||
#ifdef BCMPCIE
					(dhd_bus_is_multibp_capable(dhd_pub->bus) &&
					!bcmstricmp((char *)buf, "dwnldstate")) ||
#endif /* BCMPCIE */
					FALSE)
				{
					DHD_BUS_BUSY_CLEAR_IN_DHD_IOVAR(dhd_pub);
				}
				DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);

				/* scan past the name to any arguments */
				for (arg = buf, arglen = buflen; *arg && arglen; arg++, arglen--)
					;

				if (*arg) {
					bcmerror = BCME_BUFTOOSHORT;
					goto unlock_exit;
				}

				/* account for the NUL terminator */
				arg++, arglen--;
				/* call with the appropriate arguments */
				if (ioc->cmd == DHD_GET_VAR) {
					bcmerror = dhd_iovar_op(dhd_pub, buf, arg, arglen,
							buf, buflen, IOV_GET);
				} else {
					bcmerror = dhd_iovar_op(dhd_pub, buf, NULL, 0,
							arg, arglen, IOV_SET);
				}
				if (bcmerror != BCME_UNSUPPORTED) {
					goto unlock_exit;
				}

				/* not in generic table, try protocol module */
				if (ioc->cmd == DHD_GET_VAR) {
					bcmerror = dhd_prot_iovar_op(dhd_pub, buf, arg,
							arglen, buf, buflen, IOV_GET);
				} else {
					bcmerror = dhd_prot_iovar_op(dhd_pub, buf,
							NULL, 0, arg, arglen, IOV_SET);
				}
				if (bcmerror != BCME_UNSUPPORTED) {
					goto unlock_exit;
				}

				/* if still not found, try bus module */
				if (ioc->cmd == DHD_GET_VAR) {
					bcmerror = dhd_bus_iovar_op(dhd_pub, buf,
							arg, arglen, buf, buflen, IOV_GET);
				} else {
					bcmerror = dhd_bus_iovar_op(dhd_pub, buf,
							NULL, 0, arg, arglen, IOV_SET);
				}
				if (bcmerror != BCME_UNSUPPORTED) {
					goto unlock_exit;
				}

			}
			goto unlock_exit;

		default:
			bcmerror = BCME_UNSUPPORTED;
	}
	dhd_os_dhdiovar_unlock(dhd_pub);
	return bcmerror;

unlock_exit:
	DHD_LINUX_GENERAL_LOCK(dhd_pub, flags);
	DHD_BUS_BUSY_CLEAR_IN_DHD_IOVAR(dhd_pub);
	dhd_os_busbusy_wake(dhd_pub);
	DHD_LINUX_GENERAL_UNLOCK(dhd_pub, flags);
	dhd_os_dhdiovar_unlock(dhd_pub);
	return bcmerror;
}

#ifdef SHOW_EVENTS

static void
wl_show_host_event(dhd_pub_t *dhd_pub, wl_event_msg_t *event, void *event_data,
	void *raw_event_ptr, char *eventmask)
{
	uint i, status, reason;
	bool group = FALSE, flush_txq = FALSE, link = FALSE;
	bool host_data = FALSE; /* prints  event data after the case  when set */
	const char *auth_str;
	const char *event_name;
	uchar *buf;
	char err_msg[256], eabuf[ETHER_ADDR_STR_LEN];
	uint event_type, flags, auth_type, datalen;

	event_type = ntoh32(event->event_type);
	flags = ntoh16(event->flags);
	status = ntoh32(event->status);
	reason = ntoh32(event->reason);
	BCM_REFERENCE(reason);
	auth_type = ntoh32(event->auth_type);
	datalen = ntoh32(event->datalen);

	/* debug dump of event messages */
	snprintf(eabuf, sizeof(eabuf), MACDBG, MAC2STRDBG(event->addr.octet));

	event_name = bcmevent_get_name(event_type);
	BCM_REFERENCE(event_name);

	if (flags & WLC_EVENT_MSG_LINK)
		link = TRUE;
	if (flags & WLC_EVENT_MSG_GROUP)
		group = TRUE;
	if (flags & WLC_EVENT_MSG_FLUSHTXQ)
		flush_txq = TRUE;

	switch (event_type) {
	case WLC_E_START:
	case WLC_E_DEAUTH:
	case WLC_E_DISASSOC:
		DHD_EVENT(("MACEVENT: %s, MAC %s\n", event_name, eabuf));
		break;

	case WLC_E_ASSOC_IND:
	case WLC_E_REASSOC_IND:

		DHD_EVENT(("MACEVENT: %s, MAC %s\n", event_name, eabuf));

		break;

	case WLC_E_ASSOC:
	case WLC_E_REASSOC:
		if (status == WLC_E_STATUS_SUCCESS) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, SUCCESS\n", event_name, eabuf));
		} else if (status == WLC_E_STATUS_TIMEOUT) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, TIMEOUT\n", event_name, eabuf));
		} else if (status == WLC_E_STATUS_FAIL) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, FAILURE, status %d reason %d\n",
			       event_name, eabuf, (int)status, (int)reason));
		} else {
			DHD_EVENT(("MACEVENT: %s, MAC %s, unexpected status %d\n",
			       event_name, eabuf, (int)status));
		}

		break;

	case WLC_E_DEAUTH_IND:
	case WLC_E_DISASSOC_IND:
		DHD_EVENT(("MACEVENT: %s, MAC %s, reason %d\n", event_name, eabuf, (int)reason));
		break;

	case WLC_E_AUTH:
	case WLC_E_AUTH_IND:
		if (auth_type == DOT11_OPEN_SYSTEM)
			auth_str = "Open System";
		else if (auth_type == DOT11_SHARED_KEY)
			auth_str = "Shared Key";
		else if (auth_type == DOT11_SAE)
			auth_str = "SAE";
		else {
			snprintf(err_msg, sizeof(err_msg), "AUTH unknown: %d", (int)auth_type);
			auth_str = err_msg;
		}

		if (event_type == WLC_E_AUTH_IND) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, %s\n", event_name, eabuf, auth_str));
		} else if (status == WLC_E_STATUS_SUCCESS) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, %s, SUCCESS\n",
				event_name, eabuf, auth_str));
		} else if (status == WLC_E_STATUS_TIMEOUT) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, %s, TIMEOUT\n",
				event_name, eabuf, auth_str));
		} else if (status == WLC_E_STATUS_FAIL) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, %s, FAILURE, status %d reason %d\n",
			       event_name, eabuf, auth_str, (int)status, (int)reason));
		} else if (status == WLC_E_STATUS_NO_ACK) {
			DHD_EVENT(("MACEVENT: %s, MAC %s, %s, NOACK\n",
			       event_name, eabuf, auth_str));
		} else {
			DHD_EVENT(("MACEVENT: %s, MAC %s, %s, status %d reason %d\n",
				event_name, eabuf, auth_str, (int)status, (int)reason));
		}
		BCM_REFERENCE(auth_str);

		break;

	case WLC_E_JOIN:
	case WLC_E_ROAM:
	case WLC_E_SET_SSID:
		if (status == WLC_E_STATUS_SUCCESS) {
			DHD_EVENT(("MACEVENT: %s, MAC %s\n", event_name, eabuf));
		} else {
			if (status == WLC_E_STATUS_FAIL) {
				DHD_EVENT(("MACEVENT: %s, failed status %d\n", event_name, status));
			} else if (status == WLC_E_STATUS_NO_NETWORKS) {
				DHD_EVENT(("MACEVENT: %s, no networks found\n", event_name));
			} else {
				DHD_EVENT(("MACEVENT: %s, unexpected status %d\n",
					event_name, (int)status));
			}
		}
		break;

	case WLC_E_BEACON_RX:
		if (status == WLC_E_STATUS_SUCCESS) {
			DHD_EVENT(("MACEVENT: %s, SUCCESS\n", event_name));
		} else if (status == WLC_E_STATUS_FAIL) {
			DHD_EVENT(("MACEVENT: %s, FAIL\n", event_name));
		} else {
			DHD_EVENT(("MACEVENT: %s, status %d\n", event_name, status));
		}
		break;

	case WLC_E_LINK:
		DHD_EVENT(("MACEVENT: %s %s flags:0x%x status:%d\n",
			event_name, link?"UP":"DOWN", flags, status));
		BCM_REFERENCE(link);
		break;

	case WLC_E_MIC_ERROR:
		DHD_EVENT(("MACEVENT: %s, MAC %s, Group %d, Flush %d\n",
		       event_name, eabuf, group, flush_txq));
		BCM_REFERENCE(group);
		BCM_REFERENCE(flush_txq);
		break;

	case WLC_E_ICV_ERROR:
	case WLC_E_UNICAST_DECODE_ERROR:
	case WLC_E_MULTICAST_DECODE_ERROR:
		DHD_EVENT(("MACEVENT: %s, MAC %s\n",
		       event_name, eabuf));
		break;

	case WLC_E_TXFAIL:
		DHD_EVENT(("MACEVENT: %s, RA %s status %d\n", event_name, eabuf, status));
		break;

	case WLC_E_ASSOC_REQ_IE:
	case WLC_E_ASSOC_RESP_IE:
	case WLC_E_PMKID_CACHE:
		DHD_EVENT(("MACEVENT: %s\n", event_name));
		break;

	case WLC_E_SCAN_COMPLETE:
		DHD_EVENT(("MACEVENT: %s\n", event_name));
		break;
	case WLC_E_RSSI_LQM:
	case WLC_E_PFN_NET_FOUND:
	case WLC_E_PFN_NET_LOST:
	case WLC_E_PFN_SCAN_COMPLETE:
	case WLC_E_PFN_SCAN_NONE:
	case WLC_E_PFN_SCAN_ALLGONE:
	case WLC_E_PFN_GSCAN_FULL_RESULT:
	case WLC_E_PFN_SSID_EXT:
		DHD_EVENT(("PNOEVENT: %s\n", event_name));
		break;

	case WLC_E_PFN_SCAN_BACKOFF:
	case WLC_E_PFN_BSSID_SCAN_BACKOFF:
		DHD_EVENT(("PNOEVENT: %s, status %d, reason %d\n",
		           event_name, (int)status, (int)reason));
		break;

	case WLC_E_PSK_SUP:
	case WLC_E_PRUNE:
		DHD_EVENT(("MACEVENT: %s, status %d, reason %d\n",
		           event_name, (int)status, (int)reason));
		break;

#ifdef WIFI_ACT_FRAME
	case WLC_E_ACTION_FRAME:
		DHD_TRACE(("MACEVENT: %s Bssid %s\n", event_name, eabuf));
		break;
#endif /* WIFI_ACT_FRAME */

#ifdef SHOW_LOGTRACE
	case WLC_E_TRACE:
	{
		dhd_dbg_trace_evnt_handler(dhd_pub, event_data, raw_event_ptr, datalen);
		break;
	}
#endif /* SHOW_LOGTRACE */

	case WLC_E_RSSI:
		DHD_EVENT(("MACEVENT: %s %d\n", event_name, ntoh32(*((int *)event_data))));
		break;

	case WLC_E_SERVICE_FOUND:
	case WLC_E_P2PO_ADD_DEVICE:
	case WLC_E_P2PO_DEL_DEVICE:
		DHD_EVENT(("MACEVENT: %s, MAC %s\n", event_name, eabuf));
		break;

#ifdef BT_WIFI_HANDOBER
	case WLC_E_BT_WIFI_HANDOVER_REQ:
		DHD_EVENT(("MACEVENT: %s, MAC %s\n", event_name, eabuf));
		break;
#endif // endif

	case WLC_E_CCA_CHAN_QUAL:
		if (datalen) {
			cca_chan_qual_event_t *cca_event = (cca_chan_qual_event_t *)event_data;
			if (cca_event->id == WL_CHAN_QUAL_FULLPM_CCA) {
				cca_only_chan_qual_event_t *cca_only_event =
					(cca_only_chan_qual_event_t *)cca_event;
				BCM_REFERENCE(cca_only_event);
				DHD_EVENT((
					"MACEVENT: %s %d, MAC %s, status %d, reason %d, auth %d,"
					" channel 0x%02x\n",
					event_name, event_type, eabuf, (int)status,
					(int)reason, (int)auth_type, cca_event->chanspec));
				DHD_EVENT((
					"\tTOTAL (dur %dms me %dms notme %dms interf %dms"
					" ts 0x%08x)\n",
					cca_only_event->cca_busy_ext.duration,
					cca_only_event->cca_busy_ext.congest_ibss,
					cca_only_event->cca_busy_ext.congest_obss,
					cca_only_event->cca_busy_ext.interference,
					cca_only_event->cca_busy_ext.timestamp));
				DHD_EVENT((
					"\t  !PM (dur %dms me %dms notme %dms interf %dms)\n",
					cca_only_event->cca_busy_nopm.duration,
					cca_only_event->cca_busy_nopm.congest_ibss,
					cca_only_event->cca_busy_nopm.congest_obss,
					cca_only_event->cca_busy_nopm.interference));
				DHD_EVENT((
					"\t   PM (dur %dms me %dms notme %dms interf %dms)\n",
					cca_only_event->cca_busy_pm.duration,
					cca_only_event->cca_busy_pm.congest_ibss,
					cca_only_event->cca_busy_pm.congest_obss,
					cca_only_event->cca_busy_pm.interference));
			} else if (cca_event->id == WL_CHAN_QUAL_FULL_CCA) {
				DHD_EVENT((
					"MACEVENT: %s %d, MAC %s, status %d, reason %d, auth %d,"
					" channel 0x%02x (dur %dms ibss %dms obss %dms interf %dms"
					" ts 0x%08x)\n",
					event_name, event_type, eabuf, (int)status,
					(int)reason, (int)auth_type, cca_event->chanspec,
					cca_event->cca_busy_ext.duration,
					cca_event->cca_busy_ext.congest_ibss,
					cca_event->cca_busy_ext.congest_obss,
					cca_event->cca_busy_ext.interference,
					cca_event->cca_busy_ext.timestamp));
			} else if (cca_event->id == WL_CHAN_QUAL_CCA) {
				DHD_EVENT((
					"MACEVENT: %s %d, MAC %s, status %d, reason %d, auth %d,"
					" channel 0x%02x (dur %dms busy %dms ts 0x%08x)\n",
					event_name, event_type, eabuf, (int)status,
					(int)reason, (int)auth_type, cca_event->chanspec,
					cca_event->cca_busy.duration,
					cca_event->cca_busy.congest,
					cca_event->cca_busy.timestamp));
			} else if ((cca_event->id == WL_CHAN_QUAL_NF) ||
			           (cca_event->id == WL_CHAN_QUAL_NF_LTE)) {
				DHD_EVENT((
					"MACEVENT: %s %d, MAC %s, status %d, reason %d, auth %d,"
					" channel 0x%02x (NF[%d] %ddB)\n",
					event_name, event_type, eabuf, (int)status,
					(int)reason, (int)auth_type, cca_event->chanspec,
					cca_event->id, cca_event->noise));
			} else {
				DHD_EVENT((
					"MACEVENT: %s %d, MAC %s, status %d, reason %d, auth %d,"
					" channel 0x%02x (unknown ID %d)\n",
					event_name, event_type, eabuf, (int)status,
					(int)reason, (int)auth_type, cca_event->chanspec,
					cca_event->id));
			}
		}
		break;
	case WLC_E_ESCAN_RESULT:
	{
		wl_escan_result_v2_t *escan_result =
				(wl_escan_result_v2_t *)event_data;
		BCM_REFERENCE(escan_result);
		if ((status == WLC_E_STATUS_SUCCESS) || (status == WLC_E_STATUS_ABORT)) {
			DHD_EVENT(("MACEVENT: %s %d, status %d sync-id %u\n",
				event_name, event_type, (int)status,
				dtoh16(escan_result->sync_id)));
		} else {
			DHD_TRACE(("MACEVENT: %s %d, MAC %s, status %d \n",
				event_name, event_type, eabuf, (int)status));
		}

		break;
	}
	case WLC_E_IF:
	{
		struct wl_event_data_if *ifevent = (struct wl_event_data_if *)event_data;
		BCM_REFERENCE(ifevent);

		DHD_EVENT(("MACEVENT: %s, opcode:0x%d  ifidx:%d role:%d\n",
		event_name, ifevent->opcode, ifevent->ifidx, ifevent->role));
		break;
	}
#ifdef SHOW_LOGTRACE
	case WLC_E_MSCH:
	{
		wl_mschdbg_event_handler(dhd_pub, raw_event_ptr, reason, event_data, datalen);
		break;
	}
#endif /* SHOW_LOGTRACE */

	case WLC_E_PSK_AUTH:
		DHD_EVENT(("MACEVENT: %s, RA %s status %d Reason:%d\n",
			event_name, eabuf, status, reason));
		break;
	case WLC_E_AGGR_EVENT:
		{
			event_aggr_data_t *aggrbuf = event_data;
			int j = 0, len = 0;
			uint8 *data = aggrbuf->data;
			DHD_EVENT(("MACEVENT: %s, num of events %d total len %d sub events: ",
					event_name, aggrbuf->num_events, aggrbuf->len));
			for (j = 0; j < aggrbuf->num_events; j++)
			{
				wl_event_msg_t * sub_event = (wl_event_msg_t *)data;
				if (len > aggrbuf->len) {
					DHD_ERROR(("%s: Aggr events corrupted!",
						__FUNCTION__));
					break;
				}
				DHD_EVENT(("\n Event type: %d ", ntoh32(sub_event->event_type)));
				len += ALIGN_SIZE((ntoh32(sub_event->datalen) +
						sizeof(wl_event_msg_t)), sizeof(uint64));
				buf = (uchar *)(data + sizeof(wl_event_msg_t));
				BCM_REFERENCE(buf);
				DHD_EVENT((" data (%d) : ", ntoh32(sub_event->datalen)));
				for (i = 0; i < ntoh32(sub_event->datalen); i++) {
					DHD_EVENT((" 0x%02x ", buf[i]));
				}
				data = aggrbuf->data + len;
			}
			DHD_EVENT(("\n"));
		}
		break;
	case WLC_E_NAN_CRITICAL:
		{
			DHD_LOG_MEM(("MACEVENT: %s, type:%d\n", event_name, reason));
			break;
		}
	case WLC_E_NAN_NON_CRITICAL:
		{
			DHD_TRACE(("MACEVENT: %s, type:%d\n", event_name, reason));
			break;
		}
	case WLC_E_PROXD:
		{
			wl_proxd_event_t *proxd = (wl_proxd_event_t*)event_data;
			DHD_LOG_MEM(("MACEVENT: %s, event:%d, status:%d\n",
				event_name, proxd->type, reason));
			break;
		}
	case WLC_E_RPSNOA:
		{
			rpsnoa_stats_t *stat = event_data;
			if (datalen == sizeof(*stat)) {
				DHD_EVENT(("MACEVENT: %s, band %s, status %d, pps %d\n", event_name,
					(stat->band == WLC_BAND_2G) ? "2G":"5G",
					stat->state, stat->last_pps));
			}
			break;
		}
	case WLC_E_PHY_CAL:
		{
			DHD_EVENT(("MACEVENT: %s, reason:%d\n", event_name, reason));
			break;
		}
	case WLC_E_WA_LQM:
		{
			wl_event_wa_lqm_t *event_wa_lqm = (wl_event_wa_lqm_t *)event_data;
			bcm_xtlv_t *subevent;
			wl_event_wa_lqm_basic_t *elqm_basic;

			if ((event_wa_lqm->ver != WL_EVENT_WA_LQM_VER) ||
			    (event_wa_lqm->len < sizeof(wl_event_wa_lqm_t) + BCM_XTLV_HDR_SIZE)) {
				DHD_ERROR(("MACEVENT: %s invalid (ver=%d len=%d)\n",
					event_name, event_wa_lqm->ver, event_wa_lqm->len));
				break;
			}

			subevent = (bcm_xtlv_t *)event_wa_lqm->subevent;
			 if ((subevent->id != WL_EVENT_WA_LQM_BASIC) ||
			     (subevent->len < sizeof(wl_event_wa_lqm_basic_t))) {
				DHD_ERROR(("MACEVENT: %s invalid sub-type (id=%d len=%d)\n",
					event_name, subevent->id, subevent->len));
				break;
			}

			elqm_basic = (wl_event_wa_lqm_basic_t *)subevent->data;
			BCM_REFERENCE(elqm_basic);
			DHD_EVENT(("MACEVENT: %s (RSSI=%d SNR=%d TxRate=%d RxRate=%d)\n",
				event_name, elqm_basic->rssi, elqm_basic->snr,
				elqm_basic->tx_rate, elqm_basic->rx_rate));
			break;
		}
	default:
		DHD_EVENT(("MACEVENT: %s %d, MAC %s, status %d, reason %d, auth %d\n",
		       event_name, event_type, eabuf, (int)status, (int)reason,
		       (int)auth_type));
		break;
	}

	/* show any appended data if message level is set to bytes or host_data is set */
	if ((DHD_BYTES_ON() || (host_data == TRUE)) && DHD_EVENT_ON() && datalen) {
		buf = (uchar *) event_data;
		BCM_REFERENCE(buf);
		DHD_EVENT((" data (%d) : ", datalen));
		for (i = 0; i < datalen; i++) {
			DHD_EVENT((" 0x%02x ", buf[i]));
		}
		DHD_EVENT(("\n"));
	}
} /* wl_show_host_event */
#endif /* SHOW_EVENTS */

#ifdef DNGL_EVENT_SUPPORT
/* Check whether packet is a BRCM dngl event pkt. If it is, process event data. */
int
dngl_host_event(dhd_pub_t *dhdp, void *pktdata, bcm_dngl_event_msg_t *dngl_event, size_t pktlen)
{
	bcm_dngl_event_t *pvt_data = (bcm_dngl_event_t *)pktdata;

	dngl_host_event_process(dhdp, pvt_data, dngl_event, pktlen);
	return BCME_OK;
}

#ifdef PARSE_DONGLE_HOST_EVENT
typedef struct hck_id_to_str_s {
	uint32 id;
	char *name;
} hck_id_to_str_t;

hck_id_to_str_t hck_sw_id_to_str[] = {
	{WL_HC_DD_PCIE, "WL_HC_DD_PCIE"},
	{WL_HC_DD_RX_DMA_STALL, "WL_HC_DD_RX_DMA_STALL"},
	{WL_HC_DD_RX_STALL, "WL_HC_DD_RX_STALL"},
	{WL_HC_DD_TX_STALL, "WL_HC_DD_TX_STALL"},
	{WL_HC_DD_SCAN_STALL, "WL_HC_DD_SCAN_STALL"},
	{WL_HC_DD_PHY, "WL_HC_DD_PHY"},
	{WL_HC_DD_REINIT, "WL_HC_DD_REINIT"},
	{WL_HC_DD_TXQ_STALL, "WL_HC_DD_TXQ_STALL"},
	{0, NULL}
};

hck_id_to_str_t hck_pcie_module_to_str[] = {
	{HEALTH_CHECK_PCIEDEV_INDUCED_IND, "PCIEDEV_INDUCED_IND"},
	{HEALTH_CHECK_PCIEDEV_H2D_DMA_IND, "PCIEDEV_H2D_DMA_IND"},
	{HEALTH_CHECK_PCIEDEV_D2H_DMA_IND, "PCIEDEV_D2H_DMA_IND"},
	{HEALTH_CHECK_PCIEDEV_IOCTL_STALL_IND, "PCIEDEV_IOCTL_STALL_IND"},
	{HEALTH_CHECK_PCIEDEV_D3ACK_STALL_IND, "PCIEDEV_D3ACK_STALL_IND"},
	{HEALTH_CHECK_PCIEDEV_NODS_IND, "PCIEDEV_NODS_IND"},
	{HEALTH_CHECK_PCIEDEV_LINKSPEED_FALLBACK_IND, "PCIEDEV_LINKSPEED_FALLBACK_IND"},
	{HEALTH_CHECK_PCIEDEV_DSACK_STALL_IND, "PCIEDEV_DSACK_STALL_IND"},
	{0, NULL}
};

hck_id_to_str_t hck_rx_stall_v2_to_str[] = {
	{BCM_RX_HC_RESERVED, "BCM_RX_HC_RESERVED"},
	{BCM_RX_HC_UNSPECIFIED, "BCM_RX_HC_UNSPECIFIED"},
	{BCM_RX_HC_UNICAST_DECRYPT_FAIL, "BCM_RX_HC_UNICAST_DECRYPT_FAIL"},
	{BCM_RX_HC_BCMC_DECRYPT_FAIL, "BCM_RX_HC_BCMC_DECRYPT_FAIL"},
	{BCM_RX_HC_UNICAST_REPLAY, "BCM_RX_HC_UNICAST_REPLAY"},
	{BCM_RX_HC_BCMC_REPLAY, "BCM_RX_HC_BCMC_REPLAY"},
	{BCM_RX_HC_AMPDU_DUP, "BCM_RX_HC_AMPDU_DUP"},
	{0, NULL}
};

static void
dhd_print_dongle_hck_id(uint32 id, hck_id_to_str_t *hck)
{
	while (hck->name != NULL) {
		if (hck->id == id) {
			DHD_ERROR(("DONGLE_HCK_EVENT: %s\n", hck->name));
			return;
		}
		hck++;
	}
}

void
dhd_parse_hck_common_sw_event(bcm_xtlv_t *wl_hc)
{

	wl_rx_hc_info_v2_t *hck_rx_stall_v2;
	uint16 id;

	id = ltoh16(wl_hc->id);

	if (id == WL_HC_DD_RX_STALL_V2) {
		/*  map the hck_rx_stall_v2 structure to the value of the XTLV */
		hck_rx_stall_v2 =
			(wl_rx_hc_info_v2_t*)wl_hc;
		DHD_ERROR(("type:%d len:%d if_idx:%d ac:%d pkts:%d"
			" drop:%d alert_th:%d reason:%d peer_ea:"MACF"\n",
			hck_rx_stall_v2->type,
			hck_rx_stall_v2->length,
			hck_rx_stall_v2->if_idx,
			hck_rx_stall_v2->ac,
			hck_rx_stall_v2->rx_hc_pkts,
			hck_rx_stall_v2->rx_hc_dropped_all,
			hck_rx_stall_v2->rx_hc_alert_th,
			hck_rx_stall_v2->reason,
			ETHER_TO_MACF(hck_rx_stall_v2->peer_ea)));
		dhd_print_dongle_hck_id(
				ltoh32(hck_rx_stall_v2->reason),
				hck_rx_stall_v2_to_str);
	} else {
		dhd_print_dongle_hck_id(ltoh16(wl_hc->id),
				hck_sw_id_to_str);
	}

}

#endif /* PARSE_DONGLE_HOST_EVENT */

void
dngl_host_event_process(dhd_pub_t *dhdp, bcm_dngl_event_t *event,
	bcm_dngl_event_msg_t *dngl_event, size_t pktlen)
{
	uint8 *p = (uint8 *)(event + 1);
	uint16 type = ntoh16_ua((void *)&dngl_event->event_type);
	uint16 datalen = ntoh16_ua((void *)&dngl_event->datalen);
	uint16 version = ntoh16_ua((void *)&dngl_event->version);

	DHD_EVENT(("VERSION:%d, EVENT TYPE:%d, DATALEN:%d\n", version, type, datalen));
	if (datalen > (pktlen - sizeof(bcm_dngl_event_t) + ETHER_TYPE_LEN)) {
		return;
	}
	if (version != BCM_DNGL_EVENT_MSG_VERSION) {
		DHD_ERROR(("%s:version mismatch:%d:%d\n", __FUNCTION__,
			version, BCM_DNGL_EVENT_MSG_VERSION));
		return;
	}
	switch (type) {
	   case DNGL_E_SOCRAM_IND:
		{
		   bcm_dngl_socramind_t *socramind_ptr = (bcm_dngl_socramind_t *)p;
		   uint16 tag = ltoh32(socramind_ptr->tag);
		   uint16 taglen = ltoh32(socramind_ptr->length);
		   p = (uint8 *)socramind_ptr->value;
		   DHD_EVENT(("Tag:%d Len:%d Datalen:%d\n", tag, taglen, datalen));
		   switch (tag) {
			case SOCRAM_IND_ASSERT_TAG:
			    {
				/*
				* The payload consists of -
				* null terminated function name padded till 32 bit boundary +
				* Line number - (32 bits)
				* Caller address (32 bits)
				*/
				char *fnname = (char *)p;
				if (datalen < (ROUNDUP(strlen(fnname) + 1, sizeof(uint32)) +
					sizeof(uint32) * 2)) {
					DHD_ERROR(("Wrong length:%d\n", datalen));
					return;
				}
				DHD_EVENT(("ASSRT Function:%s ", p));
				p += ROUNDUP(strlen(p) + 1, sizeof(uint32));
				DHD_EVENT(("Line:%d ", *(uint32 *)p));
				p += sizeof(uint32);
				DHD_EVENT(("Caller Addr:0x%x\n", *(uint32 *)p));
#ifdef PARSE_DONGLE_HOST_EVENT
				DHD_ERROR(("DONGLE_HCK_EVENT: SOCRAM_IND_ASSERT_TAG\n"));
#endif /* PARSE_DONGLE_HOST_EVENT */
				break;
			    }
			case SOCRAM_IND_TAG_HEALTH_CHECK:
			   {
				bcm_dngl_healthcheck_t *dngl_hc = (bcm_dngl_healthcheck_t *)p;
				DHD_EVENT(("SOCRAM_IND_HEALTHCHECK_TAG:%d Len:%d datalen:%d\n",
					ltoh32(dngl_hc->top_module_tag),
					ltoh32(dngl_hc->top_module_len),
					datalen));
				if (DHD_EVENT_ON()) {
					prhex("HEALTHCHECK", p, MIN(ltoh32(dngl_hc->top_module_len)
						+ BCM_XTLV_HDR_SIZE, datalen));
				}
#ifdef DHD_LOG_DUMP
				memset(dhdp->health_chk_event_data, 0, HEALTH_CHK_BUF_SIZE);
				memcpy(dhdp->health_chk_event_data, p,
						MIN(ltoh32(dngl_hc->top_module_len),
						HEALTH_CHK_BUF_SIZE));
#endif /* DHD_LOG_DUMP */
				p = (uint8 *)dngl_hc->value;

				switch (ltoh32(dngl_hc->top_module_tag)) {
					case HEALTH_CHECK_TOP_LEVEL_MODULE_PCIEDEV_RTE:
					   {
						bcm_dngl_pcie_hc_t *pcie_hc;
						pcie_hc = (bcm_dngl_pcie_hc_t *)p;
						BCM_REFERENCE(pcie_hc);
						if (ltoh32(dngl_hc->top_module_len) <
								sizeof(bcm_dngl_pcie_hc_t)) {
							DHD_ERROR(("Wrong length:%d\n",
								ltoh32(dngl_hc->top_module_len)));
							return;
						}
						DHD_EVENT(("%d:PCIE HC error:%d flag:0x%x,"
							" control:0x%x\n",
							ltoh32(pcie_hc->version),
							ltoh32(pcie_hc->pcie_err_ind_type),
							ltoh32(pcie_hc->pcie_flag),
							ltoh32(pcie_hc->pcie_control_reg)));
#ifdef PARSE_DONGLE_HOST_EVENT
						dhd_print_dongle_hck_id(
							ltoh32(pcie_hc->pcie_err_ind_type),
								hck_pcie_module_to_str);
#endif /* PARSE_DONGLE_HOST_EVENT */
						break;
					   }
#ifdef HCHK_COMMON_SW_EVENT
					case HCHK_SW_ENTITY_WL_PRIMARY:
					case HCHK_SW_ENTITY_WL_SECONDARY:
					{
						bcm_xtlv_t *wl_hc = (bcm_xtlv_t*)p;

						if (ltoh32(dngl_hc->top_module_len) <
								sizeof(bcm_xtlv_t)) {
							DHD_ERROR(("WL SW HC Wrong length:%d\n",
								ltoh32(dngl_hc->top_module_len)));
							return;
						}
						BCM_REFERENCE(wl_hc);
						DHD_EVENT(("WL SW HC type %d len %d\n",
						ltoh16(wl_hc->id), ltoh16(wl_hc->len)));

#ifdef PARSE_DONGLE_HOST_EVENT
						dhd_parse_hck_common_sw_event(wl_hc);
#endif /* PARSE_DONGLE_HOST_EVENT */
						break;

					}
#endif /* HCHK_COMMON_SW_EVENT */
					default:
					{
						DHD_ERROR(("%s:Unknown module TAG:%d\n",
						  __FUNCTION__,
						  ltoh32(dngl_hc->top_module_tag)));
						break;
					}
				}
				break;
			   }
			default:
			   DHD_ERROR(("%s:Unknown TAG\n", __FUNCTION__));
			   if (p && DHD_EVENT_ON()) {
				   prhex("SOCRAMIND", p, taglen);
			   }
			   break;
		   }
		   break;
		}
	   default:
		DHD_ERROR(("%s:Unknown DNGL Event Type:%d\n", __FUNCTION__, type));
		if (p && DHD_EVENT_ON()) {
			prhex("SOCRAMIND", p, datalen);
		}
		break;
	}
#ifndef BCMDBUS
#ifdef DHD_FW_COREDUMP
	if (dhdp->memdump_enabled) {
		dhdp->memdump_type = DUMP_TYPE_DONGLE_HOST_EVENT;
		if (dhd_socram_dump(dhdp->bus)) {
			DHD_ERROR(("%s: socram dump failed\n", __FUNCTION__));
		}
	}
#else
	dhd_dbg_send_urgent_evt(dhdp, p, datalen);
#endif /* DHD_FW_COREDUMP */
#endif /* !BCMDBUS */
}

#endif /* DNGL_EVENT_SUPPORT */

/* Stub for now. Will become real function as soon as shim
 * is being integrated to Android, Linux etc.
 */
int
wl_event_process_default(wl_event_msg_t *event, struct wl_evt_pport *evt_pport)
{
	return BCME_OK;
}

int
wl_event_process(dhd_pub_t *dhd_pub, int *ifidx, void *pktdata,
	uint pktlen, void **data_ptr, void *raw_event)
{
	wl_evt_pport_t evt_pport;
	wl_event_msg_t event;
	bcm_event_msg_u_t evu;
	int ret;

	/* make sure it is a BRCM event pkt and record event data */
	ret = wl_host_event_get_data(pktdata, pktlen, &evu);
	if (ret != BCME_OK) {
		return ret;
	}

	memcpy(&event, &evu.event, sizeof(wl_event_msg_t));

	/* convert event from network order to host order */
	wl_event_to_host_order(&event);

	/* record event params to evt_pport */
	evt_pport.dhd_pub = dhd_pub;
	evt_pport.ifidx = ifidx;
	evt_pport.pktdata = pktdata;
	evt_pport.data_ptr = data_ptr;
	evt_pport.raw_event = raw_event;
	evt_pport.data_len = pktlen;

	ret = wl_event_process_default(&event, &evt_pport);

	return ret;
} /* wl_event_process */

/* Check whether packet is a BRCM event pkt. If it is, record event data. */
int
wl_host_event_get_data(void *pktdata, uint pktlen, bcm_event_msg_u_t *evu)
{
	int ret;

	ret = is_wlc_event_frame(pktdata, pktlen, 0, evu);
	if (ret != BCME_OK) {
		DHD_ERROR(("%s: Invalid event frame, err = %d\n",
			__FUNCTION__, ret));
	}

	return ret;
}

int
wl_process_host_event(dhd_pub_t *dhd_pub, int *ifidx, void *pktdata, uint pktlen,
	wl_event_msg_t *event, void **data_ptr, void *raw_event)
{
	bcm_event_t *pvt_data = (bcm_event_t *)pktdata;
	bcm_event_msg_u_t evu;
	uint8 *event_data;
	uint32 type, status, datalen, reason;
	uint16 flags;
	uint evlen;
	int ret;
	uint16 usr_subtype;
#ifdef DHD_POST_EAPOL_M1_AFTER_ROAM_EVT
	dhd_if_t *ifp = NULL;
#endif /* DHD_POST_EAPOL_M1_AFTER_ROAM_EVT */

	ret = wl_host_event_get_data(pktdata, pktlen, &evu);
	if (ret != BCME_OK) {
		return ret;
	}

	usr_subtype = ntoh16_ua((void *)&pvt_data->bcm_hdr.usr_subtype);
	switch (usr_subtype) {
	case BCMILCP_BCM_SUBTYPE_EVENT:
		memcpy(event, &evu.event, sizeof(wl_event_msg_t));
		*data_ptr = &pvt_data[1];
		break;
	case BCMILCP_BCM_SUBTYPE_DNGLEVENT:
#ifdef DNGL_EVENT_SUPPORT
		/* If it is a DNGL event process it first */
		if (dngl_host_event(dhd_pub, pktdata, &evu.dngl_event, pktlen) == BCME_OK) {
			/*
			 * Return error purposely to prevent DNGL event being processed
			 * as BRCM event
			 */
			return BCME_ERROR;
		}
#endif /* DNGL_EVENT_SUPPORT */
		return BCME_NOTFOUND;
	default:
		return BCME_NOTFOUND;
	}

	/* start wl_event_msg process */
	event_data = *data_ptr;
	type = ntoh32_ua((void *)&event->event_type);
	flags = ntoh16_ua((void *)&event->flags);
	status = ntoh32_ua((void *)&event->status);
	reason = ntoh32_ua((void *)&event->reason);
	datalen = ntoh32_ua((void *)&event->datalen);
	evlen = datalen + sizeof(bcm_event_t);

	switch (type) {
#ifdef PROP_TXSTATUS
	case WLC_E_FIFO_CREDIT_MAP:
		dhd_wlfc_enable(dhd_pub);
		dhd_wlfc_FIFOcreditmap_event(dhd_pub, event_data);
		WLFC_DBGMESG(("WLC_E_FIFO_CREDIT_MAP:(AC0,AC1,AC2,AC3),(BC_MC),(OTHER): "
			"(%d,%d,%d,%d),(%d),(%d)\n", event_data[0], event_data[1],
			event_data[2],
			event_data[3], event_data[4], event_data[5]));
		break;

	case WLC_E_BCMC_CREDIT_SUPPORT:
		dhd_wlfc_BCMCCredit_support_event(dhd_pub);
		break;
#ifdef LIMIT_BORROW
	case WLC_E_ALLOW_CREDIT_BORROW:
		dhd_wlfc_disable_credit_borrow_event(dhd_pub, event_data);
		break;
#endif /* LIMIT_BORROW */
#endif /* PROP_TXSTATUS */

	case WLC_E_ULP:
#ifdef DHD_ULP
	{
		wl_ulp_event_t *ulp_evt = (wl_ulp_event_t *)event_data;

		/* Flush and disable console messages */
		if (ulp_evt->ulp_dongle_action == WL_ULP_DISABLE_CONSOLE) {
#ifdef DHD_ULP_NOT_USED
			dhd_bus_ulp_disable_console(dhd_pub);
#endif /* DHD_ULP_NOT_USED */
		}
		if (ulp_evt->ulp_dongle_action == WL_ULP_UCODE_DOWNLOAD) {
			dhd_bus_ucode_download(dhd_pub->bus);
		}
	}
#endif /* DHD_ULP */
		break;
	case WLC_E_TDLS_PEER_EVENT:
#if defined(WLTDLS) && defined(PCIE_FULL_DONGLE)
		{
			dhd_tdls_event_handler(dhd_pub, event);
		}
#endif // endif
		break;

	case WLC_E_IF:
		{
		struct wl_event_data_if *ifevent = (struct wl_event_data_if *)event_data;

		/* Ignore the event if NOIF is set */
		if (ifevent->reserved & WLC_E_IF_FLAGS_BSSCFG_NOIF) {
			DHD_ERROR(("WLC_E_IF: NO_IF set, event Ignored\r\n"));
			return (BCME_UNSUPPORTED);
		}
#ifdef PCIE_FULL_DONGLE
		dhd_update_interface_flow_info(dhd_pub, ifevent->ifidx,
			ifevent->opcode, ifevent->role);
#endif // endif
#ifdef PROP_TXSTATUS
		{
			uint8* ea = pvt_data->eth.ether_dhost;
			WLFC_DBGMESG(("WLC_E_IF: idx:%d, action:%s, iftype:%s, ["MACDBG"]\n"
						  ifevent->ifidx,
						  ((ifevent->opcode == WLC_E_IF_ADD) ? "ADD":"DEL"),
						  ((ifevent->role == 0) ? "STA":"AP "),
						  MAC2STRDBG(ea)));
			(void)ea;

			if (ifevent->opcode == WLC_E_IF_CHANGE)
				dhd_wlfc_interface_event(dhd_pub,
					eWLFC_MAC_ENTRY_ACTION_UPDATE,
					ifevent->ifidx, ifevent->role, ea);
			else
				dhd_wlfc_interface_event(dhd_pub,
					((ifevent->opcode == WLC_E_IF_ADD) ?
					eWLFC_MAC_ENTRY_ACTION_ADD : eWLFC_MAC_ENTRY_ACTION_DEL),
					ifevent->ifidx, ifevent->role, ea);

			/* dhd already has created an interface by default, for 0 */
			if (ifevent->ifidx == 0)
				break;
		}
#endif /* PROP_TXSTATUS */

		if (ifevent->ifidx > 0 && ifevent->ifidx < DHD_MAX_IFS) {
			if (ifevent->opcode == WLC_E_IF_ADD) {
				if (dhd_event_ifadd(dhd_pub->info, ifevent, event->ifname,
					event->addr.octet)) {

					DHD_ERROR(("%s: dhd_event_ifadd failed ifidx: %d  %s\n",
						__FUNCTION__, ifevent->ifidx, event->ifname));
					return (BCME_ERROR);
				}
			} else if (ifevent->opcode == WLC_E_IF_DEL) {
#ifdef PCIE_FULL_DONGLE
				/* Delete flowrings unconditionally for i/f delete */
				dhd_flow_rings_delete(dhd_pub, (uint8)dhd_ifname2idx(dhd_pub->info,
					event->ifname));
#endif /* PCIE_FULL_DONGLE */
				dhd_event_ifdel(dhd_pub->info, ifevent, event->ifname,
					event->addr.octet);
			} else if (ifevent->opcode == WLC_E_IF_CHANGE) {
#ifdef WL_CFG80211
				dhd_event_ifchange(dhd_pub->info, ifevent, event->ifname,
					event->addr.octet);
#endif /* WL_CFG80211 */
			}
		} else {
#if !defined(PROP_TXSTATUS) && !defined(PCIE_FULL_DONGLE) && defined(WL_CFG80211)
			DHD_INFO(("%s: Invalid ifidx %d for %s\n",
			   __FUNCTION__, ifevent->ifidx, event->ifname));
#endif /* !PROP_TXSTATUS && !PCIE_FULL_DONGLE && WL_CFG80211 */
		}
			/* send up the if event: btamp user needs it */
			*ifidx = dhd_ifname2idx(dhd_pub->info, event->ifname);
			/* push up to external supp/auth */
			dhd_event(dhd_pub->info, (char *)pvt_data, evlen, *ifidx);
		break;
	}

	case WLC_E_NDIS_LINK:
		break;
	case WLC_E_PFN_NET_FOUND:
	case WLC_E_PFN_SCAN_ALLGONE: /* share with WLC_E_PFN_BSSID_NET_LOST */
	case WLC_E_PFN_NET_LOST:
		break;
#if defined(PNO_SUPPORT)
	case WLC_E_PFN_BSSID_NET_FOUND:
	case WLC_E_PFN_BEST_BATCHING:
		dhd_pno_event_handler(dhd_pub, event, (void *)event_data);
		break;
#endif // endif
#if defined(RTT_SUPPORT)
	case WLC_E_PROXD:
#ifndef WL_CFG80211
		dhd_rtt_event_handler(dhd_pub, event, (void *)event_data);
#endif /* WL_CFG80211 */
		break;
#endif /* RTT_SUPPORT */
		/* These are what external supplicant/authenticator wants */
	case WLC_E_ASSOC_IND:
	case WLC_E_AUTH_IND:
	case WLC_E_REASSOC_IND:
		dhd_findadd_sta(dhd_pub,
			dhd_ifname2idx(dhd_pub->info, event->ifname),
			&event->addr.octet);
		break;
#ifndef BCMDBUS
#if defined(DHD_FW_COREDUMP)
	case WLC_E_PSM_WATCHDOG:
		DHD_ERROR(("%s: WLC_E_PSM_WATCHDOG event received : \n", __FUNCTION__));
		if (dhd_socram_dump(dhd_pub->bus) != BCME_OK) {
			DHD_ERROR(("%s: socram dump ERROR : \n", __FUNCTION__));
		}
	break;
#endif // endif
#endif /* !BCMDBUS */

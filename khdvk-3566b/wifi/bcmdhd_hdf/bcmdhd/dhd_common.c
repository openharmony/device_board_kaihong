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

/*
 * Broadcom Dongle Host Driver (DHD), RTT
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
 * $Id$
 */
#include <typedefs.h>
#include <osl.h>

#include <epivers.h>
#include <bcmutils.h>

#include <bcmendian.h>
#include <linuxver.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/sort.h>
#include <dngl_stats.h>
#include <wlioctl.h>
#include <bcmwifi_rspec.h>

#include <bcmevent.h>
#include <dhd.h>
#include <dhd_rtt.h>
#include <dhd_dbg.h>
#include <dhd_bus.h>
#include <wldev_common.h>
#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#endif /* WL_CFG80211 */
#ifdef WL_NAN
#include <wl_cfgnan.h>
#endif /* WL_NAN */

static DEFINE_SPINLOCK(noti_list_lock);
#define NULL_CHECK(p, s, err)  \
			do { \
				if (!(p)) { \
					printf("NULL POINTER (%s) : %s\n", __FUNCTION__, (s)); \
					err = BCME_ERROR; \
					return err; \
				} \
			} while (0)

#define TIMESPEC_TO_US(ts)  (((uint64)(ts).tv_sec * USEC_PER_SEC) + \
							(ts).tv_nsec / NSEC_PER_USEC)

#undef DHD_RTT_MEM
#undef DHD_RTT_ERR
#define DHD_RTT_MEM DHD_LOG_MEM
#define DHD_RTT_ERR DHD_ERROR

#define FTM_IOC_BUFSZ  2048	/* ioc buffsize for our module (> BCM_XTLV_HDR_SIZE) */
#define FTM_AVAIL_MAX_SLOTS		32
#define FTM_MAX_CONFIGS 10
#define FTM_MAX_PARAMS 10
#define FTM_DEFAULT_SESSION 1
#define FTM_BURST_TIMEOUT_UNIT 250 /* 250 ns */
#define FTM_INVALID -1
#define	FTM_DEFAULT_CNT_20M		24u
#define FTM_DEFAULT_CNT_40M		16u
#define FTM_DEFAULT_CNT_80M		11u
/* To handle congestion env, set max dur/timeout */
#define FTM_MAX_BURST_DUR_TMO_MS	128u

/* convenience macros */
#define FTM_TU2MICRO(_tu) ((uint64)(_tu) << 10)
#define FTM_MICRO2TU(_tu) ((uint64)(_tu) >> 10)
#define FTM_TU2MILLI(_tu) ((uint32)FTM_TU2MICRO(_tu) / 1000)
#define FTM_MICRO2MILLI(_x) ((uint32)(_x) / 1000)
#define FTM_MICRO2SEC(_x) ((uint32)(_x) / 1000000)
#define FTM_INTVL2NSEC(_intvl) ((uint32)ftm_intvl2nsec(_intvl))
#define FTM_INTVL2USEC(_intvl) ((uint32)ftm_intvl2usec(_intvl))
#define FTM_INTVL2MSEC(_intvl) (FTM_INTVL2USEC(_intvl) / 1000)
#define FTM_INTVL2SEC(_intvl) (FTM_INTVL2USEC(_intvl) / 1000000)
#define FTM_USECIN100MILLI(_usec) ((_usec) / 100000)

/* broadcom specific set to have more accurate data */
#define ENABLE_VHT_ACK
#define CH_MIN_5G_CHANNEL 34

/* CUR ETH became obsolete with this major version onwards */
#define RTT_IOV_CUR_ETH_OBSOLETE 12

/* PROXD TIMEOUT */
#define DHD_RTT_TIMER_INTERVAL_MS	5000u
#define DHD_NAN_RTT_TIMER_INTERVAL_MS	20000u

struct rtt_noti_callback {
	struct list_head list;
	void *ctx;
	dhd_rtt_compl_noti_fn noti_fn;
};

/* bitmask indicating which command groups; */
typedef enum {
	FTM_SUBCMD_FLAG_METHOD	= 0x01,	/* FTM method command */
	FTM_SUBCMD_FLAG_SESSION = 0x02,	/* FTM session command */
	FTM_SUBCMD_FLAG_ALL = FTM_SUBCMD_FLAG_METHOD | FTM_SUBCMD_FLAG_SESSION
} ftm_subcmd_flag_t;

/* proxd ftm config-category definition */
typedef enum {
	FTM_CONFIG_CAT_GENERAL = 1,	/* generial configuration */
	FTM_CONFIG_CAT_OPTIONS = 2,	/* 'config options' */
	FTM_CONFIG_CAT_AVAIL = 3,	/* 'config avail' */
} ftm_config_category_t;

typedef struct ftm_subcmd_info {
	int16				version;    /* FTM version (optional) */
	char				*name;		/* cmd-name string as cmdline input */
	wl_proxd_cmd_t		cmdid;		/* cmd-id */
	bcm_xtlv_unpack_cbfn_t *handler;  /* cmd response handler (optional) */
	ftm_subcmd_flag_t	cmdflag; /* CMD flag (optional)  */
} ftm_subcmd_info_t;

typedef struct ftm_config_options_info {
	uint32 flags;				/* wl_proxd_flags_t/wl_proxd_session_flags_t */
	bool enable;
} ftm_config_options_info_t;

typedef struct ftm_config_param_info {
	uint16		tlvid;	/* mapping TLV id for the item */
	union {
		uint32  chanspec;
		struct ether_addr mac_addr;
		wl_proxd_intvl_t data_intvl;
		uint32 data32;
		uint16 data16;
		uint8 data8;
		uint32 event_mask;
	};
} ftm_config_param_info_t;

/*
* definition for id-string mapping.
*   This is used to map an id (can be cmd-id, tlv-id, ....) to a text-string
*   for debug-display or cmd-log-display
*/
typedef struct ftm_strmap_entry {
	int32		id;
	char		*text;
} ftm_strmap_entry_t;

typedef struct ftm_status_map_host_entry {
	wl_proxd_status_t proxd_status;
	rtt_reason_t rtt_reason;
} ftm_status_map_host_entry_t;

static uint16
rtt_result_ver(uint16 tlvid, const uint8 *p_data);

static int
dhd_rtt_convert_results_to_host_v1(rtt_result_t *rtt_result, const uint8 *p_data,
	uint16 tlvid, uint16 len);

static int
dhd_rtt_convert_results_to_host_v2(rtt_result_t *rtt_result, const uint8 *p_data,
	uint16 tlvid, uint16 len);

static wifi_rate_t
dhd_rtt_convert_rate_to_host(uint32 ratespec);

#if defined(WL_CFG80211) && defined(RTT_DEBUG)
const char *
ftm_cmdid_to_str(uint16 cmdid);
#endif /* WL_CFG80211 && RTT_DEBUG */

#ifdef WL_CFG80211
static int
dhd_rtt_start(dhd_pub_t *dhd);
static int dhd_rtt_create_failure_result(rtt_status_info_t *rtt_status,
	struct ether_addr *addr);
static void dhd_rtt_handle_rtt_session_end(dhd_pub_t *dhd);
static void dhd_rtt_timeout_work(struct work_struct *work);
#endif /* WL_CFG80211 */
static const int burst_duration_idx[]  = {0, 0, 1, 2, 4, 8, 16, 32, 64, 128, 0, 0};

/* ftm status mapping to host status */
static const ftm_status_map_host_entry_t ftm_status_map_info[] = {
	{WL_PROXD_E_INCOMPLETE, RTT_STATUS_FAILURE},
	{WL_PROXD_E_OVERRIDDEN, RTT_STATUS_FAILURE},
	{WL_PROXD_E_ASAP_FAILED, RTT_STATUS_FAILURE},
	{WL_PROXD_E_NOTSTARTED, RTT_STATUS_FAIL_NOT_SCHEDULED_YET},
	{WL_PROXD_E_INVALIDMEAS, RTT_STATUS_FAIL_INVALID_TS},
	{WL_PROXD_E_INCAPABLE, RTT_STATUS_FAIL_NO_CAPABILITY},
	{WL_PROXD_E_MISMATCH, RTT_STATUS_FAILURE},
	{WL_PROXD_E_DUP_SESSION, RTT_STATUS_FAILURE},
	{WL_PROXD_E_REMOTE_FAIL, RTT_STATUS_FAILURE},
	{WL_PROXD_E_REMOTE_INCAPABLE, RTT_STATUS_FAILURE},
	{WL_PROXD_E_SCHED_FAIL, RTT_STATUS_FAIL_SCHEDULE},
	{WL_PROXD_E_PROTO, RTT_STATUS_FAIL_PROTOCOL},
	{WL_PROXD_E_EXPIRED, RTT_STATUS_FAILURE},
	{WL_PROXD_E_TIMEOUT, RTT_STATUS_FAIL_TM_TIMEOUT},
	{WL_PROXD_E_NOACK, RTT_STATUS_FAIL_NO_RSP},
	{WL_PROXD_E_DEFERRED, RTT_STATUS_FAILURE},
	{WL_PROXD_E_INVALID_SID, RTT_STATUS_FAILURE},
	{WL_PROXD_E_REMOTE_CANCEL, RTT_STATUS_FAILURE},
	{WL_PROXD_E_CANCELED, RTT_STATUS_ABORTED},
	{WL_PROXD_E_INVALID_SESSION, RTT_STATUS_FAILURE},
	{WL_PROXD_E_BAD_STATE, RTT_STATUS_FAILURE},
	{WL_PROXD_E_ERROR, RTT_STATUS_FAILURE},
	{WL_PROXD_E_OK, RTT_STATUS_SUCCESS}
};

static const ftm_strmap_entry_t ftm_event_type_loginfo[] = {
	/* wl_proxd_event_type_t,		text-string */
	{ WL_PROXD_EVENT_NONE,			"none" },
	{ WL_PROXD_EVENT_SESSION_CREATE,	"session create" },
	{ WL_PROXD_EVENT_SESSION_START,		"session start" },
	{ WL_PROXD_EVENT_FTM_REQ,		"FTM req" },
	{ WL_PROXD_EVENT_BURST_START,		"burst start" },
	{ WL_PROXD_EVENT_BURST_END,		"burst end" },
	{ WL_PROXD_EVENT_SESSION_END,		"session end" },
	{ WL_PROXD_EVENT_SESSION_RESTART,	"session restart" },
	{ WL_PROXD_EVENT_BURST_RESCHED,		"burst rescheduled" },
	{ WL_PROXD_EVENT_SESSION_DESTROY,	"session destroy" },
	{ WL_PROXD_EVENT_RANGE_REQ,		"range request" },
	{ WL_PROXD_EVENT_FTM_FRAME,		"FTM frame" },
	{ WL_PROXD_EVENT_DELAY,			"delay" },
	{ WL_PROXD_EVENT_VS_INITIATOR_RPT,	"initiator-report " }, /* rx initiator-rpt */
	{ WL_PROXD_EVENT_RANGING,		"ranging " },
	{ WL_PROXD_EVENT_COLLECT,		"collect" },
	{ WL_PROXD_EVENT_MF_STATS,		"mf_stats" },
};

/*
* session-state --> text string mapping
*/
static const ftm_strmap_entry_t ftm_session_state_value_loginfo[] = {
	/* wl_proxd_session_state_t,		text string */
	{ WL_PROXD_SESSION_STATE_CREATED,	"created" },
	{ WL_PROXD_SESSION_STATE_CONFIGURED,	"configured" },
	{ WL_PROXD_SESSION_STATE_STARTED,	"started" },
	{ WL_PROXD_SESSION_STATE_DELAY,		"delay" },
	{ WL_PROXD_SESSION_STATE_USER_WAIT,	"user-wait" },
	{ WL_PROXD_SESSION_STATE_SCHED_WAIT,	"sched-wait" },
	{ WL_PROXD_SESSION_STATE_BURST,		"burst" },
	{ WL_PROXD_SESSION_STATE_STOPPING,	"stopping" },
	{ WL_PROXD_SESSION_STATE_ENDED,		"ended" },
	{ WL_PROXD_SESSION_STATE_DESTROYING,	"destroying" },
	{ WL_PROXD_SESSION_STATE_NONE,		"none" }
};

/*
* status --> text string mapping
*/
static const ftm_strmap_entry_t ftm_status_value_loginfo[] = {
	/* wl_proxd_status_t,			text-string */
	{ WL_PROXD_E_OVERRIDDEN,		"overridden" },
	{ WL_PROXD_E_ASAP_FAILED,		"ASAP failed" },
	{ WL_PROXD_E_NOTSTARTED,		"not started" },
	{ WL_PROXD_E_INVALIDMEAS,		"invalid measurement" },
	{ WL_PROXD_E_INCAPABLE,			"incapable" },
	{ WL_PROXD_E_MISMATCH,			"mismatch"},
	{ WL_PROXD_E_DUP_SESSION,		"dup session" },
	{ WL_PROXD_E_REMOTE_FAIL,		"remote fail" },
	{ WL_PROXD_E_REMOTE_INCAPABLE,		"remote incapable" },
	{ WL_PROXD_E_SCHED_FAIL,		"sched failure" },
	{ WL_PROXD_E_PROTO,			"protocol error" },
	{ WL_PROXD_E_EXPIRED,			"expired" },
	{ WL_PROXD_E_TIMEOUT,			"timeout" },
	{ WL_PROXD_E_NOACK,			"no ack" },
	{ WL_PROXD_E_DEFERRED,			"deferred" },
	{ WL_PROXD_E_INVALID_SID,		"invalid session id" },
	{ WL_PROXD_E_REMOTE_CANCEL,		"remote cancel" },
	{ WL_PROXD_E_CANCELED,			"canceled" },
	{ WL_PROXD_E_INVALID_SESSION,		"invalid session" },
	{ WL_PROXD_E_BAD_STATE,			"bad state" },
	{ WL_PROXD_E_ERROR,			"error" },
	{ WL_PROXD_E_OK,			"OK" }
};

/*
* time interval unit --> text string mapping
*/
static const ftm_strmap_entry_t ftm_tmu_value_loginfo[] = {
	/* wl_proxd_tmu_t,		text-string */
	{ WL_PROXD_TMU_TU,		"TU" },
	{ WL_PROXD_TMU_SEC,		"sec" },
	{ WL_PROXD_TMU_MILLI_SEC,	"ms" },
	{ WL_PROXD_TMU_MICRO_SEC,	"us" },
	{ WL_PROXD_TMU_NANO_SEC,	"ns" },
	{ WL_PROXD_TMU_PICO_SEC,	"ps" }
};

struct ieee_80211_mcs_rate_info {
	uint8 constellation_bits;
	uint8 coding_q;
	uint8 coding_d;
};

static const struct ieee_80211_mcs_rate_info wl_mcs_info[] = {
	{ 1, 1, 2 }, /* MCS  0: MOD: BPSK,   CR 1/2 */
	{ 2, 1, 2 }, /* MCS  1: MOD: QPSK,   CR 1/2 */
	{ 2, 3, 4 }, /* MCS  2: MOD: QPSK,   CR 3/4 */
	{ 4, 1, 2 }, /* MCS  3: MOD: 16QAM,  CR 1/2 */
	{ 4, 3, 4 }, /* MCS  4: MOD: 16QAM,  CR 3/4 */
	{ 6, 2, 3 }, /* MCS  5: MOD: 64QAM,  CR 2/3 */
	{ 6, 3, 4 }, /* MCS  6: MOD: 64QAM,  CR 3/4 */
	{ 6, 5, 6 }, /* MCS  7: MOD: 64QAM,  CR 5/6 */
	{ 8, 3, 4 }, /* MCS  8: MOD: 256QAM, CR 3/4 */
	{ 8, 5, 6 }  /* MCS  9: MOD: 256QAM, CR 5/6 */
};

/**
 * Returns the rate in [Kbps] units for a caller supplied MCS/bandwidth/Nss/Sgi combination.
 *     'mcs' : a *single* spatial stream MCS (11n or 11ac)
 */
uint
rate_mcs2rate(uint mcs, uint nss, uint bw, int sgi)
{
	const int ksps = 250; /* kilo symbols per sec, 4 us sym */
	const int Nsd_20MHz = 52;
	const int Nsd_40MHz = 108;
	const int Nsd_80MHz = 234;
	const int Nsd_160MHz = 468;
	uint rate;

	if (mcs == 32) {
		/* just return fixed values for mcs32 instead of trying to parametrize */
		rate = (sgi == 0) ? 6000 : 6778;
	} else if (mcs <= 9) {
		/* This calculation works for 11n HT and 11ac VHT if the HT mcs values
		 * are decomposed into a base MCS = MCS % 8, and Nss = 1 + MCS / 8.
		 * That is, HT MCS 23 is a base MCS = 7, Nss = 3
		 */

		/* find the number of complex numbers per symbol */
		if (RSPEC_IS20MHZ(bw)) {
			rate = Nsd_20MHz;
		} else if (RSPEC_IS40MHZ(bw)) {
			rate = Nsd_40MHz;
		} else if (bw == WL_RSPEC_BW_80MHZ) {
			rate = Nsd_80MHz;
		} else if (bw == WL_RSPEC_BW_160MHZ) {
			rate = Nsd_160MHz;
		} else {
			rate = 0;
		}

		/* multiply by bits per number from the constellation in use */
		rate = rate * wl_mcs_info[mcs].constellation_bits;

		/* adjust for the number of spatial streams */
		rate = rate * nss;

		/* adjust for the coding rate given as a quotient and divisor */
		rate = (rate * wl_mcs_info[mcs].coding_q) / wl_mcs_info[mcs].coding_d;

		/* multiply by Kilo symbols per sec to get Kbps */
		rate = rate * ksps;

		/* adjust the symbols per sec for SGI
		 * symbol duration is 4 us without SGI, and 3.6 us with SGI,
		 * so ratio is 10 / 9
		 */
		if (sgi) {
			/* add 4 for rounding of division by 9 */
			rate = ((rate * 10) + 4) / 9;
		}
	} else {
		rate = 0;
	}

	return rate;
} /* wlc_rate_mcs2rate */

/** take a well formed ratespec_t arg and return phy rate in [Kbps] units */
static uint32
rate_rspec2rate(uint32 rspec)
{
	int rate = 0;

	if (RSPEC_ISLEGACY(rspec)) {
		rate = 500 * (rspec & WL_RSPEC_RATE_MASK);
	} else if (RSPEC_ISHT(rspec)) {
		uint mcs = (rspec & WL_RSPEC_RATE_MASK);

		if (mcs == 32) {
			rate = rate_mcs2rate(mcs, 1, WL_RSPEC_BW_40MHZ, RSPEC_ISSGI(rspec));
		} else {
			uint nss = 1 + (mcs / 8);
			mcs = mcs % 8;
			rate = rate_mcs2rate(mcs, nss, RSPEC_BW(rspec), RSPEC_ISSGI(rspec));
		}
	} else if (RSPEC_ISVHT(rspec)) {
		uint mcs = (rspec & WL_RSPEC_VHT_MCS_MASK);
		uint nss = (rspec & WL_RSPEC_VHT_NSS_MASK) >> WL_RSPEC_VHT_NSS_SHIFT;
		if (mcs > 9 || nss > 8) {
			DHD_RTT(("%s: Invalid mcs %d or nss %d\n", __FUNCTION__, mcs, nss));
			goto exit;
		}

		rate = rate_mcs2rate(mcs, nss, RSPEC_BW(rspec), RSPEC_ISSGI(rspec));
	} else {
		DHD_RTT(("%s: wrong rspec:%d\n", __FUNCTION__, rspec));
	}
exit:
	return rate;
}

char resp_buf[WLC_IOCTL_SMLEN];

static uint64
ftm_intvl2nsec(const wl_proxd_intvl_t *intvl)
{
	uint64 ret;
	ret = intvl->intvl;
	switch (intvl->tmu) {
	case WL_PROXD_TMU_TU:			ret = FTM_TU2MICRO(ret) * 1000; break;
	case WL_PROXD_TMU_SEC:			ret *= 1000000000; break;
	case WL_PROXD_TMU_MILLI_SEC:	ret *= 1000000; break;
	case WL_PROXD_TMU_MICRO_SEC:	ret *= 1000; break;
	case WL_PROXD_TMU_PICO_SEC:		ret = intvl->intvl / 1000; break;
	case WL_PROXD_TMU_NANO_SEC:		/* fall through */
	default:						break;
	}
	return ret;
}
uint64
ftm_intvl2usec(const wl_proxd_intvl_t *intvl)
{
	uint64 ret;
	ret = intvl->intvl;
	switch (intvl->tmu) {
	case WL_PROXD_TMU_TU:			ret = FTM_TU2MICRO(ret); break;
	case WL_PROXD_TMU_SEC:			ret *= 1000000; break;
	case WL_PROXD_TMU_NANO_SEC:		ret = intvl->intvl / 1000; break;
	case WL_PROXD_TMU_PICO_SEC:		ret = intvl->intvl / 1000000; break;
	case WL_PROXD_TMU_MILLI_SEC:	ret *= 1000; break;
	case WL_PROXD_TMU_MICRO_SEC:	/* fall through */
	default:						break;
	}
	return ret;
}

/*
* lookup 'id' (as a key) from a fw status to host map table
* if found, return the corresponding reason code
*/

static rtt_reason_t
ftm_get_statusmap_info(wl_proxd_status_t id, const ftm_status_map_host_entry_t *p_table,
	uint32 num_entries)
{
	int i;
	const ftm_status_map_host_entry_t *p_entry;
	/* scan thru the table till end */
	p_entry = p_table;
	for (i = 0; i < (int) num_entries; i++)
	{
		if (p_entry->proxd_status == id) {
			return p_entry->rtt_reason;
		}
		p_entry++;		/* next entry */
	}
	return RTT_STATUS_FAILURE; /* not found */
}
/*
* lookup 'id' (as a key) from a table
* if found, return the entry pointer, otherwise return NULL
*/
static const ftm_strmap_entry_t*
ftm_get_strmap_info(int32 id, const ftm_strmap_entry_t *p_table, uint32 num_entries)
{
	int i;
	const ftm_strmap_entry_t *p_entry;

	/* scan thru the table till end */
	p_entry = p_table;
	for (i = 0; i < (int) num_entries; i++)
	{
		if (p_entry->id == id)
			return p_entry;
		p_entry++;		/* next entry */
	}
	return NULL;			/* not found */
}

/*
* map enum to a text-string for display, this function is called by the following:
* For debug/trace:
*     ftm_[cmdid|tlvid]_to_str()
* For TLV-output log for 'get' commands
*     ftm_[method|tmu|caps|status|state]_value_to_logstr()
* Input:
*     pTable -- point to a 'enum to string' table.
*/
static const char *
ftm_map_id_to_str(int32 id, const ftm_strmap_entry_t *p_table, uint32 num_entries)
{
	const ftm_strmap_entry_t*p_entry = ftm_get_strmap_info(id, p_table, num_entries);
	if (p_entry)
		return (p_entry->text);

	return "invalid";
}

#if defined(WL_CFG80211) && defined(RTT_DEBUG)
/* define entry, e.g. { WL_PROXD_CMD_xxx, "WL_PROXD_CMD_xxx" } */
#define DEF_STRMAP_ENTRY(id) { (id), #id }

/* ftm cmd-id mapping */
static const ftm_strmap_entry_t ftm_cmdid_map[] = {
	/* {wl_proxd_cmd_t(WL_PROXD_CMD_xxx), "WL_PROXD_CMD_xxx" }, */
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_NONE),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_GET_VERSION),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_ENABLE),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_DISABLE),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_CONFIG),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_START_SESSION),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_BURST_REQUEST),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_STOP_SESSION),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_DELETE_SESSION),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_GET_RESULT),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_GET_INFO),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_GET_STATUS),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_GET_SESSIONS),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_GET_COUNTERS),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_CLEAR_COUNTERS),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_COLLECT),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_TUNE),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_DUMP),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_START_RANGING),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_STOP_RANGING),
	DEF_STRMAP_ENTRY(WL_PROXD_CMD_GET_RANGING_INFO),
};

/*
* map a ftm cmd-id to a text-string for display
*/
const char *
ftm_cmdid_to_str(uint16 cmdid)
{
	return ftm_map_id_to_str((int32) cmdid, &ftm_cmdid_map[0], ARRAYSIZE(ftm_cmdid_map));
}
#endif /* WL_CFG80211 && RTT_DEBUG */

/*
* convert BCME_xxx error codes into related error strings
* note, bcmerrorstr() defined in bcmutils is for BCMDRIVER only,
*       this duplicate copy is for WL access and may need to clean up later
*/
static const char *ftm_bcmerrorstrtable[] = BCMERRSTRINGTABLE;
static const char *
ftm_status_value_to_logstr(wl_proxd_status_t status)
{
	static char ftm_msgbuf_status_undef[32];
	const ftm_strmap_entry_t *p_loginfo;
	int bcmerror;

	/* check if within BCME_xxx error range */
	bcmerror = (int) status;
	if (VALID_BCMERROR(bcmerror))
		return ftm_bcmerrorstrtable[-bcmerror];

	/* otherwise, look for 'proxd ftm status' range */
	p_loginfo = ftm_get_strmap_info((int32) status,
		&ftm_status_value_loginfo[0], ARRAYSIZE(ftm_status_value_loginfo));
	if (p_loginfo)
		return p_loginfo->text;

	/* report for 'out of range' FTM-status error code */
	memset(ftm_msgbuf_status_undef, 0, sizeof(ftm_msgbuf_status_undef));
	snprintf(ftm_msgbuf_status_undef, sizeof(ftm_msgbuf_status_undef),
		"Undefined status %d", status);
	return &ftm_msgbuf_status_undef[0];
}

static const char *
ftm_tmu_value_to_logstr(wl_proxd_tmu_t tmu)
{
	return ftm_map_id_to_str((int32)tmu,
		&ftm_tmu_value_loginfo[0], ARRAYSIZE(ftm_tmu_value_loginfo));
}

static const ftm_strmap_entry_t*
ftm_get_event_type_loginfo(wl_proxd_event_type_t	event_type)
{
	/* look up 'event-type' from a predefined table  */
	return ftm_get_strmap_info((int32) event_type,
		ftm_event_type_loginfo, ARRAYSIZE(ftm_event_type_loginfo));
}

static const char *
ftm_session_state_value_to_logstr(wl_proxd_session_state_t state)
{
	return ftm_map_id_to_str((int32)state, &ftm_session_state_value_loginfo[0],
		ARRAYSIZE(ftm_session_state_value_loginfo));
}

#ifdef WL_CFG80211
/*
* send 'proxd' iovar for all ftm get-related commands
*/
static int
rtt_do_get_ioctl(dhd_pub_t *dhd, wl_proxd_iov_t *p_proxd_iov, uint16 proxd_iovsize,
		ftm_subcmd_info_t *p_subcmd_info)
{

	wl_proxd_iov_t *p_iovresp = (wl_proxd_iov_t *)resp_buf;
	int status;
	int tlvs_len;
	/*  send getbuf proxd iovar */
	status = dhd_getiovar(dhd, 0, "proxd", (char *)p_proxd_iov,
			proxd_iovsize, (char **)&p_iovresp, WLC_IOCTL_SMLEN);
	if (status != BCME_OK) {
		DHD_RTT_ERR(("%s: failed to send getbuf proxd iovar (CMD ID : %d), status=%d\n",
			__FUNCTION__, p_subcmd_info->cmdid, status));
		return status;
	}
	if (p_subcmd_info->cmdid == WL_PROXD_CMD_GET_VERSION) {
		p_subcmd_info->version = ltoh16(p_iovresp->version);
		DHD_RTT(("ftm version: 0x%x\n", ltoh16(p_iovresp->version)));
		goto exit;
	}

	tlvs_len = ltoh16(p_iovresp->len) - WL_PROXD_IOV_HDR_SIZE;
	if (tlvs_len < 0) {
		DHD_RTT_ERR(("%s: alert, p_iovresp->len(%d) should not be smaller than %d\n",
			__FUNCTION__, ltoh16(p_iovresp->len), (int) WL_PROXD_IOV_HDR_SIZE));
		tlvs_len = 0;
	}

	if (tlvs_len > 0 && p_subcmd_info->handler) {
		/* unpack TLVs and invokes the cbfn for processing */
		status = bcm_unpack_xtlv_buf(p_proxd_iov, (uint8 *)p_iovresp->tlvs,
				tlvs_len, BCM_XTLV_OPTION_ALIGN32, p_subcmd_info->handler);
	}
exit:
	return status;
}

static wl_proxd_iov_t *
rtt_alloc_getset_buf(wl_proxd_method_t method, wl_proxd_session_id_t session_id,
	wl_proxd_cmd_t cmdid, uint16 tlvs_bufsize, uint16 *p_out_bufsize)
{
	uint16 proxd_iovsize;
	uint32 kflags;
	wl_proxd_tlv_t *p_tlv;
	wl_proxd_iov_t *p_proxd_iov = (wl_proxd_iov_t *) NULL;

	*p_out_bufsize = 0;	/* init */
	kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;
	/* calculate the whole buffer size, including one reserve-tlv entry in the header */
	proxd_iovsize = sizeof(wl_proxd_iov_t) + tlvs_bufsize;

	p_proxd_iov = kzalloc(proxd_iovsize, kflags);
	if (p_proxd_iov == NULL) {
		DHD_RTT_ERR(("error: failed to allocate %d bytes of memory\n", proxd_iovsize));
		return NULL;
	}

	/* setup proxd-FTM-method iovar header */
	p_proxd_iov->version = htol16(WL_PROXD_API_VERSION);
	p_proxd_iov->len = htol16(proxd_iovsize); /* caller may adjust it based on #of TLVs */
	p_proxd_iov->cmd = htol16(cmdid);
	p_proxd_iov->method = htol16(method);
	p_proxd_iov->sid = htol16(session_id);

	/* initialize the reserved/dummy-TLV in iovar header */
	p_tlv = p_proxd_iov->tlvs;
	p_tlv->id = htol16(WL_PROXD_TLV_ID_NONE);
	p_tlv->len = htol16(0);

	*p_out_bufsize = proxd_iovsize;	/* for caller's reference */

	return p_proxd_iov;
}

static int
dhd_rtt_common_get_handler(dhd_pub_t *dhd, ftm_subcmd_info_t *p_subcmd_info,
		wl_proxd_method_t method,
		wl_proxd_session_id_t session_id)
{
	int status = BCME_OK;
	uint16 proxd_iovsize = 0;
	wl_proxd_iov_t *p_proxd_iov;
#ifdef RTT_DEBUG
	DHD_RTT(("enter %s: method=%d, session_id=%d, cmdid=%d(%s)\n",
		__FUNCTION__, method, session_id, p_subcmd_info->cmdid,
		ftm_cmdid_to_str(p_subcmd_info->cmdid)));
#endif // endif
	/* alloc mem for ioctl headr + reserved 0 bufsize for tlvs (initialize to zero) */
	p_proxd_iov = rtt_alloc_getset_buf(method, session_id, p_subcmd_info->cmdid,
		0, &proxd_iovsize);

	if (p_proxd_iov == NULL)
		return BCME_NOMEM;

	status = rtt_do_get_ioctl(dhd, p_proxd_iov, proxd_iovsize, p_subcmd_info);

	if (status != BCME_OK) {
		DHD_RTT(("%s failed: status=%d\n", __FUNCTION__, status));
	}
	kfree(p_proxd_iov);
	return status;
}

/*
* common handler for set-related proxd method commands which require no TLV as input
*   wl proxd ftm [session-id] <set-subcmd>
* e.g.
*   wl proxd ftm enable -- to enable ftm
*   wl proxd ftm disable -- to disable ftm
*   wl proxd ftm <session-id> start -- to start a specified session
*   wl proxd ftm <session-id> stop  -- to cancel a specified session;
*                                    state is maintained till session is delete.
*   wl proxd ftm <session-id> delete -- to delete a specified session
*   wl proxd ftm [<session-id>] clear-counters -- to clear counters
*   wl proxd ftm <session-id> burst-request -- on initiator: to send burst request;
*                                              on target: send FTM frame
*   wl proxd ftm <session-id> collect
*   wl proxd ftm tune     (TBD)
*/
static int
dhd_rtt_common_set_handler(dhd_pub_t *dhd, const ftm_subcmd_info_t *p_subcmd_info,
	wl_proxd_method_t method, wl_proxd_session_id_t session_id)
{
	uint16 proxd_iovsize;
	wl_proxd_iov_t *p_proxd_iov;
	int ret;

#ifdef RTT_DEBUG
	DHD_RTT(("enter %s: method=%d, session_id=%d, cmdid=%d(%s)\n",
		__FUNCTION__, method, session_id, p_subcmd_info->cmdid,
		ftm_cmdid_to_str(p_subcmd_info->cmdid)));
#endif // endif

	/* allocate and initialize a temp buffer for 'set proxd' iovar */
	proxd_iovsize = 0;
	p_proxd_iov = rtt_alloc_getset_buf(method, session_id, p_subcmd_info->cmdid,
							0, &proxd_iovsize);		/* no TLV */
	if (p_proxd_iov == NULL)
		return BCME_NOMEM;

	/* no TLV to pack, simply issue a set-proxd iovar */
	ret = dhd_iovar(dhd, 0, "proxd", (char *)p_proxd_iov, proxd_iovsize, NULL, 0, TRUE);
#ifdef RTT_DEBUG
	if (ret != BCME_OK) {
		DHD_RTT(("error: IOVAR failed, status=%d\n", ret));
	}
#endif // endif
	/* clean up */
	kfree(p_proxd_iov);

	return ret;
}
#endif /* WL_CFG80211 */

/* gets the length and returns the version
 * of the wl_proxd_collect_event_t version
 */
static uint
rtt_collect_data_event_ver(uint16 len)
{
	if (len > sizeof(wl_proxd_collect_event_data_v3_t)) {
		return WL_PROXD_COLLECT_EVENT_DATA_VERSION_MAX;
	} else if (len == sizeof(wl_proxd_collect_event_data_v3_t)) {
		return WL_PROXD_COLLECT_EVENT_DATA_VERSION_3;
	} else if (len == sizeof(wl_proxd_collect_event_data_v2_t)) {
		return WL_PROXD_COLLECT_EVENT_DATA_VERSION_2;
	} else {
		return WL_PROXD_COLLECT_EVENT_DATA_VERSION_1;
	}
}

static void
rtt_collect_event_data_display(uint8 ver, void *ctx, const uint8 *p_data, uint16 len)
{
	int i;
	wl_proxd_collect_event_data_v1_t *p_collect_data_v1 = NULL;
	wl_proxd_collect_event_data_v2_t *p_collect_data_v2 = NULL;
	wl_proxd_collect_event_data_v3_t *p_collect_data_v3 = NULL;

	if (!ctx || !p_data) {
		return;
	}

	switch (ver) {
	case WL_PROXD_COLLECT_EVENT_DATA_VERSION_1:
		DHD_RTT(("\tVERSION_1\n"));
		memcpy(ctx, p_data, sizeof(wl_proxd_collect_event_data_v1_t));
		p_collect_data_v1 = (wl_proxd_collect_event_data_v1_t *)ctx;
		DHD_RTT(("\tH_RX\n"));
		for (i = 0; i < K_TOF_COLLECT_H_SIZE_20MHZ; i++) {
			p_collect_data_v1->H_RX[i] = ltoh32_ua(&p_collect_data_v1->H_RX[i]);
			DHD_RTT(("\t%u\n", p_collect_data_v1->H_RX[i]));
		}
		DHD_RTT(("\n"));
		DHD_RTT(("\tH_LB\n"));
		for (i = 0; i < K_TOF_COLLECT_H_SIZE_20MHZ; i++) {
			p_collect_data_v1->H_LB[i] = ltoh32_ua(&p_collect_data_v1->H_LB[i]);
			DHD_RTT(("\t%u\n", p_collect_data_v1->H_LB[i]));
		}
		DHD_RTT(("\n"));
		DHD_RTT(("\tri_rr\n"));
		for (i = 0; i < FTM_TPK_RI_RR_LEN; i++) {
			DHD_RTT(("\t%u\n", p_collect_data_v1->ri_rr[i]));
		}
		p_collect_data_v1->phy_err_mask = ltoh32_ua(&p_collect_data_v1->phy_err_mask);
		DHD_RTT(("\tphy_err_mask=0x%x\n", p_collect_data_v1->phy_err_mask));
		break;
	case WL_PROXD_COLLECT_EVENT_DATA_VERSION_2:
		memcpy(ctx, p_data, sizeof(wl_proxd_collect_event_data_v2_t));
		p_collect_data_v2 = (wl_proxd_collect_event_data_v2_t *)ctx;
		DHD_RTT(("\tH_RX\n"));
		for (i = 0; i < K_TOF_COLLECT_H_SIZE_20MHZ; i++) {
			p_collect_data_v2->H_RX[i] = ltoh32_ua(&p_collect_data_v2->H_RX[i]);
			DHD_RTT(("\t%u\n", p_collect_data_v2->H_RX[i]));
		}
		DHD_RTT(("\n"));
		DHD_RTT(("\tH_LB\n"));
		for (i = 0; i < K_TOF_COLLECT_H_SIZE_20MHZ; i++) {
			p_collect_data_v2->H_LB[i] = ltoh32_ua(&p_collect_data_v2->H_LB[i]);
			DHD_RTT(("\t%u\n", p_collect_data_v2->H_LB[i]));
		}
		DHD_RTT(("\n"));
		DHD_RTT(("\tri_rr\n"));
		for (i = 0; i < FTM_TPK_RI_RR_LEN_SECURE_2_0; i++) {
			DHD_RTT(("\t%u\n", p_collect_data_v2->ri_rr[i]));
		}
		p_collect_data_v2->phy_err_mask = ltoh32_ua(&p_collect_data_v2->phy_err_mask);
		DHD_RTT(("\tphy_err_mask=0x%x\n", p_collect_data_v2->phy_err_mask));
		break;
	case WL_PROXD_COLLECT_EVENT_DATA_VERSION_3:
		memcpy(ctx, p_data, sizeof(wl_proxd_collect_event_data_v3_t));
		p_collect_data_v3 = (wl_proxd_collect_event_data_v3_t *)ctx;
		switch (p_collect_data_v3->version) {
		case WL_PROXD_COLLECT_EVENT_DATA_VERSION_3:
			if (p_collect_data_v3->length !=
				(len - OFFSETOF(wl_proxd_collect_event_data_v3_t, H_LB))) {
				DHD_RTT(("\tversion/length mismatch\n"));
				break;
			}
			DHD_RTT(("\tH_RX\n"));
			for (i = 0; i < K_TOF_COLLECT_H_SIZE_20MHZ; i++) {
				p_collect_data_v3->H_RX[i] =
					ltoh32_ua(&p_collect_data_v3->H_RX[i]);
				DHD_RTT(("\t%u\n", p_collect_data_v3->H_RX[i]));
			}
			DHD_RTT(("\n"));
			DHD_RTT(("\tH_LB\n"));
			for (i = 0; i < K_TOF_COLLECT_H_SIZE_20MHZ; i++) {
				p_collect_data_v3->H_LB[i] =
					ltoh32_ua(&p_collect_data_v3->H_LB[i]);
				DHD_RTT(("\t%u\n", p_collect_data_v3->H_LB[i]));
			}
			DHD_RTT(("\n"));
			DHD_RTT(("\tri_rr\n"));
			for (i = 0; i < FTM_TPK_RI_RR_LEN_SECURE_2_0; i++) {
				DHD_RTT(("\t%u\n", p_collect_data_v3->ri_rr[i]));
			}
			p_collect_data_v3->phy_err_mask =
				ltoh32_ua(&p_collect_data_v3->phy_err_mask);
			DHD_RTT(("\tphy_err_mask=0x%x\n", p_collect_data_v3->phy_err_mask));
			break;
		/* future case */
		}
		break;
	}
}

static uint16
rtt_result_ver(uint16 tlvid, const uint8 *p_data)
{
	uint16 ret = BCME_OK;
	const wl_proxd_rtt_result_v2_t *r_v2 = NULL;

	switch (tlvid) {
	case WL_PROXD_TLV_ID_RTT_RESULT:
		BCM_REFERENCE(p_data);
		ret = WL_PROXD_RTT_RESULT_VERSION_1;
		break;
	case WL_PROXD_TLV_ID_RTT_RESULT_V2:
		if (p_data) {
			r_v2 = (const wl_proxd_rtt_result_v2_t *)p_data;
			if (r_v2->version == WL_PROXD_RTT_RESULT_VERSION_2) {
				ret = WL_PROXD_RTT_RESULT_VERSION_2;
			}
		}
		break;
	default:
		DHD_RTT_ERR(("%s: > Unsupported TLV ID %d\n",
			__FUNCTION__, tlvid));
		break;
	}
	return ret;
}

/* pretty hex print a contiguous buffer */
static void
rtt_prhex(const char *msg, const uint8 *buf, uint nbytes)
{
	char line[128], *p;
	int len = sizeof(line);
	int nchar;
	uint i;

	if (msg && (msg[0] != '\0'))
		DHD_RTT(("%s:\n", msg));

	p = line;
	for (i = 0; i < nbytes; i++) {
		if (i % 16 == 0) {
			nchar = snprintf(p, len, "  %04d: ", i);	/* line prefix */
			p += nchar;
			len -= nchar;
		}
		if (len > 0) {
			nchar = snprintf(p, len, "%02x ", buf[i]);
			p += nchar;
			len -= nchar;
		}

		if (i % 16 == 15) {
			DHD_RTT(("%s\n", line));	/* flush line */
			p = line;
			len = sizeof(line);
		}
	}

	/* flush last partial line */
	if (p != line)
		DHD_RTT(("%s\n", line));
}

static int
rtt_unpack_xtlv_cbfn(void *ctx, const uint8 *p_data, uint16 tlvid, uint16 len)
{
	int ret = BCME_OK;
	int i;
	wl_proxd_ftm_session_status_t *p_data_info = NULL;
	uint32 chan_data_entry = 0;
	uint16 expected_rtt_result_ver = 0;

	BCM_REFERENCE(p_data_info);

	switch (tlvid) {
	case WL_PROXD_TLV_ID_RTT_RESULT:
	case WL_PROXD_TLV_ID_RTT_RESULT_V2:
		DHD_RTT(("WL_PROXD_TLV_ID_RTT_RESULT\n"));
		expected_rtt_result_ver = rtt_result_ver(tlvid, p_data);
		switch (expected_rtt_result_ver) {
		case WL_PROXD_RTT_RESULT_VERSION_1:
			ret = dhd_rtt_convert_results_to_host_v1((rtt_result_t *)ctx,
					p_data, tlvid, len);
			break;
		case WL_PROXD_RTT_RESULT_VERSION_2:
			ret = dhd_rtt_convert_results_to_host_v2((rtt_result_t *)ctx,
					p_data, tlvid, len);
			break;
		default:
			DHD_RTT_ERR((" > Unsupported RTT_RESULT version\n"));
			ret = BCME_UNSUPPORTED;
			break;
		}
		break;
	case WL_PROXD_TLV_ID_SESSION_STATUS:
		DHD_RTT(("WL_PROXD_TLV_ID_SESSION_STATUS\n"));
		memcpy(ctx, p_data, sizeof(wl_proxd_ftm_session_status_t));
		p_data_info = (wl_proxd_ftm_session_status_t *)ctx;
		p_data_info->sid = ltoh16_ua(&p_data_info->sid);
		p_data_info->state = ltoh16_ua(&p_data_info->state);
		p_data_info->status = ltoh32_ua(&p_data_info->status);
		p_data_info->burst_num = ltoh16_ua(&p_data_info->burst_num);
		DHD_RTT(("\tsid=%u, state=%d, status=%d, burst_num=%u\n",
			p_data_info->sid, p_data_info->state,
			p_data_info->status, p_data_info->burst_num));

		break;
	case WL_PROXD_TLV_ID_COLLECT_DATA:
		DHD_RTT(("WL_PROXD_TLV_ID_COLLECT_DATA\n"));
		rtt_collect_event_data_display(
			rtt_collect_data_event_ver(len),
			ctx, p_data, len);
		break;
	case WL_PROXD_TLV_ID_COLLECT_CHAN_DATA:
		GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
		DHD_RTT(("WL_PROXD_TLV_ID_COLLECT_CHAN_DATA\n"));
		DHD_RTT(("\tchan est %u\n", (uint32) (len / sizeof(uint32))));
		for (i = 0; (uint16)i < (len/sizeof(chan_data_entry)); i++) {
			uint32 *p = (uint32*)p_data;
			chan_data_entry = ltoh32_ua(p + i);
			DHD_RTT(("\t%u\n", chan_data_entry));
		}
		GCC_DIAGNOSTIC_POP();
		break;
	case WL_PROXD_TLV_ID_MF_STATS_DATA:
		DHD_RTT(("WL_PROXD_TLV_ID_MF_STATS_DATA\n"));
		DHD_RTT(("\tmf stats len=%u\n", len));
		rtt_prhex("", p_data, len);
		break;
	default:
		DHD_RTT_ERR(("> Unsupported TLV ID %d\n", tlvid));
		ret = BCME_ERROR;
		break;
	}

	return ret;
}

#ifdef WL_CFG80211
static int
rtt_handle_config_options(wl_proxd_session_id_t session_id, wl_proxd_tlv_t **p_tlv,
	uint16 *p_buf_space_left, ftm_config_options_info_t *ftm_configs, int ftm_cfg_cnt)
{
	int ret = BCME_OK;
	int cfg_idx = 0;
	uint32 flags = WL_PROXD_FLAG_NONE;
	uint32 flags_mask = WL_PROXD_FLAG_NONE;
	uint32 new_mask;		/* cmdline input */
	ftm_config_options_info_t *p_option_info;
	uint16 type = (session_id == WL_PROXD_SESSION_ID_GLOBAL) ?
			WL_PROXD_TLV_ID_FLAGS_MASK : WL_PROXD_TLV_ID_SESSION_FLAGS_MASK;
	for (cfg_idx = 0; cfg_idx < ftm_cfg_cnt; cfg_idx++) {
		p_option_info = (ftm_configs + cfg_idx);
		if (p_option_info != NULL) {
			new_mask = p_option_info->flags;
			/* update flags mask */
			flags_mask |= new_mask;
			if (p_option_info->enable) {
				flags |= new_mask;	/* set the bit on */
			} else {
				flags &= ~new_mask;	/* set the bit off */
			}
		}
	}
	flags = htol32(flags);
	flags_mask = htol32(flags_mask);
	/* setup flags_mask TLV */
	ret = bcm_pack_xtlv_entry((uint8 **)p_tlv, p_buf_space_left,
		type, sizeof(uint32), (uint8 *)&flags_mask, BCM_XTLV_OPTION_ALIGN32);
	if (ret != BCME_OK) {
		DHD_RTT_ERR(("%s : bcm_pack_xltv_entry() for mask flags failed, status=%d\n",
			__FUNCTION__, ret));
		goto exit;
	}

	type = (session_id == WL_PROXD_SESSION_ID_GLOBAL)?
		WL_PROXD_TLV_ID_FLAGS : WL_PROXD_TLV_ID_SESSION_FLAGS;
	/* setup flags TLV */
	ret = bcm_pack_xtlv_entry((uint8 **)p_tlv, p_buf_space_left,
			type, sizeof(uint32), (uint8 *)&flags, BCM_XTLV_OPTION_ALIGN32);
		if (ret != BCME_OK) {
#ifdef RTT_DEBUG
			DHD_RTT(("%s: bcm_pack_xltv_entry() for flags failed, status=%d\n",
				__FUNCTION__, ret));
#endif // endif
		}
exit:
	return ret;
}

static int
rtt_handle_config_general(wl_proxd_session_id_t session_id, wl_proxd_tlv_t **p_tlv,
	uint16 *p_buf_space_left, ftm_config_param_info_t *ftm_configs, int ftm_cfg_cnt)
{
	int ret = BCME_OK;
	int cfg_idx = 0;
	uint32 chanspec;
	ftm_config_param_info_t *p_config_param_info;
	void		*p_src_data;
	uint16	src_data_size;	/* size of data pointed by p_src_data as 'source' */
	for (cfg_idx = 0; cfg_idx < ftm_cfg_cnt; cfg_idx++) {
		p_config_param_info = (ftm_configs + cfg_idx);
		if (p_config_param_info != NULL) {
			switch (p_config_param_info->tlvid)	{
			case WL_PROXD_TLV_ID_BSS_INDEX:
			case WL_PROXD_TLV_ID_FTM_RETRIES:
			case WL_PROXD_TLV_ID_FTM_REQ_RETRIES:
				p_src_data = &p_config_param_info->data8;
				src_data_size = sizeof(uint8);
				break;
			case WL_PROXD_TLV_ID_BURST_NUM_FTM: /* uint16 */
			case WL_PROXD_TLV_ID_NUM_BURST:
			case WL_PROXD_TLV_ID_RX_MAX_BURST:
				p_src_data = &p_config_param_info->data16;
				src_data_size = sizeof(uint16);
				break;
			case WL_PROXD_TLV_ID_TX_POWER:		/* uint32 */
			case WL_PROXD_TLV_ID_RATESPEC:
			case WL_PROXD_TLV_ID_EVENT_MASK: /* wl_proxd_event_mask_t/uint32 */
			case WL_PROXD_TLV_ID_DEBUG_MASK:
				p_src_data = &p_config_param_info->data32;
				src_data_size = sizeof(uint32);
				break;
			case WL_PROXD_TLV_ID_CHANSPEC:		/* chanspec_t --> 32bit */
				chanspec = p_config_param_info->chanspec;
				p_src_data = (void *) &chanspec;
				src_data_size = sizeof(uint32);
				break;
			case WL_PROXD_TLV_ID_BSSID: /* mac address */
			case WL_PROXD_TLV_ID_PEER_MAC:
			case WL_PROXD_TLV_ID_CUR_ETHER_ADDR:
				p_src_data = &p_config_param_info->mac_addr;
				src_data_size = sizeof(struct ether_addr);
				break;
			case WL_PROXD_TLV_ID_BURST_DURATION:	/* wl_proxd_intvl_t */
			case WL_PROXD_TLV_ID_BURST_PERIOD:
			case WL_PROXD_TLV_ID_BURST_FTM_SEP:
			case WL_PROXD_TLV_ID_BURST_TIMEOUT:
			case WL_PROXD_TLV_ID_INIT_DELAY:
				p_src_data = &p_config_param_info->data_intvl;
				src_data_size = sizeof(wl_proxd_intvl_t);
				break;
			default:
				ret = BCME_BADARG;
				break;
			}
			if (ret != BCME_OK) {
				DHD_RTT_ERR(("%s bad TLV ID : %d\n",
					__FUNCTION__, p_config_param_info->tlvid));
				break;
			}

			ret = bcm_pack_xtlv_entry((uint8 **) p_tlv, p_buf_space_left,
				p_config_param_info->tlvid, src_data_size, (uint8 *)p_src_data,
				BCM_XTLV_OPTION_ALIGN32);
			if (ret != BCME_OK) {
				DHD_RTT_ERR(("%s: bcm_pack_xltv_entry() failed,"
					" status=%d\n", __FUNCTION__, ret));
				break;
			}

		}
	}
	return ret;
}

static int
dhd_rtt_ftm_enable(dhd_pub_t *dhd, bool enable)
{
	ftm_subcmd_info_t subcmd_info;
	subcmd_info.name = (enable)? "enable" : "disable";
	subcmd_info.cmdid = (enable)? WL_PROXD_CMD_ENABLE: WL_PROXD_CMD_DISABLE;
	subcmd_info.handler = NULL;
	return dhd_rtt_common_set_handler(dhd, &subcmd_info,
			WL_PROXD_METHOD_FTM, WL_PROXD_SESSION_ID_GLOBAL);
}

static int
dhd_rtt_start_session(dhd_pub_t *dhd, wl_proxd_session_id_t session_id, bool start)
{
	ftm_subcmd_info_t subcmd_info;
	subcmd_info.name = (start)? "start session" : "stop session";
	subcmd_info.cmdid = (start)? WL_PROXD_CMD_START_SESSION: WL_PROXD_CMD_STOP_SESSION;
	subcmd_info.handler = NULL;
	return dhd_rtt_common_set_handler(dhd, &subcmd_info,
			WL_PROXD_METHOD_FTM, session_id);
}

static int
dhd_rtt_delete_session(dhd_pub_t *dhd, wl_proxd_session_id_t session_id)
{
	ftm_subcmd_info_t subcmd_info;
	subcmd_info.name = "delete session";
	subcmd_info.cmdid = WL_PROXD_CMD_DELETE_SESSION;
	subcmd_info.handler = NULL;
	return dhd_rtt_common_set_handler(dhd, &subcmd_info,
			WL_PROXD_METHOD_FTM, session_id);
}
#ifdef WL_NAN
int
dhd_rtt_delete_nan_session(dhd_pub_t *dhd)
{
	struct net_device *dev = dhd_linux_get_primary_netdev(dhd);
	struct wireless_dev *wdev = ndev_to_wdev(dev);
	struct wiphy *wiphy = wdev->wiphy;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	wl_cfgnan_terminate_directed_rtt_sessions(dev, cfg);
	return BCME_OK;
}
#endif /* WL_NAN */
/* API to find out if the given Peer Mac from FTM events
* is nan-peer. Based on this we will handle the SESSION_END
* event. For nan-peer FTM_SESSION_END event is ignored and handled in
* nan-ranging-cancel or nan-ranging-end event.
*/
static bool
dhd_rtt_is_nan_peer(dhd_pub_t *dhd, struct ether_addr *peer_mac)
{
#ifdef WL_NAN
	struct net_device *dev = dhd_linux_get_primary_netdev(dhd);
	struct wireless_dev *wdev = ndev_to_wdev(dev);
	struct wiphy *wiphy = wdev->wiphy;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	nan_ranging_inst_t *ranging_inst = NULL;
	bool ret = FALSE;

	if (cfg->nan_enable == FALSE || ETHER_ISNULLADDR(peer_mac)) {
		goto exit;
	}

	ranging_inst = wl_cfgnan_check_for_ranging(cfg, peer_mac);
	if (ranging_inst) {
		DHD_RTT((" RTT peer is of type NAN\n"));
		ret = TRUE;
		goto exit;
	}
exit:
	return ret;
#else
	return FALSE;
#endif /* WL_NAN */
}

#ifdef WL_NAN
static int
dhd_rtt_nan_start_session(dhd_pub_t *dhd, rtt_target_info_t *rtt_target)
{
	s32 err = BCME_OK;
	struct net_device *dev = dhd_linux_get_primary_netdev(dhd);
	struct wireless_dev *wdev = ndev_to_wdev(dev);
	struct wiphy *wiphy = wdev->wiphy;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	wl_nan_ev_rng_rpt_ind_t range_res;
	nan_ranging_inst_t *ranging_inst = NULL;
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);

	NAN_MUTEX_LOCK();

	bzero(&range_res, sizeof(range_res));

	if (!rtt_status) {
		err = BCME_NOTENABLED;
		goto done;
	}

	if (!cfg->nan_enable) { /* If nan is not enabled report error */
		err = BCME_NOTENABLED;
		goto done;
	}

	/* check if new ranging session allowed */
	if (!wl_cfgnan_ranging_allowed(cfg)) {
		/* responder should be in progress because initiator requests are
		* queued in DHD. Since initiator has more proef cancel responder
		* sessions
		*/
		wl_cfgnan_cancel_rng_responders(dev, cfg);
	}

	ranging_inst = wl_cfgnan_get_ranging_inst(cfg,
			&rtt_target->addr, NAN_RANGING_ROLE_INITIATOR);
	if (!ranging_inst) {
		err = BCME_NORESOURCE;
		goto done;
	}

	DHD_RTT(("Trigger nan based range request\n"));
	err = wl_cfgnan_trigger_ranging(bcmcfg_to_prmry_ndev(cfg),
			cfg, ranging_inst, NULL, NAN_RANGE_REQ_CMD, TRUE);
	if (unlikely(err)) {
		goto done;
	}
	ranging_inst->range_type = RTT_TYPE_NAN_DIRECTED;
	ranging_inst->range_role = NAN_RANGING_ROLE_INITIATOR;
	/* schedule proxd timeout */
	schedule_delayed_work(&rtt_status->proxd_timeout,
		msecs_to_jiffies(DHD_NAN_RTT_TIMER_INTERVAL_MS));
done:
	if (err) { /* notify failure RTT event to host */
		DHD_RTT_ERR(("Failed to issue Nan Ranging Request err %d\n", err));
		dhd_rtt_handle_nan_rtt_session_end(dhd, &rtt_target->addr);
		/* try to reset geofence */
		if (ranging_inst) {
			wl_cfgnan_reset_geofence_ranging(cfg, ranging_inst,
				RTT_SCHED_DIR_TRIGGER_FAIL);
		}
	}
	NAN_MUTEX_UNLOCK();
	return err;
}
#endif /* WL_NAN */

static int
dhd_rtt_ftm_config(dhd_pub_t *dhd, wl_proxd_session_id_t session_id,
	ftm_config_category_t catagory, void *ftm_configs, int ftm_cfg_cnt)
{
	ftm_subcmd_info_t subcmd_info;
	wl_proxd_tlv_t *p_tlv;
	/* alloc mem for ioctl headr + reserved 0 bufsize for tlvs (initialize to zero) */
	wl_proxd_iov_t *p_proxd_iov;
	uint16 proxd_iovsize = 0;
	uint16 bufsize;
	uint16 buf_space_left;
	uint16 all_tlvsize;
	int ret = BCME_OK;

	subcmd_info.name = "config";
	subcmd_info.cmdid = WL_PROXD_CMD_CONFIG;

	p_proxd_iov = rtt_alloc_getset_buf(WL_PROXD_METHOD_FTM, session_id, subcmd_info.cmdid,
		FTM_IOC_BUFSZ, &proxd_iovsize);

	if (p_proxd_iov == NULL) {
		DHD_RTT_ERR(("%s : failed to allocate the iovar (size :%d)\n",
			__FUNCTION__, FTM_IOC_BUFSZ));
		return BCME_NOMEM;
	}
	/* setup TLVs */
	bufsize = proxd_iovsize - WL_PROXD_IOV_HDR_SIZE; /* adjust available size for TLVs */
	p_tlv = &p_proxd_iov->tlvs[0];
	/* TLV buffer starts with a full size, will decrement for each packed TLV */
	buf_space_left = bufsize;
	if (catagory == FTM_CONFIG_CAT_OPTIONS) {
		ret = rtt_handle_config_options(session_id, &p_tlv, &buf_space_left,
				(ftm_config_options_info_t *)ftm_configs, ftm_cfg_cnt);
	} else if (catagory == FTM_CONFIG_CAT_GENERAL) {
		ret = rtt_handle_config_general(session_id, &p_tlv, &buf_space_left,
				(ftm_config_param_info_t *)ftm_configs, ftm_cfg_cnt);
	}
	if (ret == BCME_OK) {
		/* update the iov header, set len to include all TLVs + header */
		all_tlvsize = (bufsize - buf_space_left);
		p_proxd_iov->len = htol16(all_tlvsize + WL_PROXD_IOV_HDR_SIZE);
		ret = dhd_iovar(dhd, 0, "proxd", (char *)p_proxd_iov,
				all_tlvsize + WL_PROXD_IOV_HDR_SIZE, NULL, 0, TRUE);
		if (ret != BCME_OK) {
			DHD_RTT_ERR(("%s : failed to set config\n", __FUNCTION__));
		}
	}
	/* clean up */
	kfree(p_proxd_iov);
	return ret;
}

static int
dhd_rtt_get_version(dhd_pub_t *dhd, int *out_version)
{
	int ret;
	ftm_subcmd_info_t subcmd_info;
	subcmd_info.name = "ver";
	subcmd_info.cmdid = WL_PROXD_CMD_GET_VERSION;
	subcmd_info.handler = NULL;
	ret = dhd_rtt_common_get_handler(dhd, &subcmd_info,
			WL_PROXD_METHOD_FTM, WL_PROXD_SESSION_ID_GLOBAL);
	*out_version = (ret == BCME_OK) ? subcmd_info.version : 0;
	return ret;
}
#endif /* WL_CFG80211 */

chanspec_t
dhd_rtt_convert_to_chspec(wifi_channel_info_t channel)
{
	int bw;
	chanspec_t chanspec = 0;
	uint8 center_chan;
	uint8 primary_chan;
	/* set witdh to 20MHZ for 2.4G HZ */
	if (channel.center_freq >= 2400 && channel.center_freq <= 2500) {
		channel.width = WIFI_CHAN_WIDTH_20;
	}
	switch (channel.width) {
	case WIFI_CHAN_WIDTH_20:
		bw = WL_CHANSPEC_BW_20;
		primary_chan = wf_mhz2channel(channel.center_freq, 0);
		chanspec = wf_channel2chspec(primary_chan, bw);
		break;
	case WIFI_CHAN_WIDTH_40:
		bw = WL_CHANSPEC_BW_40;
		primary_chan = wf_mhz2channel(channel.center_freq, 0);
		chanspec = wf_channel2chspec(primary_chan, bw);
		break;
	case WIFI_CHAN_WIDTH_80:
		bw = WL_CHANSPEC_BW_80;
		primary_chan = wf_mhz2channel(channel.center_freq, 0);
		center_chan = wf_mhz2channel(channel.center_freq0, 0);
		chanspec = wf_chspec_80(center_chan, primary_chan);
		break;
	default:
		DHD_RTT_ERR(("doesn't support this bandwith : %d", channel.width));
		bw = -1;
		break;
	}
	return chanspec;
}

int
dhd_rtt_idx_to_burst_duration(uint idx)
{
	if (idx >= ARRAY_SIZE(burst_duration_idx)) {
		return -1;
	}
	return burst_duration_idx[idx];
}

int
dhd_rtt_set_cfg(dhd_pub_t *dhd, rtt_config_params_t *params)
{
	int err = BCME_OK;
	int idx;
	rtt_status_info_t *rtt_status = NULL;
	struct net_device *dev = NULL;

	NULL_CHECK(params, "params is NULL", err);
	NULL_CHECK(dhd, "dhd is NULL", err);

	dev = dhd_linux_get_primary_netdev(dhd);
	rtt_status = GET_RTTSTATE(dhd);
	NULL_CHECK(rtt_status, "rtt_status is NULL", err);
	NULL_CHECK(dev, "dev is NULL", err);

	mutex_lock(&rtt_status->rtt_work_mutex);
	if (!HAS_11MC_CAP(rtt_status->rtt_capa.proto)) {
		DHD_RTT_ERR(("doesn't support RTT \n"));
		err = BCME_ERROR;
		goto exit;
	}

	DHD_RTT(("%s enter\n", __FUNCTION__));

	if (params->rtt_target_cnt > 0) {
#ifdef WL_NAN
		/* cancel ongoing geofence RTT if there */
		if ((err = wl_cfgnan_suspend_geofence_rng_session(dev,
			NULL, RTT_GEO_SUSPN_HOST_DIR_RTT_TRIG, 0)) != BCME_OK) {
			goto exit;
		}
#endif /* WL_NAN */
	} else {
		err = BCME_BADARG;
		goto exit;
	}

	mutex_lock(&rtt_status->rtt_mutex);
	if (rtt_status->status != RTT_STOPPED) {
		DHD_RTT_ERR(("rtt is already started\n"));
		err = BCME_BUSY;
		goto exit;
	}
	memset(rtt_status->rtt_config.target_info, 0, TARGET_INFO_SIZE(RTT_MAX_TARGET_CNT));
	rtt_status->rtt_config.rtt_target_cnt = params->rtt_target_cnt;
	memcpy(rtt_status->rtt_config.target_info,
		params->target_info, TARGET_INFO_SIZE(params->rtt_target_cnt));
	rtt_status->status = RTT_STARTED;
	DHD_RTT_MEM(("dhd_rtt_set_cfg: RTT Started, target_cnt = %d\n", params->rtt_target_cnt));
	/* start to measure RTT from first device */
	/* find next target to trigger RTT */
	for (idx = rtt_status->cur_idx; idx < rtt_status->rtt_config.rtt_target_cnt; idx++) {
		/* skip the disabled device */
		if (rtt_status->rtt_config.target_info[idx].disable) {
			continue;
		} else {
			/* set the idx to cur_idx */
			rtt_status->cur_idx = idx;
			break;
		}
	}
	if (idx < rtt_status->rtt_config.rtt_target_cnt) {
		DHD_RTT(("rtt_status->cur_idx : %d\n", rtt_status->cur_idx));
		rtt_status->rtt_sched_reason = RTT_SCHED_HOST_TRIGGER;
		/* Cancel pending retry timer if any */
		if (delayed_work_pending(&rtt_status->rtt_retry_timer)) {
			cancel_delayed_work(&rtt_status->rtt_retry_timer);
		}
		schedule_work(&rtt_status->work);
	}
exit:
	mutex_unlock(&rtt_status->rtt_mutex);
	mutex_unlock(&rtt_status->rtt_work_mutex);
	return err;
}

#ifdef WL_NAN
void
dhd_rtt_initialize_geofence_cfg(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return;
	}

	GEOFENCE_RTT_LOCK(rtt_status);
	memset_s(&rtt_status->geofence_cfg, sizeof(rtt_status->geofence_cfg),
		0, sizeof(rtt_status->geofence_cfg));

	/* initialize non zero params of geofence cfg */
	rtt_status->geofence_cfg.cur_target_idx = DHD_RTT_INVALID_TARGET_INDEX;
	rtt_status->geofence_cfg.geofence_rtt_interval = DHD_RTT_RETRY_TIMER_INTERVAL_MS;
	GEOFENCE_RTT_UNLOCK(rtt_status);
	return;
}

#ifdef RTT_GEOFENCE_CONT
void
dhd_rtt_get_geofence_cont_ind(dhd_pub_t *dhd, bool* geofence_cont)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return;
	}
	GEOFENCE_RTT_LOCK(rtt_status);
	*geofence_cont = rtt_status->geofence_cfg.geofence_cont;
	GEOFENCE_RTT_UNLOCK(rtt_status);
}

void
dhd_rtt_set_geofence_cont_ind(dhd_pub_t *dhd, bool geofence_cont)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return;
	}
	GEOFENCE_RTT_LOCK(rtt_status);
	rtt_status->geofence_cfg.geofence_cont = geofence_cont;
	DHD_RTT(("dhd_rtt_set_geofence_cont_override, geofence_cont = %d\n",
		rtt_status->geofence_cfg.geofence_cont));
	GEOFENCE_RTT_UNLOCK(rtt_status);
}
#endif /* RTT_GEOFENCE_CONT */

#ifdef RTT_GEOFENCE_INTERVAL
void
dhd_rtt_set_geofence_rtt_interval(dhd_pub_t *dhd, int interval)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return;
	}
	GEOFENCE_RTT_LOCK(rtt_status);
	rtt_status->geofence_cfg.geofence_rtt_interval = interval;
	DHD_RTT(("dhd_rtt_set_geofence_rtt_interval: geofence interval = %d\n",
		rtt_status->geofence_cfg.geofence_rtt_interval));
	GEOFENCE_RTT_UNLOCK(rtt_status);
}
#endif /* RTT_GEOFENCE_INTERVAL */

/* sets geofence role concurrency state TRUE/FALSE */
void
dhd_rtt_set_role_concurrency_state(dhd_pub_t *dhd, bool state)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return;
	}
	GEOFENCE_RTT_LOCK(rtt_status);
	rtt_status->geofence_cfg.role_concurr_state = state;
	GEOFENCE_RTT_UNLOCK(rtt_status);
}

/* returns TRUE if geofence role concurrency constraint exists */
bool
dhd_rtt_get_role_concurrency_state(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return FALSE;
	}
	return rtt_status->geofence_cfg.role_concurr_state;
}

int8
dhd_rtt_get_geofence_target_cnt(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return 0;
	}
	return rtt_status->geofence_cfg.geofence_target_cnt;
}

/* sets geofence rtt state TRUE/FALSE */
void
dhd_rtt_set_geofence_rtt_state(dhd_pub_t *dhd, bool state)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	if (!rtt_status) {
		return;
	}
	GEOFENCE_RTT_LOCK(rtt_status);
	rtt_status->geofence_cfg.rtt_in_progress = state;
	GEOFENCE_RTT_UNLOCK(rtt_status);
}

/* returns TRUE if geofence rtt is in progress */
bool
dhd_rtt_get_geofence_rtt_state(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);

	if (!rtt_status) {
		return FALSE;
	}

	return rtt_status->geofence_cfg.rtt_in_progress;
}

/* returns geofence RTT target list Head */
rtt_geofence_target_info_t*
dhd_rtt_get_geofence_target_head(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	rtt_geofence_target_info_t* head = NULL;

	if (!rtt_status) {
		return NULL;
	}

	if (rtt_status->geofence_cfg.geofence_target_cnt) {
		head = &rtt_status->geofence_cfg.geofence_target_info[0];
	}

	return head;
}

int8
dhd_rtt_get_geofence_cur_target_idx(dhd_pub_t *dhd)
{
	int8 target_cnt = 0, cur_idx = DHD_RTT_INVALID_TARGET_INDEX;
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);

	if (!rtt_status) {
		goto exit;
	}

	target_cnt = rtt_status->geofence_cfg.geofence_target_cnt;
	if (target_cnt == 0) {
		goto exit;
	}

	cur_idx = rtt_status->geofence_cfg.cur_target_idx;
	ASSERT(cur_idx <= target_cnt);

exit:
	return cur_idx;
}

void
dhd_rtt_move_geofence_cur_target_idx_to_next(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);

	if (!rtt_status) {
		return;
	}

	if (rtt_status->geofence_cfg.geofence_target_cnt == 0) {
		/* Invalidate current idx if no targets */
		rtt_status->geofence_cfg.cur_target_idx =
			DHD_RTT_INVALID_TARGET_INDEX;
		/* Cancel pending retry timer if any */
		if (delayed_work_pending(&rtt_status->rtt_retry_timer)) {
			cancel_delayed_work(&rtt_status->rtt_retry_timer);
		}
		return;
	}
	rtt_status->geofence_cfg.cur_target_idx++;

	if (rtt_status->geofence_cfg.cur_target_idx >=
		rtt_status->geofence_cfg.geofence_target_cnt) {
		/* Reset once all targets done */
		rtt_status->geofence_cfg.cur_target_idx = 0;
	}
}

/* returns geofence current RTT target */
rtt_geofence_target_info_t*
dhd_rtt_get_geofence_current_target(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);
	rtt_geofence_target_info_t* cur_target = NULL;
	int cur_idx = 0;

	if (!rtt_status) {
		return NULL;
	}

	cur_idx = dhd_rtt_get_geofence_cur_target_idx(dhd);
	if (cur_idx >= 0) {
		cur_target = &rtt_status->geofence_cfg.geofence_target_info[cur_idx];
	}

	return cur_target;
}

/* returns geofence target from list for the peer */
rtt_geofence_target_info_t*
dhd_rtt_get_geofence_target(dhd_pub_t *dhd, struct ether_addr* peer_addr, int8 *index)
{
	int8 i;
	rtt_status_info_t *rtt_status;
	int target_cnt;
	rtt_geofence_target_info_t *geofence_target_info, *tgt = NULL;

	rtt_status = GET_RTTSTATE(dhd);

	if (!rtt_status) {
		return NULL;
	}

	target_cnt = rtt_status->geofence_cfg.geofence_target_cnt;
	geofence_target_info = rtt_status->geofence_cfg.geofence_target_info;

	/* Loop through to find target */
	for (i = 0; i < target_cnt; i++) {
		if (geofence_target_info[i].valid == FALSE) {
			break;
		}
		if (!memcmp(peer_addr, &geofence_target_info[i].peer_addr,
				ETHER_ADDR_LEN)) {
			*index = i;
			tgt = &geofence_target_info[i];
		}
	}
	if (!tgt) {
		DHD_RTT(("dhd_rtt_get_geofence_target: Target not found in list,"
			" MAC ADDR: "MACDBG" \n", MAC2STRDBG(peer_addr)));
	}
	return tgt;
}

/* add geofence target to the target list */
int
dhd_rtt_add_geofence_target(dhd_pub_t *dhd, rtt_geofence_target_info_t *target)
{
	int err = BCME_OK;
	rtt_status_info_t *rtt_status;
	rtt_geofence_target_info_t  *geofence_target_info;
	int8 geofence_target_cnt, index;

	NULL_CHECK(dhd, "dhd is NULL", err);
	rtt_status = GET_RTTSTATE(dhd);
	NULL_CHECK(rtt_status, "rtt_status is NULL", err);

	GEOFENCE_RTT_LOCK(rtt_status);

	/* Get the geofence_target via peer addr, index param is dumm here */
	geofence_target_info = dhd_rtt_get_geofence_target(dhd, &target->peer_addr, &index);
	if (geofence_target_info) {
		DHD_RTT(("Duplicate geofencing RTT add request dropped\n"));
		err = BCME_OK;
		goto exit;
	}

	geofence_target_cnt = rtt_status->geofence_cfg.geofence_target_cnt;
	if (geofence_target_cnt >= RTT_MAX_GEOFENCE_TARGET_CNT) {
		DHD_RTT(("Queue full, Geofencing RTT add request dropped\n"));
		err = BCME_NORESOURCE;
		goto exit;
	}

	/* Add Geofence RTT request and increment target count */
	geofence_target_info = rtt_status->geofence_cfg.geofence_target_info;
	/* src and dest buffer len same, pointers of same DS statically allocated */
	(void)memcpy_s(&geofence_target_info[geofence_target_cnt],
		sizeof(geofence_target_info[geofence_target_cnt]), target,
		sizeof(*target));
	geofence_target_info[geofence_target_cnt].valid = TRUE;
	rtt_status->geofence_cfg.geofence_target_cnt++;
	if (rtt_status->geofence_cfg.geofence_target_cnt == 1) {
		/* Adding first target */
		rtt_status->geofence_cfg.cur_target_idx = 0;
	}

exit:
	GEOFENCE_RTT_UNLOCK(rtt_status);
	return err;
}

/* removes geofence target from the target list */
int
dhd_rtt_remove_geofence_target(dhd_pub_t *dhd, struct ether_addr *peer_addr)
{
	int err = BCME_OK;
	rtt_status_info_t *rtt_status;
	rtt_geofence_target_info_t  *geofence_target_info;
	int8 geofence_target_cnt, j, index = 0;

	NULL_CHECK(dhd, "dhd is NULL", err);
	rtt_status = GET_RTTSTATE(dhd);
	NULL_CHECK(rtt_status, "rtt_status is NULL", err);

	GEOFENCE_RTT_LOCK(rtt_status);

	geofence_target_cnt = dhd_rtt_get_geofence_target_cnt(dhd);
	if (geofence_target_cnt == 0) {
		DHD_RTT(("Queue Empty, Geofencing RTT remove request dropped\n"));
		ASSERT(0);
		goto exit;
	}

	/* Get the geofence_target via peer addr */
	geofence_target_info = dhd_rtt_get_geofence_target(dhd, peer_addr, &index);
	if (geofence_target_info == NULL) {
		DHD_RTT(("Geofencing RTT target not found, remove request dropped\n"));
		err = BCME_NOTFOUND;
		goto exit;
	}

	/* left shift all the valid entries, as we dont keep holes in list */
	for (j = index; (j+1) < geofence_target_cnt; j++) {
		if (geofence_target_info[j].valid == TRUE) {
			/*
			 * src and dest buffer len same, pointers of same DS
			 * statically allocated
			 */
			(void)memcpy_s(&geofence_target_info[j], sizeof(geofence_target_info[j]),
				&geofence_target_info[j + 1],
				sizeof(geofence_target_info[j + 1]));
		} else {
			break;
		}
	}
	rtt_status->geofence_cfg.geofence_target_cnt--;
	if ((rtt_status->geofence_cfg.geofence_target_cnt == 0) ||
		(index == rtt_status->geofence_cfg.cur_target_idx)) {
		/* Move cur_idx to next target */
		dhd_rtt_move_geofence_cur_target_idx_to_next(dhd);
	} else if (index < rtt_status->geofence_cfg.cur_target_idx) {
		/* Decrement cur index if cur target position changed */
		rtt_status->geofence_cfg.cur_target_idx--;
	}

exit:
	GEOFENCE_RTT_UNLOCK(rtt_status);
	return err;
}

/* deletes/empty geofence target list */
int
dhd_rtt_delete_geofence_target_list(dhd_pub_t *dhd)
{
	rtt_status_info_t *rtt_status;

	int err = BCME_OK;

	NULL_CHECK(dhd, "dhd is NULL", err);
	rtt_status = GET_RTTSTATE(dhd);
	NULL_CHECK(rtt_status, "rtt_status is NULL", err);
	GEOFENCE_RTT_LOCK(rtt_status);
	memset_s(&rtt_status->geofence_cfg, sizeof(rtt_geofence_cfg_t),
		0, sizeof(rtt_geofence_cfg_t));
	GEOFENCE_RTT_UNLOCK(rtt_status);
	return err;
}

int
dhd_rtt_sched_geofencing_target(dhd_pub_t *dhd)
{
	rtt_geofence_target_info_t  *geofence_target_info;
	struct net_device *dev = dhd_linux_get_primary_netdev(dhd);
	int ret = BCME_OK;
	bool geofence_state;
	bool role_concurrency_state;
	u8 rtt_invalid_reason = RTT_STATE_VALID;
	struct bcm_cfg80211 *cfg = wl_get_cfg(dev);
	rtt_status_info_t *rtt_status = GET_RTTSTATE(dhd);

	NAN_MUTEX_LOCK();

	if ((cfg->nan_init_state == FALSE) ||
		(cfg->nan_enable == FALSE)) {
		ret = BCME_NOTENABLED;
		goto done;
	}
	geofence_state = dhd_rtt_get_geofence_rtt_state(dhd);
	role_concurrency_state = dhd_rtt_get_role_concurrency_state(dhd);

	DHD_RTT_ERR(("dhd_rtt_sched_geofencing_target: sched_reason = %d\n",
		rtt_status->rtt_sched_reason));

	if (geofence_state == TRUE || role_concurrency_state == TRUE) {
		ret = BCME_ERROR;
		DHD_RTT_ERR(("geofencing constraint , sched request dropped,"
			" geofence_state = %d, role_concurrency_state = %d\n",
			geofence_state, role_concurrency_state));
		goto done;
	}

	/* Get current geofencing target */
	geofence_target_info = dhd_rtt_get_geofence_current_target(dhd);

	/* call cfg API for trigerring geofencing RTT */
	if (geofence_target_info) {
		/* check for dp/others concurrency */
		rtt_invalid_reason = dhd_rtt_invalid_states(dev,
				&geofence_target_info->peer_addr);
		if (rtt_invalid_reason != RTT_STATE_VALID) {
			ret = BCME_BUSY;
			DHD_RTT_ERR(("DRV State is not valid for RTT, "
				"invalid_state = %d\n", rtt_invalid_reason));
			goto done;
		}

		ret = wl_cfgnan_trigger_geofencing_ranging(dev,
				&geofence_target_info->peer_addr);
		if (ret == BCME_OK) {
			dhd_rtt_set_geofence_rtt_state(dhd, TRUE);
		}
	} else {
		DHD_RTT(("No RTT target to schedule\n"));
		ret = BCME_NOTFOUND;
	}

done:
	NAN_MUTEX_UNLOCK();
	return ret;
}
#endif /* WL_NAN */

/*
 * Linux Wireless Extensions support
 *
 * Copyright (C) 2022 Broadcom Corporation
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
 * $Id: wl_iw.c 616333 2016-02-01 05:30:29Z $
 */

#if defined(USE_IW)
#define LINUX_PORT

#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>

#include <bcmutils.h>
#include <bcmendian.h>
#include <ethernet.h>

#include <linux/if_arp.h>
#include <asm/uaccess.h>
#include <wlioctl.h>
#ifdef WL_NAN
#include <wlioctl_utils.h>
#endif
#include <wl_iw.h>
#include <wl_android.h>
#ifdef WL_ESCAN
#include <wl_escan.h>
#endif
#include <dhd_config.h>

uint iw_msg_level = WL_ERROR_LEVEL;

#define WL_ERROR_MSG(x, args...) \
	do { \
		if (iw_msg_level & WL_ERROR_LEVEL) { \
			printk(KERN_ERR DHD_LOG_PREFIXS "WEXT-ERROR) %s : " x, __func__, ## args); \
		} \
	} while (0)
#define WL_TRACE_MSG(x, args...) \
	do { \
		if (iw_msg_level & WL_TRACE_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIXS "WEXT-TRACE) %s : " x, __func__, ## args); \
		} \
	} while (0)
#define WL_SCAN_MSG(x, args...) \
	do { \
		if (iw_msg_level & WL_SCAN_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIXS "WEXT-SCAN) %s : " x, __func__, ## args); \
		} \
	} while (0)
#define WL_WSEC_MSG(x, args...) \
	do { \
		if (iw_msg_level & WL_WSEC_LEVEL) { \
			printk(KERN_INFO DHD_LOG_PREFIXS "WEXT-WSEC) %s : " x, __func__, ## args); \
		} \
	} while (0)
#define WL_ERROR(x) WL_ERROR_MSG x
#define WL_TRACE(x) WL_TRACE_MSG x
#define WL_SCAN(x) WL_SCAN_MSG x
#define WL_WSEC(x) WL_WSEC_MSG x
 
#ifdef BCMWAPI_WPI
/* these items should evetually go into wireless.h of the linux system headfile dir */
#ifndef IW_ENCODE_ALG_SM4
#define IW_ENCODE_ALG_SM4 0x20
#endif

#ifndef IW_AUTH_WAPI_ENABLED
#define IW_AUTH_WAPI_ENABLED 0x20
#endif

#ifndef IW_AUTH_WAPI_VERSION_1
#define IW_AUTH_WAPI_VERSION_1	0x00000008
#endif

#ifndef IW_AUTH_CIPHER_SMS4
#define IW_AUTH_CIPHER_SMS4	0x00000020
#endif

#ifndef IW_AUTH_KEY_MGMT_WAPI_PSK
#define IW_AUTH_KEY_MGMT_WAPI_PSK 4
#endif

#ifndef IW_AUTH_KEY_MGMT_WAPI_CERT
#define IW_AUTH_KEY_MGMT_WAPI_CERT 8
#endif
#endif /* BCMWAPI_WPI */

/* Broadcom extensions to WEXT, linux upstream has obsoleted WEXT */
#ifndef IW_AUTH_KEY_MGMT_FT_802_1X
#define IW_AUTH_KEY_MGMT_FT_802_1X 0x04
#endif

#ifndef IW_AUTH_KEY_MGMT_FT_PSK
#define IW_AUTH_KEY_MGMT_FT_PSK 0x08
#endif

#ifndef IW_ENC_CAPA_FW_ROAM_ENABLE
#define IW_ENC_CAPA_FW_ROAM_ENABLE	0x00000020
#endif


/* FC9: wireless.h 2.6.25-14.fc9.i686 is missing these, even though WIRELESS_EXT is set to latest
 * version 22.
 */
#ifndef IW_ENCODE_ALG_PMK
#define IW_ENCODE_ALG_PMK 4
#endif
#ifndef IW_ENC_CAPA_4WAY_HANDSHAKE
#define IW_ENC_CAPA_4WAY_HANDSHAKE 0x00000010
#endif
/* End FC9. */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27))
#include <linux/rtnetlink.h>
#endif

extern bool wl_iw_conn_status_str(uint32 event_type, uint32 status,
	uint32 reason, char* stringBuf, uint buflen);

uint wl_msg_level = WL_ERROR_VAL;

#define MAX_WLIW_IOCTL_LEN WLC_IOCTL_MEDLEN

/* IOCTL swapping mode for Big Endian host with Little Endian dongle.  Default to off */
#define htod32(i) (i)
#define htod16(i) (i)
#define dtoh32(i) (i)
#define dtoh16(i) (i)
#define htodchanspec(i) (i)
#define dtohchanspec(i) (i)

extern struct iw_statistics *dhd_get_wireless_stats(struct net_device *dev);
extern int dhd_wait_pend8021x(struct net_device *dev);

#if WIRELESS_EXT < 19
#define IW_IOCTL_IDX(cmd)	((cmd) - SIOCIWFIRST)
#define IW_EVENT_IDX(cmd)	((cmd) - IWEVFIRST)
#endif /* WIRELESS_EXT < 19 */


#ifndef WL_ESCAN
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
#define DAEMONIZE(a)	do { \
		allow_signal(SIGKILL);	\
		allow_signal(SIGTERM);	\
	} while (0)
#elif ((LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)) && \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)))
#define DAEMONIZE(a) daemonize(a); \
	allow_signal(SIGKILL); \
	allow_signal(SIGTERM);
#else /* Linux 2.4 (w/o preemption patch) */
#define RAISE_RX_SOFTIRQ() \
	cpu_raise_softirq(smp_processor_id(), NET_RX_SOFTIRQ)
#define DAEMONIZE(a) daemonize(); \
	do { if (a) \
		strncpy(current->comm, a, MIN(sizeof(current->comm), (strlen(a) + 1))); \
	} while (0);
#endif /* LINUX_VERSION_CODE  */

#define ISCAN_STATE_IDLE   0
#define ISCAN_STATE_SCANING 1

/* the buf lengh can be WLC_IOCTL_MAXLEN (8K) to reduce iteration */
#define WLC_IW_ISCAN_MAXLEN   2048
typedef struct iscan_buf {
	struct iscan_buf * next;
	char   iscan_buf[WLC_IW_ISCAN_MAXLEN];
} iscan_buf_t;

typedef struct iscan_info {
	struct net_device *dev;
	timer_list_compat_t timer;
	uint32 timer_ms;
	uint32 timer_on;
	int    iscan_state;
	iscan_buf_t * list_hdr;
	iscan_buf_t * list_cur;

	/* Thread to work on iscan */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0))
	struct task_struct *kthread;
#endif
	long sysioc_pid;
	struct semaphore sysioc_sem;
	struct completion sysioc_exited;
	char ioctlbuf[WLC_IOCTL_SMLEN];
} iscan_info_t;
static void wl_iw_timerfunc(ulong data);
static void wl_iw_set_event_mask(struct net_device *dev);
static int wl_iw_iscan(iscan_info_t *iscan, wlc_ssid_t *ssid, uint16 action);
#endif /* !WL_ESCAN */

struct pmk_list {
	pmkid_list_t pmkids;
	pmkid_t foo[MAXPMKID - 1];
};

typedef struct wl_wext_info {
	struct net_device *dev;
	dhd_pub_t *dhd;
	struct delayed_work pm_enable_work;
	struct mutex pm_sync;
	struct wl_conn_info conn_info;
	struct pmk_list pmk_list;
#ifndef WL_ESCAN
	struct iscan_info iscan;
#endif
} wl_wext_info_t;

/* priv_link becomes netdev->priv and is the link between netdev and wlif struct */
typedef struct priv_link {
	wl_iw_t *wliw;
} priv_link_t;

/* dev to priv_link */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
#define WL_DEV_LINK(dev)       (priv_link_t*)(dev->priv)
#else
#ifdef CONFIG_AP6XXX_WIFI6_HDF
void * VOID_DEV_PRIV(struct net_device *dev);
#define WL_DEV_LINK(dev)       (priv_link_t*)VOID_DEV_PRIV(dev)
#else
#define WL_DEV_LINK(dev)       (priv_link_t*)netdev_priv(dev)
#endif
#endif

/* dev to wl_iw_t */
#define IW_DEV_IF(dev)          ((wl_iw_t*)(WL_DEV_LINK(dev))->wliw)

static void swap_key_from_BE(
	        wl_wsec_key_t *key
)
{
	key->index = htod32(key->index);
	key->len = htod32(key->len);
	key->algo = htod32(key->algo);
	key->flags = htod32(key->flags);
	key->rxiv.hi = htod32(key->rxiv.hi);
	key->rxiv.lo = htod16(key->rxiv.lo);
	key->iv_initialized = htod32(key->iv_initialized);
}

static void swap_key_to_BE(
	        wl_wsec_key_t *key
)
{
	key->index = dtoh32(key->index);
	key->len = dtoh32(key->len);
	key->algo = dtoh32(key->algo);
	key->flags = dtoh32(key->flags);
	key->rxiv.hi = dtoh32(key->rxiv.hi);
	key->rxiv.lo = dtoh16(key->rxiv.lo);
	key->iv_initialized = dtoh32(key->iv_initialized);
}

static int
dev_wlc_ioctl(
	struct net_device *dev,
	int cmd,
	void *arg,
	int len
)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	dhd_ioctl_t ioc;
	int8 index;
	int ret;

	memset(&ioc, 0, sizeof(ioc));
	ioc.cmd = cmd;
	ioc.buf = arg;
	ioc.len = len;

	index = dhd_net2idx(dhd->info, dev);
	if (index == DHD_BAD_IF) {
		WL_ERROR(("Bad ifidx from dev:%p\n", dev));
		return -ENODEV;
	}
	ret = dhd_ioctl_process(dhd, index, &ioc, arg);

	return ret;
}

/*
set named driver variable to int value and return error indication
calling example: dev_wlc_intvar_set(dev, "arate", rate)
*/

static int
dev_wlc_intvar_set(
	struct net_device *dev,
	char *name,
	int val)
{
	char buf[WLC_IOCTL_SMLEN];
	uint len;

	val = htod32(val);
	len = bcm_mkiovar(name, (char *)(&val), sizeof(val), buf, sizeof(buf));
	ASSERT(len);

	return (dev_wlc_ioctl(dev, WLC_SET_VAR, buf, len));
}

#ifndef WL_ESCAN
static int
dev_iw_iovar_setbuf(
	struct net_device *dev,
	char *iovar,
	void *param,
	int paramlen,
	void *bufptr,
	int buflen)
{
	int iolen;

	iolen = bcm_mkiovar(iovar, param, paramlen, bufptr, buflen);
	ASSERT(iolen);
	BCM_REFERENCE(iolen);

	return (dev_wlc_ioctl(dev, WLC_SET_VAR, bufptr, iolen));
}

static int
dev_iw_iovar_getbuf(
	struct net_device *dev,
	char *iovar,
	void *param,
	int paramlen,
	void *bufptr,
	int buflen)
{
	int iolen;

	iolen = bcm_mkiovar(iovar, param, paramlen, bufptr, buflen);
	ASSERT(iolen);
	BCM_REFERENCE(iolen);

	return (dev_wlc_ioctl(dev, WLC_GET_VAR, bufptr, buflen));
}
#endif

#if WIRELESS_EXT > 17
static int
dev_wlc_bufvar_set(
	struct net_device *dev,
	char *name,
	char *buf, int len)
{
	char *ioctlbuf;
	uint buflen;
	int error;

	ioctlbuf = kmalloc(MAX_WLIW_IOCTL_LEN, GFP_KERNEL);
	if (!ioctlbuf)
		return -ENOMEM;

	buflen = bcm_mkiovar(name, buf, len, ioctlbuf, MAX_WLIW_IOCTL_LEN);
	ASSERT(buflen);
	error = dev_wlc_ioctl(dev, WLC_SET_VAR, ioctlbuf, buflen);

	kfree(ioctlbuf);
	return error;
}
#endif /* WIRELESS_EXT > 17 */

/*
get named driver variable to int value and return error indication
calling example: dev_wlc_bufvar_get(dev, "arate", &rate)
*/

static int
dev_wlc_bufvar_get(
	struct net_device *dev,
	char *name,
	char *buf, int buflen)
{
	char *ioctlbuf;
	int error;

	uint len;

	ioctlbuf = kmalloc(MAX_WLIW_IOCTL_LEN, GFP_KERNEL);
	if (!ioctlbuf)
		return -ENOMEM;
	len = bcm_mkiovar(name, NULL, 0, ioctlbuf, MAX_WLIW_IOCTL_LEN);
	ASSERT(len);
	BCM_REFERENCE(len);
	error = dev_wlc_ioctl(dev, WLC_GET_VAR, (void *)ioctlbuf, MAX_WLIW_IOCTL_LEN);
	if (!error)
		bcopy(ioctlbuf, buf, buflen);

	kfree(ioctlbuf);
	return (error);
}

/*
get named driver variable to int value and return error indication
calling example: dev_wlc_intvar_get(dev, "arate", &rate)
*/

static int
dev_wlc_intvar_get(
	struct net_device *dev,
	char *name,
	int *retval)
{
	union {
		char buf[WLC_IOCTL_SMLEN];
		int val;
	} var;
	int error;

	uint len;
	uint data_null;

	len = bcm_mkiovar(name, (char *)(&data_null), 0, (char *)(&var), sizeof(var.buf));
	ASSERT(len);
	error = dev_wlc_ioctl(dev, WLC_GET_VAR, (void *)&var, len);

	*retval = dtoh32(var.val);

	return (error);
}

/* Maintain backward compatibility */
#if WIRELESS_EXT < 13
struct iw_request_info
{
	__u16		cmd;		/* Wireless Extension command */
	__u16		flags;		/* More to come ;-) */
};

typedef int (*iw_handler)(struct net_device *dev, struct iw_request_info *info,
	void *wrqu, char *extra);
#endif /* WIRELESS_EXT < 13 */

#if WIRELESS_EXT > 12
static int
wl_iw_set_leddc(
	struct net_device *dev,
	struct iw_request_info *info,
	union iwreq_data *wrqu,
	char *extra
)
{
	int dc = *(int *)extra;
	int error;

	error = dev_wlc_intvar_set(dev, "leddc", dc);
	return error;
}

static int
wl_iw_set_vlanmode(
	struct net_device *dev,
	struct iw_request_info *info,
	union iwreq_data *wrqu,
	char *extra
)
{
	int mode = *(int *)extra;
	int error;

	mode = htod32(mode);
	error = dev_wlc_intvar_set(dev, "vlan_mode", mode);
	return error;
}

static int
wl_iw_set_pm(
	struct net_device *dev,
	struct iw_request_info *info,
	union iwreq_data *wrqu,
	char *extra
)
{
	int pm = *(int *)extra;
	int error;

	pm = htod32(pm);
	error = dev_wlc_ioctl(dev, WLC_SET_PM, &pm, sizeof(pm));
	return error;
}
#endif /* WIRELESS_EXT > 12 */

int
wl_iw_send_priv_event(
	struct net_device *dev,
	char *flag
)
{
	union iwreq_data wrqu;
	char extra[IW_CUSTOM_MAX + 1];
	int cmd;

	cmd = IWEVCUSTOM;
	memset(&wrqu, 0, sizeof(wrqu));
	if (strlen(flag) > sizeof(extra))
		return -1;

	strncpy(extra, flag, sizeof(extra));
	extra[sizeof(extra) - 1] = '\0';
	wrqu.data.length = strlen(extra);
	wireless_send_event(dev, cmd, &wrqu, extra);
	WL_TRACE(("Send IWEVCUSTOM Event as %s\n", extra));

	return 0;
}

static int
wl_iw_config_commit(
	struct net_device *dev,
	struct iw_request_info *info,
	void *zwrq,
	char *extra
)
{
	wlc_ssid_t ssid;
	int error;
	struct sockaddr bssid;

	WL_TRACE(("%s: SIOCSIWCOMMIT\n", dev->name));

	if ((error = dev_wlc_ioctl(dev, WLC_GET_SSID, &ssid, sizeof(ssid))))
		return error;

	ssid.SSID_len = dtoh32(ssid.SSID_len);

	if (!ssid.SSID_len)
		return 0;

	bzero(&bssid, sizeof(struct sockaddr));
	if ((error = dev_wlc_ioctl(dev, WLC_REASSOC, &bssid, ETHER_ADDR_LEN))) {
		WL_ERROR(("WLC_REASSOC failed (%d)\n", error));
		return error;
	}

	return 0;
}

static int
wl_iw_get_name(
	struct net_device *dev,
	struct iw_request_info *info,
	union iwreq_data *cwrq,
	char *extra
)
{
	int phytype, err;
	uint band[3];
	char cap[5];

	WL_TRACE(("%s: SIOCGIWNAME\n", dev->name));

	cap[0] = 0;
	if ((err = dev_wlc_ioctl(dev, WLC_GET_PHYTYPE, &phytype, sizeof(phytype))) < 0)
		goto done;
	if ((err = dev_wlc_ioctl(dev, WLC_GET_BANDLIST, band, sizeof(band))) < 0)
		goto done;

	band[0] = dtoh32(band[0]);
	switch (phytype) {
		case WLC_PHY_TYPE_A:
			strncpy(cap, "a", sizeof(cap));
			break;
		case WLC_PHY_TYPE_B:
			strncpy(cap, "b", sizeof(cap));
			break;
		case WLC_PHY_TYPE_G:
			if (band[0] >= 2)
				strncpy(cap, "abg", sizeof(cap));
			else
				strncpy(cap, "bg", sizeof(cap));
			break;
		case WLC_PHY_TYPE_N:
			if (band[0] >= 2)
				strncpy(cap, "abgn", sizeof(cap));
			else
				strncpy(cap, "bgn", sizeof(cap));
			break;
	}
done:
	(void)snprintf(cwrq->name, IFNAMSIZ, "IEEE 802.11%s", cap);

	return 0;
}

#define DHD_CHECK(dhd, dev) \
 	if (!dhd) { \
		WL_ERROR (("[%s] dhd is NULL\n", dev->name)); \
		return -ENODEV; \
	} \

static int
wl_iw_set_freq(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_freq *fwrq,
	char *extra
)
{
	int error, chan;
	uint sf = 0;
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_wext_info_t *wext_info = NULL;

	WL_TRACE(("%s: SIOCSIWFREQ\n", dev->name));
	DHD_CHECK(dhd, dev);
	wext_info = dhd->wext_info;

	/* Setting by channel number */
	if (fwrq->e == 0 && fwrq->m < MAXCHANNEL) {
		chan = fwrq->m;
	}

	/* Setting by frequency */
	else {
		/* Convert to MHz as best we can */
		if (fwrq->e >= 6) {
			fwrq->e -= 6;
			while (fwrq->e--)
				fwrq->m *= 10;
		} else if (fwrq->e < 6) {
			while (fwrq->e++ < 6)
				fwrq->m /= 10;
		}
	/* handle 4.9GHz frequencies as Japan 4 GHz based channelization */
		if (fwrq->m > 4000 && fwrq->m < 5000) {
			sf = WF_CHAN_FACTOR_4_G; /* start factor for 4 GHz */
		}
		chan = wf_mhz2channel(fwrq->m, sf);
	}
	if (wext_info)
		wext_info->conn_info.channel = chan;
	WL_MSG(dev->name, "chan=%d\n", chan);
	chan = htod32(chan);
	if ((error = dev_wlc_ioctl(dev, WLC_SET_CHANNEL, &chan, sizeof(chan)))) {
		WL_ERROR(("WLC_SET_CHANNEL failed (%d).\n", error));
		return error;
	}

	/* -EINPROGRESS: Call commit handler */
	return -EINPROGRESS;
}

static int
wl_iw_get_freq(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_freq *fwrq,
	char *extra
)
{
	int error;
	u32 chanspec = 0;
	int ctl_chan;

	WL_TRACE(("%s: SIOCGIWFREQ\n", dev->name));

	if ((error = dev_wlc_intvar_get(dev, "chanspec", &chanspec)))
		return error;
	ctl_chan = wf_chspec_ctlchan(chanspec);

	/* Return radio channel in channel form */
	fwrq->m = ctl_chan;
	fwrq->e = dtoh32(0);
	return 0;
}

static int
wl_iw_set_mode(
	struct net_device *dev,
	struct iw_request_info *info,
	__u32 *uwrq,
	char *extra
)
{
	int infra = 0, ap = 0, error = 0;
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_wext_info_t *wext_info = NULL;

	WL_TRACE(("%s: SIOCSIWMODE\n", dev->name));
	DHD_CHECK(dhd, dev);
	wext_info = dhd->wext_info;
	if (wext_info) {
		memset(&wext_info->conn_info.ssid, 0, sizeof(wlc_ssid_t));
		memset(&wext_info->conn_info.bssid, 0, sizeof(struct ether_addr));
		wext_info->conn_info.channel = 0;
	}

	switch (*uwrq) {
	case IW_MODE_MASTER:
		infra = ap = 1;
		break;
	case IW_MODE_ADHOC:
	case IW_MODE_AUTO:
		break;
	case IW_MODE_INFRA:
		infra = 1;
		break;
	default:
		return -EINVAL;
	}
	infra = htod32(infra);
	ap = htod32(ap);

	if ((error = dev_wlc_ioctl(dev, WLC_SET_INFRA, &infra, sizeof(infra))) ||
	    (error = dev_wlc_ioctl(dev, WLC_SET_AP, &ap, sizeof(ap))))
		return error;

	/* -EINPROGRESS: Call commit handler */
	return -EINPROGRESS;
}

static int
wl_iw_get_mode(
	struct net_device *dev,
	struct iw_request_info *info,
	__u32 *uwrq,
	char *extra
)
{
	int error, infra = 0, ap = 0;

	WL_TRACE(("%s: SIOCGIWMODE\n", dev->name));

	if ((error = dev_wlc_ioctl(dev, WLC_GET_INFRA, &infra, sizeof(infra))) ||
	    (error = dev_wlc_ioctl(dev, WLC_GET_AP, &ap, sizeof(ap))))
		return error;

	infra = dtoh32(infra);
	ap = dtoh32(ap);
	*uwrq = infra ? ap ? IW_MODE_MASTER : IW_MODE_INFRA : IW_MODE_ADHOC;

	return 0;
}

static int
wl_iw_get_range(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_point *dwrq,
	char *extra
)
{
	struct iw_range *range = (struct iw_range *) extra;
	static int channels[MAXCHANNEL+1];
	wl_uint32_list_t *list = (wl_uint32_list_t *) channels;
	wl_rateset_t rateset;
	int error, i, k;
	uint sf, ch;

	int phytype;
	int bw_cap = 0, sgi_tx = 0, nmode = 0;
	channel_info_t ci;
	uint8 nrate_list2copy = 0;
	uint16 nrate_list[4][8] = { {13, 26, 39, 52, 78, 104, 117, 130},
		{14, 29, 43, 58, 87, 116, 130, 144},
		{27, 54, 81, 108, 162, 216, 243, 270},
		{30, 60, 90, 120, 180, 240, 270, 300}};
	int fbt_cap = 0;

	WL_TRACE(("%s: SIOCGIWRANGE\n", dev->name));

	if (!extra)
		return -EINVAL;

	dwrq->length = sizeof(struct iw_range);
	memset(range, 0, sizeof(*range));

	/* We don't use nwids */
	range->min_nwid = range->max_nwid = 0;

	/* Set available channels/frequencies */
	list->count = htod32(MAXCHANNEL);
	if ((error = dev_wlc_ioctl(dev, WLC_GET_VALID_CHANNELS, channels, sizeof(channels))))
		return error;
	for (i = 0; i < dtoh32(list->count) && i < IW_MAX_FREQUENCIES; i++) {
		range->freq[i].i = dtoh32(list->element[i]);

		ch = dtoh32(list->element[i]);
		if (ch <= CH_MAX_2G_CHANNEL)
			sf = WF_CHAN_FACTOR_2_4_G;
		else
			sf = WF_CHAN_FACTOR_5_G;

		range->freq[i].m = wf_channel2mhz(ch, sf);
		range->freq[i].e = 6;
	}
	range->num_frequency = range->num_channels = i;

	/* Link quality (use NDIS cutoffs) */
	range->max_qual.qual = 5;
	/* Signal level (use RSSI) */
	range->max_qual.level = 0x100 - 200;	/* -200 dBm */
	/* Noise level (use noise) */
	range->max_qual.noise = 0x100 - 200;	/* -200 dBm */
	/* Signal level threshold range (?) */
	range->sensitivity = 65535;

#if WIRELESS_EXT > 11
	/* Link quality (use NDIS cutoffs) */
	range->avg_qual.qual = 3;
	/* Signal level (use RSSI) */
	range->avg_qual.level = 0x100 + WL_IW_RSSI_GOOD;
	/* Noise level (use noise) */
	range->avg_qual.noise = 0x100 - 75;	/* -75 dBm */
#endif /* WIRELESS_EXT > 11 */

	/* Set available bitrates */
	if ((error = dev_wlc_ioctl(dev, WLC_GET_CURR_RATESET, &rateset, sizeof(rateset))))
		return error;
	rateset.count = dtoh32(rateset.count);
	range->num_bitrates = rateset.count;
	for (i = 0; i < rateset.count && i < IW_MAX_BITRATES; i++)
		range->bitrate[i] = (rateset.rates[i] & 0x7f) * 500000; /* convert to bps */
	if ((error = dev_wlc_intvar_get(dev, "nmode", &nmode)))
		return error;
	if ((error = dev_wlc_ioctl(dev, WLC_GET_PHYTYPE, &phytype, sizeof(phytype))))
		return error;
	if (nmode == 1 && (((phytype == WLC_PHY_TYPE_LCN) ||
	                    (phytype == WLC_PHY_TYPE_LCN40)))) {
		if ((error = dev_wlc_intvar_get(dev, "mimo_bw_cap", &bw_cap)))
			return error;
		if ((error = dev_wlc_intvar_get(dev, "sgi_tx", &sgi_tx)))
			return error;
		if ((error = dev_wlc_ioctl(dev, WLC_GET_CHANNEL, &ci, sizeof(channel_info_t))))
			return error;
		ci.hw_channel = dtoh32(ci.hw_channel);

		if (bw_cap == 0 ||
			(bw_cap == 2 && ci.hw_channel <= 14)) {
			if (sgi_tx == 0)
				nrate_list2copy = 0;
			else
				nrate_list2copy = 1;
		}
		if (bw_cap == 1 ||
			(bw_cap == 2 && ci.hw_channel >= 36)) {
			if (sgi_tx == 0)
				nrate_list2copy = 2;
			else
				nrate_list2copy = 3;
		}
		range->num_bitrates += 8;
		ASSERT(range->num_bitrates < IW_MAX_BITRATES);
		for (k = 0; i < range->num_bitrates; k++, i++) {
			/* convert to bps */
			range->bitrate[i] = (nrate_list[nrate_list2copy][k]) * 500000;
		}
	}

	/* Set an indication of the max TCP throughput
	 * in bit/s that we can expect using this interface.
	 * May be use for QoS stuff... Jean II
	 */
	if ((error = dev_wlc_ioctl(dev, WLC_GET_PHYTYPE, &i, sizeof(i))))
		return error;
	i = dtoh32(i);
	if (i == WLC_PHY_TYPE_A)
		range->throughput = 24000000;	/* 24 Mbits/s */
	else
		range->throughput = 1500000;	/* 1.5 Mbits/s */

	/* RTS and fragmentation thresholds */
	range->min_rts = 0;
	range->max_rts = 2347;
	range->min_frag = 256;
	range->max_frag = 2346;

	range->max_encoding_tokens = DOT11_MAX_DEFAULT_KEYS;
	range->num_encoding_sizes = 4;
	range->encoding_size[0] = WEP1_KEY_SIZE;
	range->encoding_size[1] = WEP128_KEY_SIZE;
#if WIRELESS_EXT > 17
	range->encoding_size[2] = TKIP_KEY_SIZE;
#else
	range->encoding_size[2] = 0;
#endif
	range->encoding_size[3] = AES_KEY_SIZE;

	/* Do not support power micro-management */
	range->min_pmp = 0;
	range->max_pmp = 0;
	range->min_pmt = 0;
	range->max_pmt = 0;
	range->pmp_flags = 0;
	range->pm_capa = 0;

	/* Transmit Power - values are in mW */
	range->num_txpower = 2;
	range->txpower[0] = 1;
	range->txpower[1] = 255;
	range->txpower_capa = IW_TXPOW_MWATT;

#if WIRELESS_EXT > 10
	range->we_version_compiled = WIRELESS_EXT;
	range->we_version_source = 19;

	/* Only support retry limits */
	range->retry_capa = IW_RETRY_LIMIT;
	range->retry_flags = IW_RETRY_LIMIT;
	range->r_time_flags = 0;
	/* SRL and LRL limits */
	range->min_retry = 1;
	range->max_retry = 255;
	/* Retry lifetime limits unsupported */
	range->min_r_time = 0;
	range->max_r_time = 0;
#endif /* WIRELESS_EXT > 10 */

#if WIRELESS_EXT > 17
	range->enc_capa = IW_ENC_CAPA_WPA;
	range->enc_capa |= IW_ENC_CAPA_CIPHER_TKIP;
	range->enc_capa |= IW_ENC_CAPA_CIPHER_CCMP;
	range->enc_capa |= IW_ENC_CAPA_WPA2;

	/* Determine driver FBT capability. */
	if (dev_wlc_intvar_get(dev, "fbt_cap", &fbt_cap) == 0) {
		if (fbt_cap == WLC_FBT_CAP_DRV_4WAY_AND_REASSOC) {
			/* Tell the host (e.g. wpa_supplicant) to let driver do the handshake */
//			range->enc_capa |= IW_ENC_CAPA_4WAY_HANDSHAKE;
		}
	}

#ifdef BCMFW_ROAM_ENABLE_WEXT
	/* Advertise firmware roam capability to the external supplicant */
	range->enc_capa |= IW_ENC_CAPA_FW_ROAM_ENABLE;
#endif /* BCMFW_ROAM_ENABLE_WEXT */

	/* Event capability (kernel) */
	IW_EVENT_CAPA_SET_KERNEL(range->event_capa);
	/* Event capability (driver) */
	IW_EVENT_CAPA_SET(range->event_capa, SIOCGIWAP);
	IW_EVENT_CAPA_SET(range->event_capa, SIOCGIWSCAN);
	IW_EVENT_CAPA_SET(range->event_capa, IWEVTXDROP);
	IW_EVENT_CAPA_SET(range->event_capa, IWEVMICHAELMICFAILURE);
	IW_EVENT_CAPA_SET(range->event_capa, IWEVASSOCREQIE);
	IW_EVENT_CAPA_SET(range->event_capa, IWEVASSOCRESPIE);
	IW_EVENT_CAPA_SET(range->event_capa, IWEVPMKIDCAND);

#if WIRELESS_EXT >= 22 && defined(IW_SCAN_CAPA_ESSID)
	/* FC7 wireless.h defines EXT 22 but doesn't define scan_capa bits */
	range->scan_capa = IW_SCAN_CAPA_ESSID;
#endif
#endif /* WIRELESS_EXT > 17 */

	return 0;
}

#ifndef WL_ESCAN
static int
rssi_to_qual(int rssi)
{
	if (rssi <= WL_IW_RSSI_NO_SIGNAL)
		return 0;
	else if (rssi <= WL_IW_RSSI_VERY_LOW)
		return 1;
	else if (rssi <= WL_IW_RSSI_LOW)
		return 2;
	else if (rssi <= WL_IW_RSSI_GOOD)
		return 3;
	else if (rssi <= WL_IW_RSSI_VERY_GOOD)
		return 4;
	else
		return 5;
}
#endif /* WL_ESCAN */

static int
wl_iw_set_spy(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_point *dwrq,
	char *extra
)
{
	wl_iw_t *iw = IW_DEV_IF(dev);
	struct sockaddr *addr = (struct sockaddr *) extra;
	int i;

	WL_TRACE(("%s: SIOCSIWSPY\n", dev->name));

	if (!extra)
		return -EINVAL;

	iw->spy_num = MIN(ARRAYSIZE(iw->spy_addr), dwrq->length);
	for (i = 0; i < iw->spy_num; i++)
		memcpy(&iw->spy_addr[i], addr[i].sa_data, ETHER_ADDR_LEN);
	memset(iw->spy_qual, 0, sizeof(iw->spy_qual));

	return 0;
}

static int
wl_iw_get_spy(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_point *dwrq,
	char *extra
)
{
	wl_iw_t *iw = IW_DEV_IF(dev);
	struct sockaddr *addr = (struct sockaddr *) extra;
	struct iw_quality *qual = (struct iw_quality *) &addr[iw->spy_num];
	int i;

	WL_TRACE(("%s: SIOCGIWSPY\n", dev->name));

	if (!extra)
		return -EINVAL;

	dwrq->length = iw->spy_num;
	for (i = 0; i < iw->spy_num; i++) {
		memcpy(addr[i].sa_data, &iw->spy_addr[i], ETHER_ADDR_LEN);
		addr[i].sa_family = AF_UNIX;
		memcpy(&qual[i], &iw->spy_qual[i], sizeof(struct iw_quality));
		iw->spy_qual[i].updated = 0;
	}

	return 0;
}

static int
wl_iw_set_wap(
	struct net_device *dev,
	struct iw_request_info *info,
	struct sockaddr *awrq,
	char *extra
)
{
	int error = -EINVAL;
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_wext_info_t *wext_info = NULL;

	WL_TRACE(("%s: SIOCSIWAP\n", dev->name));
	DHD_CHECK(dhd, dev);
 	wext_info = dhd->wext_info;
	if (awrq->sa_family != ARPHRD_ETHER) {
		WL_ERROR(("Invalid Header...sa_family\n"));
		return -EINVAL;
	}

	/* Ignore "auto" or "off" */
	if (ETHER_ISBCAST(awrq->sa_data) || ETHER_ISNULLADDR(awrq->sa_data)) {
		scb_val_t scbval;
		bzero(&scbval, sizeof(scb_val_t));
		WL_MSG(dev->name, "WLC_DISASSOC\n");
		if ((error = dev_wlc_ioctl(dev, WLC_DISASSOC, &scbval, sizeof(scb_val_t)))) {
			WL_ERROR(("WLC_DISASSOC failed (%d).\n", error));
		}
#ifdef WL_EXT_IAPSTA
		wl_ext_in4way_sync_wext(dev,
			STA_NO_SCAN_IN4WAY|STA_NO_BTC_IN4WAY|STA_WAIT_DISCONNECTED,
			WL_EXT_STATUS_DISCONNECTING, NULL);
#endif
		return 0;
	}
	/* WL_ASSOC(("Assoc to %s\n", bcm_ether_ntoa((struct ether_addr *)&(awrq->sa_data),
	 * eabuf)));
	 */
	/* Reassociate to the specified AP */
	if (wext_info)
		memcpy(&wext_info->conn_info.bssid, awrq->sa_data, ETHER_ADDR_LEN);
	if (wext_info && wext_info->conn_info.ssid.SSID_len) {
		if ((error = wl_ext_connect(dev, &wext_info->conn_info)))
			return error;
	} else {
		if ((error = dev_wlc_ioctl(dev, WLC_REASSOC, awrq->sa_data, ETHER_ADDR_LEN))) {
			WL_ERROR(("WLC_REASSOC failed (%d).\n", error));
			return error;
		}
		WL_MSG(dev->name, "join BSSID="MACSTR"\n", MAC2STR((u8 *)awrq->sa_data));
	}
#ifdef WL_EXT_IAPSTA
	wl_ext_in4way_sync_wext(dev, STA_NO_SCAN_IN4WAY|STA_NO_BTC_IN4WAY,
		WL_EXT_STATUS_CONNECTING, NULL);
#endif

	return 0;
}

static int
wl_iw_get_wap(
	struct net_device *dev,
	struct iw_request_info *info,
	struct sockaddr *awrq,
	char *extra
)
{
	WL_TRACE(("%s: SIOCGIWAP\n", dev->name));

	awrq->sa_family = ARPHRD_ETHER;
	memset(awrq->sa_data, 0, ETHER_ADDR_LEN);

	/* Ignore error (may be down or disassociated) */
	(void) dev_wlc_ioctl(dev, WLC_GET_BSSID, awrq->sa_data, ETHER_ADDR_LEN);

	return 0;
}

#if WIRELESS_EXT > 17
static int
wl_iw_mlme(
	struct net_device *dev,
	struct iw_request_info *info,
	struct sockaddr *awrq,
	char *extra
)
{
	struct iw_mlme *mlme;
	scb_val_t scbval;
	int error  = -EINVAL;

	WL_TRACE(("%s: SIOCSIWMLME\n", dev->name));

	mlme = (struct iw_mlme *)extra;
	if (mlme == NULL) {
		WL_ERROR(("Invalid ioctl data.\n"));
		return error;
	}

	scbval.val = mlme->reason_code;
	bcopy(&mlme->addr.sa_data, &scbval.ea, ETHER_ADDR_LEN);

	if (mlme->cmd == IW_MLME_DISASSOC) {
		scbval.val = htod32(scbval.val);
		WL_MSG(dev->name, "WLC_DISASSOC\n");
		error = dev_wlc_ioctl(dev, WLC_DISASSOC, &scbval, sizeof(scb_val_t));
	}
	else if (mlme->cmd == IW_MLME_DEAUTH) {
		scbval.val = htod32(scbval.val);
		WL_MSG(dev->name, "WLC_SCB_DEAUTHENTICATE_FOR_REASON\n");
		error = dev_wlc_ioctl(dev, WLC_SCB_DEAUTHENTICATE_FOR_REASON, &scbval,
			sizeof(scb_val_t));
	}
	else {
		WL_ERROR(("Invalid ioctl data.\n"));
		return error;
	}
#ifdef WL_EXT_IAPSTA
	wl_ext_in4way_sync_wext(dev,
			STA_NO_SCAN_IN4WAY|STA_NO_BTC_IN4WAY|STA_WAIT_DISCONNECTED,
			WL_EXT_STATUS_DISCONNECTING, NULL);
#endif

	return error;
}
#endif /* WIRELESS_EXT > 17 */

#ifndef WL_ESCAN
static int
wl_iw_get_aplist(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_point *dwrq,
	char *extra
)
{
	wl_scan_results_t *list;
	struct sockaddr *addr = (struct sockaddr *) extra;
	struct iw_quality qual[IW_MAX_AP];
	wl_bss_info_t *bi = NULL;
	int error, i;
	uint buflen = dwrq->length;
	int16 rssi;

	WL_TRACE(("%s: SIOCGIWAPLIST\n", dev->name));

	if (!extra)
		return -EINVAL;

	/* Get scan results (too large to put on the stack) */
	list = kmalloc(buflen, GFP_KERNEL);
	if (!list)
		return -ENOMEM;
	memset(list, 0, buflen);
	list->buflen = htod32(buflen);
	if ((error = dev_wlc_ioctl(dev, WLC_SCAN_RESULTS, list, buflen))) {
		WL_ERROR(("%d: Scan results error %d\n", __LINE__, error));
		kfree(list);
		return error;
	}
	list->buflen = dtoh32(list->buflen);
	list->version = dtoh32(list->version);
	list->count = dtoh32(list->count);
	ASSERT(list->version == WL_BSS_INFO_VERSION);

	for (i = 0, dwrq->length = 0; i < list->count && dwrq->length < IW_MAX_AP; i++) {
		bi = bi ? (wl_bss_info_t *)((uintptr)bi + dtoh32(bi->length)) : list->bss_info;
		ASSERT(((uintptr)bi + dtoh32(bi->length)) <= ((uintptr)list +
			buflen));

		/* Infrastructure only */
		if (!(dtoh16(bi->capability) & DOT11_CAP_ESS))
			continue;

		/* BSSID */
		memcpy(addr[dwrq->length].sa_data, &bi->BSSID, ETHER_ADDR_LEN);
		addr[dwrq->length].sa_family = ARPHRD_ETHER;
		// terence 20150419: limit the max. rssi to -2 or the bss will be filtered out in android OS
		rssi = MIN(dtoh16(bi->RSSI), RSSI_MAXVAL);
		qual[dwrq->length].qual = rssi_to_qual(rssi);
		qual[dwrq->length].level = 0x100 + rssi;
		qual[dwrq->length].noise = 0x100 + bi->phy_noise;

		/* Updated qual, level, and noise */
#if WIRELESS_EXT > 18
		qual[dwrq->length].updated = IW_QUAL_ALL_UPDATED | IW_QUAL_DBM;
#else
		qual[dwrq->length].updated = 7;
#endif /* WIRELESS_EXT > 18 */

		dwrq->length++;
	}

	kfree(list);

	if (dwrq->length) {
		memcpy(&addr[dwrq->length], qual, sizeof(struct iw_quality) * dwrq->length);
		/* Provided qual */
		dwrq->flags = 1;
	}

	return 0;
}

static int
wl_iw_iscan_get_aplist(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_point *dwrq,
	char *extra
)
{
	wl_scan_results_t *list;
	iscan_buf_t * buf;
	iscan_info_t *iscan;

	struct sockaddr *addr = (struct sockaddr *) extra;
	struct iw_quality qual[IW_MAX_AP];
	wl_bss_info_t *bi = NULL;
	int i;
	int16 rssi;
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_wext_info_t *wext_info = NULL;

	WL_TRACE(("%s: SIOCGIWAPLIST\n", dev->name));
	DHD_CHECK(dhd, dev);
 	wext_info = dhd->wext_info;
	iscan = &wext_info->iscan;

	if (!extra)
		return -EINVAL;

	if ((!iscan) || (iscan->sysioc_pid < 0)) {
		return wl_iw_get_aplist(dev, info, dwrq, extra);
	}

	buf = iscan->list_hdr;
	/* Get scan results (too large to put on the stack) */
	while (buf) {
	    list = &((wl_iscan_results_t*)buf->iscan_buf)->results;
	    ASSERT(list->version == WL_BSS_INFO_VERSION);

	    bi = NULL;
	for (i = 0, dwrq->length = 0; i < list->count && dwrq->length < IW_MAX_AP; i++) {
		bi = bi ? (wl_bss_info_t *)((uintptr)bi + dtoh32(bi->length)) : list->bss_info;
		ASSERT(((uintptr)bi + dtoh32(bi->length)) <= ((uintptr)list +
			WLC_IW_ISCAN_MAXLEN));

		/* Infrastructure only */
		if (!(dtoh16(bi->capability) & DOT11_CAP_ESS))
			continue;

		/* BSSID */
		memcpy(addr[dwrq->length].sa_data, &bi->BSSID, ETHER_ADDR_LEN);
		addr[dwrq->length].sa_family = ARPHRD_ETHER;
		// terence 20150419: limit the max. rssi to -2 or the bss will be filtered out in android OS
		rssi = MIN(dtoh16(bi->RSSI), RSSI_MAXVAL);
		qual[dwrq->length].qual = rssi_to_qual(rssi);
		qual[dwrq->length].level = 0x100 + rssi;
		qual[dwrq->length].noise = 0x100 + bi->phy_noise;

		/* Updated qual, level, and noise */
#if WIRELESS_EXT > 18
		qual[dwrq->length].updated = IW_QUAL_ALL_UPDATED | IW_QUAL_DBM;
#else
		qual[dwrq->length].updated = 7;
#endif /* WIRELESS_EXT > 18 */

		dwrq->length++;
	    }
	    buf = buf->next;
	}
	if (dwrq->length) {
		memcpy(&addr[dwrq->length], qual, sizeof(struct iw_quality) * dwrq->length);
		/* Provided qual */
		dwrq->flags = 1;
	}

	return 0;
}
#endif

#if WIRELESS_EXT > 13
#ifndef WL_ESCAN
static int
wl_iw_set_scan(
	struct net_device *dev,
	struct iw_request_info *info,
	union iwreq_data *wrqu,
	char *extra
)
{
	wlc_ssid_t ssid;

	WL_TRACE(("%s: SIOCSIWSCAN\n", dev->name));

	/* default Broadcast scan */
	memset(&ssid, 0, sizeof(ssid));

#if WIRELESS_EXT > 17
	/* check for given essid */
	if (wrqu->data.length == sizeof(struct iw_scan_req)) {
		if (wrqu->data.flags & IW_SCAN_THIS_ESSID) {
			struct iw_scan_req *req = (struct iw_scan_req *)extra;
			ssid.SSID_len = MIN(sizeof(ssid.SSID), req->essid_len);
			memcpy(ssid.SSID, req->essid, ssid.SSID_len);
			ssid.SSID_len = htod32(ssid.SSID_len);
		}
	}
#endif
	/* Ignore error (most likely scan in progress) */
	(void) dev_wlc_ioctl(dev, WLC_SCAN, &ssid, sizeof(ssid));

	return 0;
}
#endif

static int
wl_iw_iscan_set_scan(
	struct net_device *dev,
	struct iw_request_info *info,
	union iwreq_data *wrqu,
	char *extra
)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_wext_info_t *wext_info = NULL;
	wlc_ssid_t ssid;
#ifdef WL_ESCAN
	wl_scan_info_t scan_info;
#else
	iscan_info_t *iscan;
#ifdef WL_EXT_IAPSTA
	int err;
#endif
#endif

	DHD_CHECK(dhd, dev);
	wext_info = dhd->wext_info;
#ifdef WL_ESCAN
	/* default Broadcast scan */
	memset(&ssid, 0, sizeof(ssid));
#if WIRELESS_EXT > 17
	/* check for given essid */
	if (wrqu->data.length == sizeof(struct iw_scan_req)) {
		if (wrqu->data.flags & IW_SCAN_THIS_ESSID) {
			struct iw_scan_req *req = (struct iw_scan_req *)extra;
			ssid.SSID_len = MIN(sizeof(ssid.SSID), req->essid_len);
			memcpy(ssid.SSID, req->essid, ssid.SSID_len);
			ssid.SSID_len = htod32(ssid.SSID_len);
		}
	}
#endif
	memset(&scan_info, 0, sizeof(wl_scan_info_t));
	scan_info.bcast_ssid = TRUE;
	memcpy(scan_info.ssid.SSID, ssid.SSID, ssid.SSID_len);
	scan_info.ssid.SSID_len = ssid.SSID_len;
	return wl_escan_set_scan(dev, &scan_info);
#else
	iscan = &wext_info->iscan;
	WL_TRACE(("%s: SIOCSIWSCAN iscan=%p\n", dev->name, iscan));
#ifdef WL_EXT_IAPSTA
	err = wl_ext_in4way_sync_wext(dev, STA_NO_SCAN_IN4WAY, WL_EXT_STATUS_SCAN, NULL);
	if (err)
		return err;
#endif

	/* use backup if our thread is not successful */
	if ((!iscan) || (iscan->sysioc_pid < 0)) {
		return wl_iw_set_scan(dev, info, wrqu, extra);
	}
	if (iscan->iscan_state == ISCAN_STATE_SCANING) {
		return 0;
	}

	/* default Broadcast scan */
	memset(&ssid, 0, sizeof(ssid));

#if WIRELESS_EXT > 17
	/* check for given essid */
	if (wrqu->data.length == sizeof(struct iw_scan_req)) {
		if (wrqu->data.flags & IW_SCAN_THIS_ESSID) {
			struct iw_scan_req *req = (struct iw_scan_req *)extra;
			ssid.SSID_len = MIN(sizeof(ssid.SSID), req->essid_len);
			memcpy(ssid.SSID, req->essid, ssid.SSID_len);
			ssid.SSID_len = htod32(ssid.SSID_len);
		}
	}
#endif

	iscan->list_cur = iscan->list_hdr;
	iscan->iscan_state = ISCAN_STATE_SCANING;


	wl_iw_set_event_mask(dev);
	wl_iw_iscan(iscan, &ssid, WL_SCAN_ACTION_START);

	iscan->timer.expires = jiffies + msecs_to_jiffies(iscan->timer_ms);
	add_timer(&iscan->timer);
	iscan->timer_on = 1;

	return 0;
#endif
}

#if WIRELESS_EXT > 17
static bool
ie_is_wpa_ie(uint8 **wpaie, uint8 **tlvs, int *tlvs_len)
{
/* Is this body of this tlvs entry a WPA entry? If */
/* not update the tlvs buffer pointer/length */
	uint8 *ie = *wpaie;

	/* If the contents match the WPA_OUI and type=1 */
	if ((ie[1] >= 6) &&
		!bcmp((const void *)&ie[2], (const void *)(WPA_OUI "\x01"), 4)) {
		return TRUE;
	}

	/* point to the next ie */
	ie += ie[1] + 2;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;
	return FALSE;
}

static bool
ie_is_wps_ie(uint8 **wpsie, uint8 **tlvs, int *tlvs_len)
{
/* Is this body of this tlvs entry a WPS entry? If */
/* not update the tlvs buffer pointer/length */
	uint8 *ie = *wpsie;

	/* If the contents match the WPA_OUI and type=4 */
	if ((ie[1] >= 4) &&
		!bcmp((const void *)&ie[2], (const void *)(WPA_OUI "\x04"), 4)) {
		return TRUE;
	}

	/* point to the next ie */
	ie += ie[1] + 2;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;
	return FALSE;
}
#endif /* WIRELESS_EXT > 17 */

#ifdef BCMWAPI_WPI
static inline int _wpa_snprintf_hex(char *buf, size_t buf_size, const u8 *data,
	size_t len, int uppercase)
{
	size_t i;
	char *pos = buf, *end = buf + buf_size;
	int ret;
	if (buf_size == 0)
		return 0;
	for (i = 0; i < len; i++) {
		ret = snprintf(pos, end - pos, uppercase ? "%02X" : "%02x",
			data[i]);
		if (ret < 0 || ret >= end - pos) {
			end[-1] = '\0';
			return pos - buf;
		}
		pos += ret;
	}
	end[-1] = '\0';
	return pos - buf;
}

/**
 * wpa_snprintf_hex - Print data as a hex string into a buffer
 * @buf: Memory area to use as the output buffer
 * @buf_size: Maximum buffer size in bytes (should be at least 2 * len + 1)
 * @data: Data to be printed
 * @len: Length of data in bytes
 * Returns: Number of bytes written
 */
static int
wpa_snprintf_hex(char *buf, size_t buf_size, const u8 *data, size_t len)
{
	return _wpa_snprintf_hex(buf, buf_size, data, len, 0);
}
#endif /* BCMWAPI_WPI */

#ifndef WL_ESCAN
static
#endif
int
wl_iw_handle_scanresults_ies(char **event_p, char *end,
	struct iw_request_info *info, wl_bss_info_t *bi)
{
#if WIRELESS_EXT > 17
	struct iw_event	iwe;
	char *event;
#ifdef BCMWAPI_WPI
	char *buf;
	int custom_event_len;
#endif

	event = *event_p;
	if (bi->ie_length) {
		/* look for wpa/rsn ies in the ie list... */
		bcm_tlv_t *ie;
		uint8 *ptr = ((uint8 *)bi) + bi->ie_offset;
		int ptr_len = bi->ie_length;

		/* OSEN IE */
		if ((ie = bcm_parse_tlvs(ptr, ptr_len, DOT11_MNG_VS_ID)) &&
			ie->len > WFA_OUI_LEN + 1 &&
			!bcmp((const void *)&ie->data[0], (const void *)WFA_OUI, WFA_OUI_LEN) &&
			ie->data[WFA_OUI_LEN] == WFA_OUI_TYPE_OSEN) {
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = ie->len + 2;
			event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)ie);
		}
		ptr = ((uint8 *)bi) + bi->ie_offset;

		if ((ie = bcm_parse_tlvs(ptr, ptr_len, DOT11_MNG_RSN_ID))) {
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = ie->len + 2;
			event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)ie);
		}
		ptr = ((uint8 *)bi) + bi->ie_offset;

		if ((ie = bcm_parse_tlvs(ptr, ptr_len, DOT11_MNG_MDIE_ID))) {
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = ie->len + 2;
			event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)ie);
		}
		ptr = ((uint8 *)bi) + bi->ie_offset;

		while ((ie = bcm_parse_tlvs(ptr, ptr_len, DOT11_MNG_WPA_ID))) {
			/* look for WPS IE */
			if (ie_is_wps_ie(((uint8 **)&ie), &ptr, &ptr_len)) {
				iwe.cmd = IWEVGENIE;
				iwe.u.data.length = ie->len + 2;
				event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)ie);
				break;
			}
		}

		ptr = ((uint8 *)bi) + bi->ie_offset;
		ptr_len = bi->ie_length;
		while ((ie = bcm_parse_tlvs(ptr, ptr_len, DOT11_MNG_WPA_ID))) {
			if (ie_is_wpa_ie(((uint8 **)&ie), &ptr, &ptr_len)) {
				iwe.cmd = IWEVGENIE;
				iwe.u.data.length = ie->len + 2;
				event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)ie);
				break;
			}
		}
		
#ifdef BCMWAPI_WPI
		ptr = ((uint8 *)bi) + sizeof(wl_bss_info_t);
		ptr_len = bi->ie_length;

		while ((ie = bcm_parse_tlvs(ptr, ptr_len, DOT11_MNG_WAPI_ID))) {
			WL_TRACE(("found a WAPI IE...\n"));
#ifdef WAPI_IE_USE_GENIE
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = ie->len + 2;
			event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)ie);
#else /* using CUSTOM event */
			iwe.cmd = IWEVCUSTOM;
			custom_event_len = strlen("wapi_ie=") + 2*(ie->len + 2);
			iwe.u.data.length = custom_event_len;

			buf = kmalloc(custom_event_len+1, GFP_KERNEL);
			if (buf == NULL)
			{
				WL_ERROR(("malloc(%d) returned NULL...\n", custom_event_len));
				break;
			}

			memcpy(buf, "wapi_ie=", 8);
			wpa_snprintf_hex(buf + 8, 2+1, &(ie->id), 1);
			wpa_snprintf_hex(buf + 10, 2+1, &(ie->len), 1);
			wpa_snprintf_hex(buf + 12, 2*ie->len+1, ie->data, ie->len);
			event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, buf);
			kfree(buf);
#endif /* WAPI_IE_USE_GENIE */
			break;
		}
#endif /* BCMWAPI_WPI */
		*event_p = event;
	}

#endif /* WIRELESS_EXT > 17 */
	return 0;
}

#ifndef WL_ESCAN
static int
wl_iw_get_scan(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_point *dwrq,
	char *extra
)
{
	channel_info_t ci;
	wl_scan_results_t *list;
	struct iw_event	iwe;
	wl_bss_info_t *bi = NULL;
	int error, i, j;
	char *event = extra, *end = extra + dwrq->length, *value;
	uint buflen = dwrq->length;
	int16 rssi;
	int channel;

	WL_TRACE(("%s SIOCGIWSCAN\n", dev->name));

	if (!extra)
		return -EINVAL;

	/* Check for scan in progress */
	if ((error = dev_wlc_ioctl(dev, WLC_GET_CHANNEL, &ci, sizeof(ci))))
		return error;
	ci.scan_channel = dtoh32(ci.scan_channel);
	if (ci.scan_channel)
		return -EAGAIN;

	/* Get scan results (too large to put on the stack) */
	list = kmalloc(buflen, GFP_KERNEL);
	if (!list)
		return -ENOMEM;
	memset(list, 0, buflen);
	list->buflen = htod32(buflen);
	if ((error = dev_wlc_ioctl(dev, WLC_SCAN_RESULTS, list, buflen))) {
		kfree(list);
		return error;
	}
	list->buflen = dtoh32(list->buflen);
	list->version = dtoh32(list->version);
	list->count = dtoh32(list->count);

	ASSERT(list->version == WL_BSS_INFO_VERSION);

	for (i = 0; i < list->count && i < IW_MAX_AP; i++) {
		bi = bi ? (wl_bss_info_t *)((uintptr)bi + dtoh32(bi->length)) : list->bss_info;
		ASSERT(((uintptr)bi + dtoh32(bi->length)) <= ((uintptr)list +
			buflen));

		// terence 20150419: limit the max. rssi to -2 or the bss will be filtered out in android OS
		rssi = MIN(dtoh16(bi->RSSI), RSSI_MAXVAL);
		channel = (bi->ctl_ch == 0) ? CHSPEC_CHANNEL(bi->chanspec) : bi->ctl_ch;
		WL_SCAN(("BSSID="MACSTR", channel=%d, RSSI=%d, SSID=\"%s\"\n",
			MAC2STR(bi->BSSID.octet), channel, rssi, bi->SSID));

		/* First entry must be the BSSID */
		iwe.cmd = SIOCGIWAP;
		iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
		memcpy(iwe.u.ap_addr.sa_data, &bi->BSSID, ETHER_ADDR_LEN);
		event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_ADDR_LEN);

		/* SSID */
		iwe.u.data.length = dtoh32(bi->SSID_len);
		iwe.cmd = SIOCGIWESSID;
		iwe.u.data.flags = 1;
		event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, bi->SSID);

		/* Mode */
		if (dtoh16(bi->capability) & (DOT11_CAP_ESS | DOT11_CAP_IBSS)) {
			iwe.cmd = SIOCGIWMODE;
			if (dtoh16(bi->capability) & DOT11_CAP_ESS)
				iwe.u.mode = IW_MODE_INFRA;
			else
				iwe.u.mode = IW_MODE_ADHOC;
			event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_UINT_LEN);
		}

		/* Channel */
		iwe.cmd = SIOCGIWFREQ;

		iwe.u.freq.m = wf_channel2mhz(CHSPEC_CHANNEL(bi->chanspec),
			(CHSPEC_IS2G(bi->chanspec)) ?
			WF_CHAN_FACTOR_2_4_G : WF_CHAN_FACTOR_5_G);
		iwe.u.freq.e = 6;
		event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_FREQ_LEN);

		/* Channel quality */
		iwe.cmd = IWEVQUAL;
		iwe.u.qual.qual = rssi_to_qual(rssi);
		iwe.u.qual.level = 0x100 + rssi;
		iwe.u.qual.noise = 0x100 + bi->phy_noise;
		event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_QUAL_LEN);

		 wl_iw_handle_scanresults_ies(&event, end, info, bi);

		/* Encryption */
		iwe.cmd = SIOCGIWENCODE;
		if (dtoh16(bi->capability) & DOT11_CAP_PRIVACY)
			iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
		else
			iwe.u.data.flags = IW_ENCODE_DISABLED;
		iwe.u.data.length = 0;
		event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)event);

		/* Rates */
		if (bi->rateset.count) {
			value = event + IW_EV_LCP_LEN;
			iwe.cmd = SIOCGIWRATE;
			/* Those two flags are ignored... */
			iwe.u.bitrate.fixed = iwe.u.bitrate.disabled = 0;
			for (j = 0; j < bi->rateset.count && j < IW_MAX_BITRATES; j++) {
				iwe.u.bitrate.value = (bi->rateset.rates[j] & 0x7f) * 500000;
				value = IWE_STREAM_ADD_VALUE(info, event, value, end, &iwe,
					IW_EV_PARAM_LEN);
			}
			event = value;
		}
	}

	kfree(list);

	dwrq->length = event - extra;
	dwrq->flags = 0;	/* todo */

	return 0;
}
#endif /* WL_ESCAN */

static int
wl_iw_iscan_get_scan(
	struct net_device *dev,
	struct iw_request_info *info,
	struct iw_point *dwrq,
	char *extra
)
{
	struct dhd_pub *dhd = dhd_get_pub(dev);
	wl_wext_info_t *wext_info = NULL;
#ifndef WL_ESCAN
	wl_scan_results_t *list;
	struct iw_event	iwe;
	wl_bss_info_t *bi = NULL;
	int ii, j;
	int apcnt;
	char *event = extra, *end = extra + dwrq->length, *value;
	iscan_buf_t * p_buf;
	int16 rssi;
	int channel;
	iscan_info_t *iscan;
#endif

	DHD_CHECK(dhd, dev);
	wext_info = dhd->wext_info;
#ifdef WL_ESCAN
	return wl_escan_get_scan(dev, info, dwrq, extra);
#else
	WL_TRACE(("%s SIOCGIWSCAN\n", dev->name));

	if (!extra)
		return -EINVAL;

	/* use backup if our thread is not successful */
	iscan = &wext_info->iscan;
	if ((!iscan) || (iscan->sysioc_pid < 0)) {
		return wl_iw_get_scan(dev, info, dwrq, extra);
	}

	/* Check for scan in progress */
	if (iscan->iscan_state == ISCAN_STATE_SCANING) {
		WL_TRACE(("%s: SIOCGIWSCAN GET still scanning\n", dev->name));
		return -EAGAIN;
	}

	apcnt = 0;
	p_buf = iscan->list_hdr;
	/* Get scan results */
	while (p_buf != iscan->list_cur) {
		list = &((wl_iscan_results_t*)p_buf->iscan_buf)->results;

		if (list->version != WL_BSS_INFO_VERSION) {
			WL_ERROR(("list->version %d != WL_BSS_INFO_VERSION\n", list->version));
		}

		bi = NULL;
		for (ii = 0; ii < list->count && apcnt < IW_MAX_AP; apcnt++, ii++) {
			bi = bi ? (wl_bss_info_t *)((uintptr)bi + dtoh32(bi->length)) : list->bss_info;
			ASSERT(((uintptr)bi + dtoh32(bi->length)) <= ((uintptr)list +
				WLC_IW_ISCAN_MAXLEN));

			/* overflow check cover fields before wpa IEs */
			if (event + ETHER_ADDR_LEN + bi->SSID_len + IW_EV_UINT_LEN + IW_EV_FREQ_LEN +
				IW_EV_QUAL_LEN >= end)
				return -E2BIG;

			// terence 20150419: limit the max. rssi to -2 or the bss will be filtered out in android OS
			rssi = MIN(dtoh16(bi->RSSI), RSSI_MAXVAL);
			channel = (bi->ctl_ch == 0) ? CHSPEC_CHANNEL(bi->chanspec) : bi->ctl_ch;
			WL_SCAN(("BSSID="MACSTR", channel=%d, RSSI=%d, SSID=\"%s\"\n",
				MAC2STR(bi->BSSID.octet), channel, rssi, bi->SSID));

			/* First entry must be the BSSID */
			iwe.cmd = SIOCGIWAP;
			iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
			memcpy(iwe.u.ap_addr.sa_data, &bi->BSSID, ETHER_ADDR_LEN);
			event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_ADDR_LEN);

			/* SSID */
			iwe.u.data.length = dtoh32(bi->SSID_len);
			iwe.cmd = SIOCGIWESSID;
			iwe.u.data.flags = 1;
			event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, bi->SSID);

			/* Mode */
			if (dtoh16(bi->capability) & (DOT11_CAP_ESS | DOT11_CAP_IBSS)) {
				iwe.cmd = SIOCGIWMODE;
				if (dtoh16(bi->capability) & DOT11_CAP_ESS)
					iwe.u.mode = IW_MODE_INFRA;
				else
					iwe.u.mode = IW_MODE_ADHOC;
				event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_UINT_LEN);
			}

			/* Channel */
			iwe.cmd = SIOCGIWFREQ;
			iwe.u.freq.m = wf_channel2mhz(CHSPEC_CHANNEL(bi->chanspec),
				(CHSPEC_IS2G(bi->chanspec)) ?
				WF_CHAN_FACTOR_2_4_G : WF_CHAN_FACTOR_5_G);
			iwe.u.freq.e = 6;
			event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_FREQ_LEN);

			/* Channel quality */
			iwe.cmd = IWEVQUAL;
			iwe.u.qual.qual = rssi_to_qual(rssi);
			iwe.u.qual.level = 0x100 + rssi;
			iwe.u.qual.noise = 0x100 + bi->phy_noise;
			event = IWE_STREAM_ADD_EVENT(info, event, end, &iwe, IW_EV_QUAL_LEN);

			wl_iw_handle_scanresults_ies(&event, end, info, bi);

			/* Encryption */
			iwe.cmd = SIOCGIWENCODE;
			if (dtoh16(bi->capability) & DOT11_CAP_PRIVACY)
				iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
			else
				iwe.u.data.flags = IW_ENCODE_DISABLED;
			iwe.u.data.length = 0;
			event = IWE_STREAM_ADD_POINT(info, event, end, &iwe, (char *)event);

			/* Rates */
			if (bi->rateset.count <= sizeof(bi->rateset.rates)) {
				if (event + IW_MAX_BITRATES*IW_EV_PARAM_LEN >= end)
					return -E2BIG;

				value = event + IW_EV_LCP_LEN;
				iwe.cmd = SIOCGIWRATE;
				/* Those two flags are ignored... */
				iwe.u.bitrate.fixed = iwe.u.bitrate.disabled = 0;
				for (j = 0; j < bi->rateset.count && j < IW_MAX_BITRATES; j++) {
					iwe.u.bitrate.value = (bi->rateset.rates[j] & 0x7f) * 500000;
					value = IWE_STREAM_ADD_VALUE(info, event, value, end, &iwe,
						IW_EV_PARAM_LEN);
				}
				event = value;
			}
		}
		p_buf = p_buf->next;
	} /* while (p_buf) */

	dwrq->length = event - extra;
	dwrq->flags = 0;	/* todo */
	WL_SCAN(("apcnt=%d\n", apcnt));

	return 0;
#endif
}
#endif /* WIRELESS_EXT > 13 */



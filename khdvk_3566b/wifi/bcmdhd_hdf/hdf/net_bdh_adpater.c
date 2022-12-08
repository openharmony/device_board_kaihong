/*
 * net_bdh_adpater.c
 *
 * ap6275s driver header
 *
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */
#include "net_bdh_adpater.h"
#include <net/cfg80211.h>
#include <securec.h>
#include "eapol.h"
#include "hdf_wlan_utils.h"
#include "hdf_wl_interface.h"
#include "hdf_public_ap6256.h"
#include "hdf_wifi_event.h"

#define HDF_LOG_TAG BDH6Driver

typedef enum {
    WAL_ADDR_IDX_STA0 = 0,
    WAL_ADDR_IDX_AP0  = 1,
    WAL_ADDR_IDX_STA1 = 2,
    WAL_ADDR_IDX_STA2 = 3,
    WAL_ADDR_IDX_BUTT
} wal_addr_idx;

struct wiphy *g_linux_wiphy = NULL;
void set_krn_netdev(struct NetDevice *hnetdev, struct net_device *netdev, int ifidx)
{
    g_hdf_infmap[ifidx].hnetdev = hnetdev;
    g_hdf_infmap[ifidx].netdev = netdev;
}

struct NetDevice *get_hdf_netdev(int ifidx)
{
    return g_hdf_infmap[ifidx].hnetdev;
}

struct net_device *get_krn_netdev(int ifidx)
{
    return g_hdf_infmap[ifidx].netdev;
}

struct wiphy *get_krn_wiphy(void)
{
    return g_linux_wiphy;
}

void set_krn_wiphy(struct wiphy *pwiphy)
{
    g_linux_wiphy = (struct wiphy *)pwiphy;
}
struct net_device *GetLinuxInfByNetDevice(const struct NetDevice *netDevice);
struct NetDeviceInterFace *wal_get_net_p2p_ops(void);
#define WIFI_IFNAME_MAX_SIZE 16
static wal_addr_idx wal_get_dev_addr_idx(int type)
{
    wal_addr_idx addr_idx = WAL_ADDR_IDX_BUTT;

    switch (type) {
        case NL80211_IFTYPE_STATION:
            addr_idx = WAL_ADDR_IDX_STA0;
            break;
        case NL80211_IFTYPE_AP:
        case NL80211_IFTYPE_P2P_CLIENT:
        case NL80211_IFTYPE_P2P_GO:
        case NL80211_IFTYPE_MESH_POINT:
            addr_idx = WAL_ADDR_IDX_AP0;
            break;
        case NL80211_IFTYPE_P2P_DEVICE:
            addr_idx = WAL_ADDR_IDX_STA2;
            break;
        default:
            HDF_LOGE("wal_get_dev_addr_idx:: dev type [%d] is not supported !", type);
            break;
    }

    return addr_idx;
}

int wal_get_dev_addr(unsigned char *pc_addr, unsigned char addr_len, int type)
{
    unsigned char us_addr[MAC_ADDR_SIZE];
    unsigned int tmp;
    wal_addr_idx addr_idx;
    struct net_device *netdev = get_krn_netdev(0);

    if (pc_addr == NULL) {
        HDF_LOGE("wal_get_dev_addr:: pc_addr is NULL!");
        return -1;
    }

    addr_idx = wal_get_dev_addr_idx(type);
    if (addr_idx >= WAL_ADDR_IDX_BUTT) {
        return -1;
    }

    for (tmp = 0; tmp < MAC_ADDR_SIZE; tmp++) {
        us_addr[tmp] = netdev->dev_addr[tmp];
    }

    /* 1.低位自增 2.高位取其进位 3.低位将进位位置0 */
    us_addr[5] += addr_idx;                      /* 5 地址第6位 */
    us_addr[4] += ((us_addr[5] & (0x100)) >> 8); /* 4 地址第5位 5 地址第6位 8 右移8位 */
    us_addr[5] = us_addr[5] & (0xff);            /* 5 地址第6位 */
    /* 最低位运算完成,下面类似 */
    us_addr[3] += ((us_addr[4] & (0x100)) >> 8); /* 3 地址第4位 4 地址第5位 8 右移8位 */
    us_addr[4] = us_addr[4] & (0xff);            /* 4 地址第5位 */
    us_addr[2] += ((us_addr[3] & (0x100)) >> 8); /* 2 地址第3位 3 地址第4位 8 右移8位 */
    us_addr[3] = us_addr[3] & (0xff);            /* 3 地址第4位 */
    us_addr[1] += ((us_addr[2] & (0x100)) >> 8); /* 1 地址第2位 2 地址第3位 8 右移8位 */
    us_addr[2] = us_addr[2] & (0xff);            /* 2 地址第3位 */
    us_addr[0] += ((us_addr[1] & (0x100)) >> 8); /* 8 右移8位 */
    us_addr[1] = us_addr[1] & (0xff);
    if (us_addr[0] > 0xff) {
        us_addr[0] = 0;
    }
    us_addr[0] &= 0xFE;

    for (tmp = 0; tmp < addr_len; tmp++) {
        pc_addr[tmp] = us_addr[tmp];
    }

    return 0;
}


int32_t GetIfName(int type, char *ifName, uint32_t len)
{
    if (ifName == NULL || len == 0) {
        HDF_LOGE("%s:para is null!", __func__);
        return -1;
    }
    switch (type) {
        case NL80211_IFTYPE_P2P_DEVICE:
            if (snprintf_s(ifName, len, len - 1, "p2p%d", 0) < 0) {
                HDF_LOGE("%s:format ifName failed!", __func__);
                return -1;
            }
            break;
        case NL80211_IFTYPE_P2P_CLIENT:
            /*  fall-through */
        case NL80211_IFTYPE_P2P_GO:
            if (snprintf_s(ifName, len, len - 1, "p2p-p2p0-%d", 0) < 0) {
                HDF_LOGE("%s:format ifName failed!", __func__);
                return -1;
            }
            break;
        default:
            HDF_LOGE("%s:GetIfName::not supported dev type!", __func__);
            return -1;
    }
    return 0;
}

int BDH6InitNetdev(struct NetDevice *netDevice, int private_data_size, int type, int ifidx)
{
    struct NetDevice *hnetdev = NULL;
    char ifName[WIFI_IFNAME_MAX_SIZE] = {0};
    struct HdfWifiNetDeviceData *data = NULL;
    struct net_device *netdev = NULL;
    int ret = 0;
    unsigned char ac_addr[MAC_ADDR_SIZE] = {0};
    
    if (netDevice == NULL) {
        HDF_LOGE("%s:para is null!", __func__);
        return -1;
    }
    if (GetIfName(type, ifName, WIFI_IFNAME_MAX_SIZE) != 0) {
        HDF_LOGE("%s:get ifName failed!", __func__);
        return -1;
    }
	
    hnetdev = NetDeviceInit(ifName, strlen(ifName), WIFI_LINK, FULL_OS);
    if (hnetdev == NULL) {
        HDF_LOGE("%s:netdev is null!", __func__);
        return -1;
    }
    data = GetPlatformData(netDevice);
    if (data == NULL) {
        HDF_LOGE("%s:netdevice data null!", __func__);
        return -1;
    }
    hnetdev->classDriverName = netDevice->classDriverName;
    hnetdev->classDriverPriv = data;

    netdev = GetLinuxInfByNetDevice(hnetdev);
    if (netdev == NULL) {
        HDF_LOGE("%s net_device is null!", __func__);
        return HDF_FAILURE;
    }
    
    hdf_bdh6_netdev_init(hnetdev); // set net_dev_ops
    
    // create bdh6 private object
    hnetdev->mlPriv = kzalloc(private_data_size, GFP_KERNEL);
    if (hnetdev->mlPriv == NULL) {
        HDF_LOGE("%s:kzalloc mlPriv failed", __func__);
        return -1;
    }

    // set mac address
    ret = wal_get_dev_addr(ac_addr, MAC_ADDR_SIZE, type);
    if (ret != 0) {
        HDF_LOGE("generate macaddr for %s failed", hnetdev->name);
    }
    memcpy_s(hnetdev->macAddr, MAC_ADDR_SIZE, ac_addr, MAC_ADDR_SIZE);
    g_hdf_ifidx = ifidx;
    set_krn_netdev(hnetdev, netdev, ifidx);
    
    return ret;
}

static void BDH_EnableEapol(struct NetDevice *netDev)
{
    WifiEnableEapol eapol;
    const struct Eapol *eapolCB = EapolGetInstance();
    
    eapol.callback = (void *)HdfWifiEventEapolRecv;
    eapol.context = NULL;
    
    eapolCB->eapolOp->enableEapol(netDev, (struct EapolEnable *)&eapol);
}

int32_t hdf_bdh6_netdev_init(struct NetDevice *netDev)
{
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    if (netDev == NULL) {
        HDF_LOGE("%s: netDev null!", __func__);
        return HDF_FAILURE;
    }

    HDF_LOGE("%s: netDev->name:%s\n", __func__, netDev->name);
    netDev->netDeviceIf = wal_get_net_dev_ops();
    CreateEapolData(netDev);
    if (bdh6_reset_driver_flag) {
        BDH_EnableEapol(netDev);
    }

    return HDF_SUCCESS;
}

int32_t hdf_p2p_netdev_init(struct NetDevice *netDev)
{
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    if (netDev == NULL) {
        HDF_LOGE("%s: netDev null!", __func__);
        return HDF_FAILURE;
    }

    HDF_LOGE("%s: netDev->name:%s\n", __func__, netDev->name);
    netDev->netDeviceIf = wal_get_net_p2p_ops();
    CreateEapolData(netDev);
    if (bdh6_reset_driver_flag) {
        BDH_EnableEapol(netDev);
    }

    return HDF_SUCCESS;
}


void hdf_bdh6_netdev_deinit(struct NetDevice *netDev)
{
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    (void)netDev;
}

int32_t hdf_bdh6_netdev_open(struct NetDevice *netDev)
{
    int32_t retVal = 0;
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);
    if (netdev != get_krn_netdev(0)) {
        // for virtual don't call open
        return 0;
    }

    if (netdev == NULL) {
        HDF_LOGE("%s: netDev null!", __func__);
        return HDF_FAILURE;
    }

    rtnl_lock();
    retVal = (int32_t)dhd_ops_pri.ndo_open(netdev);
    if (retVal == 0) {
        netDev->flags |= NET_DEVICE_IFF_RUNNING;
    } else {
        HDF_LOGE("%s: hdf net device open failed! ret = %d", __func__, retVal);
    }

    netDev->ieee80211Ptr = netdev->ieee80211_ptr;
    if (netDev->ieee80211Ptr == NULL) {
        HDF_LOGE("%s: NULL == netDev->ieee80211Ptr", __func__);
    }

    // update mac addr to NetDevice object
    memcpy_s(netDev->macAddr, MAC_ADDR_SIZE, netdev->dev_addr, netdev->addr_len);
    rtnl_unlock();
    return retVal;
}

int32_t hdf_p2p_netdev_open(struct NetDevice *netDev)
{
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    return 0;
}


int32_t hdf_bdh6_netdev_stop(struct NetDevice *netDev)
{
    int32_t retVal = 0;
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    if (netdev != get_krn_netdev(0)) {
        return 0;
    }
    if (netdev == NULL) {
        HDF_LOGE("%s: netDev null!", __func__);
        return HDF_FAILURE;
    }

    rtnl_lock();
    retVal = (int32_t)dhd_ops_pri.ndo_stop(netdev);
    rtnl_unlock();
    if (retVal == 0) {
        netDev->flags &= (0xffff & ~NET_DEVICE_IFF_RUNNING);
    } else {
        HDF_LOGE("%s: hdf net device stop failed! ret = %d", __func__, retVal);
    }

    return retVal;
}

int32_t hdf_p2p_netdev_stop(struct NetDevice *netDev)
{
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    return 0;
}


int32_t hdf_bdh6_netdev_xmit(struct NetDevice *netDev, NetBuf *netBuff)
{
    int32_t retVal = 0;
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);

    if (netdev == NULL || netBuff == NULL) {
        HDF_LOGE("%s: netdev or netBuff null!", __func__);
        return HDF_FAILURE;
    }

    retVal = (int32_t)dhd_ops_pri.ndo_start_xmit((struct sk_buff *)netBuff, netdev);
    if (retVal < 0) {
        HDF_LOGE("%s: hdf net device xmit failed! ret = %d", __func__, retVal);
    }

    return retVal;
}

int32_t hdf_p2p_netdev_xmit(struct NetDevice *netDev, NetBuf *netBuff)
{
    HDF_LOGI("%s: start %s...", __func__, netDev->name);
    if (netBuff) {
        dev_kfree_skb_any(netBuff);
    }

    return 0;
}


int32_t hdf_bdh6_netdev_ioctl(struct NetDevice *netDev, IfReq *req, int32_t cmd)
{
    int32_t retVal = 0;
    struct ifreq dhd_req = {0};
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);

    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    if (netdev == NULL || req == NULL) {
        HDF_LOGE("%s: netdev or req null!", __func__);
        return HDF_FAILURE;
    }

    dhd_req.ifr_ifru.ifru_data = req->ifrData;

    retVal = (int32_t)dhd_ops_pri.ndo_do_ioctl(netdev, &dhd_req, cmd);
    if (retVal < 0) {
        HDF_LOGE("%s: hdf net device ioctl failed! ret = %d", __func__, retVal);
    }

    return retVal;
}

int32_t hdf_p2p_netdev_ioctl(struct NetDevice *netDev, IfReq *req, int32_t cmd)
{
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    return 0;
}

#define MC0 0
#define MC1 1
#define MC2 2
#define MC3 3
#define MC4 4
#define MC5 5
int32_t hdf_bdh6_netdev_setmacaddr(struct NetDevice *netDev, void *addr)
{
    int32_t retVal = 0;
    struct sockaddr sa;
    const uint8_t *mac = (uint8_t *)addr;
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);

    HDF_LOGE("%s: start %s...", __func__, netDev->name);

    if (netdev == NULL || mac == NULL) {
        HDF_LOGE("%s: netDev or addr null!", __func__);
        return HDF_FAILURE;
    }

    if (!is_valid_ether_addr(mac)) {
        HDF_LOGE("%s: mac is invalid %02x:%02x:%02x:%02x:%02x:%02x", __func__,
            mac[MC0], mac[MC1], mac[MC2], mac[MC3], mac[MC4], mac[MC5]);
        return -1;
    }
    memcpy_s(sa.sa_data, ETH_ALEN, mac, ETH_ALEN);

    retVal = (int32_t)dhd_ops_pri.ndo_set_mac_address(netdev, (void *)&sa);
    if (retVal < 0) {
        HDF_LOGE("%s: hdf net device setmacaddr failed! ret = %d", __func__, retVal);
    }

    return retVal;
}

int32_t hdf_p2p_netdev_setmacaddr(struct NetDevice *netDev, void *addr)
{
    int32_t retVal = 0;
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);

    HDF_LOGE("%s: start %s...", __func__, netDev->name);

    if (netdev == NULL || addr == NULL) {
        HDF_LOGE("%s: netDev or addr null!", __func__);
        return HDF_FAILURE;
    }

    memcpy_s(netdev->dev_addr, netdev->addr_len, addr, netdev->addr_len);
    memcpy_s(netDev->macAddr, MAC_ADDR_SIZE, netdev->dev_addr, netdev->addr_len);
    return retVal;
}


struct NetDevStats *hdf_bdh6_netdev_getstats(struct NetDevice *netDev)
{
    static struct NetDevStats devStat = {0};
    struct net_device_stats *kdevStat = NULL;
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);

    HDF_LOGE("%s: start %s...", __func__, netDev->name);

    if (netdev == NULL) {
        HDF_LOGE("%s: netDev null!", __func__);
        return NULL;
    }

    kdevStat = dhd_ops_pri.ndo_get_stats(netdev);
    if (kdevStat == NULL) {
        HDF_LOGE("%s: ndo_get_stats return null!", __func__);
        return NULL;
    }

    devStat.rxPackets = kdevStat->rx_packets;
    devStat.txPackets = kdevStat->tx_packets;
    devStat.rxBytes = kdevStat->rx_bytes;
    devStat.txBytes = kdevStat->tx_bytes;
    devStat.rxErrors = kdevStat->rx_errors;
    devStat.txErrors = kdevStat->tx_errors;
    devStat.rxDropped = kdevStat->rx_dropped;
    devStat.txDropped = kdevStat->tx_dropped;

    return &devStat;
}

struct NetDevStats *hdf_p2p_netdev_getstats(struct NetDevice *netDev)
{
    static struct NetDevStats devStat = {0};
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);

    HDF_LOGE("%s: start %s...", __func__, netDev->name);

    if (netdev == NULL) {
        HDF_LOGE("%s: netDev null!", __func__);
        return NULL;
    }

    return &devStat;
}


void hdf_bdh6_netdev_setnetifstats(struct NetDevice *netDev, NetIfStatus status)
{
    HDF_LOGE("%s: start...", __func__);
    (void)netDev;
    (void)status;
}

uint16_t hdf_bdh6_netdev_selectqueue(struct NetDevice *netDev, NetBuf *netBuff)
{
    HDF_LOGE("%s: start...", __func__);
    (void)netDev;
    (void)netBuff;
    return HDF_SUCCESS;
}

uint32_t hdf_bdh6_netdev_netifnotify(struct NetDevice *netDev, NetDevNotify *notify)
{
    HDF_LOGE("%s: start...", __func__);
    (void)netDev;
    (void)notify;
    return HDF_SUCCESS;
}

int32_t hdf_bdh6_netdev_changemtu(struct NetDevice *netDev, int32_t mtu)
{
    int32_t retVal = 0;
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    if (netdev == NULL) {
        HDF_LOGE("%s: netdev null!", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGE("%s: change mtu to %d\n", __FUNCTION__, mtu);
    retVal = (int32_t)dhd_netdev_changemtu_wrapper(netdev, mtu);
    if (retVal < 0) {
        HDF_LOGE("%s: hdf net device chg mtu failed! ret = %d", __func__, retVal);
    }

    return retVal;
}

int32_t hdf_p2p_netdev_changemtu(struct NetDevice *netDev, int32_t mtu)
{
    struct net_device *netdev = GetLinuxInfByNetDevice(netDev);
    HDF_LOGE("%s: start %s...", __func__, netDev->name);
    netdev->mtu = mtu;
    return 0;
}

void hdf_bdh6_netdev_linkstatuschanged(struct NetDevice *netDev)
{
    HDF_LOGE("%s: start...", __func__);
    (void)netDev;
}

void eapol_report_handler(struct work_struct *work_data)
{
    const struct Eapol *eapolInstance = NULL;
    struct hdf_eapol_event_s *eapolEvent = NULL;
    struct NetDevice *netDev = NULL;
    int32_t idx = 0, ret = 0;
    NetBuf *netBuff = NULL;
    eapolEvent = container_of(work_data, struct hdf_eapol_event_s, eapol_report);
    idx = eapolEvent->idx;
    netDev = g_hdf_infmap[idx].hnetdev;
    if (netDev == NULL) {
        HDF_LOGE("%s: idx=%d, netDev is NULL", __func__, idx);
        return;
    }

    eapolInstance = EapolGetInstance();
    while (1) {
        netBuff = NetBufQueueDequeue(&eapolEvent->eapolQueue);
        if (netBuff == NULL) {
            HDF_LOGE("%s: get sk_buff NULL from %d", __func__, idx);
            return;
        }

        eapolInstance = EapolGetInstance();
        ret = eapolInstance->eapolOp->writeEapolToQueue(netDev, netBuff);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: writeEapolToQueue failed", __func__);
            NetBufFree(netBuff);
        }
    }
}

static void hdf_bdh6_send_eapol_data(const struct NetDevice *netDev, NetBuf *buff)
{
    int idx = 0;
    struct hdf_eapol_event_s *eapolEvent = NULL;
    idx = get_scan_ifidx(netDev->name);
    eapolEvent = &g_hdf_infmap[idx].eapolEvent;
    NetBufQueueEnqueue(&eapolEvent->eapolQueue, buff);
    schedule_work(&eapolEvent->eapol_report);
}

#define PEPROCESS1 12
#define PEPROCESS2 13
#define PEPROCESS3 8
ProcessingResult hdf_bdh6_netdev_specialethertypeprocess(const struct NetDevice *netDev, NetBuf *buff)
{
    struct EtherHeader *header = NULL;
    const struct Eapol *eapolInstance = NULL;
    int ret = HDF_SUCCESS;
    uint16_t protocol;

    HDF_LOGE("%s: start %s...", __func__, netDev->name);

    if (netDev == NULL || buff == NULL) {
        return PROCESSING_ERROR;
    }

    header = (struct EtherHeader *)NetBufGetAddress(buff, E_DATA_BUF);

    protocol = (buff->data[PEPROCESS1] << PEPROCESS3) | buff->data[PEPROCESS2];
    if (protocol != ETHER_TYPE_PAE) {
        HDF_LOGE("%s: return PROCESSING_CONTINUE", __func__);
        NetBufFree(buff);
        return PROCESSING_CONTINUE;
    }
    if (netDev->specialProcPriv == NULL) {
        HDF_LOGE("%s: return PROCESSING_ERROR", __func__);
        NetBufFree(buff);
        return PROCESSING_ERROR;
    }

    hdf_bdh6_send_eapol_data(netDev, buff);
    return PROCESSING_COMPLETE;
}


struct NetDeviceInterFace g_wal_bdh6_net_dev_ops = {
    .init       = hdf_bdh6_netdev_init,
    .deInit     = hdf_bdh6_netdev_deinit,
    .open       = hdf_bdh6_netdev_open,
    .stop       = hdf_bdh6_netdev_stop,
    .xmit       = hdf_bdh6_netdev_xmit,
    .ioctl      = hdf_bdh6_netdev_ioctl,
    .setMacAddr = hdf_bdh6_netdev_setmacaddr,
    .getStats   = hdf_bdh6_netdev_getstats,
    .setNetIfStatus     = hdf_bdh6_netdev_setnetifstats,
    .selectQueue        = hdf_bdh6_netdev_selectqueue,
    .netifNotify        = hdf_bdh6_netdev_netifnotify,
    .changeMtu          = hdf_bdh6_netdev_changemtu,
    .linkStatusChanged  = hdf_bdh6_netdev_linkstatuschanged,
    .specialEtherTypeProcess  = hdf_bdh6_netdev_specialethertypeprocess,
};

struct NetDeviceInterFace *wal_get_net_dev_ops(void)
{
    return &g_wal_bdh6_net_dev_ops;
}


struct NetDeviceInterFace g_bdh6_p2p_net_dev_ops = {
    .init       = hdf_p2p_netdev_init,
    .deInit     = hdf_bdh6_netdev_deinit,
    .open       = hdf_p2p_netdev_open,
    .stop       = hdf_p2p_netdev_stop,
    .xmit       = hdf_p2p_netdev_xmit,
    .ioctl      = hdf_p2p_netdev_ioctl,
    .setMacAddr = hdf_p2p_netdev_setmacaddr,
    .getStats   = hdf_p2p_netdev_getstats,
    .setNetIfStatus     = hdf_bdh6_netdev_setnetifstats,
    .selectQueue        = hdf_bdh6_netdev_selectqueue,
    .netifNotify        = hdf_bdh6_netdev_netifnotify,
    .changeMtu          = hdf_p2p_netdev_changemtu,
    .linkStatusChanged  = hdf_bdh6_netdev_linkstatuschanged,
    .specialEtherTypeProcess  = hdf_bdh6_netdev_specialethertypeprocess,
};

struct NetDeviceInterFace *wal_get_net_p2p_ops(void)
{
    return &g_bdh6_p2p_net_dev_ops;
}


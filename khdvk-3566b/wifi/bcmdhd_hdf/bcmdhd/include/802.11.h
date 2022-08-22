/*
 * Fundamental types and constants relating to 802.11
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
 * $Id: 802.11.h 814166 2019-04-10 06:14:49Z $
 */

#ifndef _802_11_H_
#define _802_11_H_

#ifndef _TYPEDEFS_H_
#include <typedefs.h>
#endif // endif

#ifndef _NET_ETHERNET_H_
#include <ethernet.h>
#endif // endif

#include <wpa.h>

/* This marks the start of a packed structure section. */
#include <packed_section_start.h>

#define DOT11_TU_TO_US			1024	/* 802.11 Time Unit is 1024 microseconds */

/* Generic 802.11 frame constants */
#define DOT11_A3_HDR_LEN		24	/* d11 header length with A3 */
#define DOT11_A4_HDR_LEN		30	/* d11 header length with A4 */
#define DOT11_MAC_HDR_LEN		DOT11_A3_HDR_LEN	/* MAC header length */
#define DOT11_FCS_LEN			4u	/* d11 FCS length */
#define DOT11_ICV_LEN			4	/* d11 ICV length */
#define DOT11_ICV_AES_LEN		8	/* d11 ICV/AES length */
#define DOT11_MAX_ICV_AES_LEN		16	/* d11 MAX ICV/AES length */
#define DOT11_QOS_LEN			2	/* d11 QoS length */
#define DOT11_HTC_LEN			4	/* d11 HT Control field length */

#define DOT11_KEY_INDEX_SHIFT		6	/* d11 key index shift */
#define DOT11_IV_LEN			4	/* d11 IV length */
#define DOT11_IV_TKIP_LEN		8	/* d11 IV TKIP length */
#define DOT11_IV_AES_OCB_LEN		4	/* d11 IV/AES/OCB length */
#define DOT11_IV_AES_CCM_LEN		8	/* d11 IV/AES/CCM length */
#define DOT11_IV_MAX_LEN		8	/* maximum iv len for any encryption */

/* Includes MIC */
#define DOT11_MAX_MPDU_BODY_LEN		2304	/* max MPDU body length */
/* A4 header + QoS + CCMP + PDU + ICV + FCS = 2352 */
#define DOT11_MAX_MPDU_LEN		(DOT11_A4_HDR_LEN + \
					 DOT11_QOS_LEN + \
					 DOT11_IV_AES_CCM_LEN + \
					 DOT11_MAX_MPDU_BODY_LEN + \
					 DOT11_ICV_LEN + \
					 DOT11_FCS_LEN)	/* d11 max MPDU length */

#define DOT11_MAX_SSID_LEN		32	/* d11 max ssid length */

/* dot11RTSThreshold */
#define DOT11_DEFAULT_RTS_LEN		2347	/* d11 default RTS length */
#define DOT11_MAX_RTS_LEN		2347	/* d11 max RTS length */

/* dot11FragmentationThreshold */
#define DOT11_MIN_FRAG_LEN		256	/* d11 min fragmentation length */
#define DOT11_MAX_FRAG_LEN		2346	/* Max frag is also limited by aMPDUMaxLength
						* of the attached PHY
						*/
#define DOT11_DEFAULT_FRAG_LEN		2346	/* d11 default fragmentation length */

/* dot11BeaconPeriod */
#define DOT11_MIN_BEACON_PERIOD		1	/* d11 min beacon period */
#define DOT11_MAX_BEACON_PERIOD		0xFFFF	/* d11 max beacon period */

/* dot11DTIMPeriod */
#define DOT11_MIN_DTIM_PERIOD		1	/* d11 min DTIM period */
#define DOT11_MAX_DTIM_PERIOD		0xFF	/* d11 max DTIM period */

/** 802.2 LLC/SNAP header used by 802.11 per 802.1H */
#define DOT11_LLC_SNAP_HDR_LEN		8	/* d11 LLC/SNAP header length */
/* minimum LLC header length; DSAP, SSAP, 8 bit Control (unnumbered) */
#define DOT11_LLC_HDR_LEN_MIN		3
#define DOT11_OUI_LEN			3	/* d11 OUI length */
BWL_PRE_PACKED_STRUCT struct dot11_llc_snap_header {
	uint8	dsap;				/* always 0xAA */
	uint8	ssap;				/* always 0xAA */
	uint8	ctl;				/* always 0x03 */
	uint8	oui[DOT11_OUI_LEN];		/* RFC1042: 0x00 0x00 0x00
						 * Bridge-Tunnel: 0x00 0x00 0xF8
						 */
	uint16	type;				/* ethertype */
} BWL_POST_PACKED_STRUCT;

/* RFC1042 header used by 802.11 per 802.1H */
#define RFC1042_HDR_LEN	(ETHER_HDR_LEN + DOT11_LLC_SNAP_HDR_LEN)	/* RCF1042 header length */

/* Generic 802.11 MAC header */
/**
 * N.B.: This struct reflects the full 4 address 802.11 MAC header.
 *		 The fields are defined such that the shorter 1, 2, and 3
 *		 address headers just use the first k fields.
 */
BWL_PRE_PACKED_STRUCT struct dot11_header {
	uint16			fc;		/* frame control */
	uint16			durid;		/* duration/ID */
	struct ether_addr	a1;		/* address 1 */
	struct ether_addr	a2;		/* address 2 */
	struct ether_addr	a3;		/* address 3 */
	uint16			seq;		/* sequence control */
	struct ether_addr	a4;		/* address 4 */
} BWL_POST_PACKED_STRUCT;

/* Control frames */

BWL_PRE_PACKED_STRUCT struct dot11_rts_frame {
	uint16			fc;		/* frame control */
	uint16			durid;		/* duration/ID */
	struct ether_addr	ra;		/* receiver address */
	struct ether_addr	ta;		/* transmitter address */
} BWL_POST_PACKED_STRUCT;
#define	DOT11_RTS_LEN		16		/* d11 RTS frame length */

BWL_PRE_PACKED_STRUCT struct dot11_cts_frame {
	uint16			fc;		/* frame control */
	uint16			durid;		/* duration/ID */
	struct ether_addr	ra;		/* receiver address */
} BWL_POST_PACKED_STRUCT;
#define	DOT11_CTS_LEN		10u		/* d11 CTS frame length */

BWL_PRE_PACKED_STRUCT struct dot11_ack_frame {
	uint16			fc;		/* frame control */
	uint16			durid;		/* duration/ID */
	struct ether_addr	ra;		/* receiver address */
} BWL_POST_PACKED_STRUCT;
#define	DOT11_ACK_LEN		10		/* d11 ACK frame length */

BWL_PRE_PACKED_STRUCT struct dot11_ps_poll_frame {
	uint16			fc;		/* frame control */
	uint16			durid;		/* AID */
	struct ether_addr	bssid;		/* receiver address, STA in AP */
	struct ether_addr	ta;		/* transmitter address */
} BWL_POST_PACKED_STRUCT;
#define	DOT11_PS_POLL_LEN	16		/* d11 PS poll frame length */

BWL_PRE_PACKED_STRUCT struct dot11_cf_end_frame {
	uint16			fc;		/* frame control */
	uint16			durid;		/* duration/ID */
	struct ether_addr	ra;		/* receiver address */
	struct ether_addr	bssid;		/* transmitter address, STA in AP */
} BWL_POST_PACKED_STRUCT;
#define	DOT11_CS_END_LEN	16		/* d11 CF-END frame length */

/**
 * RWL wifi protocol: The Vendor Specific Action frame is defined for vendor-specific signaling
 *  category+OUI+vendor specific content ( this can be variable)
 */
BWL_PRE_PACKED_STRUCT struct dot11_action_wifi_vendor_specific {
	uint8	category;
	uint8	OUI[3];
	uint8	type;
	uint8	subtype;
	uint8	data[1040];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_action_wifi_vendor_specific dot11_action_wifi_vendor_specific_t;

/** generic vendor specific action frame with variable length */
BWL_PRE_PACKED_STRUCT struct dot11_action_vs_frmhdr {
	uint8	category;
	uint8	OUI[3];
	uint8	type;
	uint8	subtype;
	uint8	data[1];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_action_vs_frmhdr dot11_action_vs_frmhdr_t;

#define DOT11_ACTION_VS_HDR_LEN	6

#define BCM_ACTION_OUI_BYTE0	0x00
#define BCM_ACTION_OUI_BYTE1	0x90
#define BCM_ACTION_OUI_BYTE2	0x4c

/* BA/BAR Control parameters */
#define DOT11_BA_CTL_POLICY_NORMAL	0x0000	/* normal ack */
#define DOT11_BA_CTL_POLICY_NOACK	0x0001	/* no ack */
#define DOT11_BA_CTL_POLICY_MASK	0x0001	/* ack policy mask */

#define DOT11_BA_CTL_MTID		0x0002	/* multi tid BA */
#define DOT11_BA_CTL_COMPRESSED		0x0004	/* compressed bitmap */

#define DOT11_BA_CTL_NUMMSDU_MASK	0x0FC0	/* num msdu in bitmap mask */
#define DOT11_BA_CTL_NUMMSDU_SHIFT	6	/* num msdu in bitmap shift */

#define DOT11_BA_CTL_TID_MASK		0xF000	/* tid mask */
#define DOT11_BA_CTL_TID_SHIFT		12	/* tid shift */

/** control frame header (BA/BAR) */
BWL_PRE_PACKED_STRUCT struct dot11_ctl_header {
	uint16			fc;		/* frame control */
	uint16			durid;		/* duration/ID */
	struct ether_addr	ra;		/* receiver address */
	struct ether_addr	ta;		/* transmitter address */
} BWL_POST_PACKED_STRUCT;
#define DOT11_CTL_HDR_LEN	16		/* control frame hdr len */

/** BAR frame payload */
BWL_PRE_PACKED_STRUCT struct dot11_bar {
	uint16			bar_control;	/* BAR Control */
	uint16			seqnum;		/* Starting Sequence control */
} BWL_POST_PACKED_STRUCT;
#define DOT11_BAR_LEN		4		/* BAR frame payload length */

#define DOT11_BA_BITMAP_LEN	128		/* bitmap length */
#define DOT11_BA_CMP_BITMAP_LEN	8		/* compressed bitmap length */
/** BA frame payload */
BWL_PRE_PACKED_STRUCT struct dot11_ba {
	uint16			ba_control;	/* BA Control */
	uint16			seqnum;		/* Starting Sequence control */
	uint8			bitmap[DOT11_BA_BITMAP_LEN];	/* Block Ack Bitmap */
} BWL_POST_PACKED_STRUCT;
#define DOT11_BA_LEN		4		/* BA frame payload len (wo bitmap) */

/** Management frame header */
BWL_PRE_PACKED_STRUCT struct dot11_management_header {
	uint16			fc;		/* frame control */
	uint16			durid;		/* duration/ID */
	struct ether_addr	da;		/* receiver address */
	struct ether_addr	sa;		/* transmitter address */
	struct ether_addr	bssid;		/* BSS ID */
	uint16			seq;		/* sequence control */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_management_header dot11_management_header_t;
#define	DOT11_MGMT_HDR_LEN	24		/* d11 management header length */

/* Management frame payloads */

BWL_PRE_PACKED_STRUCT struct dot11_bcn_prb {
	uint32			timestamp[2];
	uint16			beacon_interval;
	uint16			capability;
} BWL_POST_PACKED_STRUCT;
#define	DOT11_BCN_PRB_LEN	12		/* 802.11 beacon/probe frame fixed length */
#define	DOT11_BCN_PRB_FIXED_LEN	12u		/* 802.11 beacon/probe frame fixed length */

BWL_PRE_PACKED_STRUCT struct dot11_auth {
	uint16			alg;		/* algorithm */
	uint16			seq;		/* sequence control */
	uint16			status;		/* status code */
} BWL_POST_PACKED_STRUCT;
#define DOT11_AUTH_FIXED_LEN		6	/* length of auth frame without challenge IE */
#define DOT11_AUTH_SEQ_STATUS_LEN	4	/* length of auth frame without challenge IE and
						 * without algorithm
						 */

BWL_PRE_PACKED_STRUCT struct dot11_assoc_req {
	uint16			capability;	/* capability information */
	uint16			listen;		/* listen interval */
} BWL_POST_PACKED_STRUCT;
#define DOT11_ASSOC_REQ_FIXED_LEN	4	/* length of assoc frame without info elts */

BWL_PRE_PACKED_STRUCT struct dot11_reassoc_req {
	uint16			capability;	/* capability information */
	uint16			listen;		/* listen interval */
	struct ether_addr	ap;		/* Current AP address */
} BWL_POST_PACKED_STRUCT;
#define DOT11_REASSOC_REQ_FIXED_LEN	10	/* length of assoc frame without info elts */

BWL_PRE_PACKED_STRUCT struct dot11_assoc_resp {
	uint16			capability;	/* capability information */
	uint16			status;		/* status code */
	uint16			aid;		/* association ID */
} BWL_POST_PACKED_STRUCT;
#define DOT11_ASSOC_RESP_FIXED_LEN	6	/* length of assoc resp frame without info elts */

BWL_PRE_PACKED_STRUCT struct dot11_action_measure {
	uint8	category;
	uint8	action;
	uint8	token;
	uint8	data[1];
} BWL_POST_PACKED_STRUCT;
#define DOT11_ACTION_MEASURE_LEN	3	/* d11 action measurement header length */

BWL_PRE_PACKED_STRUCT struct dot11_action_ht_ch_width {
	uint8	category;
	uint8	action;
	uint8	ch_width;
} BWL_POST_PACKED_STRUCT;

BWL_PRE_PACKED_STRUCT struct dot11_action_ht_mimops {
	uint8	category;
	uint8	action;
	uint8	control;
} BWL_POST_PACKED_STRUCT;

BWL_PRE_PACKED_STRUCT struct dot11_action_sa_query {
	uint8	category;
	uint8	action;
	uint16	id;
} BWL_POST_PACKED_STRUCT;

BWL_PRE_PACKED_STRUCT struct dot11_action_vht_oper_mode {
	uint8	category;
	uint8	action;
	uint8	mode;
} BWL_POST_PACKED_STRUCT;

/* These lengths assume 64 MU groups, as specified in 802.11ac-2013 */
#define DOT11_ACTION_GID_MEMBERSHIP_LEN  8    /* bytes */
#define DOT11_ACTION_GID_USER_POS_LEN   16    /* bytes */
BWL_PRE_PACKED_STRUCT struct dot11_action_group_id {
	uint8   category;
	uint8   action;
	uint8   membership_status[DOT11_ACTION_GID_MEMBERSHIP_LEN];
	uint8   user_position[DOT11_ACTION_GID_USER_POS_LEN];
} BWL_POST_PACKED_STRUCT;

#define SM_PWRSAVE_ENABLE	1
#define SM_PWRSAVE_MODE		2

/* ************* 802.11h related definitions. ************* */
BWL_PRE_PACKED_STRUCT struct dot11_power_cnst {
	uint8 id;
	uint8 len;
	uint8 power;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_power_cnst dot11_power_cnst_t;

BWL_PRE_PACKED_STRUCT struct dot11_power_cap {
	int8 min;
	int8 max;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_power_cap dot11_power_cap_t;

BWL_PRE_PACKED_STRUCT struct dot11_tpc_rep {
	uint8 id;
	uint8 len;
	uint8 tx_pwr;
	uint8 margin;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_tpc_rep dot11_tpc_rep_t;
#define DOT11_MNG_IE_TPC_REPORT_SIZE	(sizeof(dot11_tpc_rep_t))
#define DOT11_MNG_IE_TPC_REPORT_LEN	2 	/* length of IE data, not including 2 byte header */

BWL_PRE_PACKED_STRUCT struct dot11_supp_channels {
	uint8 id;
	uint8 len;
	uint8 first_channel;
	uint8 num_channels;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_supp_channels dot11_supp_channels_t;

/**
 * Extension Channel Offset IE: 802.11n-D1.0 spec. added sideband
 * offset for 40MHz operation.  The possible 3 values are:
 * 1 = above control channel
 * 3 = below control channel
 * 0 = no extension channel
 */
BWL_PRE_PACKED_STRUCT struct dot11_extch {
	uint8	id;		/* IE ID, 62, DOT11_MNG_EXT_CHANNEL_OFFSET */
	uint8	len;		/* IE length */
	uint8	extch;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_extch dot11_extch_ie_t;

BWL_PRE_PACKED_STRUCT struct dot11_brcm_extch {
	uint8	id;		/* IE ID, 221, DOT11_MNG_PROPR_ID */
	uint8	len;		/* IE length */
	uint8	oui[3];
	uint8	type;           /* type indicates what follows */
	uint8	extch;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_brcm_extch dot11_brcm_extch_ie_t;

#define BRCM_EXTCH_IE_LEN	5
#define BRCM_EXTCH_IE_TYPE	53	/* 802.11n ID not yet assigned */
#define DOT11_EXTCH_IE_LEN	1
#define DOT11_EXT_CH_MASK	0x03	/* extension channel mask */
#define DOT11_EXT_CH_UPPER	0x01	/* ext. ch. on upper sb */
#define DOT11_EXT_CH_LOWER	0x03	/* ext. ch. on lower sb */
#define DOT11_EXT_CH_NONE	0x00	/* no extension ch.  */

BWL_PRE_PACKED_STRUCT struct dot11_action_frmhdr {
	uint8	category;
	uint8	action;
	uint8	data[1];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_action_frmhdr dot11_action_frmhdr_t;

/* Action Field length */
#define DOT11_ACTION_CATEGORY_LEN	1u
#define DOT11_ACTION_ACTION_LEN		1u
#define DOT11_ACTION_DIALOG_TOKEN_LEN	1u
#define DOT11_ACTION_CAPABILITY_LEN	2u
#define DOT11_ACTION_STATUS_CODE_LEN	2u
#define DOT11_ACTION_REASON_CODE_LEN	2u
#define DOT11_ACTION_TARGET_CH_LEN	1u
#define DOT11_ACTION_OPER_CLASS_LEN	1u

#define DOT11_ACTION_FRMHDR_LEN	2

/** CSA IE data structure */
BWL_PRE_PACKED_STRUCT struct dot11_channel_switch {
	uint8 id;	/* id DOT11_MNG_CHANNEL_SWITCH_ID */
	uint8 len;	/* length of IE */
	uint8 mode;	/* mode 0 or 1 */
	uint8 channel;	/* channel switch to */
	uint8 count;	/* number of beacons before switching */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_channel_switch dot11_chan_switch_ie_t;

#define DOT11_SWITCH_IE_LEN	3	/* length of IE data, not including 2 byte header */
/* CSA mode - 802.11h-2003 $7.3.2.20 */
#define DOT11_CSA_MODE_ADVISORY		0	/* no DOT11_CSA_MODE_NO_TX restriction imposed */
#define DOT11_CSA_MODE_NO_TX		1	/* no transmission upon receiving CSA frame. */

BWL_PRE_PACKED_STRUCT struct dot11_action_switch_channel {
	uint8	category;
	uint8	action;
	dot11_chan_switch_ie_t chan_switch_ie;	/* for switch IE */
	dot11_brcm_extch_ie_t extch_ie;		/* extension channel offset */
} BWL_POST_PACKED_STRUCT;

BWL_PRE_PACKED_STRUCT struct dot11_csa_body {
	uint8 mode;	/* mode 0 or 1 */
	uint8 reg;	/* regulatory class */
	uint8 channel;	/* channel switch to */
	uint8 count;	/* number of beacons before switching */
} BWL_POST_PACKED_STRUCT;

/** 11n Extended Channel Switch IE data structure */
BWL_PRE_PACKED_STRUCT struct dot11_ext_csa {
	uint8 id;	/* id DOT11_MNG_EXT_CSA_ID */
	uint8 len;	/* length of IE */
	struct dot11_csa_body b;	/* body of the ie */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_ext_csa dot11_ext_csa_ie_t;
#define DOT11_EXT_CSA_IE_LEN	4	/* length of extended channel switch IE body */

BWL_PRE_PACKED_STRUCT struct dot11_action_ext_csa {
	uint8	category;
	uint8	action;
	dot11_ext_csa_ie_t chan_switch_ie;	/* for switch IE */
} BWL_POST_PACKED_STRUCT;

BWL_PRE_PACKED_STRUCT struct dot11y_action_ext_csa {
	uint8	category;
	uint8	action;
	struct dot11_csa_body b;	/* body of the ie */
} BWL_POST_PACKED_STRUCT;

/**  Wide Bandwidth Channel Switch IE data structure */
BWL_PRE_PACKED_STRUCT struct dot11_wide_bw_channel_switch {
	uint8 id;				/* id DOT11_MNG_WIDE_BW_CHANNEL_SWITCH_ID */
	uint8 len;				/* length of IE */
	uint8 channel_width;			/* new channel width */
	uint8 center_frequency_segment_0;	/* center frequency segment 0 */
	uint8 center_frequency_segment_1;	/* center frequency segment 1 */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_wide_bw_channel_switch dot11_wide_bw_chan_switch_ie_t;

#define DOT11_WIDE_BW_SWITCH_IE_LEN     3       /* length of IE data, not including 2 byte header */

/** Channel Switch Wrapper IE data structure */
BWL_PRE_PACKED_STRUCT struct dot11_channel_switch_wrapper {
	uint8 id;				/* id DOT11_MNG_WIDE_BW_CHANNEL_SWITCH_ID */
	uint8 len;				/* length of IE */
	dot11_wide_bw_chan_switch_ie_t wb_chan_switch_ie;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_channel_switch_wrapper dot11_chan_switch_wrapper_ie_t;

typedef enum wide_bw_chan_width {
	WIDE_BW_CHAN_WIDTH_20	= 0,
	WIDE_BW_CHAN_WIDTH_40	= 1,
	WIDE_BW_CHAN_WIDTH_80	= 2,
	WIDE_BW_CHAN_WIDTH_160	= 3,
	WIDE_BW_CHAN_WIDTH_80_80	= 4
} wide_bw_chan_width_t;

/**  Wide Bandwidth Channel IE data structure */
BWL_PRE_PACKED_STRUCT struct dot11_wide_bw_channel {
	uint8 id;				/* id DOT11_MNG_WIDE_BW_CHANNEL_ID */
	uint8 len;				/* length of IE */
	uint8 channel_width;			/* channel width */
	uint8 center_frequency_segment_0;	/* center frequency segment 0 */
	uint8 center_frequency_segment_1;	/* center frequency segment 1 */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_wide_bw_channel dot11_wide_bw_chan_ie_t;

#define DOT11_WIDE_BW_IE_LEN     3       /* length of IE data, not including 2 byte header */
/** VHT Transmit Power Envelope IE data structure */
BWL_PRE_PACKED_STRUCT struct dot11_vht_transmit_power_envelope {
	uint8 id;				/* id DOT11_MNG_WIDE_BW_CHANNEL_SWITCH_ID */
	uint8 len;				/* length of IE */
	uint8 transmit_power_info;
	uint8 local_max_transmit_power_20;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_vht_transmit_power_envelope dot11_vht_transmit_power_envelope_ie_t;

/* vht transmit power envelope IE length depends on channel width */
#define DOT11_VHT_TRANSMIT_PWR_ENVELOPE_IE_LEN_40MHZ	1
#define DOT11_VHT_TRANSMIT_PWR_ENVELOPE_IE_LEN_80MHZ	2
#define DOT11_VHT_TRANSMIT_PWR_ENVELOPE_IE_LEN_160MHZ	3

BWL_PRE_PACKED_STRUCT struct dot11_obss_coex {
	uint8	id;
	uint8	len;
	uint8	info;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_obss_coex dot11_obss_coex_t;
#define DOT11_OBSS_COEXINFO_LEN	1	/* length of OBSS Coexistence INFO IE */

#define	DOT11_OBSS_COEX_INFO_REQ		0x01
#define	DOT11_OBSS_COEX_40MHZ_INTOLERANT	0x02
#define	DOT11_OBSS_COEX_20MHZ_WIDTH_REQ	0x04

BWL_PRE_PACKED_STRUCT struct dot11_obss_chanlist {
	uint8	id;
	uint8	len;
	uint8	regclass;
	uint8	chanlist[1];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_obss_chanlist dot11_obss_chanlist_t;
#define DOT11_OBSS_CHANLIST_FIXED_LEN	1	/* fixed length of regclass */

BWL_PRE_PACKED_STRUCT struct dot11_extcap_ie {
	uint8 id;
	uint8 len;
	uint8 cap[1];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_extcap_ie dot11_extcap_ie_t;

#define DOT11_EXTCAP_LEN_COEX	1
#define DOT11_EXTCAP_LEN_BT	3
#define DOT11_EXTCAP_LEN_IW	4
#define DOT11_EXTCAP_LEN_SI	6

#define DOT11_EXTCAP_LEN_TDLS	5
#define DOT11_11AC_EXTCAP_LEN_TDLS	8

#define DOT11_EXTCAP_LEN_FMS			2
#define DOT11_EXTCAP_LEN_PROXY_ARP		2
#define DOT11_EXTCAP_LEN_TFS			3
#define DOT11_EXTCAP_LEN_WNM_SLEEP		3
#define DOT11_EXTCAP_LEN_TIMBC			3
#define DOT11_EXTCAP_LEN_BSSTRANS		3
#define DOT11_EXTCAP_LEN_DMS			4
#define DOT11_EXTCAP_LEN_WNM_NOTIFICATION	6
#define DOT11_EXTCAP_LEN_TDLS_WBW		8
#define DOT11_EXTCAP_LEN_OPMODE_NOTIFICATION	8
#define DOT11_EXTCAP_LEN_TWT			10u

/* TDLS Capabilities */
#define DOT11_TDLS_CAP_TDLS			37		/* TDLS support */
#define DOT11_TDLS_CAP_PU_BUFFER_STA	28		/* TDLS Peer U-APSD buffer STA support */
#define DOT11_TDLS_CAP_PEER_PSM		20		/* TDLS Peer PSM support */
#define DOT11_TDLS_CAP_CH_SW			30		/* TDLS Channel switch */
#define DOT11_TDLS_CAP_PROH			38		/* TDLS prohibited */
#define DOT11_TDLS_CAP_CH_SW_PROH		39		/* TDLS Channel switch prohibited */
#define DOT11_TDLS_CAP_TDLS_WIDER_BW	61	/* TDLS Wider Band-Width */

#define TDLS_CAP_MAX_BIT		39		/* TDLS max bit defined in ext cap */

/* 802.11h/802.11k Measurement Request/Report IEs */
/* Measurement Type field */
#define DOT11_MEASURE_TYPE_BASIC 	0   /* d11 measurement basic type */
#define DOT11_MEASURE_TYPE_CCA 		1   /* d11 measurement CCA type */
#define DOT11_MEASURE_TYPE_RPI		2   /* d11 measurement RPI type */
#define DOT11_MEASURE_TYPE_CHLOAD	3   /* d11 measurement Channel Load type */
#define DOT11_MEASURE_TYPE_NOISE	4   /* d11 measurement Noise Histogram type */
#define DOT11_MEASURE_TYPE_BEACON	5   /* d11 measurement Beacon type */
#define DOT11_MEASURE_TYPE_FRAME	6   /* d11 measurement Frame type */
#define DOT11_MEASURE_TYPE_STAT		7   /* d11 measurement STA Statistics type */
#define DOT11_MEASURE_TYPE_LCI		8   /* d11 measurement LCI type */
#define DOT11_MEASURE_TYPE_TXSTREAM	9   /* d11 measurement TX Stream type */
#define DOT11_MEASURE_TYPE_MCDIAGS	10  /* d11 measurement multicast diagnostics */
#define DOT11_MEASURE_TYPE_CIVICLOC	11  /* d11 measurement location civic */
#define DOT11_MEASURE_TYPE_LOC_ID	12  /* d11 measurement location identifier */
#define DOT11_MEASURE_TYPE_DIRCHANQ	13  /* d11 measurement dir channel quality */
#define DOT11_MEASURE_TYPE_DIRMEAS	14  /* d11 measurement directional */
#define DOT11_MEASURE_TYPE_DIRSTATS	15  /* d11 measurement directional stats */
#define DOT11_MEASURE_TYPE_FTMRANGE	16  /* d11 measurement Fine Timing */
#define DOT11_MEASURE_TYPE_PAUSE	255	/* d11 measurement pause type */

/* Measurement Request Modes */
#define DOT11_MEASURE_MODE_PARALLEL 	(1<<0)	/* d11 measurement parallel */
#define DOT11_MEASURE_MODE_ENABLE 	(1<<1)	/* d11 measurement enable */
#define DOT11_MEASURE_MODE_REQUEST	(1<<2)	/* d11 measurement request */
#define DOT11_MEASURE_MODE_REPORT 	(1<<3)	/* d11 measurement report */
#define DOT11_MEASURE_MODE_DUR 	(1<<4)	/* d11 measurement dur mandatory */
/* Measurement Report Modes */
#define DOT11_MEASURE_MODE_LATE 	(1<<0)	/* d11 measurement late */
#define DOT11_MEASURE_MODE_INCAPABLE	(1<<1)	/* d11 measurement incapable */
#define DOT11_MEASURE_MODE_REFUSED	(1<<2)	/* d11 measurement refuse */
/* Basic Measurement Map bits */
#define DOT11_MEASURE_BASIC_MAP_BSS	((uint8)(1<<0))	/* d11 measurement basic map BSS */
#define DOT11_MEASURE_BASIC_MAP_OFDM	((uint8)(1<<1))	/* d11 measurement map OFDM */
#define DOT11_MEASURE_BASIC_MAP_UKNOWN	((uint8)(1<<2))	/* d11 measurement map unknown */
#define DOT11_MEASURE_BASIC_MAP_RADAR	((uint8)(1<<3))	/* d11 measurement map radar */
#define DOT11_MEASURE_BASIC_MAP_UNMEAS	((uint8)(1<<4))	/* d11 measurement map unmeasuremnt */

BWL_PRE_PACKED_STRUCT struct dot11_meas_req {
	uint8 id;
	uint8 len;
	uint8 token;
	uint8 mode;
	uint8 type;
	uint8 channel;
	uint8 start_time[8];
	uint16 duration;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_meas_req dot11_meas_req_t;
#define DOT11_MNG_IE_MREQ_LEN 14	/* d11 measurement request IE length */
/* length of Measure Request IE data not including variable len */
#define DOT11_MNG_IE_MREQ_FIXED_LEN 3	/* d11 measurement request IE fixed length */

BWL_PRE_PACKED_STRUCT struct dot11_meas_req_loc {
	uint8 id;
	uint8 len;
	uint8 token;
	uint8 mode;
	uint8 type;
	BWL_PRE_PACKED_STRUCT union
	{
		BWL_PRE_PACKED_STRUCT struct {
			uint8 subject;
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT lci;
		BWL_PRE_PACKED_STRUCT struct {
			uint8 subject;
			uint8 type;  /* type of civic location */
			uint8 siu;   /* service interval units */
			uint16 si; /* service interval */
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT civic;
		BWL_PRE_PACKED_STRUCT struct {
			uint8 subject;
			uint8 siu;   /* service interval units */
			uint16 si; /* service interval */
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT locid;
		BWL_PRE_PACKED_STRUCT struct {
			uint16 max_init_delay;		/* maximum random initial delay */
			uint8 min_ap_count;
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT ftm_range;
	} BWL_POST_PACKED_STRUCT req;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_meas_req_loc dot11_meas_req_loc_t;
#define DOT11_MNG_IE_MREQ_MIN_LEN           4	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREQ_LCI_FIXED_LEN     4	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREQ_CIVIC_FIXED_LEN   8	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREQ_FRNG_FIXED_LEN    6	/* d11 measurement report IE length */

BWL_PRE_PACKED_STRUCT struct dot11_lci_subelement {
	uint8 subelement;
	uint8 length;
	uint8 lci_data[1];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_lci_subelement dot11_lci_subelement_t;

BWL_PRE_PACKED_STRUCT struct dot11_colocated_bssid_list_se {
	uint8 sub_id;
	uint8 length;
	uint8 max_bssid_ind; /* MaxBSSID Indicator */
	struct ether_addr bssid[1]; /* variable */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_colocated_bssid_list_se dot11_colocated_bssid_list_se_t;
#define DOT11_LCI_COLOCATED_BSSID_LIST_FIXED_LEN     3
#define DOT11_LCI_COLOCATED_BSSID_SUBELEM_ID         7

BWL_PRE_PACKED_STRUCT struct dot11_civic_subelement {
	uint8 type;  /* type of civic location */
	uint8 subelement;
	uint8 length;
	uint8 civic_data[1];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_civic_subelement dot11_civic_subelement_t;

BWL_PRE_PACKED_STRUCT struct dot11_meas_rep {
	uint8 id;
	uint8 len;
	uint8 token;
	uint8 mode;
	uint8 type;
	BWL_PRE_PACKED_STRUCT union
	{
		BWL_PRE_PACKED_STRUCT struct {
			uint8 channel;
			uint8 start_time[8];
			uint16 duration;
			uint8 map;
		} BWL_POST_PACKED_STRUCT basic;
		BWL_PRE_PACKED_STRUCT struct {
			uint8 subelement;
			uint8 length;
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT lci;
		BWL_PRE_PACKED_STRUCT struct {
			uint8 type;  /* type of civic location */
			uint8 subelement;
			uint8 length;
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT civic;
		BWL_PRE_PACKED_STRUCT struct {
			uint8 exp_tsf[8];
			uint8 subelement;
			uint8 length;
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT locid;
		BWL_PRE_PACKED_STRUCT struct {
			uint8 entry_count;
			uint8 data[1];
		} BWL_POST_PACKED_STRUCT ftm_range;
		uint8 data[1];
	} BWL_POST_PACKED_STRUCT rep;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_meas_rep dot11_meas_rep_t;
#define DOT11_MNG_IE_MREP_MIN_LEN           5	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREP_LCI_FIXED_LEN     5	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREP_CIVIC_FIXED_LEN   6	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREP_LOCID_FIXED_LEN   13	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREP_BASIC_FIXED_LEN   15	/* d11 measurement report IE length */
#define DOT11_MNG_IE_MREP_FRNG_FIXED_LEN    4

/* length of Measure Report IE data not including variable len */
#define DOT11_MNG_IE_MREP_FIXED_LEN	3	/* d11 measurement response IE fixed length */

BWL_PRE_PACKED_STRUCT struct dot11_meas_rep_basic {
	uint8 channel;
	uint8 start_time[8];
	uint16 duration;
	uint8 map;
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_meas_rep_basic dot11_meas_rep_basic_t;
#define DOT11_MEASURE_BASIC_REP_LEN	12	/* d11 measurement basic report length */

BWL_PRE_PACKED_STRUCT struct dot11_quiet {
	uint8 id;
	uint8 len;
	uint8 count;	/* TBTTs until beacon interval in quiet starts */
	uint8 period;	/* Beacon intervals between periodic quiet periods ? */
	uint16 duration;	/* Length of quiet period, in TU's */
	uint16 offset;	/* TU's offset from TBTT in Count field */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_quiet dot11_quiet_t;

BWL_PRE_PACKED_STRUCT struct chan_map_tuple {
	uint8 channel;
	uint8 map;
} BWL_POST_PACKED_STRUCT;
typedef struct chan_map_tuple chan_map_tuple_t;

BWL_PRE_PACKED_STRUCT struct dot11_ibss_dfs {
	uint8 id;
	uint8 len;
	uint8 eaddr[ETHER_ADDR_LEN];
	uint8 interval;
	chan_map_tuple_t map[1];
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_ibss_dfs dot11_ibss_dfs_t;

/* WME Elements */
#define WME_OUI			"\x00\x50\xf2"	/* WME OUI */
#define WME_OUI_LEN		3
#define WME_OUI_TYPE		2	/* WME type */
#define WME_TYPE		2	/* WME type, deprecated */
#define WME_SUBTYPE_IE		0	/* Information Element */
#define WME_SUBTYPE_PARAM_IE	1	/* Parameter Element */
#define WME_SUBTYPE_TSPEC	2	/* Traffic Specification */
#define WME_VER			1	/* WME version */

/* WME Access Category Indices (ACIs) */
#define AC_BE			0	/* Best Effort */
#define AC_BK			1	/* Background */
#define AC_VI			2	/* Video */
#define AC_VO			3	/* Voice */
#define AC_COUNT		4	/* number of ACs */

typedef uint8 ac_bitmap_t;	/* AC bitmap of (1 << AC_xx) */

#define AC_BITMAP_NONE		0x0	/* No ACs */
#define AC_BITMAP_ALL		0xf	/* All ACs */
#define AC_BITMAP_TST(ab, ac)	(((ab) & (1 << (ac))) != 0)
#define AC_BITMAP_SET(ab, ac)	(((ab) |= (1 << (ac))))
#define AC_BITMAP_RESET(ab, ac) (((ab) &= ~(1 << (ac))))

/* Management PKT Lifetime indices */
/* Removing flag checks 'BCMINTERNAL || WLTEST'
 * while merging MERGE BIS120RC4 to DINGO2
 */
#define MGMT_ALL		0xffff
#define MGMT_AUTH_LT	FC_SUBTYPE_AUTH
#define MGMT_ASSOC_LT	FC_SUBTYPE_ASSOC_REQ

/** WME Information Element (IE) */
BWL_PRE_PACKED_STRUCT struct wme_ie {
	uint8 oui[3];
	uint8 type;
	uint8 subtype;
	uint8 version;
	uint8 qosinfo;
} BWL_POST_PACKED_STRUCT;
typedef struct wme_ie wme_ie_t;
#define WME_IE_LEN 7	/* WME IE length */

BWL_PRE_PACKED_STRUCT struct edcf_acparam {
	uint8	ACI;
	uint8	ECW;
	uint16  TXOP;		/* stored in network order (ls octet first) */
} BWL_POST_PACKED_STRUCT;
typedef struct edcf_acparam edcf_acparam_t;

/** WME Parameter Element (PE) */
BWL_PRE_PACKED_STRUCT struct wme_param_ie {
	uint8 oui[3];
	uint8 type;
	uint8 subtype;
	uint8 version;
	uint8 qosinfo;
	uint8 rsvd;
	edcf_acparam_t acparam[AC_COUNT];
} BWL_POST_PACKED_STRUCT;
typedef struct wme_param_ie wme_param_ie_t;
#define WME_PARAM_IE_LEN            24          /* WME Parameter IE length */

/* QoS Info field for IE as sent from AP */
#define WME_QI_AP_APSD_MASK         0x80        /* U-APSD Supported mask */
#define WME_QI_AP_APSD_SHIFT        7           /* U-APSD Supported shift */
#define WME_QI_AP_COUNT_MASK        0x0f        /* Parameter set count mask */
#define WME_QI_AP_COUNT_SHIFT       0           /* Parameter set count shift */

/* QoS Info field for IE as sent from STA */
#define WME_QI_STA_MAXSPLEN_MASK    0x60        /* Max Service Period Length mask */
#define WME_QI_STA_MAXSPLEN_SHIFT   5           /* Max Service Period Length shift */
#define WME_QI_STA_APSD_ALL_MASK    0xf         /* APSD all AC bits mask */
#define WME_QI_STA_APSD_ALL_SHIFT   0           /* APSD all AC bits shift */
#define WME_QI_STA_APSD_BE_MASK     0x8         /* APSD AC_BE mask */
#define WME_QI_STA_APSD_BE_SHIFT    3           /* APSD AC_BE shift */
#define WME_QI_STA_APSD_BK_MASK     0x4         /* APSD AC_BK mask */
#define WME_QI_STA_APSD_BK_SHIFT    2           /* APSD AC_BK shift */
#define WME_QI_STA_APSD_VI_MASK     0x2         /* APSD AC_VI mask */
#define WME_QI_STA_APSD_VI_SHIFT    1           /* APSD AC_VI shift */
#define WME_QI_STA_APSD_VO_MASK     0x1         /* APSD AC_VO mask */
#define WME_QI_STA_APSD_VO_SHIFT    0           /* APSD AC_VO shift */

/* ACI */
#define EDCF_AIFSN_MIN               1           /* AIFSN minimum value */
#define EDCF_AIFSN_MAX               15          /* AIFSN maximum value */
#define EDCF_AIFSN_MASK              0x0f        /* AIFSN mask */
#define EDCF_ACM_MASK                0x10        /* ACM mask */
#define EDCF_ACI_MASK                0x60        /* ACI mask */
#define EDCF_ACI_SHIFT               5           /* ACI shift */
#define EDCF_AIFSN_SHIFT             12          /* 4 MSB(0xFFF) in ifs_ctl for AC idx */

/* ECW */
#define EDCF_ECW_MIN                 0           /* cwmin/cwmax exponent minimum value */
#define EDCF_ECW_MAX                 15          /* cwmin/cwmax exponent maximum value */
#define EDCF_ECW2CW(exp)             ((1 << (exp)) - 1)
#define EDCF_ECWMIN_MASK             0x0f        /* cwmin exponent form mask */
#define EDCF_ECWMAX_MASK             0xf0        /* cwmax exponent form mask */
#define EDCF_ECWMAX_SHIFT            4           /* cwmax exponent form shift */

/* TXOP */
#define EDCF_TXOP_MIN                0           /* TXOP minimum value */
#define EDCF_TXOP_MAX                65535       /* TXOP maximum value */
#define EDCF_TXOP2USEC(txop)         ((txop) << 5)

/* Default BE ACI value for non-WME connection STA */
#define NON_EDCF_AC_BE_ACI_STA          0x02

/* Default EDCF parameters that AP advertises for STA to use; WMM draft Table 12 */
#define EDCF_AC_BE_ACI_STA           0x03	/* STA ACI value for best effort AC */
#define EDCF_AC_BE_ECW_STA           0xA4	/* STA ECW value for best effort AC */
#define EDCF_AC_BE_TXOP_STA          0x0000	/* STA TXOP value for best effort AC */
#define EDCF_AC_BK_ACI_STA           0x27	/* STA ACI value for background AC */
#define EDCF_AC_BK_ECW_STA           0xA4	/* STA ECW value for background AC */
#define EDCF_AC_BK_TXOP_STA          0x0000	/* STA TXOP value for background AC */
#define EDCF_AC_VI_ACI_STA           0x42	/* STA ACI value for video AC */
#define EDCF_AC_VI_ECW_STA           0x43	/* STA ECW value for video AC */
#define EDCF_AC_VI_TXOP_STA          0x005e	/* STA TXOP value for video AC */
#define EDCF_AC_VO_ACI_STA           0x62	/* STA ACI value for audio AC */
#define EDCF_AC_VO_ECW_STA           0x32	/* STA ECW value for audio AC */
#define EDCF_AC_VO_TXOP_STA          0x002f	/* STA TXOP value for audio AC */

/* Default EDCF parameters that AP uses; WMM draft Table 14 */
#define EDCF_AC_BE_ACI_AP            0x03	/* AP ACI value for best effort AC */
#define EDCF_AC_BE_ECW_AP            0x64	/* AP ECW value for best effort AC */
#define EDCF_AC_BE_TXOP_AP           0x0000	/* AP TXOP value for best effort AC */
#define EDCF_AC_BK_ACI_AP            0x27	/* AP ACI value for background AC */
#define EDCF_AC_BK_ECW_AP            0xA4	/* AP ECW value for background AC */
#define EDCF_AC_BK_TXOP_AP           0x0000	/* AP TXOP value for background AC */
#define EDCF_AC_VI_ACI_AP            0x41	/* AP ACI value for video AC */
#define EDCF_AC_VI_ECW_AP            0x43	/* AP ECW value for video AC */
#define EDCF_AC_VI_TXOP_AP           0x005e	/* AP TXOP value for video AC */
#define EDCF_AC_VO_ACI_AP            0x61	/* AP ACI value for audio AC */
#define EDCF_AC_VO_ECW_AP            0x32	/* AP ECW value for audio AC */
#define EDCF_AC_VO_TXOP_AP           0x002f	/* AP TXOP value for audio AC */

/** EDCA Parameter IE */
BWL_PRE_PACKED_STRUCT struct edca_param_ie {
	uint8 qosinfo;
	uint8 rsvd;
	edcf_acparam_t acparam[AC_COUNT];
} BWL_POST_PACKED_STRUCT;
typedef struct edca_param_ie edca_param_ie_t;
#define EDCA_PARAM_IE_LEN            18          /* EDCA Parameter IE length */

/** QoS Capability IE */
BWL_PRE_PACKED_STRUCT struct qos_cap_ie {
	uint8 qosinfo;
} BWL_POST_PACKED_STRUCT;
typedef struct qos_cap_ie qos_cap_ie_t;

BWL_PRE_PACKED_STRUCT struct dot11_qbss_load_ie {
	uint8 id;			/* 11, DOT11_MNG_QBSS_LOAD_ID */
	uint8 length;
	uint16 station_count;		/* total number of STAs associated */
	uint8 channel_utilization;	/* % of time, normalized to 255, QAP sensed medium busy */
	uint16 aac;			/* available admission capacity */
} BWL_POST_PACKED_STRUCT;
typedef struct dot11_qbss_load_ie dot11_qbss_load_ie_t;
#define BSS_LOAD_IE_SIZE	7	/* BSS load IE size */

#define WLC_QBSS_LOAD_CHAN_FREE_MAX	0xff	/* max for channel free score */

/* Estimated Service Parameters (ESP) IE - 802.11-2016 9.4.2.174 */
typedef BWL_PRE_PACKED_STRUCT struct dot11_esp_ie {
	uint8		id;
	uint8		length;
	uint8		id_ext;
	/* variable len info */
	uint8		esp_info_lists[];
} BWL_POST_PACKED_STRUCT dot11_esp_ie_t;

#define DOT11_ESP_IE_HDR_SIZE	(OFFSETOF(dot11_esp_ie_t, esp_info_lists))

/* ESP Information list - 802.11-2016 9.4.2.174 */
typedef BWL_PRE_PACKED_STRUCT struct dot11_esp_ie_info_list {
	/* acess category, data format, ba win size */
	uint8		ac_df_baws;
	/* estimated air time fraction */
	uint8		eat_frac;
	/* data PPDU duration target (50us units) */
	uint8		ppdu_dur;
} BWL_POST_PACKED_STRUCT dot11_esp_ie_info_list_t;

#define DOT11_ESP_IE_INFO_LIST_SIZE	(sizeof(dot11_esp_ie_info_list_t))

#define DOT11_ESP_NBR_INFO_LISTS	4u	/* max nbr of esp information lists */
#define DOT11_ESP_INFO_LIST_AC_BK	0u	/* access category of esp information list AC_BK */
#define DOT11_ESP_INFO_LIST_AC_BE	1u	/* access category of esp information list AC_BE */
#define DOT11_ESP_INFO_LIST_AC_VI	2u	/* access category of esp information list AC_VI */
#define DOT11_ESP_INFO_LIST_AC_VO	3u	/* access category of esp information list AC_VO */

#define DOT11_ESP_INFO_LIST_DF_MASK    0x18		/* Data Format Mask */
#define DOT11_ESP_INFO_LIST_BAWS_MASK  0xE0		/* BA window size mask */

/* nom_msdu_size */
#define FIXED_MSDU_SIZE 0x8000		/* MSDU size is fixed */
#define MSDU_SIZE_MASK	0x7fff		/* (Nominal or fixed) MSDU size */

/* surplus_bandwidth */
/* Represented as 3 bits of integer, binary point, 13 bits fraction */
#define	INTEGER_SHIFT	13	/* integer shift */
#define FRACTION_MASK	0x1FFF	/* fraction mask */

/** Management Notification Frame */
BWL_PRE_PACKED_STRUCT struct dot11_management_notification {
	uint8 category;			/* DOT11_ACTION_NOTIFICATION */
	uint8 action;
	uint8 token;
	uint8 status;
	uint8 data[1];			/* Elements */
} BWL_POST_PACKED_STRUCT;
#define DOT11_MGMT_NOTIFICATION_LEN 4	/* Fixed length */

/** Timeout Interval IE */
BWL_PRE_PACKED_STRUCT struct ti_ie {
	uint8 ti_type;
	uint32 ti_val;
} BWL_POST_PACKED_STRUCT;
typedef struct ti_ie ti_ie_t;
#define TI_TYPE_REASSOC_DEADLINE	1
#define TI_TYPE_KEY_LIFETIME		2

#ifndef CISCO_AIRONET_OUI
#define CISCO_AIRONET_OUI	"\x00\x40\x96"	/* Cisco AIRONET OUI */
#endif // endif
/* QoS FastLane IE. */
BWL_PRE_PACKED_STRUCT struct ccx_qfl_ie {
	uint8	id;		/* 221, DOT11_MNG_VS_ID */
	uint8	length;		/* 5 */
	uint8	oui[3];		/* 00:40:96 */
	uint8	type;		/* 11 */
	uint8	data;
} BWL_POST_PACKED_STRUCT;
typedef struct ccx_qfl_ie ccx_qfl_ie_t;
#define CCX_QFL_IE_TYPE	11
#define CCX_QFL_ENABLE_SHIFT	5
#define CCX_QFL_ENALBE (1 << CCX_QFL_ENABLE_SHIFT)

/* WME Action Codes */
#define WME_ADDTS_REQUEST	0	/* WME ADDTS request */
#define WME_ADDTS_RESPONSE	1	/* WME ADDTS response */
#define WME_DELTS_REQUEST	2	/* WME DELTS request */

/* WME Setup Response Status Codes */
#define WME_ADMISSION_ACCEPTED		0	/* WME admission accepted */
#define WME_INVALID_PARAMETERS		1	/* WME invalide parameters */
#define WME_ADMISSION_REFUSED		3	/* WME admission refused */

/* Macro to take a pointer to a beacon or probe response
 * body and return the char* pointer to the SSID info element
 */
#define BCN_PRB_SSID(body) ((char*)(body) + DOT11_BCN_PRB_LEN)

/* Authentication frame payload constants */
#define DOT11_OPEN_SYSTEM	0	/* d11 open authentication */
#define DOT11_SHARED_KEY	1	/* d11 shared authentication */
#define DOT11_FAST_BSS		2	/* d11 fast bss authentication */
#define DOT11_SAE		3	/* d11 simultaneous authentication of equals */
#define DOT11_FILS_SKEY		4	/* d11 fils shared key authentication w/o pfs */
#define DOT11_FILS_SKEY_PFS	5	/* d11 fils shared key authentication w/ pfs */
#define DOT11_FILS_PKEY		6	/* d11 fils public key authentication */
#define DOT11_CHALLENGE_LEN	128	/* d11 challenge text length */

/* Frame control macros */
#define FC_PVER_MASK		0x3	/* PVER mask */
#define FC_PVER_SHIFT		0	/* PVER shift */
#define FC_TYPE_MASK		0xC	/* type mask */
#define FC_TYPE_SHIFT		2	/* type shift */
#define FC_SUBTYPE_MASK		0xF0	/* subtype mask */
#define FC_SUBTYPE_SHIFT	4	/* subtype shift */
#define FC_TODS			0x100	/* to DS */
#define FC_TODS_SHIFT		8	/* to DS shift */
#define FC_FROMDS		0x200	/* from DS */
#define FC_FROMDS_SHIFT		9	/* from DS shift */
#define FC_MOREFRAG		0x400	/* more frag. */
#define FC_MOREFRAG_SHIFT	10	/* more frag. shift */
#define FC_RETRY		0x800	/* retry */
#define FC_RETRY_SHIFT		11	/* retry shift */
#define FC_PM			0x1000	/* PM */
#define FC_PM_SHIFT		12	/* PM shift */
#define FC_MOREDATA		0x2000	/* more data */
#define FC_MOREDATA_SHIFT	13	/* more data shift */
#define FC_WEP			0x4000	/* WEP */
#define FC_WEP_SHIFT		14	/* WEP shift */
#define FC_ORDER		0x8000	/* order */
#define FC_ORDER_SHIFT		15	/* order shift */

/* sequence control macros */
#define SEQNUM_SHIFT		4	/* seq. number shift */
#define SEQNUM_MAX		0x1000	/* max seqnum + 1 */
#define FRAGNUM_MASK		0xF	/* frag. number mask */

/* Frame Control type/subtype defs */

/* FC Types */
#define FC_TYPE_MNG		0	/* management type */
#define FC_TYPE_CTL		1	/* control type */
#define FC_TYPE_DATA		2	/* data type */

/* Management Subtypes */
#define FC_SUBTYPE_ASSOC_REQ		0	/* assoc. request */
#define FC_SUBTYPE_ASSOC_RESP		1	/* assoc. response */
#define FC_SUBTYPE_REASSOC_REQ		2	/* reassoc. request */
#define FC_SUBTYPE_REASSOC_RESP		3	/* reassoc. response */
#define FC_SUBTYPE_PROBE_REQ		4	/* probe request */
#define FC_SUBTYPE_PROBE_RESP		5	/* probe response */
#define FC_SUBTYPE_BEACON		8	/* beacon */
#define FC_SUBTYPE_ATIM			9	/* ATIM */
#define FC_SUBTYPE_DISASSOC		10	/* disassoc. */
#define FC_SUBTYPE_AUTH			11	/* authentication */
#define FC_SUBTYPE_DEAUTH		12	/* de-authentication */
#define FC_SUBTYPE_ACTION		13	/* action */
#define FC_SUBTYPE_ACTION_NOACK		14	/* action no-ack */

/* Control Subtypes */
#define FC_SUBTYPE_TRIGGER		2	/* Trigger frame */
#define FC_SUBTYPE_CTL_WRAPPER		7	/* Control Wrapper */
#define FC_SUBTYPE_BLOCKACK_REQ		8	/* Block Ack Req */
#define FC_SUBTYPE_BLOCKACK		9	/* Block Ack */
#define FC_SUBTYPE_PS_POLL		10	/* PS poll */
#define FC_SUBTYPE_RTS			11	/* RTS */
#define FC_SUBTYPE_CTS			12	/* CTS */
#define FC_SUBTYPE_ACK			13	/* ACK */
#define FC_SUBTYPE_CF_END		14	/* CF-END */
#define FC_SUBTYPE_CF_END_ACK		15	/* CF-END ACK */

/* Data Subtypes */
#define FC_SUBTYPE_DATA			0	/* Data */
#define FC_SUBTYPE_DATA_CF_ACK		1	/* Data + CF-ACK */
#define FC_SUBTYPE_DATA_CF_POLL		2	/* Data + CF-Poll */
#define FC_SUBTYPE_DATA_CF_ACK_POLL	3	/* Data + CF-Ack + CF-Poll */
#define FC_SUBTYPE_NULL			4	/* Null */
#define FC_SUBTYPE_CF_ACK		5	/* CF-Ack */
#define FC_SUBTYPE_CF_POLL		6	/* CF-Poll */
#define FC_SUBTYPE_CF_ACK_POLL		7	/* CF-Ack + CF-Poll */
#define FC_SUBTYPE_QOS_DATA		8	/* QoS Data */
#define FC_SUBTYPE_QOS_DATA_CF_ACK	9	/* QoS Data + CF-Ack */
#define FC_SUBTYPE_QOS_DATA_CF_POLL	10	/* QoS Data + CF-Poll */
#define FC_SUBTYPE_QOS_DATA_CF_ACK_POLL	11	/* QoS Data + CF-Ack + CF-Poll */
#define FC_SUBTYPE_QOS_NULL		12	/* QoS Null */
#define FC_SUBTYPE_QOS_CF_POLL		14	/* QoS CF-Poll */
#define FC_SUBTYPE_QOS_CF_ACK_POLL	15	/* QoS CF-Ack + CF-Poll */

/* Data Subtype Groups */
#define FC_SUBTYPE_ANY_QOS(s)		(((s) & 8) != 0)
#define FC_SUBTYPE_ANY_NULL(s)		(((s) & 4) != 0)
#define FC_SUBTYPE_ANY_CF_POLL(s)	(((s) & 2) != 0)
#define FC_SUBTYPE_ANY_CF_ACK(s)	(((s) & 1) != 0)
#define FC_SUBTYPE_ANY_PSPOLL(s)	(((s) & 10) != 0)

/* Type/Subtype Combos */
#define FC_KIND_MASK		(FC_TYPE_MASK | FC_SUBTYPE_MASK)	/* FC kind mask */

#define FC_KIND(t, s)	(((t) << FC_TYPE_SHIFT) | ((s) << FC_SUBTYPE_SHIFT))	/* FC kind */

#define FC_SUBTYPE(fc)	(((fc) & FC_SUBTYPE_MASK) >> FC_SUBTYPE_SHIFT)	/* Subtype from FC */
#define FC_TYPE(fc)	(((fc) & FC_TYPE_MASK) >> FC_TYPE_SHIFT)	/* Type from FC */

#define FC_ASSOC_REQ	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_ASSOC_REQ)	/* assoc. request */
#define FC_ASSOC_RESP	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_ASSOC_RESP)	/* assoc. response */
#define FC_REASSOC_REQ	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_REASSOC_REQ)	/* reassoc. request */
#define FC_REASSOC_RESP	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_REASSOC_RESP)	/* reassoc. response */
#define FC_PROBE_REQ	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_PROBE_REQ)	/* probe request */
#define FC_PROBE_RESP	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_PROBE_RESP)	/* probe response */
#define FC_BEACON	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_BEACON)		/* beacon */
#define FC_ATIM		FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_ATIM)		/* ATIM */
#define FC_DISASSOC	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_DISASSOC)	/* disassoc */
#define FC_AUTH		FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_AUTH)		/* authentication */
#define FC_DEAUTH	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_DEAUTH)		/* deauthentication */
#define FC_ACTION	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_ACTION)		/* action */
#define FC_ACTION_NOACK	FC_KIND(FC_TYPE_MNG, FC_SUBTYPE_ACTION_NOACK)	/* action no-ack */

#define FC_CTL_TRIGGER	FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_TRIGGER)	/* Trigger frame */
#define FC_CTL_WRAPPER	FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_CTL_WRAPPER)	/* Control Wrapper */
#define FC_BLOCKACK_REQ	FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_BLOCKACK_REQ)	/* Block Ack Req */
#define FC_BLOCKACK	FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_BLOCKACK)	/* Block Ack */
#define FC_PS_POLL	FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_PS_POLL)	/* PS poll */
#define FC_RTS		FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_RTS)		/* RTS */
#define FC_CTS		FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_CTS)		/* CTS */
#define FC_ACK		FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_ACK)		/* ACK */
#define FC_CF_END	FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_CF_END)		/* CF-END */
#define FC_CF_END_ACK	FC_KIND(FC_TYPE_CTL, FC_SUBTYPE_CF_END_ACK)	/* CF-END ACK */

#define FC_DATA		FC_KIND(FC_TYPE_DATA, FC_SUBTYPE_DATA)		/* data */
#define FC_NULL_DATA	FC_KIND(FC_TYPE_DATA, FC_SUBTYPE_NULL)		/* null data */
#define FC_DATA_CF_ACK	FC_KIND(FC_TYPE_DATA, FC_SUBTYPE_DATA_CF_ACK)	/* data CF ACK */
#define FC_QOS_DATA	FC_KIND(FC_TYPE_DATA, FC_SUBTYPE_QOS_DATA)	/* QoS data */
#define FC_QOS_NULL	FC_KIND(FC_TYPE_DATA, FC_SUBTYPE_QOS_NULL)	/* QoS null */

/* QoS Control Field */

/* 802.1D Priority */
#define QOS_PRIO_SHIFT		0	/* QoS priority shift */
#define QOS_PRIO_MASK		0x0007	/* QoS priority mask */
#define QOS_PRIO(qos)		(((qos) & QOS_PRIO_MASK) >> QOS_PRIO_SHIFT)	/* QoS priority */

/* Traffic Identifier */
#define QOS_TID_SHIFT		0	/* QoS TID shift */
#define QOS_TID_MASK		0x000f	/* QoS TID mask */
#define QOS_TID(qos)		(((qos) & QOS_TID_MASK) >> QOS_TID_SHIFT)	/* QoS TID */

/* End of Service Period (U-APSD) */
#define QOS_EOSP_SHIFT		4	/* QoS End of Service Period shift */
#define QOS_EOSP_MASK		0x0010	/* QoS End of Service Period mask */
#define QOS_EOSP(qos)		(((qos) & QOS_EOSP_MASK) >> QOS_EOSP_SHIFT)	/* Qos EOSP */

/* Ack Policy */
#define QOS_ACK_NORMAL_ACK	0	/* Normal Ack */
#define QOS_ACK_NO_ACK		1	/* No Ack (eg mcast) */
#define QOS_ACK_NO_EXP_ACK	2	/* No Explicit Ack */
#define QOS_ACK_BLOCK_ACK	3	/* Block Ack */
#define QOS_ACK_SHIFT		5	/* QoS ACK shift */
#define QOS_ACK_MASK		0x0060	/* QoS ACK mask */
#define QOS_ACK(qos)		(((qos) & QOS_ACK_MASK) >> QOS_ACK_SHIFT)	/* QoS ACK */

/* A-MSDU flag */
#define QOS_AMSDU_SHIFT		7	/* AMSDU shift */
#define QOS_AMSDU_MASK		0x0080	/* AMSDU mask */

/* Management Frames */

/* Management Frame Constants */


/*
 * Driver O/S-independent utility routines
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
 * $Id: bcmutils.c 813798 2019-04-08 10:20:21Z $
 */

#include <bcm_cfg.h>
#include <typedefs.h>
#include <bcmdefs.h>
#include <stdarg.h>
#ifdef BCMDRIVER
#include <osl.h>
#include <bcmutils.h>

#else /* !BCMDRIVER */

#include <stdio.h>
#include <string.h>
#include <bcm_math.h>
#include <bcmutils.h>

#if defined(BCMEXTSUP)
#include <bcm_osl.h>
#endif // endif

#ifndef ASSERT
#define ASSERT(exp)
#endif // endif

#endif /* !BCMDRIVER */

#ifdef WL_UNITTEST
#ifdef ASSERT
#undef ASSERT
#endif /* ASSERT */
#define ASSERT(exp)
#endif /* WL_UNITTEST */

#include <bcmstdlib_s.h>
#include <bcmendian.h>
#include <bcmdevs.h>
#include <ethernet.h>
#include <vlan.h>
#include <bcmip.h>
#include <802.1d.h>
#include <802.11.h>
#include <bcmip.h>
#include <bcmipv6.h>
#include <bcmtcp.h>
#include <wl_android.h>

#ifdef BCMDRIVER

/* return total length of buffer chain */
uint BCMFASTPATH
pkttotlen(osl_t *osh, void *p)
{
	uint total;
	int len;

	total = 0;
	for (; p; p = PKTNEXT(osh, p)) {
		len = PKTLEN(osh, p);
		total += (uint)len;
#ifdef BCMLFRAG
		if (BCMLFRAG_ENAB()) {
			if (PKTISFRAG(osh, p)) {
				total += PKTFRAGTOTLEN(osh, p);
			}
		}
#endif // endif
	}

	return (total);
}

/* return the last buffer of chained pkt */
void *
pktlast(osl_t *osh, void *p)
{
	for (; PKTNEXT(osh, p); p = PKTNEXT(osh, p))
		;

	return (p);
}

/* count segments of a chained packet */
uint BCMFASTPATH
pktsegcnt(osl_t *osh, void *p)
{
	uint cnt;

	for (cnt = 0; p; p = PKTNEXT(osh, p)) {
		cnt++;
#ifdef BCMLFRAG
		if (BCMLFRAG_ENAB()) {
			if (PKTISFRAG(osh, p)) {
				cnt += PKTFRAGTOTNUM(osh, p);
			}
		}
#endif // endif
	}

	return cnt;
}

/* copy a pkt buffer chain into a buffer */
uint
pktcopy(osl_t *osh, void *p, uint offset, int len, uchar *buf)
{
	uint n, ret = 0;

	if (len < 0)
		len = 4096;	/* "infinite" */

	/* skip 'offset' bytes */
	for (; p && offset; p = PKTNEXT(osh, p)) {
		if (offset < (uint)PKTLEN(osh, p))
			break;
		offset -= (uint)PKTLEN(osh, p);
	}

	if (!p)
		return 0;

	/* copy the data */
	for (; p && len; p = PKTNEXT(osh, p)) {
		n = MIN((uint)PKTLEN(osh, p) - offset, (uint)len);
		bcopy(PKTDATA(osh, p) + offset, buf, n);
		buf += n;
		len -= n;
		ret += n;
		offset = 0;
	}

	return ret;
}

/* copy a buffer into a pkt buffer chain */
uint
pktfrombuf(osl_t *osh, void *p, uint offset, int len, uchar *buf)
{
	uint n, ret = 0;

	/* skip 'offset' bytes */
	for (; p && offset; p = PKTNEXT(osh, p)) {
		if (offset < (uint)PKTLEN(osh, p))
			break;
		offset -= (uint)PKTLEN(osh, p);
	}

	if (!p)
		return 0;

	/* copy the data */
	for (; p && len; p = PKTNEXT(osh, p)) {
		n = MIN((uint)PKTLEN(osh, p) - offset, (uint)len);
		bcopy(buf, PKTDATA(osh, p) + offset, n);
		buf += n;
		len -= n;
		ret += n;
		offset = 0;
	}

	return ret;
}

uint8 * BCMFASTPATH
pktdataoffset(osl_t *osh, void *p,  uint offset)
{
	uint total = pkttotlen(osh, p);
	uint pkt_off = 0, len = 0;
	uint8 *pdata = (uint8 *) PKTDATA(osh, p);

	if (offset > total)
		return NULL;

	for (; p; p = PKTNEXT(osh, p)) {
		pdata = (uint8 *) PKTDATA(osh, p);
		pkt_off = offset - len;
		len += (uint)PKTLEN(osh, p);
		if (len > offset)
			break;
	}
	return (uint8*) (pdata+pkt_off);
}

/* given a offset in pdata, find the pkt seg hdr */
void *
pktoffset(osl_t *osh, void *p,  uint offset)
{
	uint total = pkttotlen(osh, p);
	uint len = 0;

	if (offset > total)
		return NULL;

	for (; p; p = PKTNEXT(osh, p)) {
		len += (uint)PKTLEN(osh, p);
		if (len > offset)
			break;
	}
	return p;
}

void
bcm_mdelay(uint ms)
{
	uint i;

	for (i = 0; i < ms; i++) {
		OSL_DELAY(1000);
	}
}

#if defined(DHD_DEBUG)
/* pretty hex print a pkt buffer chain */
void
prpkt(const char *msg, osl_t *osh, void *p0)
{
	void *p;

	if (msg && (msg[0] != '\0'))
		printf("%s:\n", msg);

	for (p = p0; p; p = PKTNEXT(osh, p))
		prhex(NULL, PKTDATA(osh, p), (uint)PKTLEN(osh, p));
}
#endif // endif

/* Takes an Ethernet frame and sets out-of-bound PKTPRIO.
 * Also updates the inplace vlan tag if requested.
 * For debugging, it returns an indication of what it did.
 */
uint BCMFASTPATH
pktsetprio(void *pkt, bool update_vtag)
{
	struct ether_header *eh;
	struct ethervlan_header *evh;
	uint8 *pktdata;
	uint priority = 0;
	uint rc = 0;

	pktdata = (uint8 *)PKTDATA(OSH_NULL, pkt);
	ASSERT(ISALIGNED((uintptr)pktdata, sizeof(uint16)));

	eh = (struct ether_header *) pktdata;

	if (eh->ether_type == hton16(ETHER_TYPE_8021Q)) {
		uint16 vlan_tag;
		uint vlan_prio, dscp_prio = 0;

		evh = (struct ethervlan_header *)eh;

		vlan_tag = ntoh16(evh->vlan_tag);
		vlan_prio = (vlan_tag >> VLAN_PRI_SHIFT) & VLAN_PRI_MASK;

		if ((evh->ether_type == hton16(ETHER_TYPE_IP)) ||
			(evh->ether_type == hton16(ETHER_TYPE_IPV6))) {
			uint8 *ip_body = pktdata + sizeof(struct ethervlan_header);
			uint8 tos_tc = (uint8)IP_TOS46(ip_body);
			dscp_prio = tos_tc >> IPV4_TOS_PREC_SHIFT;
		}

		/* DSCP priority gets precedence over 802.1P (vlan tag) */
		if (dscp_prio != 0) {
			priority = dscp_prio;
			rc |= PKTPRIO_VDSCP;
		} else {
			priority = vlan_prio;
			rc |= PKTPRIO_VLAN;
		}
		/*
		 * If the DSCP priority is not the same as the VLAN priority,
		 * then overwrite the priority field in the vlan tag, with the
		 * DSCP priority value. This is required for Linux APs because
		 * the VLAN driver on Linux, overwrites the skb->priority field
		 * with the priority value in the vlan tag
		 */
		if (update_vtag && (priority != vlan_prio)) {
			vlan_tag &= ~(VLAN_PRI_MASK << VLAN_PRI_SHIFT);
			vlan_tag |= (uint16)priority << VLAN_PRI_SHIFT;
			evh->vlan_tag = hton16(vlan_tag);
			rc |= PKTPRIO_UPD;
		}
#if defined(EAPOL_PKT_PRIO) || defined(DHD_LOSSLESS_ROAMING)
	} else if (eh->ether_type == hton16(ETHER_TYPE_802_1X)) {
		priority = PRIO_8021D_NC;
		rc = PKTPRIO_DSCP;
#endif /* EAPOL_PKT_PRIO || DHD_LOSSLESS_ROAMING */
	} else if ((eh->ether_type == hton16(ETHER_TYPE_IP)) ||
		(eh->ether_type == hton16(ETHER_TYPE_IPV6))) {
		uint8 *ip_body = pktdata + sizeof(struct ether_header);
		uint8 tos_tc = (uint8)IP_TOS46(ip_body);
		uint8 dscp = tos_tc >> IPV4_TOS_DSCP_SHIFT;
		switch (dscp) {
		case DSCP_EF:
		case DSCP_VA:
			priority = PRIO_8021D_VO;
			break;
		case DSCP_AF31:
		case DSCP_AF32:
		case DSCP_AF33:
		case DSCP_CS3:
			priority = PRIO_8021D_CL;
			break;
		case DSCP_AF21:
		case DSCP_AF22:
		case DSCP_AF23:
			priority = PRIO_8021D_EE;
			break;
		case DSCP_AF11:
		case DSCP_AF12:
		case DSCP_AF13:
		case DSCP_CS2:
			priority = PRIO_8021D_BE;
			break;
		case DSCP_CS6:
		case DSCP_CS7:
			priority = PRIO_8021D_NC;
			break;
		default:
			priority = tos_tc >> IPV4_TOS_PREC_SHIFT;
			break;
		}

		rc |= PKTPRIO_DSCP;
	}

	ASSERT(priority <= MAXPRIO);
	PKTSETPRIO(pkt, (int)priority);
	return (rc | priority);
}

/* lookup user priority for specified DSCP */
static uint8
dscp2up(uint8 *up_table, uint8 dscp)
{
	uint8 user_priority = 255;

	/* lookup up from table if parameters valid */
	if (up_table != NULL && dscp < UP_TABLE_MAX) {
		user_priority = up_table[dscp];
	}

	/* 255 is unused value so return up from dscp */
	if (user_priority == 255) {
		user_priority = dscp >> (IPV4_TOS_PREC_SHIFT - IPV4_TOS_DSCP_SHIFT);
	}

	return user_priority;
}

/* set user priority by QoS Map Set table (UP table), table size is UP_TABLE_MAX */
uint BCMFASTPATH
pktsetprio_qms(void *pkt, uint8* up_table, bool update_vtag)
{
	if (up_table) {
		uint8 *pktdata;
		uint pktlen;
		uint8 dscp;
		uint user_priority = 0;
		uint rc = 0;

		pktdata = (uint8 *)PKTDATA(OSH_NULL, pkt);
		pktlen = (uint)PKTLEN(OSH_NULL, pkt);

		if (pktgetdscp(pktdata, pktlen, &dscp)) {
			rc = PKTPRIO_DSCP;
			user_priority = dscp2up(up_table, dscp);
			PKTSETPRIO(pkt, (int)user_priority);
		}

		return (rc | user_priority);
	} else {
		return pktsetprio(pkt, update_vtag);
	}
}

/* Returns TRUE and DSCP if IP header found, FALSE otherwise.
 */
bool BCMFASTPATH
pktgetdscp(uint8 *pktdata, uint pktlen, uint8 *dscp)
{
	struct ether_header *eh;
	struct ethervlan_header *evh;
	uint8 *ip_body;
	bool rc = FALSE;

	/* minimum length is ether header and IP header */
	if (pktlen < sizeof(struct ether_header) + IPV4_MIN_HEADER_LEN)
		return FALSE;

	eh = (struct ether_header *) pktdata;

	if (eh->ether_type == HTON16(ETHER_TYPE_IP)) {
		ip_body = pktdata + sizeof(struct ether_header);
		*dscp = (uint8)IP_DSCP46(ip_body);
		rc = TRUE;
	}
	else if (eh->ether_type == HTON16(ETHER_TYPE_8021Q)) {
		evh = (struct ethervlan_header *)eh;

		/* minimum length is ethervlan header and IP header */
		if (pktlen >= sizeof(struct ethervlan_header) + IPV4_MIN_HEADER_LEN &&
			evh->ether_type == HTON16(ETHER_TYPE_IP)) {
			ip_body = pktdata + sizeof(struct ethervlan_header);
			*dscp = (uint8)IP_DSCP46(ip_body);
			rc = TRUE;
		}
	}

	return rc;
}

/* usr_prio range from low to high with usr_prio value */
static bool
up_table_set(uint8 *up_table, uint8 usr_prio, uint8 low, uint8 high)
{
	int i;

	if (usr_prio > 7 || low > high || low >= UP_TABLE_MAX || high >= UP_TABLE_MAX) {
		return FALSE;
	}

	for (i = low; i <= high; i++) {
		up_table[i] = usr_prio;
	}

	return TRUE;
}

/* set user priority table */
int BCMFASTPATH
wl_set_up_table(uint8 *up_table, bcm_tlv_t *qos_map_ie)
{
	uint8 len;

	if (up_table == NULL || qos_map_ie == NULL) {
		return BCME_ERROR;
	}

	/* clear table to check table was set or not */
	memset(up_table, 0xff, UP_TABLE_MAX);

	/* length of QoS Map IE must be 16+n*2, n is number of exceptions */
	if (qos_map_ie != NULL && qos_map_ie->id == DOT11_MNG_QOS_MAP_ID &&
			(len = qos_map_ie->len) >= QOS_MAP_FIXED_LENGTH &&
			(len % 2) == 0) {
		uint8 *except_ptr = (uint8 *)qos_map_ie->data;
		uint8 except_len = len - QOS_MAP_FIXED_LENGTH;
		uint8 *range_ptr = except_ptr + except_len;
		uint8 i;

		/* fill in ranges */
		for (i = 0; i < QOS_MAP_FIXED_LENGTH; i += 2) {
			uint8 low = range_ptr[i];
			uint8 high = range_ptr[i + 1];
			if (low == 255 && high == 255) {
				continue;
			}

			if (!up_table_set(up_table, i / 2, low, high)) {
				/* clear the table on failure */
				memset(up_table, 0xff, UP_TABLE_MAX);
				return BCME_ERROR;
			}
		}

		/* update exceptions */
		for (i = 0; i < except_len; i += 2) {
			uint8 dscp = except_ptr[i];
			uint8 usr_prio = except_ptr[i+1];

			/* exceptions with invalid dscp/usr_prio are ignored */
			up_table_set(up_table, usr_prio, dscp, dscp);
		}
	}

	return BCME_OK;
}

/* The 0.5KB string table is not removed by compiler even though it's unused */

static char bcm_undeferrstr[32];
static const char *bcmerrorstrtable[] = BCMERRSTRINGTABLE;

/* Convert the error codes into related error strings  */
const char *
BCMRAMFN(bcmerrorstr)(int bcmerror)
{
	/* check if someone added a bcmerror code but forgot to add errorstring */
	ASSERT((uint)ABS(BCME_LAST) == (ARRAYSIZE(bcmerrorstrtable) - 1));

	if (bcmerror > 0 || bcmerror < BCME_LAST) {
		snprintf(bcm_undeferrstr, sizeof(bcm_undeferrstr), "Undefined error %d", bcmerror);
		return bcm_undeferrstr;
	}

	ASSERT(strlen(bcmerrorstrtable[-bcmerror]) < BCME_STRLEN);

	return bcmerrorstrtable[-bcmerror];
}

/* iovar table lookup */
/* could mandate sorted tables and do a binary search */
const bcm_iovar_t*
bcm_iovar_lookup(const bcm_iovar_t *table, const char *name)
{
	const bcm_iovar_t *vi;
	const char *lookup_name;

	/* skip any ':' delimited option prefixes */
	lookup_name = strrchr(name, ':');
	if (lookup_name != NULL)
		lookup_name++;
	else
		lookup_name = name;

	ASSERT(table != NULL);

	for (vi = table; vi->name; vi++) {
		if (!strcmp(vi->name, lookup_name))
			return vi;
	}
	/* ran to end of table */

	return NULL; /* var name not found */
}

int
bcm_iovar_lencheck(const bcm_iovar_t *vi, void *arg, int len, bool set)
{
	int bcmerror = 0;
	BCM_REFERENCE(arg);

	/* length check on io buf */
	switch (vi->type) {
	case IOVT_BOOL:
	case IOVT_INT8:
	case IOVT_INT16:
	case IOVT_INT32:
	case IOVT_UINT8:
	case IOVT_UINT16:
	case IOVT_UINT32:
		/* all integers are int32 sized args at the ioctl interface */
		if (len < (int)sizeof(int)) {
			bcmerror = BCME_BUFTOOSHORT;
		}
		break;

	case IOVT_BUFFER:
		/* buffer must meet minimum length requirement */
		if (len < vi->minlen) {
			bcmerror = BCME_BUFTOOSHORT;
		}
		break;

	case IOVT_VOID:
		if (!set) {
			/* Cannot return nil... */
			bcmerror = BCME_UNSUPPORTED;
		}
		break;

	default:
		/* unknown type for length check in iovar info */
		ASSERT(0);
		bcmerror = BCME_UNSUPPORTED;
	}

	return bcmerror;
}

#if !defined(_CFEZ_)
/*
 * Hierarchical Multiword bitmap based small id allocator.
 *
 * Multilevel hierarchy bitmap. (maximum 2 levels)
 * First hierarchy uses a multiword bitmap to identify 32bit words in the
 * second hierarchy that have at least a single bit set. Each bit in a word of
 * the second hierarchy represents a unique ID that may be allocated.
 *
 * BCM_MWBMAP_ITEMS_MAX: Maximum number of IDs managed.
 * BCM_MWBMAP_BITS_WORD: Number of bits in a bitmap word word
 * BCM_MWBMAP_WORDS_MAX: Maximum number of bitmap words needed for free IDs.
 * BCM_MWBMAP_WDMAP_MAX: Maximum number of bitmap wordss identifying first non
 *                       non-zero bitmap word carrying at least one free ID.
 * BCM_MWBMAP_SHIFT_OP:  Used in MOD, DIV and MUL operations.
 * BCM_MWBMAP_INVALID_IDX: Value ~0U is treated as an invalid ID
 *
 * Design Notes:
 * BCM_MWBMAP_USE_CNTSETBITS trades CPU for memory. A runtime count of how many
 * bits are computed each time on allocation and deallocation, requiring 4
 * array indexed access and 3 arithmetic operations. When not defined, a runtime
 * count of set bits state is maintained. Upto 32 Bytes per 1024 IDs is needed.
 * In a 4K max ID allocator, up to 128Bytes are hence used per instantiation.
 * In a memory limited system e.g. dongle builds, a CPU for memory tradeoff may
 * be used by defining BCM_MWBMAP_USE_CNTSETBITS.
 *
 * Note: wd_bitmap[] is statically declared and is not ROM friendly ... array
 * size is fixed. No intention to support larger than 4K indice allocation. ID
 * allocators for ranges smaller than 4K will have a wastage of only 12Bytes
 * with savings in not having to use an indirect access, had it been dynamically
 * allocated.
 */
#define BCM_MWBMAP_ITEMS_MAX    (64 * 1024)  /* May increase to 64K */

#define BCM_MWBMAP_BITS_WORD    (NBITS(uint32))
#define BCM_MWBMAP_WORDS_MAX    (BCM_MWBMAP_ITEMS_MAX / BCM_MWBMAP_BITS_WORD)
#define BCM_MWBMAP_WDMAP_MAX    (BCM_MWBMAP_WORDS_MAX / BCM_MWBMAP_BITS_WORD)
#define BCM_MWBMAP_SHIFT_OP     (5)
#define BCM_MWBMAP_MODOP(ix)    ((ix) & (BCM_MWBMAP_BITS_WORD - 1))
#define BCM_MWBMAP_DIVOP(ix)    ((ix) >> BCM_MWBMAP_SHIFT_OP)
#define BCM_MWBMAP_MULOP(ix)    ((ix) << BCM_MWBMAP_SHIFT_OP)

/* Redefine PTR() and/or HDL() conversion to invoke audit for debugging */
#define BCM_MWBMAP_PTR(hdl)		((struct bcm_mwbmap *)(hdl))
#define BCM_MWBMAP_HDL(ptr)		((void *)(ptr))

#if defined(BCM_MWBMAP_DEBUG)
#define BCM_MWBMAP_AUDIT(mwb) \
	do { \
		ASSERT((mwb != NULL) && \
		       (((struct bcm_mwbmap *)(mwb))->magic == (void *)(mwb))); \
		bcm_mwbmap_audit(mwb); \
	} while (0)
#define MWBMAP_ASSERT(exp)		ASSERT(exp)
#define MWBMAP_DBG(x)           printf x
#else   /* !BCM_MWBMAP_DEBUG */
#define BCM_MWBMAP_AUDIT(mwb)   do {} while (0)
#define MWBMAP_ASSERT(exp)		do {} while (0)
#define MWBMAP_DBG(x)
#endif  /* !BCM_MWBMAP_DEBUG */

typedef struct bcm_mwbmap {     /* Hierarchical multiword bitmap allocator    */
	uint16 wmaps;               /* Total number of words in free wd bitmap    */
	uint16 imaps;               /* Total number of words in free id bitmap    */
	int32  ifree;               /* Count of free indices. Used only in audits */
	uint16 total;               /* Total indices managed by multiword bitmap  */

	void * magic;               /* Audit handle parameter from user           */

	uint32 wd_bitmap[BCM_MWBMAP_WDMAP_MAX]; /* 1st level bitmap of            */
#if !defined(BCM_MWBMAP_USE_CNTSETBITS)
	int8   wd_count[BCM_MWBMAP_WORDS_MAX];  /* free id running count, 1st lvl */
#endif /*  ! BCM_MWBMAP_USE_CNTSETBITS */

	uint32 id_bitmap[0];        /* Second level bitmap                        */
} bcm_mwbmap_t;

/* Incarnate a hierarchical multiword bitmap based small index allocator. */
struct bcm_mwbmap *
bcm_mwbmap_init(osl_t *osh, uint32 items_max)
{
	struct bcm_mwbmap * mwbmap_p;
	uint32 wordix, size, words, extra;

	/* Implementation Constraint: Uses 32bit word bitmap */
	MWBMAP_ASSERT(BCM_MWBMAP_BITS_WORD == 32U);
	MWBMAP_ASSERT(BCM_MWBMAP_SHIFT_OP == 5U);
	MWBMAP_ASSERT(ISPOWEROF2(BCM_MWBMAP_ITEMS_MAX));
	MWBMAP_ASSERT((BCM_MWBMAP_ITEMS_MAX % BCM_MWBMAP_BITS_WORD) == 0U);

	ASSERT(items_max <= BCM_MWBMAP_ITEMS_MAX);

	/* Determine the number of words needed in the multiword bitmap */
	extra = BCM_MWBMAP_MODOP(items_max);
	words = BCM_MWBMAP_DIVOP(items_max) + ((extra != 0U) ? 1U : 0U);

	/* Allocate runtime state of multiword bitmap */
	/* Note: wd_count[] or wd_bitmap[] are not dynamically allocated */
	size = sizeof(bcm_mwbmap_t) + (sizeof(uint32) * words);
	mwbmap_p = (bcm_mwbmap_t *)MALLOC(osh, size);
	if (mwbmap_p == (bcm_mwbmap_t *)NULL) {
		ASSERT(0);
		goto error1;
	}
	memset(mwbmap_p, 0, size);

	/* Initialize runtime multiword bitmap state */
	mwbmap_p->imaps = (uint16)words;
	mwbmap_p->ifree = (int32)items_max;
	mwbmap_p->total = (uint16)items_max;

	/* Setup magic, for use in audit of handle */
	mwbmap_p->magic = BCM_MWBMAP_HDL(mwbmap_p);

	/* Setup the second level bitmap of free indices */
	/* Mark all indices as available */
	for (wordix = 0U; wordix < mwbmap_p->imaps; wordix++) {
		mwbmap_p->id_bitmap[wordix] = (uint32)(~0U);
#if !defined(BCM_MWBMAP_USE_CNTSETBITS)
		mwbmap_p->wd_count[wordix] = BCM_MWBMAP_BITS_WORD;
#endif /*  ! BCM_MWBMAP_USE_CNTSETBITS */
	}

	/* Ensure that extra indices are tagged as un-available */
	if (extra) { /* fixup the free ids in last bitmap and wd_count */
		uint32 * bmap_p = &mwbmap_p->id_bitmap[mwbmap_p->imaps - 1];
		*bmap_p ^= (uint32)(~0U << extra); /* fixup bitmap */
#if !defined(BCM_MWBMAP_USE_CNTSETBITS)
		mwbmap_p->wd_count[mwbmap_p->imaps - 1] = (int8)extra; /* fixup count */
#endif /*  ! BCM_MWBMAP_USE_CNTSETBITS */
	}

	/* Setup the first level bitmap hierarchy */
	extra = BCM_MWBMAP_MODOP(mwbmap_p->imaps);
	words = BCM_MWBMAP_DIVOP(mwbmap_p->imaps) + ((extra != 0U) ? 1U : 0U);

	mwbmap_p->wmaps = (uint16)words;

	for (wordix = 0U; wordix < mwbmap_p->wmaps; wordix++)
		mwbmap_p->wd_bitmap[wordix] = (uint32)(~0U);
	if (extra) {
		uint32 * bmap_p = &mwbmap_p->wd_bitmap[mwbmap_p->wmaps - 1];
		*bmap_p ^= (uint32)(~0U << extra); /* fixup bitmap */
	}

	return mwbmap_p;

error1:
	return BCM_MWBMAP_INVALID_HDL;
}

/* Release resources used by multiword bitmap based small index allocator. */
void
bcm_mwbmap_fini(osl_t * osh, struct bcm_mwbmap * mwbmap_hdl)
{
	bcm_mwbmap_t * mwbmap_p;

	BCM_MWBMAP_AUDIT(mwbmap_hdl);
	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	MFREE(osh, mwbmap_p, sizeof(struct bcm_mwbmap)
			     + (sizeof(uint32) * mwbmap_p->imaps));
	return;
}

/* Allocate a unique small index using a multiword bitmap index allocator.    */
uint32 BCMFASTPATH
bcm_mwbmap_alloc(struct bcm_mwbmap * mwbmap_hdl)
{
	bcm_mwbmap_t * mwbmap_p;
	uint32 wordix, bitmap;

	BCM_MWBMAP_AUDIT(mwbmap_hdl);
	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	/* Start with the first hierarchy */
	for (wordix = 0; wordix < mwbmap_p->wmaps; ++wordix) {

		bitmap = mwbmap_p->wd_bitmap[wordix]; /* get the word bitmap */

		if (bitmap != 0U) {

			uint32 count, bitix, *bitmap_p;

			bitmap_p = &mwbmap_p->wd_bitmap[wordix];

			/* clear all except trailing 1 */
			bitmap   = (uint32)(((int)(bitmap)) & (-((int)(bitmap))));
			MWBMAP_ASSERT(C_bcm_count_leading_zeros(bitmap) ==
			              bcm_count_leading_zeros(bitmap));
			bitix    = (BCM_MWBMAP_BITS_WORD - 1)
				 - (uint32)bcm_count_leading_zeros(bitmap); /* use asm clz */
			wordix   = BCM_MWBMAP_MULOP(wordix) + bitix;

			/* Clear bit if wd count is 0, without conditional branch */
#if defined(BCM_MWBMAP_USE_CNTSETBITS)
			count = bcm_cntsetbits(mwbmap_p->id_bitmap[wordix]) - 1;
#else  /* ! BCM_MWBMAP_USE_CNTSETBITS */
			mwbmap_p->wd_count[wordix]--;
			count = (uint32)mwbmap_p->wd_count[wordix];
			MWBMAP_ASSERT(count ==
			              (bcm_cntsetbits(mwbmap_p->id_bitmap[wordix]) - 1));
#endif /* ! BCM_MWBMAP_USE_CNTSETBITS */
			MWBMAP_ASSERT(count >= 0);

			/* clear wd_bitmap bit if id_map count is 0 */
			bitmap = ((uint32)(count == 0)) << BCM_MWBMAP_MODOP(bitix);

			MWBMAP_DBG((
			    "Lvl1: bitix<%02u> wordix<%02u>: %08x ^ %08x = %08x wfree %d",
			    bitix, wordix, *bitmap_p, bitmap, (*bitmap_p) ^ bitmap, count));

			*bitmap_p ^= bitmap;

			/* Use bitix in the second hierarchy */
			bitmap_p = &mwbmap_p->id_bitmap[wordix];

			bitmap = mwbmap_p->id_bitmap[wordix]; /* get the id bitmap */
			MWBMAP_ASSERT(bitmap != 0U);

			/* clear all except trailing 1 */
			bitmap   = (uint32)(((int)(bitmap)) & (-((int)(bitmap))));
			MWBMAP_ASSERT(C_bcm_count_leading_zeros(bitmap) ==
			              bcm_count_leading_zeros(bitmap));
			bitix    = BCM_MWBMAP_MULOP(wordix)
				 + (BCM_MWBMAP_BITS_WORD - 1)
				 - (uint32)bcm_count_leading_zeros(bitmap); /* use asm clz */

			mwbmap_p->ifree--; /* decrement system wide free count */
			MWBMAP_ASSERT(mwbmap_p->ifree >= 0);

			MWBMAP_DBG((
			    "Lvl2: bitix<%02u> wordix<%02u>: %08x ^ %08x = %08x ifree %d",
			    bitix, wordix, *bitmap_p, bitmap, (*bitmap_p) ^ bitmap,
			    mwbmap_p->ifree));

			*bitmap_p ^= bitmap; /* mark as allocated = 1b0 */

			return bitix;
		}
	}

	ASSERT(mwbmap_p->ifree == 0);

	return BCM_MWBMAP_INVALID_IDX;
}

/* Force an index at a specified position to be in use */
void
bcm_mwbmap_force(struct bcm_mwbmap * mwbmap_hdl, uint32 bitix)
{
	bcm_mwbmap_t * mwbmap_p;
	uint32 count, wordix, bitmap, *bitmap_p;

	BCM_MWBMAP_AUDIT(mwbmap_hdl);
	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	ASSERT(bitix < mwbmap_p->total);

	/* Start with second hierarchy */
	wordix   = BCM_MWBMAP_DIVOP(bitix);
	bitmap   = (uint32)(1U << BCM_MWBMAP_MODOP(bitix));
	bitmap_p = &mwbmap_p->id_bitmap[wordix];

	ASSERT((*bitmap_p & bitmap) == bitmap);

	mwbmap_p->ifree--; /* update free count */
	ASSERT(mwbmap_p->ifree >= 0);

	MWBMAP_DBG(("Lvl2: bitix<%u> wordix<%u>: %08x ^ %08x = %08x ifree %d",
	            bitix, wordix, *bitmap_p, bitmap, (*bitmap_p) ^ bitmap,
	            mwbmap_p->ifree));

	*bitmap_p ^= bitmap; /* mark as in use */

	/* Update first hierarchy */
	bitix    = wordix;

	wordix   = BCM_MWBMAP_DIVOP(bitix);
	bitmap_p = &mwbmap_p->wd_bitmap[wordix];

#if defined(BCM_MWBMAP_USE_CNTSETBITS)
	count = bcm_cntsetbits(mwbmap_p->id_bitmap[bitix]);
#else  /* ! BCM_MWBMAP_USE_CNTSETBITS */
	mwbmap_p->wd_count[bitix]--;
	count = (uint32)mwbmap_p->wd_count[bitix];
	MWBMAP_ASSERT(count == bcm_cntsetbits(mwbmap_p->id_bitmap[bitix]));
#endif /* ! BCM_MWBMAP_USE_CNTSETBITS */
	MWBMAP_ASSERT(count >= 0);

	bitmap   = (uint32)(count == 0) << BCM_MWBMAP_MODOP(bitix);

	MWBMAP_DBG(("Lvl1: bitix<%02lu> wordix<%02u>: %08x ^ %08x = %08x wfree %d",
	            BCM_MWBMAP_MODOP(bitix), wordix, *bitmap_p, bitmap,
	            (*bitmap_p) ^ bitmap, count));

	*bitmap_p ^= bitmap; /* mark as in use */

	return;
}

/* Free a previously allocated index back into the multiword bitmap allocator */
void BCMFASTPATH
bcm_mwbmap_free(struct bcm_mwbmap * mwbmap_hdl, uint32 bitix)
{
	bcm_mwbmap_t * mwbmap_p;
	uint32 wordix, bitmap, *bitmap_p;

	BCM_MWBMAP_AUDIT(mwbmap_hdl);
	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	ASSERT(bitix < mwbmap_p->total);

	/* Start with second level hierarchy */
	wordix   = BCM_MWBMAP_DIVOP(bitix);
	bitmap   = (1U << BCM_MWBMAP_MODOP(bitix));
	bitmap_p = &mwbmap_p->id_bitmap[wordix];

	ASSERT((*bitmap_p & bitmap) == 0U);	/* ASSERT not a double free */

	mwbmap_p->ifree++; /* update free count */
	ASSERT(mwbmap_p->ifree <= mwbmap_p->total);

	MWBMAP_DBG(("Lvl2: bitix<%02u> wordix<%02u>: %08x | %08x = %08x ifree %d",
	            bitix, wordix, *bitmap_p, bitmap, (*bitmap_p) | bitmap,
	            mwbmap_p->ifree));

	*bitmap_p |= bitmap; /* mark as available */

	/* Now update first level hierarchy */

	bitix    = wordix;

	wordix   = BCM_MWBMAP_DIVOP(bitix); /* first level's word index */
	bitmap   = (1U << BCM_MWBMAP_MODOP(bitix));
	bitmap_p = &mwbmap_p->wd_bitmap[wordix];

#if !defined(BCM_MWBMAP_USE_CNTSETBITS)
	mwbmap_p->wd_count[bitix]++;
#endif // endif

#if defined(BCM_MWBMAP_DEBUG)
	{
		uint32 count;
#if defined(BCM_MWBMAP_USE_CNTSETBITS)
		count = bcm_cntsetbits(mwbmap_p->id_bitmap[bitix]);
#else  /*  ! BCM_MWBMAP_USE_CNTSETBITS */
		count = mwbmap_p->wd_count[bitix];
		MWBMAP_ASSERT(count == bcm_cntsetbits(mwbmap_p->id_bitmap[bitix]));
#endif /*  ! BCM_MWBMAP_USE_CNTSETBITS */

		MWBMAP_ASSERT(count <= BCM_MWBMAP_BITS_WORD);

		MWBMAP_DBG(("Lvl1: bitix<%02u> wordix<%02u>: %08x | %08x = %08x wfree %d",
		            bitix, wordix, *bitmap_p, bitmap, (*bitmap_p) | bitmap, count));
	}
#endif /* BCM_MWBMAP_DEBUG */

	*bitmap_p |= bitmap;

	return;
}

/* Fetch the toal number of free indices in the multiword bitmap allocator */
uint32
bcm_mwbmap_free_cnt(struct bcm_mwbmap * mwbmap_hdl)
{
	bcm_mwbmap_t * mwbmap_p;

	BCM_MWBMAP_AUDIT(mwbmap_hdl);
	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	ASSERT(mwbmap_p->ifree >= 0);

	return (uint32)mwbmap_p->ifree;
}

/* Determine whether an index is inuse or free */
bool
bcm_mwbmap_isfree(struct bcm_mwbmap * mwbmap_hdl, uint32 bitix)
{
	bcm_mwbmap_t * mwbmap_p;
	uint32 wordix, bitmap;

	BCM_MWBMAP_AUDIT(mwbmap_hdl);
	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	ASSERT(bitix < mwbmap_p->total);

	wordix   = BCM_MWBMAP_DIVOP(bitix);
	bitmap   = (1U << BCM_MWBMAP_MODOP(bitix));

	return ((mwbmap_p->id_bitmap[wordix] & bitmap) != 0U);
}

/* Debug dump a multiword bitmap allocator */
void
bcm_mwbmap_show(struct bcm_mwbmap * mwbmap_hdl)
{
	uint32 ix, count;
	bcm_mwbmap_t * mwbmap_p;

	BCM_MWBMAP_AUDIT(mwbmap_hdl);
	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	printf("mwbmap_p %p wmaps %u imaps %u ifree %d total %u\n",
		OSL_OBFUSCATE_BUF((void *)mwbmap_p),
	       mwbmap_p->wmaps, mwbmap_p->imaps, mwbmap_p->ifree, mwbmap_p->total);
	for (ix = 0U; ix < mwbmap_p->wmaps; ix++) {
		printf("\tWDMAP:%2u. 0x%08x\t", ix, mwbmap_p->wd_bitmap[ix]);
		bcm_bitprint32(mwbmap_p->wd_bitmap[ix]);
		printf("\n");
	}
	for (ix = 0U; ix < mwbmap_p->imaps; ix++) {
#if defined(BCM_MWBMAP_USE_CNTSETBITS)
		count = bcm_cntsetbits(mwbmap_p->id_bitmap[ix]);
#else  /* ! BCM_MWBMAP_USE_CNTSETBITS */
		count = (uint32)mwbmap_p->wd_count[ix];
		MWBMAP_ASSERT(count == bcm_cntsetbits(mwbmap_p->id_bitmap[ix]));
#endif /* ! BCM_MWBMAP_USE_CNTSETBITS */
		printf("\tIDMAP:%2u. 0x%08x %02u\t", ix, mwbmap_p->id_bitmap[ix], count);
		bcm_bitprint32(mwbmap_p->id_bitmap[ix]);
		printf("\n");
	}

	return;
}

/* Audit a hierarchical multiword bitmap */
void
bcm_mwbmap_audit(struct bcm_mwbmap * mwbmap_hdl)
{
	bcm_mwbmap_t * mwbmap_p;
	uint32 count, free_cnt = 0U, wordix, idmap_ix, bitix, *bitmap_p;

	mwbmap_p = BCM_MWBMAP_PTR(mwbmap_hdl);

	for (wordix = 0U; wordix < mwbmap_p->wmaps; ++wordix) {

		bitmap_p = &mwbmap_p->wd_bitmap[wordix];

		for (bitix = 0U; bitix < BCM_MWBMAP_BITS_WORD; bitix++) {
			if ((*bitmap_p) & (1 << bitix)) {
				idmap_ix = BCM_MWBMAP_MULOP(wordix) + bitix;
#if defined(BCM_MWBMAP_USE_CNTSETBITS)
				count = bcm_cntsetbits(mwbmap_p->id_bitmap[idmap_ix]);
#else  /* ! BCM_MWBMAP_USE_CNTSETBITS */
				count = (uint32)mwbmap_p->wd_count[idmap_ix];
				ASSERT(count == bcm_cntsetbits(mwbmap_p->id_bitmap[idmap_ix]));
#endif /* ! BCM_MWBMAP_USE_CNTSETBITS */
				ASSERT(count != 0U);
				free_cnt += count;
			}
		}
	}

	ASSERT((int)free_cnt == mwbmap_p->ifree);
}
/* END : Multiword bitmap based 64bit to Unique 32bit Id allocator. */

/* Simple 16bit Id allocator using a stack implementation. */
typedef struct id16_map {
	uint32  failures;  /* count of failures */
	void    *dbg;      /* debug placeholder */
	uint16  total;     /* total number of ids managed by allocator */
	uint16  start;     /* start value of 16bit ids to be managed */
	int     stack_idx; /* index into stack of available ids */
	uint16  stack[0];  /* stack of 16 bit ids */
} id16_map_t;

#define ID16_MAP_SZ(items)      (sizeof(id16_map_t) + \
				     (sizeof(uint16) * (items)))

#if defined(BCM_DBG)

/* Uncomment BCM_DBG_ID16 to debug double free */
/* #define BCM_DBG_ID16 */

typedef struct id16_map_dbg {
	uint16  total;
	bool    avail[0];
} id16_map_dbg_t;
#define ID16_MAP_DBG_SZ(items)  (sizeof(id16_map_dbg_t) + \
				     (sizeof(bool) * (items)))
#define ID16_MAP_MSG(x)         print x
#else
#define ID16_MAP_MSG(x)
#endif /* BCM_DBG */

void * /* Construct an id16 allocator: [start_val16 .. start_val16+total_ids) */
id16_map_init(osl_t *osh, uint16 total_ids, uint16 start_val16)
{
	uint16 idx, val16;
	id16_map_t * id16_map;

	ASSERT(total_ids > 0);

	/* A start_val16 of ID16_UNDEFINED, allows the caller to fill the id16 map
	 * with random values.
	 */
	ASSERT((start_val16 == ID16_UNDEFINED) ||
	       (start_val16 + total_ids) < ID16_INVALID);

	id16_map = (id16_map_t *) MALLOC(osh, ID16_MAP_SZ(total_ids));
	if (id16_map == NULL) {
		return NULL;
	}

	id16_map->total = total_ids;
	id16_map->start = start_val16;
	id16_map->failures = 0;
	id16_map->dbg = NULL;

	/*
	 * Populate stack with 16bit id values, commencing with start_val16.
	 * if start_val16 is ID16_UNDEFINED, then do not populate the id16 map.
	 */
	id16_map->stack_idx = -1;

	if (id16_map->start != ID16_UNDEFINED) {
		val16 = start_val16;

		for (idx = 0; idx < total_ids; idx++, val16++) {
			id16_map->stack_idx = idx;
			id16_map->stack[id16_map->stack_idx] = val16;
		}
	}

#if defined(BCM_DBG) && defined(BCM_DBG_ID16)
	if (id16_map->start != ID16_UNDEFINED) {
		id16_map->dbg = MALLOC(osh, ID16_MAP_DBG_SZ(total_ids));

		if (id16_map->dbg) {
			id16_map_dbg_t *id16_map_dbg = (id16_map_dbg_t *)id16_map->dbg;

			id16_map_dbg->total = total_ids;
			for (idx = 0; idx < total_ids; idx++) {
				id16_map_dbg->avail[idx] = TRUE;
			}
		}
	}
#endif /* BCM_DBG && BCM_DBG_ID16 */

	return (void *)id16_map;
}

void * /* Destruct an id16 allocator instance */
id16_map_fini(osl_t *osh, void * id16_map_hndl)
{
	uint16 total_ids;
	id16_map_t * id16_map;

	if (id16_map_hndl == NULL)
		return NULL;

	id16_map = (id16_map_t *)id16_map_hndl;

	total_ids = id16_map->total;
	ASSERT(total_ids > 0);

#if defined(BCM_DBG) && defined(BCM_DBG_ID16)
	if (id16_map->dbg) {
		MFREE(osh, id16_map->dbg, ID16_MAP_DBG_SZ(total_ids));
		id16_map->dbg = NULL;
	}
#endif /* BCM_DBG && BCM_DBG_ID16 */

	id16_map->total = 0;
	MFREE(osh, id16_map, ID16_MAP_SZ(total_ids));

	return NULL;
}

void
id16_map_clear(void * id16_map_hndl, uint16 total_ids, uint16 start_val16)
{
	uint16 idx, val16;
	id16_map_t * id16_map;

	ASSERT(total_ids > 0);
	/* A start_val16 of ID16_UNDEFINED, allows the caller to fill the id16 map
	 * with random values.
	 */
	ASSERT((start_val16 == ID16_UNDEFINED) ||
	       (start_val16 + total_ids) < ID16_INVALID);

	id16_map = (id16_map_t *)id16_map_hndl;
	if (id16_map == NULL) {
		return;
	}

	id16_map->total = total_ids;
	id16_map->start = start_val16;
	id16_map->failures = 0;

	/* Populate stack with 16bit id values, commencing with start_val16 */
	id16_map->stack_idx = -1;

	if (id16_map->start != ID16_UNDEFINED) {
		val16 = start_val16;

		for (idx = 0; idx < total_ids; idx++, val16++) {
			id16_map->stack_idx = idx;
			id16_map->stack[id16_map->stack_idx] = val16;
		}
	}

#if defined(BCM_DBG) && defined(BCM_DBG_ID16)
	if (id16_map->start != ID16_UNDEFINED) {
		if (id16_map->dbg) {
			id16_map_dbg_t *id16_map_dbg = (id16_map_dbg_t *)id16_map->dbg;

			id16_map_dbg->total = total_ids;
			for (idx = 0; idx < total_ids; idx++) {
				id16_map_dbg->avail[idx] = TRUE;
			}
		}
	}
#endif /* BCM_DBG && BCM_DBG_ID16 */
}

uint16 BCMFASTPATH /* Allocate a unique 16bit id */
id16_map_alloc(void * id16_map_hndl)
{
	uint16 val16;
	id16_map_t * id16_map;

	ASSERT(id16_map_hndl != NULL);
	if (!id16_map_hndl) {
		return ID16_INVALID;
	}
	id16_map = (id16_map_t *)id16_map_hndl;

	ASSERT(id16_map->total > 0);

	if (id16_map->stack_idx < 0) {
		id16_map->failures++;
		return ID16_INVALID;
	}

	val16 = id16_map->stack[id16_map->stack_idx];
	id16_map->stack_idx--;

#if defined(BCM_DBG) && defined(BCM_DBG_ID16)
	ASSERT((id16_map->start == ID16_UNDEFINED) ||
	       (val16 < (id16_map->start + id16_map->total)));

	if (id16_map->dbg) { /* Validate val16 */
		id16_map_dbg_t *id16_map_dbg = (id16_map_dbg_t *)id16_map->dbg;

		ASSERT(id16_map_dbg->avail[val16 - id16_map->start] == TRUE);
		id16_map_dbg->avail[val16 - id16_map->start] = FALSE;
	}
#endif /* BCM_DBG && BCM_DBG_ID16 */

	return val16;
}

void BCMFASTPATH /* Free a 16bit id value into the id16 allocator */
id16_map_free(void * id16_map_hndl, uint16 val16)
{
	id16_map_t * id16_map;

	ASSERT(id16_map_hndl != NULL);

	id16_map = (id16_map_t *)id16_map_hndl;

#if defined(BCM_DBG) && defined(BCM_DBG_ID16)
	ASSERT((id16_map->start == ID16_UNDEFINED) ||
	       (val16 < (id16_map->start + id16_map->total)));

	if (id16_map->dbg) { /* Validate val16 */
		id16_map_dbg_t *id16_map_dbg = (id16_map_dbg_t *)id16_map->dbg;

		ASSERT(id16_map_dbg->avail[val16 - id16_map->start] == FALSE);
		id16_map_dbg->avail[val16 - id16_map->start] = TRUE;
	}
#endif /* BCM_DBG && BCM_DBG_ID16 */

	id16_map->stack_idx++;
	id16_map->stack[id16_map->stack_idx] = val16;
}

uint32 /* Returns number of failures to allocate an unique id16 */
id16_map_failures(void * id16_map_hndl)
{
	ASSERT(id16_map_hndl != NULL);
	return ((id16_map_t *)id16_map_hndl)->failures;
}

bool
id16_map_audit(void * id16_map_hndl)
{
	int idx;
	int insane = 0;
	id16_map_t * id16_map;

	ASSERT(id16_map_hndl != NULL);
	if (!id16_map_hndl) {
		goto done;
	}
	id16_map = (id16_map_t *)id16_map_hndl;

	ASSERT(id16_map->stack_idx >= -1);
	ASSERT(id16_map->stack_idx < (int)id16_map->total);

	if (id16_map->start == ID16_UNDEFINED)
		goto done;

	for (idx = 0; idx <= id16_map->stack_idx; idx++) {
		ASSERT(id16_map->stack[idx] >= id16_map->start);
		ASSERT(id16_map->stack[idx] < (id16_map->start + id16_map->total));

#if defined(BCM_DBG) && defined(BCM_DBG_ID16)
		if (id16_map->dbg) {
			uint16 val16 = id16_map->stack[idx];
			if (((id16_map_dbg_t *)(id16_map->dbg))->avail[val16] != TRUE) {
				insane |= 1;
				ID16_MAP_MSG(("id16_map<%p>: stack_idx %u invalid val16 %u\n",
				              OSL_OBFUSATE_BUF(id16_map_hndl), idx, val16));
			}
		}
#endif /* BCM_DBG && BCM_DBG_ID16 */
	}

#if defined(BCM_DBG) && defined(BCM_DBG_ID16)
	if (id16_map->dbg) {
		uint16 avail = 0; /* Audit available ids counts */
		for (idx = 0; idx < id16_map_dbg->total; idx++) {
			if (((id16_map_dbg_t *)(id16_map->dbg))->avail[idx16] == TRUE)
				avail++;
		}
		if (avail && (avail != (id16_map->stack_idx + 1))) {
			insane |= 1;
			ID16_MAP_MSG(("id16_map<%p>: avail %u stack_idx %u\n",
			              OSL_OBFUSCATE_BUF(id16_map_hndl),
			              avail, id16_map->stack_idx));
		}
	}
#endif /* BCM_DBG && BCM_DBG_ID16 */

done:
	/* invoke any other system audits */
	return (!!insane);
}
/* END: Simple id16 allocator */

void
dll_pool_detach(void * osh, dll_pool_t * pool, uint16 elems_max, uint16 elem_size)
{
	uint32 memsize;
	memsize = sizeof(dll_pool_t) + (elems_max * elem_size);
	if (pool)
		MFREE(osh, pool, memsize);
}
dll_pool_t *
dll_pool_init(void * osh, uint16 elems_max, uint16 elem_size)
{
	uint32 memsize, i;
	dll_pool_t * dll_pool_p;
	dll_t * elem_p;

	ASSERT(elem_size > sizeof(dll_t));

	memsize = sizeof(dll_pool_t) + (elems_max * elem_size);

	if ((dll_pool_p = (dll_pool_t *)MALLOCZ(osh, memsize)) == NULL) {
		printf("dll_pool_init: elems_max<%u> elem_size<%u> malloc failure\n",
			elems_max, elem_size);
		ASSERT(0);
		return dll_pool_p;
	}

	dll_init(&dll_pool_p->free_list);
	dll_pool_p->elems_max = elems_max;
	dll_pool_p->elem_size = elem_size;

	elem_p = dll_pool_p->elements;
	for (i = 0; i < elems_max; i++) {
		dll_append(&dll_pool_p->free_list, elem_p);
		elem_p = (dll_t *)((uintptr)elem_p + elem_size);
	}

	dll_pool_p->free_count = elems_max;

	return dll_pool_p;
}

void *
dll_pool_alloc(dll_pool_t * dll_pool_p)
{
	dll_t * elem_p;

	if (dll_pool_p->free_count == 0) {
		ASSERT(dll_empty(&dll_pool_p->free_list));
		return NULL;
	}

	elem_p = dll_head_p(&dll_pool_p->free_list);
	dll_delete(elem_p);
	dll_pool_p->free_count -= 1;

	return (void *)elem_p;
}

void
dll_pool_free(dll_pool_t * dll_pool_p, void * elem_p)
{
	dll_t * node_p = (dll_t *)elem_p;
	dll_prepend(&dll_pool_p->free_list, node_p);
	dll_pool_p->free_count += 1;
}

void
dll_pool_free_tail(dll_pool_t * dll_pool_p, void * elem_p)
{
	dll_t * node_p = (dll_t *)elem_p;
	dll_append(&dll_pool_p->free_list, node_p);
	dll_pool_p->free_count += 1;
}

#endif // endif

#endif /* BCMDRIVER */

#if defined(BCMDRIVER) || defined(WL_UNITTEST)

/* triggers bcm_bprintf to print to kernel log */
bool bcm_bprintf_bypass = FALSE;

/* Initialization of bcmstrbuf structure */
void
bcm_binit(struct bcmstrbuf *b, char *buf, uint size)
{
	b->origsize = b->size = size;
	b->origbuf = b->buf = buf;
	if (size > 0) {
		buf[0] = '\0';
	}
}

/* Buffer sprintf wrapper to guard against buffer overflow */
int
bcm_bprintf(struct bcmstrbuf *b, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);

	r = vsnprintf(b->buf, b->size, fmt, ap);
	if (bcm_bprintf_bypass == TRUE) {
		printf("%s", b->buf);
		goto exit;
	}

	/* Non Ansi C99 compliant returns -1,
	 * Ansi compliant return r >= b->size,
	 * bcmstdlib returns 0, handle all
	 */
	/* r == 0 is also the case when strlen(fmt) is zero.
	 * typically the case when "" is passed as argument.
	 */
	if ((r == -1) || (r >= (int)b->size)) {
		b->size = 0;
	} else {
		b->size -= (uint)r;
		b->buf += r;
	}

exit:
	va_end(ap);

	return r;
}

void
bcm_bprhex(struct bcmstrbuf *b, const char *msg, bool newline, const uint8 *buf, int len)
{
	int i;

	if (msg != NULL && msg[0] != '\0')
		bcm_bprintf(b, "%s", msg);
	for (i = 0; i < len; i ++)
		bcm_bprintf(b, "%02X", buf[i]);
	if (newline)
		bcm_bprintf(b, "\n");
}

void
bcm_inc_bytes(uchar *num, int num_bytes, uint8 amount)
{
	int i;

	for (i = 0; i < num_bytes; i++) {
		num[i] += amount;
		if (num[i] >= amount)
			break;
		amount = 1;
	}
}

int
bcm_cmp_bytes(const uchar *arg1, const uchar *arg2, uint8 nbytes)
{
	int i;

	for (i = nbytes - 1; i >= 0; i--) {
		if (arg1[i] != arg2[i])
			return (arg1[i] - arg2[i]);
	}
	return 0;
}

void
bcm_print_bytes(const char *name, const uchar *data, int len)
{
	int i;
	int per_line = 0;

	printf("%s: %d \n", name ? name : "", len);
	for (i = 0; i < len; i++) {
		printf("%02x ", *data++);
		per_line++;
		if (per_line == 16) {
			per_line = 0;
			printf("\n");
		}
	}
	printf("\n");
}

/* Look for vendor-specific IE with specified OUI and optional type */
bcm_tlv_t *
bcm_find_vendor_ie(const  void *tlvs, uint tlvs_len, const char *voui, uint8 *type, uint type_len)
{
	const  bcm_tlv_t *ie;
	uint8 ie_len;

	ie = (const  bcm_tlv_t*)tlvs;

	/* make sure we are looking at a valid IE */
	if (ie == NULL || !bcm_valid_tlv(ie, tlvs_len)) {
		return NULL;
	}

	/* Walk through the IEs looking for an OUI match */
	do {
		ie_len = ie->len;
		if ((ie->id == DOT11_MNG_VS_ID) &&
		    (ie_len >= (DOT11_OUI_LEN + type_len)) &&
		    !bcmp(ie->data, voui, DOT11_OUI_LEN))
		{
			/* compare optional type */
			if (type_len == 0 ||
			    !bcmp(&ie->data[DOT11_OUI_LEN], type, type_len)) {
				GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
				return (bcm_tlv_t *)(ie);		/* a match */
				GCC_DIAGNOSTIC_POP();
			}
		}
	} while ((ie = bcm_next_tlv(ie, &tlvs_len)) != NULL);

	return NULL;
}

#if defined(WLTINYDUMP) || defined(WLMSG_INFORM) || defined(WLMSG_ASSOC) || \
	defined(WLMSG_PRPKT) || defined(WLMSG_WSEC)
#define SSID_FMT_BUF_LEN	((4 * DOT11_MAX_SSID_LEN) + 1)

int
bcm_format_ssid(char* buf, const uchar ssid[], uint ssid_len)
{
	uint i, c;
	char *p = buf;
	char *endp = buf + SSID_FMT_BUF_LEN;

	if (ssid_len > DOT11_MAX_SSID_LEN) ssid_len = DOT11_MAX_SSID_LEN;

	for (i = 0; i < ssid_len; i++) {
		c = (uint)ssid[i];
		if (c == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else if (bcm_isprint((uchar)c)) {
			*p++ = (char)c;
		} else {
			p += snprintf(p, (size_t)(endp - p), "\\x%02X", c);
		}
	}
	*p = '\0';
	ASSERT(p < endp);

	return (int)(p - buf);
}
#endif // endif

#endif /* BCMDRIVER || WL_UNITTEST */

char *
bcm_ether_ntoa(const struct ether_addr *ea, char *buf)
{
	static const char hex[] =
	  {
		  '0', '1', '2', '3', '4', '5', '6', '7',
		  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	  };
	const uint8 *octet = ea->octet;
	char *p = buf;
	int i;

	for (i = 0; i < 6; i++, octet++) {
		*p++ = hex[(*octet >> 4) & 0xf];
		*p++ = hex[*octet & 0xf];
		*p++ = ':';
	}

	*(p-1) = '\0';

	return (buf);
}

/* Find the position of first bit set
 * in the given number.
 */
int
bcm_find_fsb(uint32 num)
{
	uint8 pos = 0;
	if (!num)
		return pos;
	while (!(num & 1)) {
		num >>= 1;
		pos++;
	}
	return (pos+1);
}

char *
bcm_ip_ntoa(struct ipv4_addr *ia, char *buf)
{
	snprintf(buf, 16, "%d.%d.%d.%d",
	         ia->addr[0], ia->addr[1], ia->addr[2], ia->addr[3]);
	return (buf);
}

char *
bcm_ipv6_ntoa(void *ipv6, char *buf)
{
	/* Implementing RFC 5952 Sections 4 + 5 */
	/* Not thoroughly tested */
	uint16 tmp[8];
	uint16 *a = &tmp[0];
	char *p = buf;
	int i, i_max = -1, cnt = 0, cnt_max = 1;
	uint8 *a4 = NULL;
	memcpy((uint8 *)&tmp[0], (uint8 *)ipv6, IPV6_ADDR_LEN);

	for (i = 0; i < IPV6_ADDR_LEN/2; i++) {
		if (a[i]) {
			if (cnt > cnt_max) {
				cnt_max = cnt;
				i_max = i - cnt;
			}
			cnt = 0;
		} else
			cnt++;
	}
	if (cnt > cnt_max) {
		cnt_max = cnt;
		i_max = i - cnt;
	}
	if (i_max == 0 &&
		/* IPv4-translated: ::ffff:0:a.b.c.d */
		((cnt_max == 4 && a[4] == 0xffff && a[5] == 0) ||
		/* IPv4-mapped: ::ffff:a.b.c.d */
		(cnt_max == 5 && a[5] == 0xffff)))
		a4 = (uint8*) (a + 6);

	for (i = 0; i < IPV6_ADDR_LEN/2; i++) {
		if ((uint8*) (a + i) == a4) {
			snprintf(p, 16, ":%u.%u.%u.%u", a4[0], a4[1], a4[2], a4[3]);
			break;
		} else if (i == i_max) {
			*p++ = ':';
			i += cnt_max - 1;
			p[0] = ':';
			p[1] = '\0';
		} else {
			if (i)
				*p++ = ':';
			p += snprintf(p, 8, "%x", ntoh16(a[i]));
		}
	}

	return buf;
}

#if !defined(BCMROMOFFLOAD_EXCLUDE_BCMUTILS_FUNCS)
const unsigned char bcm_ctype[] = {

	_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,			/* 0-7 */
	_BCM_C, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C,
	_BCM_C,	/* 8-15 */
	_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,			/* 16-23 */
	_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,			/* 24-31 */
	_BCM_S|_BCM_SP,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,		/* 32-39 */
	_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,			/* 40-47 */
	_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,			/* 48-55 */
	_BCM_D,_BCM_D,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,			/* 56-63 */
	_BCM_P, _BCM_U|_BCM_X, _BCM_U|_BCM_X, _BCM_U|_BCM_X, _BCM_U|_BCM_X, _BCM_U|_BCM_X,
	_BCM_U|_BCM_X, _BCM_U, /* 64-71 */
	_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,			/* 72-79 */
	_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,			/* 80-87 */
	_BCM_U,_BCM_U,_BCM_U,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,			/* 88-95 */
	_BCM_P, _BCM_L|_BCM_X, _BCM_L|_BCM_X, _BCM_L|_BCM_X, _BCM_L|_BCM_X, _BCM_L|_BCM_X,
	_BCM_L|_BCM_X, _BCM_L, /* 96-103 */
	_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L, /* 104-111 */
	_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L, /* 112-119 */
	_BCM_L,_BCM_L,_BCM_L,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_C, /* 120-127 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,		/* 128-143 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,		/* 144-159 */
	_BCM_S|_BCM_SP, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,
	_BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,	/* 160-175 */
	_BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,
	_BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,	/* 176-191 */
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U,
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U,	/* 192-207 */
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_P, _BCM_U, _BCM_U, _BCM_U,
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_L,	/* 208-223 */
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L,
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L,	/* 224-239 */
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_P, _BCM_L, _BCM_L, _BCM_L,
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L /* 240-255 */
};

uint64
bcm_strtoull(const char *cp, char **endp, uint base)
{
	uint64 result, last_result = 0, value;
	bool minus;

	minus = FALSE;

	while (bcm_isspace(*cp))
		cp++;

	if (cp[0] == '+')
		cp++;
	else if (cp[0] == '-') {
		minus = TRUE;
		cp++;
	}

	if (base == 0) {
		if (cp[0] == '0') {
			if ((cp[1] == 'x') || (cp[1] == 'X')) {
				base = 16;
				cp = &cp[2];
			} else {
				base = 8;
				cp = &cp[1];
			}
		} else
			base = 10;
	} else if (base == 16 && (cp[0] == '0') && ((cp[1] == 'x') || (cp[1] == 'X'))) {
		cp = &cp[2];
	}

	result = 0;

	while (bcm_isxdigit(*cp) &&
	       (value = (uint64)(bcm_isdigit(*cp) ? *cp-'0' : bcm_toupper(*cp)-'A'+10)) < base) {
		result = result*base + value;
		/* Detected overflow */
		if (result < last_result && !minus) {
			if (endp) {
				/* Go to the end of current number */
				while (bcm_isxdigit(*cp)) {
					cp++;
				}
				*endp = DISCARD_QUAL(cp, char);
			}
			return (ulong)-1;
		}
		last_result = result;
		cp++;
	}

	if (minus)
		result = (ulong)(-(long)result);

	if (endp)
		*endp = DISCARD_QUAL(cp, char);

	return (result);
}

ulong
bcm_strtoul(const char *cp, char **endp, uint base)
{
	return (ulong) bcm_strtoull(cp, endp, base);
}

int
bcm_atoi(const char *s)
{
	return (int)bcm_strtoul(s, NULL, 10);
}

/* return pointer to location of substring 'needle' in 'haystack' */
char *
bcmstrstr(const char *haystack, const char *needle)
{
	int len, nlen;
	int i;

	if ((haystack == NULL) || (needle == NULL))
		return DISCARD_QUAL(haystack, char);

	nlen = (int)strlen(needle);
	len = (int)strlen(haystack) - nlen + 1;

	for (i = 0; i < len; i++)
		if (memcmp(needle, &haystack[i], (size_t)nlen) == 0)
			return DISCARD_QUAL(&haystack[i], char);
	return (NULL);
}

char *
bcmstrnstr(const char *s, uint s_len, const char *substr, uint substr_len)
{
	for (; s_len >= substr_len; s++, s_len--)
		if (strncmp(s, substr, substr_len) == 0)
			return DISCARD_QUAL(s, char);

	return NULL;
}

char *
bcmstrcat(char *dest, const char *src)
{
	char *p;

	p = dest + strlen(dest);

	while ((*p++ = *src++) != '\0')
		;

	return (dest);
}

char *
bcmstrncat(char *dest, const char *src, uint size)
{
	char *endp;
	char *p;

	p = dest + strlen(dest);
	endp = p + size;

	while (p != endp && (*p++ = *src++) != '\0')
		;

	return (dest);
}

/****************************************************************************
* Function:   bcmstrtok
*
* Purpose:
*  Tokenizes a string. This function is conceptually similiar to ANSI C strtok(),
*  but allows strToken() to be used by different strings or callers at the same
*  time. Each call modifies '*string' by substituting a NULL character for the
*  first delimiter that is encountered, and updates 'string' to point to the char
*  after the delimiter. Leading delimiters are skipped.
*
* Parameters:
*  string      (mod) Ptr to string ptr, updated by token.
*  delimiters  (in)  Set of delimiter characters.
*  tokdelim    (out) Character that delimits the returned token. (May
*                    be set to NULL if token delimiter is not required).
*
* Returns:  Pointer to the next token found. NULL when no more tokens are found.
*****************************************************************************
*/
char *
bcmstrtok(char **string, const char *delimiters, char *tokdelim)
{
	unsigned char *str;
	unsigned long map[8];
	int count;
	char *nextoken;

	if (tokdelim != NULL) {
		/* Prime the token delimiter */
		*tokdelim = '\0';
	}

	/* Clear control map */
	for (count = 0; count < 8; count++) {
		map[count] = 0;
	}

	/* Set bits in delimiter table */
	do {
		map[*delimiters >> 5] |= (1 << (*delimiters & 31));
	}
	while (*delimiters++);

	str = (unsigned char*)*string;

	/* Find beginning of token (skip over leading delimiters). Note that
	 * there is no token iff this loop sets str to point to the terminal
	 * null (*str == '\0')
	 */
	while (((map[*str >> 5] & (1 << (*str & 31))) && *str) || (*str == ' ')) {
		str++;
	}

	nextoken = (char*)str;

	/* Find the end of the token. If it is not the end of the string,
	 * put a null there.
	 */
	for (; *str; str++) {
		if (map[*str >> 5] & (1 << (*str & 31))) {
			if (tokdelim != NULL) {
				*tokdelim = (char)*str;
			}

			*str++ = '\0';
			break;
		}
	}

	*string = (char*)str;

	/* Determine if a token has been found. */
	if (nextoken == (char *) str) {
		return NULL;
	}
	else {
		return nextoken;
	}
}

#define xToLower(C) \
	((C >= 'A' && C <= 'Z') ? (char)((int)C - (int)'A' + (int)'a') : C)

/****************************************************************************
* Function:   bcmstricmp
*
* Purpose:    Compare to strings case insensitively.
*
* Parameters: s1 (in) First string to compare.
*             s2 (in) Second string to compare.
*
* Returns:    Return 0 if the two strings are equal, -1 if t1 < t2 and 1 if
*             t1 > t2, when ignoring case sensitivity.
*****************************************************************************
*/
int
bcmstricmp(const char *s1, const char *s2)
{
	char dc, sc;

	while (*s2 && *s1) {
		dc = xToLower(*s1);
		sc = xToLower(*s2);
		if (dc < sc) return -1;
		if (dc > sc) return 1;
		s1++;
		s2++;
	}

	if (*s1 && !*s2) return 1;
	if (!*s1 && *s2) return -1;
	return 0;
}

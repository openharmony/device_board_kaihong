// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * hcd_queue.c - DesignWare HS OTG Controller host queuing routines
 *
 * Copyright (C) 2004-2013 Synopsys, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the above-listed copyright holders may not be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file contains the functions to manage Queue Heads and Queue
 * Transfer Descriptors for Host mode
 */
#include <linux/gcd.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/usb.h>

#include <linux/usb/hcd.h>
#include <linux/usb/ch11.h>

#include "core.h"
#include "hcd.h"

/* Wait this long before releasing periodic reservation */
#define DWC2_UNRESERVE_DELAY (msecs_to_jiffies(5))

/* If we get a NAK, wait this long before retrying */
#define DWC2_RETRY_WAIT_DELAY (1 * NSEC_PER_MSEC)

/**
 * dwc2_periodic_channel_available() - Checks that a channel is available for a
 * periodic transfer
 *
 * @hsotg: The HCD state structure for the DWC OTG controller
 *
 * Return: 0 if successful, negative error code otherwise
 */
static int dwc2_periodic_channel_available(struct dwc2_hsotg *hsotg)
{
	/*
	 * Currently assuming that there is a dedicated host channel for
	 * each periodic transaction plus at least one host channel for
	 * non-periodic transactions
	 */
	int status;
	int num_channels;

	num_channels = hsotg->params.host_channels;
	if ((hsotg->periodic_channels + hsotg->non_periodic_channels <
	     num_channels) && (hsotg->periodic_channels < num_channels - 1)) {
		status = 0;
	} else {
		dev_dbg(hsotg->dev,
			"%s: Total channels: %d, Periodic: %d, Non-periodic: %d\n",
			__func__, num_channels,
			hsotg->periodic_channels, hsotg->non_periodic_channels);
		status = -ENOSPC;
	}

	return status;
}

/**
 * dwc2_check_periodic_bandwidth() - Checks that there is sufficient bandwidth
 * for the specified QH in the periodic schedule
 *
 * @hsotg: The HCD state structure for the DWC OTG controller
 * @qh:    QH containing periodic bandwidth required
 *
 * Return: 0 if successful, negative error code otherwise
 *
 * For simplicity, this calculation assumes that all the transfers in the
 * periodic schedule may occur in the same (micro)frame
 */
static int dwc2_check_periodic_bandwidth(struct dwc2_hsotg *hsotg,
					 struct dwc2_qh *qh)
{
	int status;
	s16 max_claimed_usecs;

	status = 0;

	if (qh->dev_speed == USB_SPEED_HIGH || qh->do_split) {
		/*
		 * High speed mode
		 * Max periodic usecs is 80% x 125 usec = 100 usec
		 */
		max_claimed_usecs = 100 - qh->host_us;
	} else {
		/*
		 * Full speed mode
		 * Max periodic usecs is 90% x 1000 usec = 900 usec
		 */
		max_claimed_usecs = 900 - qh->host_us;
	}

	if (hsotg->periodic_usecs > max_claimed_usecs) {
		dev_err(hsotg->dev,
			"%s: already claimed usecs %d, required usecs %d\n",
			__func__, hsotg->periodic_usecs, qh->host_us);
		status = -ENOSPC;
	}

	return status;
}

/**
 * pmap_schedule() - Schedule time in a periodic bitmap (pmap).
 *
 * @map:             The bitmap representing the schedule; will be updated
 *                   upon success.
 * @bits_per_period: The schedule represents several periods.  This is how many
 *                   bits are in each period.  It's assumed that the beginning
 *                   of the schedule will repeat after its end.
 * @periods_in_map:  The number of periods in the schedule.
 * @num_bits:        The number of bits we need per period we want to reserve
 *                   in this function call.
 * @interval:        How often we need to be scheduled for the reservation this
 *                   time.  1 means every period.  2 means every other period.
 *                   ...you get the picture?
 * @start:           The bit number to start at.  Normally 0.  Must be within
 *                   the interval or we return failure right away.
 * @only_one_period: Normally we'll allow picking a start anywhere within the
 *                   first interval, since we can still make all repetition
 *                   requirements by doing that.  However, if you pass true
 *                   here then we'll return failure if we can't fit within
 *                   the period that "start" is in.
 *
 * The idea here is that we want to schedule time for repeating events that all
 * want the same resource.  The resource is divided into fixed-sized periods
 * and the events want to repeat every "interval" periods.  The schedule
 * granularity is one bit.
 *
 * To keep things "simple", we'll represent our schedule with a bitmap that
 * contains a fixed number of periods.  This gets rid of a lot of complexity
 * but does mean that we need to handle things specially (and non-ideally) if
 * the number of the periods in the schedule doesn't match well with the
 * intervals that we're trying to schedule.
 *
 * Here's an explanation of the scheme we'll implement, assuming 8 periods.
 * - If interval is 1, we need to take up space in each of the 8
 *   periods we're scheduling.  Easy.
 * - If interval is 2, we need to take up space in half of the
 *   periods.  Again, easy.
 * - If interval is 3, we actually need to fall back to interval 1.
 *   Why?  Because we might need time in any period.  AKA for the
 *   first 8 periods, we'll be in slot 0, 3, 6.  Then we'll be
 *   in slot 1, 4, 7.  Then we'll be in 2, 5.  Then we'll be back to
 *   0, 3, and 6.  Since we could be in any frame we need to reserve
 *   for all of them.  Sucks, but that's what you gotta do.  Note that
 *   if we were instead scheduling 8 * 3 = 24 we'd do much better, but
 *   then we need more memory and time to do scheduling.
 * - If interval is 4, easy.
 * - If interval is 5, we again need interval 1.  The schedule will be
 *   0, 5, 2, 7, 4, 1, 6, 3, 0
 * - If interval is 6, we need interval 2.  0, 6, 4, 2.
 * - If interval is 7, we need interval 1.
 * - If interval is 8, we need interval 8.
 *
 * If you do the math, you'll see that we need to pretend that interval is
 * equal to the greatest_common_divisor(interval, periods_in_map).
 *
 * Note that at the moment this function tends to front-pack the schedule.
 * In some cases that's really non-ideal (it's hard to schedule things that
 * need to repeat every period).  In other cases it's perfect (you can easily
 * schedule bigger, less often repeating things).
 *
 * Here's the algorithm in action (8 periods, 5 bits per period):
 *  |**   |     |**   |     |**   |     |**   |     |   OK 2 bits, intv 2 at 0
 *  |*****|  ***|*****|  ***|*****|  ***|*****|  ***|   OK 3 bits, intv 3 at 2
 *  |*****|* ***|*****|  ***|*****|* ***|*****|  ***|   OK 1 bits, intv 4 at 5
 *  |**   |*    |**   |     |**   |*    |**   |     | Remv 3 bits, intv 3 at 2
 *  |***  |*    |***  |     |***  |*    |***  |     |   OK 1 bits, intv 6 at 2
 *  |**** |*  * |**** |   * |**** |*  * |**** |   * |   OK 1 bits, intv 1 at 3
 *  |**** |**** |**** | *** |**** |**** |**** | *** |   OK 2 bits, intv 2 at 6
 *  |*****|*****|*****| ****|*****|*****|*****| ****|   OK 1 bits, intv 1 at 4
 *  |*****|*****|*****| ****|*****|*****|*****| ****| FAIL 1 bits, intv 1
 *  |  ***|*****|  ***| ****|  ***|*****|  ***| ****| Remv 2 bits, intv 2 at 0
 *  |  ***| ****|  ***| ****|  ***| ****|  ***| ****| Remv 1 bits, intv 4 at 5
 *  |   **| ****|   **| ****|   **| ****|   **| ****| Remv 1 bits, intv 6 at 2
 *  |    *| ** *|    *| ** *|    *| ** *|    *| ** *| Remv 1 bits, intv 1 at 3
 *  |    *|    *|    *|    *|    *|    *|    *|    *| Remv 2 bits, intv 2 at 6
 *  |     |     |     |     |     |     |     |     | Remv 1 bits, intv 1 at 4
 *  |**   |     |**   |     |**   |     |**   |     |   OK 2 bits, intv 2 at 0
 *  |***  |     |**   |     |***  |     |**   |     |   OK 1 bits, intv 4 at 2
 *  |*****|     |** **|     |*****|     |** **|     |   OK 2 bits, intv 2 at 3
 *  |*****|*    |** **|     |*****|*    |** **|     |   OK 1 bits, intv 4 at 5
 *  |*****|***  |** **| **  |*****|***  |** **| **  |   OK 2 bits, intv 2 at 6
 *  |*****|*****|** **| ****|*****|*****|** **| ****|   OK 2 bits, intv 2 at 8
 *  |*****|*****|*****| ****|*****|*****|*****| ****|   OK 1 bits, intv 4 at 12
 *
 * This function is pretty generic and could be easily abstracted if anything
 * needed similar scheduling.
 *
 * Returns either -ENOSPC or a >= 0 start bit which should be passed to the
 * unschedule routine.  The map bitmap will be updated on a non-error result.
 */
static int pmap_schedule(unsigned long *map, int bits_per_period,
			 int periods_in_map, int num_bits,
			 int interval, int start, bool only_one_period)
{
	int interval_bits;
	int to_reserve;
	int first_end;
	int i;

	if (num_bits > bits_per_period)
		return -ENOSPC;

	/* Adjust interval as per description */
	interval = gcd(interval, periods_in_map);

	interval_bits = bits_per_period * interval;
	to_reserve = periods_in_map / interval;

	/* If start has gotten us past interval then we can't schedule */
	if (start >= interval_bits)
		return -ENOSPC;

	if (only_one_period)
		/* Must fit within same period as start; end at begin of next */
		first_end = (start / bits_per_period + 1) * bits_per_period;
	else
		/* Can fit anywhere in the first interval */
		first_end = interval_bits;

	/*
	 * We'll try to pick the first repetition, then see if that time
	 * is free for each of the subsequent repetitions.  If it's not
	 * we'll adjust the start time for the next search of the first
	 * repetition.
	 */
	while (start + num_bits <= first_end) {
		int end;

		/* Need to stay within this period */
		end = (start / bits_per_period + 1) * bits_per_period;

		/* Look for num_bits us in this microframe starting at start */
		start = bitmap_find_next_zero_area(map, end, start, num_bits,
						   0);

		/*
		 * We should get start >= end if we fail.  We might be
		 * able to check the next microframe depending on the
		 * interval, so continue on (start already updated).
		 */
		if (start >= end) {
			start = end;
			continue;
		}

		/* At this point we have a valid point for first one */
		for (i = 1; i < to_reserve; i++) {
			int ith_start = start + interval_bits * i;
			int ith_end = end + interval_bits * i;
			int ret;

			/* Use this as a dumb "check if bits are 0" */
			ret = bitmap_find_next_zero_area(
				map, ith_start + num_bits, ith_start, num_bits,
				0);

			/* We got the right place, continue checking */
			if (ret == ith_start)
				continue;

			/* Move start up for next time and exit for loop */
			ith_start = bitmap_find_next_zero_area(
				map, ith_end, ith_start, num_bits, 0);
			if (ith_start >= ith_end)
				/* Need a while new period next time */
				start = end;
			else
				start = ith_start - interval_bits * i;
			break;
		}

		/* If didn't exit the for loop with a break, we have success */
		if (i == to_reserve)
			break;
	}

	if (start + num_bits > first_end)
		return -ENOSPC;

	for (i = 0; i < to_reserve; i++) {
		int ith_start = start + interval_bits * i;

		bitmap_set(map, ith_start, num_bits);
	}

	return start;
}

/**
 * pmap_unschedule() - Undo work done by pmap_schedule()
 *
 * @map:             See pmap_schedule().
 * @bits_per_period: See pmap_schedule().
 * @periods_in_map:  See pmap_schedule().
 * @num_bits:        The number of bits that was passed to schedule.
 * @interval:        The interval that was passed to schedule.
 * @start:           The return value from pmap_schedule().
 */
static void pmap_unschedule(unsigned long *map, int bits_per_period,
			    int periods_in_map, int num_bits,
			    int interval, int start)
{
	int interval_bits;
	int to_release;
	int i;

	/* Adjust interval as per description in pmap_schedule() */
	interval = gcd(interval, periods_in_map);

	interval_bits = bits_per_period * interval;
	to_release = periods_in_map / interval;

	for (i = 0; i < to_release; i++) {
		int ith_start = start + interval_bits * i;

		bitmap_clear(map, ith_start, num_bits);
	}
}

/**
 * dwc2_get_ls_map() - Get the map used for the given qh
 *
 * @hsotg: The HCD state structure for the DWC OTG controller.
 * @qh:    QH for the periodic transfer.
 *
 * We'll always get the periodic map out of our TT.  Note that even if we're
 * running the host straight in low speed / full speed mode it appears as if
 * a TT is allocated for us, so we'll use it.  If that ever changes we can
 * add logic here to get a map out of "hsotg" if !qh->do_split.
 *
 * Returns: the map or NULL if a map couldn't be found.
 */
static unsigned long *dwc2_get_ls_map(struct dwc2_hsotg *hsotg,
				      struct dwc2_qh *qh)
{
	unsigned long *map;

	/* Don't expect to be missing a TT and be doing low speed scheduling */
	if (WARN_ON(!qh->dwc_tt))
		return NULL;

	/* Get the map and adjust if this is a multi_tt hub */
	map = qh->dwc_tt->periodic_bitmaps;
	if (qh->dwc_tt->usb_tt->multi)
		map += DWC2_ELEMENTS_PER_LS_BITMAP * (qh->ttport - 1);

	return map;
}

#ifdef DWC2_PRINT_SCHEDULE
/*
 * cat_printf() - A printf() + strcat() helper
 *
 * This is useful for concatenating a bunch of strings where each string is
 * constructed using printf.
 *
 * @buf:   The destination buffer; will be updated to point after the printed
 *         data.
 * @size:  The number of bytes in the buffer (includes space for '\0').
 * @fmt:   The format for printf.
 * @...:   The args for printf.
 */
static __printf(3, 4)
void cat_printf(char **buf, size_t *size, const char *fmt, ...)
{
	va_list args;
	int i;

	if (*size == 0)
		return;

	va_start(args, fmt);
	i = vsnprintf(*buf, *size, fmt, args);
	va_end(args);

	if (i >= *size) {
		(*buf)[*size - 1] = '\0';
		*buf += *size;
		*size = 0;
	} else {
		*buf += i;
		*size -= i;
	}
}

/*
 * pmap_print() - Print the given periodic map
 *
 * Will attempt to print out the periodic schedule.
 *
 * @map:             See pmap_schedule().
 * @bits_per_period: See pmap_schedule().
 * @periods_in_map:  See pmap_schedule().
 * @period_name:     The name of 1 period, like "uFrame"
 * @units:           The name of the units, like "us".
 * @print_fn:        The function to call for printing.
 * @print_data:      Opaque data to pass to the print function.
 */
static void pmap_print(unsigned long *map, int bits_per_period,
		       int periods_in_map, const char *period_name,
		       const char *units,
		       void (*print_fn)(const char *str, void *data),
		       void *print_data)
{
	int period;

	for (period = 0; period < periods_in_map; period++) {
		char tmp[64];
		char *buf = tmp;
		size_t buf_size = sizeof(tmp);
		int period_start = period * bits_per_period;
		int period_end = period_start + bits_per_period;
		int start = 0;
		int count = 0;
		bool printed = false;
		int i;

		for (i = period_start; i < period_end + 1; i++) {
			/* Handle case when ith bit is set */
			if (i < period_end &&
			    bitmap_find_next_zero_area(map, i + 1,
						       i, 1, 0) != i) {
				if (count == 0)
					start = i - period_start;
				count++;
				continue;
			}

			/* ith bit isn't set; don't care if count == 0 */
			if (count == 0)
				continue;

			if (!printed)
				cat_printf(&buf, &buf_size, "%s %d: ",
					   period_name, period);
			else
				cat_printf(&buf, &buf_size, ", ");
			printed = true;

			cat_printf(&buf, &buf_size, "%d %s -%3d %s", start,
				   units, start + count - 1, units);
			count = 0;
		}

		if (printed)
			print_fn(tmp, print_data);
	}
}

struct dwc2_qh_print_data {
	struct dwc2_hsotg *hsotg;
	struct dwc2_qh *qh;
};

/**
 * dwc2_qh_print() - Helper function for dwc2_qh_schedule_print()
 *
 * @str:  The string to print
 * @data: A pointer to a struct dwc2_qh_print_data
 */
static void dwc2_qh_print(const char *str, void *data)
{
	struct dwc2_qh_print_data *print_data = data;

	dwc2_sch_dbg(print_data->hsotg, "QH=%p ...%s\n", print_data->qh, str);
}

/**
 * dwc2_qh_schedule_print() - Print the periodic schedule
 *
 * @hsotg: The HCD state structure for the DWC OTG controller.
 * @qh:    QH to print.
 */
static void dwc2_qh_schedule_print(struct dwc2_hsotg *hsotg,
				   struct dwc2_qh *qh)
{
	struct dwc2_qh_print_data print_data = { hsotg, qh };
	int i;

	/*
	 * The printing functions are quite slow and inefficient.
	 * If we don't have tracing turned on, don't run unless the special
	 * define is turned on.
	 */

	if (qh->schedule_low_speed) {
		unsigned long *map = dwc2_get_ls_map(hsotg, qh);

		dwc2_sch_dbg(hsotg, "QH=%p LS/FS trans: %d=>%d us @ %d us",
			     qh, qh->device_us,
			     DWC2_ROUND_US_TO_SLICE(qh->device_us),
			     DWC2_US_PER_SLICE * qh->ls_start_schedule_slice);

		if (map) {
			dwc2_sch_dbg(hsotg,
				     "QH=%p Whole low/full speed map %p now:\n",
				     qh, map);
			pmap_print(map, DWC2_LS_PERIODIC_SLICES_PER_FRAME,
				   DWC2_LS_SCHEDULE_FRAMES, "Frame ", "slices",
				   dwc2_qh_print, &print_data);
		}
	}

	for (i = 0; i < qh->num_hs_transfers; i++) {
		struct dwc2_hs_transfer_time *trans_time = qh->hs_transfers + i;
		int uframe = trans_time->start_schedule_us /
			     DWC2_HS_PERIODIC_US_PER_UFRAME;
		int rel_us = trans_time->start_schedule_us %
			     DWC2_HS_PERIODIC_US_PER_UFRAME;

		dwc2_sch_dbg(hsotg,
			     "QH=%p HS trans #%d: %d us @ uFrame %d + %d us\n",
			     qh, i, trans_time->duration_us, uframe, rel_us);
	}
	if (qh->num_hs_transfers) {
		dwc2_sch_dbg(hsotg, "QH=%p Whole high speed map now:\n", qh);
		pmap_print(hsotg->hs_periodic_bitmap,
			   DWC2_HS_PERIODIC_US_PER_UFRAME,
			   DWC2_HS_SCHEDULE_UFRAMES, "uFrame", "us",
			   dwc2_qh_print, &print_data);
	}
}
#else
static inline void dwc2_qh_schedule_print(struct dwc2_hsotg *hsotg,
					  struct dwc2_qh *qh) {};
#endif

/**
 * dwc2_ls_pmap_schedule() - Schedule a low speed QH
 *
 * @hsotg:        The HCD state structure for the DWC OTG controller.
 * @qh:           QH for the periodic transfer.
 * @search_slice: We'll start trying to schedule at the passed slice.
 *                Remember that slices are the units of the low speed
 *                schedule (think 25us or so).
 *
 * Wraps pmap_schedule() with the right parameters for low speed scheduling.
 *
 * Normally we schedule low speed devices on the map associated with the TT.
 *
 * Returns: 0 for success or an error code.
 */
static int dwc2_ls_pmap_schedule(struct dwc2_hsotg *hsotg, struct dwc2_qh *qh,
				 int search_slice)
{
	int slices = DIV_ROUND_UP(qh->device_us, DWC2_US_PER_SLICE);
	unsigned long *map = dwc2_get_ls_map(hsotg, qh);
	int slice;

	if (!map)
		return -EINVAL;

	/*
	 * Schedule on the proper low speed map with our low speed scheduling
	 * parameters.  Note that we use the "device_interval" here since
	 * we want the low speed interval and the only way we'd be in this
	 * function is if the device is low speed.
	 *
	 * If we happen to be doing low speed and high speed scheduling for the
	 * same transaction (AKA we have a split) we always do low speed first.
	 * That means we can always pass "false" for only_one_period (that
	 * parameters is only useful when we're trying to get one schedule to
	 * match what we already planned in the other schedule).
	 */
	slice = pmap_schedule(map, DWC2_LS_PERIODIC_SLICES_PER_FRAME,
			      DWC2_LS_SCHEDULE_FRAMES, slices,
			      qh->device_interval, search_slice, false);

	if (slice < 0)
		return slice;

	qh->ls_start_schedule_slice = slice;
	return 0;
}

/**
 * dwc2_ls_pmap_unschedule() - Undo work done by dwc2_ls_pmap_schedule()
 *
 * @hsotg:       The HCD state structure for the DWC OTG controller.
 * @qh:          QH for the periodic transfer.
 */
static void dwc2_ls_pmap_unschedule(struct dwc2_hsotg *hsotg,
				    struct dwc2_qh *qh)
{
	int slices = DIV_ROUND_UP(qh->device_us, DWC2_US_PER_SLICE);
	unsigned long *map = dwc2_get_ls_map(hsotg, qh);

	/* Schedule should have failed, so no worries about no error code */
	if (!map)
		return;

	pmap_unschedule(map, DWC2_LS_PERIODIC_SLICES_PER_FRAME,
			DWC2_LS_SCHEDULE_FRAMES, slices, qh->device_interval,
			qh->ls_start_schedule_slice);
}

/**
 * dwc2_hs_pmap_schedule - Schedule in the main high speed schedule
 *
 * This will schedule something on the main dwc2 schedule.
 *
 * We'll start looking in qh->hs_transfers[index].start_schedule_us.  We'll
 * update this with the result upon success.  We also use the duration from
 * the same structure.
 *
 * @hsotg:           The HCD state structure for the DWC OTG controller.
 * @qh:              QH for the periodic transfer.
 * @only_one_period: If true we will limit ourselves to just looking at
 *                   one period (aka one 100us chunk).  This is used if we have
 *                   already scheduled something on the low speed schedule and
 *                   need to find something that matches on the high speed one.
 * @index:           The index into qh->hs_transfers that we're working with.
 *
 * Returns: 0 for success or an error code.  Upon success the
 *          dwc2_hs_transfer_time specified by "index" will be updated.
 */
static int dwc2_hs_pmap_schedule(struct dwc2_hsotg *hsotg, struct dwc2_qh *qh,
				 bool only_one_period, int index)
{
	struct dwc2_hs_transfer_time *trans_time = qh->hs_transfers + index;
	int us;

	us = pmap_schedule(hsotg->hs_periodic_bitmap,
			   DWC2_HS_PERIODIC_US_PER_UFRAME,
			   DWC2_HS_SCHEDULE_UFRAMES, trans_time->duration_us,
			   qh->host_interval, trans_time->start_schedule_us,
			   only_one_period);

	if (us < 0)
		return us;

	trans_time->start_schedule_us = us;
	return 0;
}

/**
 * dwc2_ls_pmap_unschedule() - Undo work done by dwc2_hs_pmap_schedule()
 *
 * @hsotg:       The HCD state structure for the DWC OTG controller.
 * @qh:          QH for the periodic transfer.
 * @index:       Transfer index
 */
static void dwc2_hs_pmap_unschedule(struct dwc2_hsotg *hsotg,
				    struct dwc2_qh *qh, int index)
{
	struct dwc2_hs_transfer_time *trans_time = qh->hs_transfers + index;

	pmap_unschedule(hsotg->hs_periodic_bitmap,
			DWC2_HS_PERIODIC_US_PER_UFRAME,
			DWC2_HS_SCHEDULE_UFRAMES, trans_time->duration_us,
			qh->host_interval, trans_time->start_schedule_us);
}

/**
 * dwc2_uframe_schedule_split - Schedule a QH for a periodic split xfer.
 *
 * This is the most complicated thing in USB.  We have to find matching time
 * in both the global high speed schedule for the port and the low speed
 * schedule for the TT associated with the given device.
 *
 * Being here means that the host must be running in high speed mode and the
 * device is in low or full speed mode (and behind a hub).
 *
 * @hsotg:       The HCD state structure for the DWC OTG controller.
 * @qh:          QH for the periodic transfer.
 */
static int dwc2_uframe_schedule_split(struct dwc2_hsotg *hsotg,
				      struct dwc2_qh *qh)
{
	int bytecount = qh->maxp_mult * qh->maxp;
	int ls_search_slice;
	int err = 0;
	int host_interval_in_sched;

	/*
	 * The interval (how often to repeat) in the actual host schedule.
	 * See pmap_schedule() for gcd() explanation.
	 */
	host_interval_in_sched = gcd(qh->host_interval,
				     DWC2_HS_SCHEDULE_UFRAMES);

	/*
	 * We always try to find space in the low speed schedule first, then
	 * try to find high speed time that matches.  If we don't, we'll bump

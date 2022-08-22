/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ethernet Bonding driver Vendor Hooks
 *
 * Copyright (c) 2022, Huawei Tech. Co., Ltd.
 */


#undef TRACE_SYSTEM
#define TRACE_SYSTEM cam_heap_hooks

#define TRACE_INCLUDE_PATH trace/hooks
#if !defined(_TRACE_CAM_HEAP_BONDING_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CAM_HEAP_BONDING_H
#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>

struct cma_heap_buffer;
struct page;
struct cma_heap;
struct dma_buf;
struct dma_buf_ops;
struct dma_heap;
DECLARE_HOOK(cam_heap_hooks,
	TP_PROTO(struct cma_heap_buffer *buffer, struct page *cma_pages, struct cma_heap *cma_heap, pgoff_t pagecount, unsigned long fd_flags, struct dma_buf *dmabuf, struct dma_buf_ops *pcma_heap_buf_ops, struct dma_heap *heap, void *data ),
	TP_ARGS( buffer, cma_pages, cma_heap, pagecount, fd_flags, dmabuf, pcma_heap_buf_ops, heap, data )); 



DECLARE_HOOK(cam_heap_config_hooks,
	TP_PROTO( void *data ),
	TP_ARGS( data )); 

#endif
/* This part must be outside protection */
#include <trace/define_trace.h>

#ifdef CONFIG_VENDOR_DTC_HOOKS
#endif


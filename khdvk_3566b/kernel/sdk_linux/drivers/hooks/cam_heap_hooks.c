// SPDX-License-Identifier: GPL-2.0-only
/* vendor_hook.c
 *
 * Vendor Hook Support
 *
 * Copyright (C) 2020 Google, Inc.
 */

#define CREATE_TRACE_POINTS
#include <trace/hooks/cam_heap_hooks.h>

/*
 * Export tracepoints that act as a bare tracehook (ie: have no trace event
 * associated with them) to allow external modules to probe them.
 */

EXPORT_TRACEPOINT_SYMBOL_GPL(cam_heap_hooks);
EXPORT_TRACEPOINT_SYMBOL_GPL(cam_heap_config_hooks);
#ifdef CONFIG_VENDOR_BOND_HOOKS
#endif

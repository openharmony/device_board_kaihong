// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013-2017 ARM Limited, All Rights Reserved.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/acpi.h>
#include <linux/acpi_iort.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/crash_dump.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/efi.h>
#include <linux/interrupt.h>
#include <linux/iopoll.h>
#include <linux/irqdomain.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/syscore_ops.h>

#include <linux/irqchip.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqchip/arm-gic-v4.h>

#include <asm/cputype.h>
#include <asm/exception.h>

#include "irq-gic-common.h"

#define ITS_FLAGS_CMDQ_NEEDS_FLUSHING		(1ULL << 0)
#define ITS_FLAGS_WORKAROUND_CAVIUM_22375	(1ULL << 1)
#define ITS_FLAGS_WORKAROUND_CAVIUM_23144	(1ULL << 2)

#define RDIST_FLAGS_PROPBASE_NEEDS_FLUSHING	(1 << 0)
#define RDIST_FLAGS_RD_TABLES_PREALLOCATED	(1 << 1)

static u32 lpi_id_bits;

/*
 * We allocate memory for PROPBASE to cover 2 ^ lpi_id_bits LPIs to
 * deal with (one configuration byte per interrupt). PENDBASE has to
 * be 64kB aligned (one bit per LPI, plus 8192 bits for SPI/PPI/SGI).
 */
#define LPI_NRBITS		lpi_id_bits
#define LPI_PROPBASE_SZ		ALIGN(BIT(LPI_NRBITS), SZ_64K)
#define LPI_PENDBASE_SZ		ALIGN(BIT(LPI_NRBITS) / 8, SZ_64K)

#define LPI_PROP_DEFAULT_PRIO	GICD_INT_DEF_PRI

/*
 * Collection structure - just an ID, and a redistributor address to
 * ping. We use one per CPU as a bag of interrupts assigned to this
 * CPU.
 */
struct its_collection {
	u64			target_address;
	u16			col_id;
};

/*
 * The ITS_BASER structure - contains memory information, cached
 * value of BASER register configuration and ITS page size.
 */
struct its_baser {
	void		*base;
	u64		val;
	u32		order;
	u32		psz;
};

struct its_device;

/*
 * The ITS structure - contains most of the infrastructure, with the
 * top-level MSI domain, the command queue, the collections, and the
 * list of devices writing to it.
 *
 * dev_alloc_lock has to be taken for device allocations, while the
 * spinlock must be taken to parse data structures such as the device
 * list.
 */
struct its_node {
	raw_spinlock_t		lock;
	struct mutex		dev_alloc_lock;
	struct list_head	entry;
	void __iomem		*base;
	void __iomem		*sgir_base;
	phys_addr_t		phys_base;
	struct its_cmd_block	*cmd_base;
	struct its_cmd_block	*cmd_write;
	struct its_baser	tables[GITS_BASER_NR_REGS];
	struct its_collection	*collections;
	struct fwnode_handle	*fwnode_handle;
	u64			(*get_msi_base)(struct its_device *its_dev);
	u64			typer;
	u64			cbaser_save;
	u32			ctlr_save;
	u32			mpidr;
	struct list_head	its_device_list;
	u64			flags;
	unsigned long		list_nr;
	int			numa_node;
	unsigned int		msi_domain_flags;
	u32			pre_its_base; /* for Socionext Synquacer */
	int			vlpi_redist_offset;
};

#define is_v4(its)		(!!((its)->typer & GITS_TYPER_VLPIS))
#define is_v4_1(its)		(!!((its)->typer & GITS_TYPER_VMAPP))
#define device_ids(its)		(FIELD_GET(GITS_TYPER_DEVBITS, (its)->typer) + 1)

#define ITS_ITT_ALIGN		SZ_256

/* The maximum number of VPEID bits supported by VLPI commands */
#define ITS_MAX_VPEID_BITS						\
	({								\
		int nvpeid = 16;					\
		if (gic_rdists->has_rvpeid &&				\
		    gic_rdists->gicd_typer2 & GICD_TYPER2_VIL)		\
			nvpeid = 1 + (gic_rdists->gicd_typer2 &		\
				      GICD_TYPER2_VID);			\
									\
		nvpeid;							\
	})
#define ITS_MAX_VPEID		(1 << (ITS_MAX_VPEID_BITS))

/* Convert page order to size in bytes */
#define PAGE_ORDER_TO_SIZE(o)	(PAGE_SIZE << (o))

struct event_lpi_map {
	unsigned long		*lpi_map;
	u16			*col_map;
	irq_hw_number_t		lpi_base;
	int			nr_lpis;
	raw_spinlock_t		vlpi_lock;
	struct its_vm		*vm;
	struct its_vlpi_map	*vlpi_maps;
	int			nr_vlpis;
};

/*
 * The ITS view of a device - belongs to an ITS, owns an interrupt
 * translation table, and a list of interrupts.  If it some of its
 * LPIs are injected into a guest (GICv4), the event_map.vm field
 * indicates which one.
 */
struct its_device {
	struct list_head	entry;
	struct its_node		*its;
	struct event_lpi_map	event_map;
	void			*itt;
	u32			nr_ites;
	u32			device_id;
	bool			shared;
};

static struct {
	raw_spinlock_t		lock;
	struct its_device	*dev;
	struct its_vpe		**vpes;
	int			next_victim;
} vpe_proxy;

struct cpu_lpi_count {
	atomic_t	managed;
	atomic_t	unmanaged;
};

static DEFINE_PER_CPU(struct cpu_lpi_count, cpu_lpi_count);

static LIST_HEAD(its_nodes);
static DEFINE_RAW_SPINLOCK(its_lock);
static struct rdists *gic_rdists;
static struct irq_domain *its_parent;

static unsigned long its_list_map;
static u16 vmovp_seq_num;
static DEFINE_RAW_SPINLOCK(vmovp_lock);

static DEFINE_IDA(its_vpeid_ida);

#define gic_data_rdist()		(raw_cpu_ptr(gic_rdists->rdist))
#define gic_data_rdist_cpu(cpu)		(per_cpu_ptr(gic_rdists->rdist, cpu))
#define gic_data_rdist_rd_base()	(gic_data_rdist()->rd_base)
#define gic_data_rdist_vlpi_base()	(gic_data_rdist_rd_base() + SZ_128K)

/*
 * Skip ITSs that have no vLPIs mapped, unless we're on GICv4.1, as we
 * always have vSGIs mapped.
 */
static bool require_its_list_vmovp(struct its_vm *vm, struct its_node *its)
{
	return (gic_rdists->has_rvpeid || vm->vlpi_count[its->list_nr]);
}

static u16 get_its_list(struct its_vm *vm)
{
	struct its_node *its;
	unsigned long its_list = 0;

	list_for_each_entry(its, &its_nodes, entry) {
		if (!is_v4(its))
			continue;

		if (require_its_list_vmovp(vm, its))
			__set_bit(its->list_nr, &its_list);
	}

	return (u16)its_list;
}

static inline u32 its_get_event_id(struct irq_data *d)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	return d->hwirq - its_dev->event_map.lpi_base;
}

static struct its_collection *dev_event_to_col(struct its_device *its_dev,
					       u32 event)
{
	struct its_node *its = its_dev->its;

	return its->collections + its_dev->event_map.col_map[event];
}

static struct its_vlpi_map *dev_event_to_vlpi_map(struct its_device *its_dev,
					       u32 event)
{
	if (WARN_ON_ONCE(event >= its_dev->event_map.nr_lpis))
		return NULL;

	return &its_dev->event_map.vlpi_maps[event];
}

static struct its_vlpi_map *get_vlpi_map(struct irq_data *d)
{
	if (irqd_is_forwarded_to_vcpu(d)) {
		struct its_device *its_dev = irq_data_get_irq_chip_data(d);
		u32 event = its_get_event_id(d);

		return dev_event_to_vlpi_map(its_dev, event);
	}

	return NULL;
}

static int vpe_to_cpuid_lock(struct its_vpe *vpe, unsigned long *flags)
{
	raw_spin_lock_irqsave(&vpe->vpe_lock, *flags);
	return vpe->col_idx;
}

static void vpe_to_cpuid_unlock(struct its_vpe *vpe, unsigned long flags)
{
	raw_spin_unlock_irqrestore(&vpe->vpe_lock, flags);
}

static int irq_to_cpuid_lock(struct irq_data *d, unsigned long *flags)
{
	struct its_vlpi_map *map = get_vlpi_map(d);
	int cpu;

	if (map) {
		cpu = vpe_to_cpuid_lock(map->vpe, flags);
	} else {
		/* Physical LPIs are already locked via the irq_desc lock */
		struct its_device *its_dev = irq_data_get_irq_chip_data(d);
		cpu = its_dev->event_map.col_map[its_get_event_id(d)];
		/* Keep GCC quiet... */
		*flags = 0;
	}

	return cpu;
}

static void irq_to_cpuid_unlock(struct irq_data *d, unsigned long flags)
{
	struct its_vlpi_map *map = get_vlpi_map(d);

	if (map)
		vpe_to_cpuid_unlock(map->vpe, flags);
}

static struct its_collection *valid_col(struct its_collection *col)
{
	if (WARN_ON_ONCE(col->target_address & GENMASK_ULL(15, 0)))
		return NULL;

	return col;
}

static struct its_vpe *valid_vpe(struct its_node *its, struct its_vpe *vpe)
{
	if (valid_col(its->collections + vpe->col_idx))
		return vpe;

	return NULL;
}

/*
 * ITS command descriptors - parameters to be encoded in a command
 * block.
 */
struct its_cmd_desc {
	union {
		struct {
			struct its_device *dev;
			u32 event_id;
		} its_inv_cmd;

		struct {
			struct its_device *dev;
			u32 event_id;
		} its_clear_cmd;

		struct {
			struct its_device *dev;
			u32 event_id;
		} its_int_cmd;

		struct {
			struct its_device *dev;
			int valid;
		} its_mapd_cmd;

		struct {
			struct its_collection *col;
			int valid;
		} its_mapc_cmd;

		struct {
			struct its_device *dev;
			u32 phys_id;
			u32 event_id;
		} its_mapti_cmd;

		struct {
			struct its_device *dev;
			struct its_collection *col;
			u32 event_id;
		} its_movi_cmd;

		struct {
			struct its_device *dev;
			u32 event_id;
		} its_discard_cmd;

		struct {
			struct its_collection *col;
		} its_invall_cmd;

		struct {
			struct its_vpe *vpe;
		} its_vinvall_cmd;

		struct {
			struct its_vpe *vpe;
			struct its_collection *col;
			bool valid;
		} its_vmapp_cmd;

		struct {
			struct its_vpe *vpe;
			struct its_device *dev;
			u32 virt_id;
			u32 event_id;
			bool db_enabled;
		} its_vmapti_cmd;

		struct {
			struct its_vpe *vpe;
			struct its_device *dev;
			u32 event_id;
			bool db_enabled;
		} its_vmovi_cmd;

		struct {
			struct its_vpe *vpe;
			struct its_collection *col;
			u16 seq_num;
			u16 its_list;
		} its_vmovp_cmd;

		struct {
			struct its_vpe *vpe;
		} its_invdb_cmd;

		struct {
			struct its_vpe *vpe;
			u8 sgi;
			u8 priority;
			bool enable;
			bool group;
			bool clear;
		} its_vsgi_cmd;
	};
};

/*
 * The ITS command block, which is what the ITS actually parses.
 */
struct its_cmd_block {
	union {
		u64	raw_cmd[4];
		__le64	raw_cmd_le[4];
	};
};

#define ITS_CMD_QUEUE_SZ		SZ_64K
#define ITS_CMD_QUEUE_NR_ENTRIES	(ITS_CMD_QUEUE_SZ / sizeof(struct its_cmd_block))

typedef struct its_collection *(*its_cmd_builder_t)(struct its_node *,
						    struct its_cmd_block *,
						    struct its_cmd_desc *);

typedef struct its_vpe *(*its_cmd_vbuilder_t)(struct its_node *,
					      struct its_cmd_block *,
					      struct its_cmd_desc *);

static void its_mask_encode(u64 *raw_cmd, u64 val, int h, int l)
{
	u64 mask = GENMASK_ULL(h, l);
	*raw_cmd &= ~mask;
	*raw_cmd |= (val << l) & mask;
}

static void its_encode_cmd(struct its_cmd_block *cmd, u8 cmd_nr)
{
	its_mask_encode(&cmd->raw_cmd[0], cmd_nr, 7, 0);
}

static void its_encode_devid(struct its_cmd_block *cmd, u32 devid)
{
	its_mask_encode(&cmd->raw_cmd[0], devid, 63, 32);
}

static void its_encode_event_id(struct its_cmd_block *cmd, u32 id)
{
	its_mask_encode(&cmd->raw_cmd[1], id, 31, 0);
}

static void its_encode_phys_id(struct its_cmd_block *cmd, u32 phys_id)
{
	its_mask_encode(&cmd->raw_cmd[1], phys_id, 63, 32);
}

static void its_encode_size(struct its_cmd_block *cmd, u8 size)
{
	its_mask_encode(&cmd->raw_cmd[1], size, 4, 0);
}

static void its_encode_itt(struct its_cmd_block *cmd, u64 itt_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], itt_addr >> 8, 51, 8);
}

static void its_encode_valid(struct its_cmd_block *cmd, int valid)
{
	its_mask_encode(&cmd->raw_cmd[2], !!valid, 63, 63);
}

static void its_encode_target(struct its_cmd_block *cmd, u64 target_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], target_addr >> 16, 51, 16);
}

static void its_encode_collection(struct its_cmd_block *cmd, u16 col)
{
	its_mask_encode(&cmd->raw_cmd[2], col, 15, 0);
}

static void its_encode_vpeid(struct its_cmd_block *cmd, u16 vpeid)
{
	its_mask_encode(&cmd->raw_cmd[1], vpeid, 47, 32);
}

static void its_encode_virt_id(struct its_cmd_block *cmd, u32 virt_id)
{
	its_mask_encode(&cmd->raw_cmd[2], virt_id, 31, 0);
}

static void its_encode_db_phys_id(struct its_cmd_block *cmd, u32 db_phys_id)
{
	its_mask_encode(&cmd->raw_cmd[2], db_phys_id, 63, 32);
}

static void its_encode_db_valid(struct its_cmd_block *cmd, bool db_valid)
{
	its_mask_encode(&cmd->raw_cmd[2], db_valid, 0, 0);
}

static void its_encode_seq_num(struct its_cmd_block *cmd, u16 seq_num)
{
	its_mask_encode(&cmd->raw_cmd[0], seq_num, 47, 32);
}

static void its_encode_its_list(struct its_cmd_block *cmd, u16 its_list)
{
	its_mask_encode(&cmd->raw_cmd[1], its_list, 15, 0);
}

static void its_encode_vpt_addr(struct its_cmd_block *cmd, u64 vpt_pa)
{
	its_mask_encode(&cmd->raw_cmd[3], vpt_pa >> 16, 51, 16);
}

static void its_encode_vpt_size(struct its_cmd_block *cmd, u8 vpt_size)
{
	its_mask_encode(&cmd->raw_cmd[3], vpt_size, 4, 0);
}

static void its_encode_vconf_addr(struct its_cmd_block *cmd, u64 vconf_pa)
{
	its_mask_encode(&cmd->raw_cmd[0], vconf_pa >> 16, 51, 16);
}

static void its_encode_alloc(struct its_cmd_block *cmd, bool alloc)
{
	its_mask_encode(&cmd->raw_cmd[0], alloc, 8, 8);
}

static void its_encode_ptz(struct its_cmd_block *cmd, bool ptz)
{
	its_mask_encode(&cmd->raw_cmd[0], ptz, 9, 9);
}

static void its_encode_vmapp_default_db(struct its_cmd_block *cmd,
					u32 vpe_db_lpi)
{
	its_mask_encode(&cmd->raw_cmd[1], vpe_db_lpi, 31, 0);
}

static void its_encode_vmovp_default_db(struct its_cmd_block *cmd,
					u32 vpe_db_lpi)
{
	its_mask_encode(&cmd->raw_cmd[3], vpe_db_lpi, 31, 0);
}

static void its_encode_db(struct its_cmd_block *cmd, bool db)
{
	its_mask_encode(&cmd->raw_cmd[2], db, 63, 63);
}

static void its_encode_sgi_intid(struct its_cmd_block *cmd, u8 sgi)
{
	its_mask_encode(&cmd->raw_cmd[0], sgi, 35, 32);
}

static void its_encode_sgi_priority(struct its_cmd_block *cmd, u8 prio)
{
	its_mask_encode(&cmd->raw_cmd[0], prio >> 4, 23, 20);
}

static void its_encode_sgi_group(struct its_cmd_block *cmd, bool grp)
{
	its_mask_encode(&cmd->raw_cmd[0], grp, 10, 10);
}

static void its_encode_sgi_clear(struct its_cmd_block *cmd, bool clr)
{
	its_mask_encode(&cmd->raw_cmd[0], clr, 9, 9);
}

static void its_encode_sgi_enable(struct its_cmd_block *cmd, bool en)
{
	its_mask_encode(&cmd->raw_cmd[0], en, 8, 8);
}

static inline void its_fixup_cmd(struct its_cmd_block *cmd)
{
	/* Let's fixup BE commands */
	cmd->raw_cmd_le[0] = cpu_to_le64(cmd->raw_cmd[0]);
	cmd->raw_cmd_le[1] = cpu_to_le64(cmd->raw_cmd[1]);
	cmd->raw_cmd_le[2] = cpu_to_le64(cmd->raw_cmd[2]);
	cmd->raw_cmd_le[3] = cpu_to_le64(cmd->raw_cmd[3]);
}

static struct its_collection *its_build_mapd_cmd(struct its_node *its,
						 struct its_cmd_block *cmd,
						 struct its_cmd_desc *desc)
{
	unsigned long itt_addr;
	u8 size = ilog2(desc->its_mapd_cmd.dev->nr_ites);

	itt_addr = virt_to_phys(desc->its_mapd_cmd.dev->itt);
	itt_addr = ALIGN(itt_addr, ITS_ITT_ALIGN);

	its_encode_cmd(cmd, GITS_CMD_MAPD);
	its_encode_devid(cmd, desc->its_mapd_cmd.dev->device_id);
	its_encode_size(cmd, size - 1);
	its_encode_itt(cmd, itt_addr);
	its_encode_valid(cmd, desc->its_mapd_cmd.valid);

	its_fixup_cmd(cmd);

	return NULL;
}

static struct its_collection *its_build_mapc_cmd(struct its_node *its,
						 struct its_cmd_block *cmd,
						 struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MAPC);
	its_encode_collection(cmd, desc->its_mapc_cmd.col->col_id);
	its_encode_target(cmd, desc->its_mapc_cmd.col->target_address);
	its_encode_valid(cmd, desc->its_mapc_cmd.valid);

	its_fixup_cmd(cmd);

	return desc->its_mapc_cmd.col;
}

static struct its_collection *its_build_mapti_cmd(struct its_node *its,
						  struct its_cmd_block *cmd,
						  struct its_cmd_desc *desc)
{
	struct its_collection *col;

	col = dev_event_to_col(desc->its_mapti_cmd.dev,
			       desc->its_mapti_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_MAPTI);
	its_encode_devid(cmd, desc->its_mapti_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_mapti_cmd.event_id);
	its_encode_phys_id(cmd, desc->its_mapti_cmd.phys_id);
	its_encode_collection(cmd, col->col_id);

	its_fixup_cmd(cmd);

	return valid_col(col);
}

static struct its_collection *its_build_movi_cmd(struct its_node *its,
						 struct its_cmd_block *cmd,
						 struct its_cmd_desc *desc)
{
	struct its_collection *col;

	col = dev_event_to_col(desc->its_movi_cmd.dev,
			       desc->its_movi_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_MOVI);
	its_encode_devid(cmd, desc->its_movi_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_movi_cmd.event_id);
	its_encode_collection(cmd, desc->its_movi_cmd.col->col_id);

	its_fixup_cmd(cmd);

	return valid_col(col);
}

static struct its_collection *its_build_discard_cmd(struct its_node *its,
						    struct its_cmd_block *cmd,
						    struct its_cmd_desc *desc)
{
	struct its_collection *col;

	col = dev_event_to_col(desc->its_discard_cmd.dev,
			       desc->its_discard_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_DISCARD);
	its_encode_devid(cmd, desc->its_discard_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_discard_cmd.event_id);

	its_fixup_cmd(cmd);

	return valid_col(col);
}

static struct its_collection *its_build_inv_cmd(struct its_node *its,
						struct its_cmd_block *cmd,
						struct its_cmd_desc *desc)
{
	struct its_collection *col;

	col = dev_event_to_col(desc->its_inv_cmd.dev,
			       desc->its_inv_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_INV);
	its_encode_devid(cmd, desc->its_inv_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_inv_cmd.event_id);

	its_fixup_cmd(cmd);

	return valid_col(col);
}

static struct its_collection *its_build_int_cmd(struct its_node *its,
						struct its_cmd_block *cmd,
						struct its_cmd_desc *desc)
{
	struct its_collection *col;

	col = dev_event_to_col(desc->its_int_cmd.dev,
			       desc->its_int_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_INT);
	its_encode_devid(cmd, desc->its_int_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_int_cmd.event_id);

	its_fixup_cmd(cmd);

	return valid_col(col);
}

static struct its_collection *its_build_clear_cmd(struct its_node *its,
						  struct its_cmd_block *cmd,
						  struct its_cmd_desc *desc)
{
	struct its_collection *col;

	col = dev_event_to_col(desc->its_clear_cmd.dev,
			       desc->its_clear_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_CLEAR);
	its_encode_devid(cmd, desc->its_clear_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_clear_cmd.event_id);

	its_fixup_cmd(cmd);

	return valid_col(col);
}

static struct its_collection *its_build_invall_cmd(struct its_node *its,
						   struct its_cmd_block *cmd,
						   struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_INVALL);
	its_encode_collection(cmd, desc->its_invall_cmd.col->col_id);

	its_fixup_cmd(cmd);

	return NULL;
}

static struct its_vpe *its_build_vinvall_cmd(struct its_node *its,
					     struct its_cmd_block *cmd,
					     struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_VINVALL);
	its_encode_vpeid(cmd, desc->its_vinvall_cmd.vpe->vpe_id);

	its_fixup_cmd(cmd);

	return valid_vpe(its, desc->its_vinvall_cmd.vpe);
}

static struct its_vpe *its_build_vmapp_cmd(struct its_node *its,
					   struct its_cmd_block *cmd,
					   struct its_cmd_desc *desc)
{
	unsigned long vpt_addr, vconf_addr;
	u64 target;
	bool alloc;

	its_encode_cmd(cmd, GITS_CMD_VMAPP);
	its_encode_vpeid(cmd, desc->its_vmapp_cmd.vpe->vpe_id);
	its_encode_valid(cmd, desc->its_vmapp_cmd.valid);

	if (!desc->its_vmapp_cmd.valid) {
		if (is_v4_1(its)) {
			alloc = !atomic_dec_return(&desc->its_vmapp_cmd.vpe->vmapp_count);
			its_encode_alloc(cmd, alloc);
		}

		goto out;
	}

	vpt_addr = virt_to_phys(page_address(desc->its_vmapp_cmd.vpe->vpt_page));
	target = desc->its_vmapp_cmd.col->target_address + its->vlpi_redist_offset;

	its_encode_target(cmd, target);
	its_encode_vpt_addr(cmd, vpt_addr);
	its_encode_vpt_size(cmd, LPI_NRBITS - 1);

	if (!is_v4_1(its))
		goto out;

	vconf_addr = virt_to_phys(page_address(desc->its_vmapp_cmd.vpe->its_vm->vprop_page));

	alloc = !atomic_fetch_inc(&desc->its_vmapp_cmd.vpe->vmapp_count);

	its_encode_alloc(cmd, alloc);

	/* We can only signal PTZ when alloc==1. Why do we have two bits? */
	its_encode_ptz(cmd, alloc);
	its_encode_vconf_addr(cmd, vconf_addr);
	its_encode_vmapp_default_db(cmd, desc->its_vmapp_cmd.vpe->vpe_db_lpi);

out:
	its_fixup_cmd(cmd);

	return valid_vpe(its, desc->its_vmapp_cmd.vpe);
}

static struct its_vpe *its_build_vmapti_cmd(struct its_node *its,
					    struct its_cmd_block *cmd,
					    struct its_cmd_desc *desc)
{
	u32 db;

	if (!is_v4_1(its) && desc->its_vmapti_cmd.db_enabled)
		db = desc->its_vmapti_cmd.vpe->vpe_db_lpi;
	else
		db = 1023;

	its_encode_cmd(cmd, GITS_CMD_VMAPTI);
	its_encode_devid(cmd, desc->its_vmapti_cmd.dev->device_id);
	its_encode_vpeid(cmd, desc->its_vmapti_cmd.vpe->vpe_id);
	its_encode_event_id(cmd, desc->its_vmapti_cmd.event_id);
	its_encode_db_phys_id(cmd, db);
	its_encode_virt_id(cmd, desc->its_vmapti_cmd.virt_id);

	its_fixup_cmd(cmd);

	return valid_vpe(its, desc->its_vmapti_cmd.vpe);
}

static struct its_vpe *its_build_vmovi_cmd(struct its_node *its,
					   struct its_cmd_block *cmd,
					   struct its_cmd_desc *desc)
{
	u32 db;

	if (!is_v4_1(its) && desc->its_vmovi_cmd.db_enabled)
		db = desc->its_vmovi_cmd.vpe->vpe_db_lpi;
	else
		db = 1023;

	its_encode_cmd(cmd, GITS_CMD_VMOVI);
	its_encode_devid(cmd, desc->its_vmovi_cmd.dev->device_id);
	its_encode_vpeid(cmd, desc->its_vmovi_cmd.vpe->vpe_id);
	its_encode_event_id(cmd, desc->its_vmovi_cmd.event_id);
	its_encode_db_phys_id(cmd, db);
	its_encode_db_valid(cmd, true);

	its_fixup_cmd(cmd);

	return valid_vpe(its, desc->its_vmovi_cmd.vpe);
}

static struct its_vpe *its_build_vmovp_cmd(struct its_node *its,
					   struct its_cmd_block *cmd,
					   struct its_cmd_desc *desc)
{
	u64 target;

	target = desc->its_vmovp_cmd.col->target_address + its->vlpi_redist_offset;
	its_encode_cmd(cmd, GITS_CMD_VMOVP);
	its_encode_seq_num(cmd, desc->its_vmovp_cmd.seq_num);
	its_encode_its_list(cmd, desc->its_vmovp_cmd.its_list);
	its_encode_vpeid(cmd, desc->its_vmovp_cmd.vpe->vpe_id);
	its_encode_target(cmd, target);

	if (is_v4_1(its)) {
		its_encode_db(cmd, true);
		its_encode_vmovp_default_db(cmd, desc->its_vmovp_cmd.vpe->vpe_db_lpi);
	}

	its_fixup_cmd(cmd);

	return valid_vpe(its, desc->its_vmovp_cmd.vpe);
}

static struct its_vpe *its_build_vinv_cmd(struct its_node *its,
					  struct its_cmd_block *cmd,
					  struct its_cmd_desc *desc)
{
	struct its_vlpi_map *map;

	map = dev_event_to_vlpi_map(desc->its_inv_cmd.dev,
				    desc->its_inv_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_INV);
	its_encode_devid(cmd, desc->its_inv_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_inv_cmd.event_id);

	its_fixup_cmd(cmd);

	return valid_vpe(its, map->vpe);
}

static struct its_vpe *its_build_vint_cmd(struct its_node *its,
					  struct its_cmd_block *cmd,
					  struct its_cmd_desc *desc)
{
	struct its_vlpi_map *map;

	map = dev_event_to_vlpi_map(desc->its_int_cmd.dev,
				    desc->its_int_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_INT);
	its_encode_devid(cmd, desc->its_int_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_int_cmd.event_id);

	its_fixup_cmd(cmd);

	return valid_vpe(its, map->vpe);
}

static struct its_vpe *its_build_vclear_cmd(struct its_node *its,
					    struct its_cmd_block *cmd,
					    struct its_cmd_desc *desc)
{
	struct its_vlpi_map *map;

	map = dev_event_to_vlpi_map(desc->its_clear_cmd.dev,
				    desc->its_clear_cmd.event_id);

	its_encode_cmd(cmd, GITS_CMD_CLEAR);
	its_encode_devid(cmd, desc->its_clear_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_clear_cmd.event_id);

	its_fixup_cmd(cmd);

	return valid_vpe(its, map->vpe);
}

static struct its_vpe *its_build_invdb_cmd(struct its_node *its,
					   struct its_cmd_block *cmd,
					   struct its_cmd_desc *desc)
{
	if (WARN_ON(!is_v4_1(its)))
		return NULL;

	its_encode_cmd(cmd, GITS_CMD_INVDB);
	its_encode_vpeid(cmd, desc->its_invdb_cmd.vpe->vpe_id);

	its_fixup_cmd(cmd);

	return valid_vpe(its, desc->its_invdb_cmd.vpe);
}

static struct its_vpe *its_build_vsgi_cmd(struct its_node *its,
					  struct its_cmd_block *cmd,
					  struct its_cmd_desc *desc)
{
	if (WARN_ON(!is_v4_1(its)))
		return NULL;

	its_encode_cmd(cmd, GITS_CMD_VSGI);
	its_encode_vpeid(cmd, desc->its_vsgi_cmd.vpe->vpe_id);
	its_encode_sgi_intid(cmd, desc->its_vsgi_cmd.sgi);
	its_encode_sgi_priority(cmd, desc->its_vsgi_cmd.priority);
	its_encode_sgi_group(cmd, desc->its_vsgi_cmd.group);
	its_encode_sgi_clear(cmd, desc->its_vsgi_cmd.clear);
	its_encode_sgi_enable(cmd, desc->its_vsgi_cmd.enable);

	its_fixup_cmd(cmd);

	return valid_vpe(its, desc->its_vsgi_cmd.vpe);
}

static u64 its_cmd_ptr_to_offset(struct its_node *its,
				 struct its_cmd_block *ptr)
{
	return (ptr - its->cmd_base) * sizeof(*ptr);
}

static int its_queue_full(struct its_node *its)
{
	int widx;
	int ridx;

	widx = its->cmd_write - its->cmd_base;
	ridx = readl_relaxed(its->base + GITS_CREADR) / sizeof(struct its_cmd_block);

	/* This is incredibly unlikely to happen, unless the ITS locks up. */
	if (((widx + 1) % ITS_CMD_QUEUE_NR_ENTRIES) == ridx)
		return 1;

	return 0;
}

static struct its_cmd_block *its_allocate_entry(struct its_node *its)
{
	struct its_cmd_block *cmd;
	u32 count = 1000000;	/* 1s! */

	while (its_queue_full(its)) {
		count--;
		if (!count) {
			pr_err_ratelimited("ITS queue not draining\n");
			return NULL;
		}
		cpu_relax();
		udelay(1);
	}

	cmd = its->cmd_write++;

	/* Handle queue wrapping */
	if (its->cmd_write == (its->cmd_base + ITS_CMD_QUEUE_NR_ENTRIES))
		its->cmd_write = its->cmd_base;

	/* Clear command  */
	cmd->raw_cmd[0] = 0;
	cmd->raw_cmd[1] = 0;
	cmd->raw_cmd[2] = 0;
	cmd->raw_cmd[3] = 0;

	return cmd;
}

static struct its_cmd_block *its_post_commands(struct its_node *its)
{
	u64 wr = its_cmd_ptr_to_offset(its, its->cmd_write);

	writel_relaxed(wr, its->base + GITS_CWRITER);

	return its->cmd_write;
}

static void its_flush_cmd(struct its_node *its, struct its_cmd_block *cmd)
{
	/*
	 * Make sure the commands written to memory are observable by
	 * the ITS.
	 */
	if (its->flags & ITS_FLAGS_CMDQ_NEEDS_FLUSHING)
		gic_flush_dcache_to_poc(cmd, sizeof(*cmd));
	else
		dsb(ishst);
}

static int its_wait_for_range_completion(struct its_node *its,
					 u64	prev_idx,
					 struct its_cmd_block *to)
{
	u64 rd_idx, to_idx, linear_idx;
	u32 count = 1000000;	/* 1s! */

	/* Linearize to_idx if the command set has wrapped around */
	to_idx = its_cmd_ptr_to_offset(its, to);
	if (to_idx < prev_idx)
		to_idx += ITS_CMD_QUEUE_SZ;

	linear_idx = prev_idx;

	while (1) {
		s64 delta;

		rd_idx = readl_relaxed(its->base + GITS_CREADR);

		/*
		 * Compute the read pointer progress, taking the
		 * potential wrap-around into account.
		 */
		delta = rd_idx - prev_idx;
		if (rd_idx < prev_idx)
			delta += ITS_CMD_QUEUE_SZ;

		linear_idx += delta;
		if (linear_idx >= to_idx)
			break;

		count--;
		if (!count) {
			pr_err_ratelimited("ITS queue timeout (%llu %llu)\n",
					   to_idx, linear_idx);
			return -1;
		}
		prev_idx = rd_idx;
		cpu_relax();
		udelay(1);
	}

	return 0;
}

/* Warning, macro hell follows */
#define BUILD_SINGLE_CMD_FUNC(name, buildtype, synctype, buildfn)	\
void name(struct its_node *its,						\
	  buildtype builder,						\
	  struct its_cmd_desc *desc)					\
{									\
	struct its_cmd_block *cmd, *sync_cmd, *next_cmd;		\
	synctype *sync_obj;						\
	unsigned long flags;						\
	u64 rd_idx;							\
									\
	raw_spin_lock_irqsave(&its->lock, flags);			\
									\
	cmd = its_allocate_entry(its);					\
	if (!cmd) {		/* We're soooooo screewed... */		\
		raw_spin_unlock_irqrestore(&its->lock, flags);		\
		return;							\
	}								\
	sync_obj = builder(its, cmd, desc);				\
	its_flush_cmd(its, cmd);					\
									\
	if (sync_obj) {							\
		sync_cmd = its_allocate_entry(its);			\
		if (!sync_cmd)						\
			goto post;					\
									\
		buildfn(its, sync_cmd, sync_obj);			\
		its_flush_cmd(its, sync_cmd);				\
	}								\
									\
post:									\
	rd_idx = readl_relaxed(its->base + GITS_CREADR);		\
	next_cmd = its_post_commands(its);				\
	raw_spin_unlock_irqrestore(&its->lock, flags);			\
									\
	if (its_wait_for_range_completion(its, rd_idx, next_cmd))	\
		pr_err_ratelimited("ITS cmd %ps failed\n", builder);	\
}

static void its_build_sync_cmd(struct its_node *its,
			       struct its_cmd_block *sync_cmd,
			       struct its_collection *sync_col)
{
	its_encode_cmd(sync_cmd, GITS_CMD_SYNC);
	its_encode_target(sync_cmd, sync_col->target_address);

	its_fixup_cmd(sync_cmd);
}

static BUILD_SINGLE_CMD_FUNC(its_send_single_command, its_cmd_builder_t,
			     struct its_collection, its_build_sync_cmd)

static void its_build_vsync_cmd(struct its_node *its,
				struct its_cmd_block *sync_cmd,
				struct its_vpe *sync_vpe)
{
	its_encode_cmd(sync_cmd, GITS_CMD_VSYNC);
	its_encode_vpeid(sync_cmd, sync_vpe->vpe_id);

	its_fixup_cmd(sync_cmd);
}

static BUILD_SINGLE_CMD_FUNC(its_send_single_vcommand, its_cmd_vbuilder_t,
			     struct its_vpe, its_build_vsync_cmd)

static void its_send_int(struct its_device *dev, u32 event_id)
{
	struct its_cmd_desc desc;

	desc.its_int_cmd.dev = dev;
	desc.its_int_cmd.event_id = event_id;

	its_send_single_command(dev->its, its_build_int_cmd, &desc);
}

static void its_send_clear(struct its_device *dev, u32 event_id)
{
	struct its_cmd_desc desc;

	desc.its_clear_cmd.dev = dev;
	desc.its_clear_cmd.event_id = event_id;

	its_send_single_command(dev->its, its_build_clear_cmd, &desc);
}

static void its_send_inv(struct its_device *dev, u32 event_id)
{
	struct its_cmd_desc desc;

	desc.its_inv_cmd.dev = dev;
	desc.its_inv_cmd.event_id = event_id;

	its_send_single_command(dev->its, its_build_inv_cmd, &desc);
}

static void its_send_mapd(struct its_device *dev, int valid)
{
	struct its_cmd_desc desc;

	desc.its_mapd_cmd.dev = dev;
	desc.its_mapd_cmd.valid = !!valid;

	its_send_single_command(dev->its, its_build_mapd_cmd, &desc);
}

static void its_send_mapc(struct its_node *its, struct its_collection *col,
			  int valid)
{
	struct its_cmd_desc desc;

	desc.its_mapc_cmd.col = col;
	desc.its_mapc_cmd.valid = !!valid;

	its_send_single_command(its, its_build_mapc_cmd, &desc);
}

static void its_send_mapti(struct its_device *dev, u32 irq_id, u32 id)
{
	struct its_cmd_desc desc;

	desc.its_mapti_cmd.dev = dev;
	desc.its_mapti_cmd.phys_id = irq_id;
	desc.its_mapti_cmd.event_id = id;

	its_send_single_command(dev->its, its_build_mapti_cmd, &desc);
}

static void its_send_movi(struct its_device *dev,
			  struct its_collection *col, u32 id)
{
	struct its_cmd_desc desc;

	desc.its_movi_cmd.dev = dev;
	desc.its_movi_cmd.col = col;
	desc.its_movi_cmd.event_id = id;

	its_send_single_command(dev->its, its_build_movi_cmd, &desc);
}

static void its_send_discard(struct its_device *dev, u32 id)
{
	struct its_cmd_desc desc;

	desc.its_discard_cmd.dev = dev;
	desc.its_discard_cmd.event_id = id;

	its_send_single_command(dev->its, its_build_discard_cmd, &desc);
}

static void its_send_invall(struct its_node *its, struct its_collection *col)
{
	struct its_cmd_desc desc;

	desc.its_invall_cmd.col = col;

	its_send_single_command(its, its_build_invall_cmd, &desc);
}

static void its_send_vmapti(struct its_device *dev, u32 id)
{
	struct its_vlpi_map *map = dev_event_to_vlpi_map(dev, id);
	struct its_cmd_desc desc;

	desc.its_vmapti_cmd.vpe = map->vpe;
	desc.its_vmapti_cmd.dev = dev;
	desc.its_vmapti_cmd.virt_id = map->vintid;
	desc.its_vmapti_cmd.event_id = id;
	desc.its_vmapti_cmd.db_enabled = map->db_enabled;

	its_send_single_vcommand(dev->its, its_build_vmapti_cmd, &desc);
}

static void its_send_vmovi(struct its_device *dev, u32 id)
{
	struct its_vlpi_map *map = dev_event_to_vlpi_map(dev, id);
	struct its_cmd_desc desc;

	desc.its_vmovi_cmd.vpe = map->vpe;
	desc.its_vmovi_cmd.dev = dev;
	desc.its_vmovi_cmd.event_id = id;
	desc.its_vmovi_cmd.db_enabled = map->db_enabled;

	its_send_single_vcommand(dev->its, its_build_vmovi_cmd, &desc);
}

static void its_send_vmapp(struct its_node *its,
			   struct its_vpe *vpe, bool valid)
{
	struct its_cmd_desc desc;

	desc.its_vmapp_cmd.vpe = vpe;
	desc.its_vmapp_cmd.valid = valid;
	desc.its_vmapp_cmd.col = &its->collections[vpe->col_idx];

	its_send_single_vcommand(its, its_build_vmapp_cmd, &desc);
}

static void its_send_vmovp(struct its_vpe *vpe)
{
	struct its_cmd_desc desc = {};
	struct its_node *its;
	unsigned long flags;
	int col_id = vpe->col_idx;

	desc.its_vmovp_cmd.vpe = vpe;

	if (!its_list_map) {
		its = list_first_entry(&its_nodes, struct its_node, entry);
		desc.its_vmovp_cmd.col = &its->collections[col_id];
		its_send_single_vcommand(its, its_build_vmovp_cmd, &desc);
		return;
	}

	/*
	 * Yet another marvel of the architecture. If using the
	 * its_list "feature", we need to make sure that all ITSs
	 * receive all VMOVP commands in the same order. The only way
	 * to guarantee this is to make vmovp a serialization point.
	 *
	 * Wall <-- Head.
	 */
	raw_spin_lock_irqsave(&vmovp_lock, flags);

	desc.its_vmovp_cmd.seq_num = vmovp_seq_num++;
	desc.its_vmovp_cmd.its_list = get_its_list(vpe->its_vm);

	/* Emit VMOVPs */
	list_for_each_entry(its, &its_nodes, entry) {
		if (!is_v4(its))
			continue;

		if (!require_its_list_vmovp(vpe->its_vm, its))
			continue;

		desc.its_vmovp_cmd.col = &its->collections[col_id];
		its_send_single_vcommand(its, its_build_vmovp_cmd, &desc);
	}

	raw_spin_unlock_irqrestore(&vmovp_lock, flags);
}

static void its_send_vinvall(struct its_node *its, struct its_vpe *vpe)
{
	struct its_cmd_desc desc;

	desc.its_vinvall_cmd.vpe = vpe;
	its_send_single_vcommand(its, its_build_vinvall_cmd, &desc);
}

static void its_send_vinv(struct its_device *dev, u32 event_id)
{
	struct its_cmd_desc desc;

	/*
	 * There is no real VINV command. This is just a normal INV,
	 * with a VSYNC instead of a SYNC.
	 */
	desc.its_inv_cmd.dev = dev;
	desc.its_inv_cmd.event_id = event_id;

	its_send_single_vcommand(dev->its, its_build_vinv_cmd, &desc);
}

static void its_send_vint(struct its_device *dev, u32 event_id)
{
	struct its_cmd_desc desc;

	/*
	 * There is no real VINT command. This is just a normal INT,
	 * with a VSYNC instead of a SYNC.
	 */
	desc.its_int_cmd.dev = dev;
	desc.its_int_cmd.event_id = event_id;

	its_send_single_vcommand(dev->its, its_build_vint_cmd, &desc);
}

static void its_send_vclear(struct its_device *dev, u32 event_id)
{
	struct its_cmd_desc desc;

	/*
	 * There is no real VCLEAR command. This is just a normal CLEAR,
	 * with a VSYNC instead of a SYNC.
	 */
	desc.its_clear_cmd.dev = dev;
	desc.its_clear_cmd.event_id = event_id;

	its_send_single_vcommand(dev->its, its_build_vclear_cmd, &desc);
}

static void its_send_invdb(struct its_node *its, struct its_vpe *vpe)
{
	struct its_cmd_desc desc;

	desc.its_invdb_cmd.vpe = vpe;
	its_send_single_vcommand(its, its_build_invdb_cmd, &desc);
}

/*
 * irqchip functions - assumes MSI, mostly.
 */
static void lpi_write_config(struct irq_data *d, u8 clr, u8 set)
{
	struct its_vlpi_map *map = get_vlpi_map(d);
	irq_hw_number_t hwirq;
	void *va;
	u8 *cfg;

	if (map) {
		va = page_address(map->vm->vprop_page);
		hwirq = map->vintid;

		/* Remember the updated property */
		map->properties &= ~clr;
		map->properties |= set | LPI_PROP_GROUP1;
	} else {
		va = gic_rdists->prop_table_va;
		hwirq = d->hwirq;
	}

	cfg = va + hwirq - 8192;
	*cfg &= ~clr;
	*cfg |= set | LPI_PROP_GROUP1;

	/*
	 * Make the above write visible to the redistributors.
	 * And yes, we're flushing exactly: One. Single. Byte.
	 * Humpf...
	 */
	if (gic_rdists->flags & RDIST_FLAGS_PROPBASE_NEEDS_FLUSHING)
		gic_flush_dcache_to_poc(cfg, sizeof(*cfg));
	else
		dsb(ishst);
}

static void wait_for_syncr(void __iomem *rdbase)
{
	while (readl_relaxed(rdbase + GICR_SYNCR) & 1)
		cpu_relax();
}

static void direct_lpi_inv(struct irq_data *d)
{
	struct its_vlpi_map *map = get_vlpi_map(d);
	void __iomem *rdbase;
	unsigned long flags;
	u64 val;
	int cpu;

	if (map) {
		struct its_device *its_dev = irq_data_get_irq_chip_data(d);

		WARN_ON(!is_v4_1(its_dev->its));

		val  = GICR_INVLPIR_V;
		val |= FIELD_PREP(GICR_INVLPIR_VPEID, map->vpe->vpe_id);
		val |= FIELD_PREP(GICR_INVLPIR_INTID, map->vintid);
	} else {
		val = d->hwirq;
	}

	/* Target the redistributor this LPI is currently routed to */
	cpu = irq_to_cpuid_lock(d, &flags);
	raw_spin_lock(&gic_data_rdist_cpu(cpu)->rd_lock);
	rdbase = per_cpu_ptr(gic_rdists->rdist, cpu)->rd_base;
	gic_write_lpir(val, rdbase + GICR_INVLPIR);

	wait_for_syncr(rdbase);
	raw_spin_unlock(&gic_data_rdist_cpu(cpu)->rd_lock);
	irq_to_cpuid_unlock(d, flags);
}

static void lpi_update_config(struct irq_data *d, u8 clr, u8 set)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);

	lpi_write_config(d, clr, set);
	if (gic_rdists->has_direct_lpi &&
	    (is_v4_1(its_dev->its) || !irqd_is_forwarded_to_vcpu(d)))
		direct_lpi_inv(d);
	else if (!irqd_is_forwarded_to_vcpu(d))
		its_send_inv(its_dev, its_get_event_id(d));
	else
		its_send_vinv(its_dev, its_get_event_id(d));
}

static void its_vlpi_set_doorbell(struct irq_data *d, bool enable)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	u32 event = its_get_event_id(d);
	struct its_vlpi_map *map;

	/*
	 * GICv4.1 does away with the per-LPI nonsense, nothing to do
	 * here.
	 */
	if (is_v4_1(its_dev->its))
		return;

	map = dev_event_to_vlpi_map(its_dev, event);

	if (map->db_enabled == enable)
		return;

	map->db_enabled = enable;

	/*
	 * More fun with the architecture:
	 *
	 * Ideally, we'd issue a VMAPTI to set the doorbell to its LPI
	 * value or to 1023, depending on the enable bit. But that
	 * would be issueing a mapping for an /existing/ DevID+EventID
	 * pair, which is UNPREDICTABLE. Instead, let's issue a VMOVI
	 * to the /same/ vPE, using this opportunity to adjust the
	 * doorbell. Mouahahahaha. We loves it, Precious.
	 */
	its_send_vmovi(its_dev, event);
}

static void its_mask_irq(struct irq_data *d)
{
	if (irqd_is_forwarded_to_vcpu(d))
		its_vlpi_set_doorbell(d, false);

	lpi_update_config(d, LPI_PROP_ENABLED, 0);
}

static void its_unmask_irq(struct irq_data *d)
{
	if (irqd_is_forwarded_to_vcpu(d))
		its_vlpi_set_doorbell(d, true);

	lpi_update_config(d, 0, LPI_PROP_ENABLED);
}

static __maybe_unused u32 its_read_lpi_count(struct irq_data *d, int cpu)
{
	if (irqd_affinity_is_managed(d))
		return atomic_read(&per_cpu_ptr(&cpu_lpi_count, cpu)->managed);

	return atomic_read(&per_cpu_ptr(&cpu_lpi_count, cpu)->unmanaged);
}

static void its_inc_lpi_count(struct irq_data *d, int cpu)
{
	if (irqd_affinity_is_managed(d))
		atomic_inc(&per_cpu_ptr(&cpu_lpi_count, cpu)->managed);
	else
		atomic_inc(&per_cpu_ptr(&cpu_lpi_count, cpu)->unmanaged);
}

static void its_dec_lpi_count(struct irq_data *d, int cpu)
{
	if (irqd_affinity_is_managed(d))
		atomic_dec(&per_cpu_ptr(&cpu_lpi_count, cpu)->managed);
	else
		atomic_dec(&per_cpu_ptr(&cpu_lpi_count, cpu)->unmanaged);
}

static unsigned int cpumask_pick_least_loaded(struct irq_data *d,
					      const struct cpumask *cpu_mask)
{
	unsigned int cpu = nr_cpu_ids, tmp;
	int count = S32_MAX;

	for_each_cpu(tmp, cpu_mask) {
		int this_count = its_read_lpi_count(d, tmp);
		if (this_count < count) {
			cpu = tmp;
		        count = this_count;
		}
	}

	return cpu;
}

/*
 * As suggested by Thomas Gleixner in:
 * https://lore.kernel.org/r/87h80q2aoc.fsf@nanos.tec.linutronix.de
 */
static int its_select_cpu(struct irq_data *d,
			  const struct cpumask *aff_mask)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	cpumask_var_t tmpmask;
	int cpu, node;

	if (!alloc_cpumask_var(&tmpmask, GFP_ATOMIC))
		return -ENOMEM;

	node = its_dev->its->numa_node;

	if (!irqd_affinity_is_managed(d)) {
		/* First try the NUMA node */
		if (node != NUMA_NO_NODE) {
			/*
			 * Try the intersection of the affinity mask and the
			 * node mask (and the online mask, just to be safe).
			 */
			cpumask_and(tmpmask, cpumask_of_node(node), aff_mask);
			cpumask_and(tmpmask, tmpmask, cpu_online_mask);

			/*
			 * Ideally, we would check if the mask is empty, and
			 * try again on the full node here.
			 *
			 * But it turns out that the way ACPI describes the
			 * affinity for ITSs only deals about memory, and
			 * not target CPUs, so it cannot describe a single
			 * ITS placed next to two NUMA nodes.
			 *
			 * Instead, just fallback on the online mask. This
			 * diverges from Thomas' suggestion above.
			 */
			cpu = cpumask_pick_least_loaded(d, tmpmask);
			if (cpu < nr_cpu_ids)
				goto out;

			/* If we can't cross sockets, give up */
			if ((its_dev->its->flags & ITS_FLAGS_WORKAROUND_CAVIUM_23144))
				goto out;

			/* If the above failed, expand the search */
		}

		/* Try the intersection of the affinity and online masks */
		cpumask_and(tmpmask, aff_mask, cpu_online_mask);

		/* If that doesn't fly, the online mask is the last resort */
		if (cpumask_empty(tmpmask))
			cpumask_copy(tmpmask, cpu_online_mask);

		cpu = cpumask_pick_least_loaded(d, tmpmask);
	} else {
		cpumask_and(tmpmask, irq_data_get_affinity_mask(d), cpu_online_mask);

		/* If we cannot cross sockets, limit the search to that node */
		if ((its_dev->its->flags & ITS_FLAGS_WORKAROUND_CAVIUM_23144) &&
		    node != NUMA_NO_NODE)
			cpumask_and(tmpmask, tmpmask, cpumask_of_node(node));

		cpu = cpumask_pick_least_loaded(d, tmpmask);
	}
out:
	free_cpumask_var(tmpmask);

	pr_debug("IRQ%d -> %*pbl CPU%d\n", d->irq, cpumask_pr_args(aff_mask), cpu);
	return cpu;
}

static int its_set_affinity(struct irq_data *d, const struct cpumask *mask_val,
			    bool force)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	struct its_collection *target_col;
	u32 id = its_get_event_id(d);
	int cpu, prev_cpu;

	/* A forwarded interrupt should use irq_set_vcpu_affinity */
	if (irqd_is_forwarded_to_vcpu(d))
		return -EINVAL;

	prev_cpu = its_dev->event_map.col_map[id];
	its_dec_lpi_count(d, prev_cpu);

	if (!force)
		cpu = its_select_cpu(d, mask_val);
	else
		cpu = cpumask_pick_least_loaded(d, mask_val);

	if (cpu < 0 || cpu >= nr_cpu_ids)
		goto err;

	/* don't set the affinity when the target cpu is same as current one */
	if (cpu != prev_cpu) {
		target_col = &its_dev->its->collections[cpu];
		its_send_movi(its_dev, target_col, id);
		its_dev->event_map.col_map[id] = cpu;
		irq_data_update_effective_affinity(d, cpumask_of(cpu));
	}

	its_inc_lpi_count(d, cpu);

	return IRQ_SET_MASK_OK_DONE;

err:
	its_inc_lpi_count(d, prev_cpu);
	return -EINVAL;
}

static u64 its_irq_get_msi_base(struct its_device *its_dev)
{
	struct its_node *its = its_dev->its;

	return its->phys_base + GITS_TRANSLATER;
}

static void its_irq_compose_msi_msg(struct irq_data *d, struct msi_msg *msg)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	struct its_node *its;
	u64 addr;

	its = its_dev->its;
	addr = its->get_msi_base(its_dev);

	msg->address_lo		= lower_32_bits(addr);
	msg->address_hi		= upper_32_bits(addr);
	msg->data		= its_get_event_id(d);

	iommu_dma_compose_msi_msg(irq_data_get_msi_desc(d), msg);
}

static int its_irq_set_irqchip_state(struct irq_data *d,
				     enum irqchip_irq_state which,
				     bool state)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	u32 event = its_get_event_id(d);

	if (which != IRQCHIP_STATE_PENDING)
		return -EINVAL;

	if (irqd_is_forwarded_to_vcpu(d)) {
		if (state)
			its_send_vint(its_dev, event);
		else
			its_send_vclear(its_dev, event);
	} else {
		if (state)
			its_send_int(its_dev, event);
		else
			its_send_clear(its_dev, event);
	}

	return 0;
}

static int its_irq_retrigger(struct irq_data *d)
{
	return !its_irq_set_irqchip_state(d, IRQCHIP_STATE_PENDING, true);
}

/*
 * Two favourable cases:
 *
 * (a) Either we have a GICv4.1, and all vPEs have to be mapped at all times
 *     for vSGI delivery
 *
 * (b) Or the ITSs do not use a list map, meaning that VMOVP is cheap enough
 *     and we're better off mapping all VPEs always
 *
 * If neither (a) nor (b) is true, then we map vPEs on demand.
 *
 */
static bool gic_requires_eager_mapping(void)
{
	if (!its_list_map || gic_rdists->has_rvpeid)
		return true;

	return false;
}

static void its_map_vm(struct its_node *its, struct its_vm *vm)
{
	unsigned long flags;

	if (gic_requires_eager_mapping())
		return;

	raw_spin_lock_irqsave(&vmovp_lock, flags);

	/*
	 * If the VM wasn't mapped yet, iterate over the vpes and get
	 * them mapped now.
	 */
	vm->vlpi_count[its->list_nr]++;

	if (vm->vlpi_count[its->list_nr] == 1) {
		int i;

		for (i = 0; i < vm->nr_vpes; i++) {
			struct its_vpe *vpe = vm->vpes[i];
			struct irq_data *d = irq_get_irq_data(vpe->irq);

			/* Map the VPE to the first possible CPU */
			vpe->col_idx = cpumask_first(cpu_online_mask);
			its_send_vmapp(its, vpe, true);
			its_send_vinvall(its, vpe);
			irq_data_update_effective_affinity(d, cpumask_of(vpe->col_idx));
		}
	}

	raw_spin_unlock_irqrestore(&vmovp_lock, flags);
}

static void its_unmap_vm(struct its_node *its, struct its_vm *vm)
{
	unsigned long flags;

	/* Not using the ITS list? Everything is always mapped. */
	if (gic_requires_eager_mapping())
		return;

	raw_spin_lock_irqsave(&vmovp_lock, flags);

	if (!--vm->vlpi_count[its->list_nr]) {
		int i;

		for (i = 0; i < vm->nr_vpes; i++)
			its_send_vmapp(its, vm->vpes[i], false);
	}

	raw_spin_unlock_irqrestore(&vmovp_lock, flags);
}

static int its_vlpi_map(struct irq_data *d, struct its_cmd_info *info)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	u32 event = its_get_event_id(d);
	int ret = 0;

	if (!info->map)
		return -EINVAL;

	raw_spin_lock(&its_dev->event_map.vlpi_lock);

	if (!its_dev->event_map.vm) {
		struct its_vlpi_map *maps;

		maps = kcalloc(its_dev->event_map.nr_lpis, sizeof(*maps),
			       GFP_ATOMIC);
		if (!maps) {
			ret = -ENOMEM;
			goto out;
		}

		its_dev->event_map.vm = info->map->vm;
		its_dev->event_map.vlpi_maps = maps;
	} else if (its_dev->event_map.vm != info->map->vm) {
		ret = -EINVAL;
		goto out;
	}

	/* Get our private copy of the mapping information */
	its_dev->event_map.vlpi_maps[event] = *info->map;

	if (irqd_is_forwarded_to_vcpu(d)) {
		/* Already mapped, move it around */
		its_send_vmovi(its_dev, event);
	} else {
		/* Ensure all the VPEs are mapped on this ITS */
		its_map_vm(its_dev->its, info->map->vm);

		/*
		 * Flag the interrupt as forwarded so that we can
		 * start poking the virtual property table.
		 */
		irqd_set_forwarded_to_vcpu(d);

		/* Write out the property to the prop table */
		lpi_write_config(d, 0xff, info->map->properties);

		/* Drop the physical mapping */
		its_send_discard(its_dev, event);

		/* and install the virtual one */
		its_send_vmapti(its_dev, event);

		/* Increment the number of VLPIs */
		its_dev->event_map.nr_vlpis++;
	}

out:
	raw_spin_unlock(&its_dev->event_map.vlpi_lock);
	return ret;
}

static int its_vlpi_get(struct irq_data *d, struct its_cmd_info *info)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	struct its_vlpi_map *map;
	int ret = 0;

	raw_spin_lock(&its_dev->event_map.vlpi_lock);

	map = get_vlpi_map(d);

	if (!its_dev->event_map.vm || !map) {
		ret = -EINVAL;
		goto out;
	}

	/* Copy our mapping information to the incoming request */
	*info->map = *map;

out:
	raw_spin_unlock(&its_dev->event_map.vlpi_lock);
	return ret;
}

static int its_vlpi_unmap(struct irq_data *d)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	u32 event = its_get_event_id(d);
	int ret = 0;

	raw_spin_lock(&its_dev->event_map.vlpi_lock);

	if (!its_dev->event_map.vm || !irqd_is_forwarded_to_vcpu(d)) {
		ret = -EINVAL;
		goto out;
	}

	/* Drop the virtual mapping */
	its_send_discard(its_dev, event);

	/* and restore the physical one */
	irqd_clr_forwarded_to_vcpu(d);
	its_send_mapti(its_dev, d->hwirq, event);
	lpi_update_config(d, 0xff, (LPI_PROP_DEFAULT_PRIO |
				    LPI_PROP_ENABLED |
				    LPI_PROP_GROUP1));

	/* Potentially unmap the VM from this ITS */
	its_unmap_vm(its_dev->its, its_dev->event_map.vm);

	/*
	 * Drop the refcount and make the device available again if
	 * this was the last VLPI.
	 */
	if (!--its_dev->event_map.nr_vlpis) {
		its_dev->event_map.vm = NULL;
		kfree(its_dev->event_map.vlpi_maps);
	}

out:
	raw_spin_unlock(&its_dev->event_map.vlpi_lock);
	return ret;
}

static int its_vlpi_prop_update(struct irq_data *d, struct its_cmd_info *info)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);

	if (!its_dev->event_map.vm || !irqd_is_forwarded_to_vcpu(d))
		return -EINVAL;

	if (info->cmd_type == PROP_UPDATE_AND_INV_VLPI)
		lpi_update_config(d, 0xff, info->config);
	else
		lpi_write_config(d, 0xff, info->config);
	its_vlpi_set_doorbell(d, !!(info->config & LPI_PROP_ENABLED));

	return 0;
}

static int its_irq_set_vcpu_affinity(struct irq_data *d, void *vcpu_info)
{
	struct its_device *its_dev = irq_data_get_irq_chip_data(d);
	struct its_cmd_info *info = vcpu_info;

	/* Need a v4 ITS */
	if (!is_v4(its_dev->its))
		return -EINVAL;

	/* Unmap request? */
	if (!info)
		return its_vlpi_unmap(d);

	switch (info->cmd_type) {
	case MAP_VLPI:
		return its_vlpi_map(d, info);

	case GET_VLPI:
		return its_vlpi_get(d, info);

	case PROP_UPDATE_VLPI:
	case PROP_UPDATE_AND_INV_VLPI:
		return its_vlpi_prop_update(d, info);

	default:
		return -EINVAL;
	}
}

static struct irq_chip its_irq_chip = {
	.name			= "ITS",
	.irq_mask		= its_mask_irq,
	.irq_unmask		= its_unmask_irq,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= its_set_affinity,
	.irq_compose_msi_msg	= its_irq_compose_msi_msg,
	.irq_set_irqchip_state	= its_irq_set_irqchip_state,
	.irq_retrigger		= its_irq_retrigger,
	.irq_set_vcpu_affinity	= its_irq_set_vcpu_affinity,
};


/*
 * How we allocate LPIs:
 *
 * lpi_range_list contains ranges of LPIs that are to available to
 * allocate from. To allocate LPIs, just pick the first range that
 * fits the required allocation, and reduce it by the required
 * amount. Once empty, remove the range from the list.
 *
 * To free a range of LPIs, add a free range to the list, sort it and
 * merge the result if the new range happens to be adjacent to an
 * already free block.
 *
 * The consequence of the above is that allocation is cost is low, but
 * freeing is expensive. We assumes that freeing rarely occurs.
 */
#define ITS_MAX_LPI_NRBITS	16 /* 64K LPIs */

static DEFINE_MUTEX(lpi_range_lock);
static LIST_HEAD(lpi_range_list);

struct lpi_range {
	struct list_head	entry;
	u32			base_id;
	u32			span;
};

static struct lpi_range *mk_lpi_range(u32 base, u32 span)
{
	struct lpi_range *range;

	range = kmalloc(sizeof(*range), GFP_KERNEL);
	if (range) {
		range->base_id = base;
		range->span = span;
	}

	return range;
}

static int alloc_lpi_range(u32 nr_lpis, u32 *base)
{
	struct lpi_range *range, *tmp;
	int err = -ENOSPC;

	mutex_lock(&lpi_range_lock);

	list_for_each_entry_safe(range, tmp, &lpi_range_list, entry) {
		if (range->span >= nr_lpis) {
			*base = range->base_id;
			range->base_id += nr_lpis;
			range->span -= nr_lpis;

			if (range->span == 0) {
				list_del(&range->entry);
				kfree(range);
			}

			err = 0;
			break;
		}
	}

	mutex_unlock(&lpi_range_lock);

	pr_debug("ITS: alloc %u:%u\n", *base, nr_lpis);
	return err;
}

static void merge_lpi_ranges(struct lpi_range *a, struct lpi_range *b)
{
	if (&a->entry == &lpi_range_list || &b->entry == &lpi_range_list)
		return;
	if (a->base_id + a->span != b->base_id)
		return;
	b->base_id = a->base_id;
	b->span += a->span;
	list_del(&a->entry);
	kfree(a);
}

static int free_lpi_range(u32 base, u32 nr_lpis)
{
	struct lpi_range *new, *old;

	new = mk_lpi_range(base, nr_lpis);
	if (!new)
		return -ENOMEM;

	mutex_lock(&lpi_range_lock);

	list_for_each_entry_reverse(old, &lpi_range_list, entry) {
		if (old->base_id < base)
			break;
	}
	/*
	 * old is the last element with ->base_id smaller than base,
	 * so new goes right after it. If there are no elements with
	 * ->base_id smaller than base, &old->entry ends up pointing
	 * at the head of the list, and inserting new it the start of
	 * the list is the right thing to do in that case as well.
	 */
	list_add(&new->entry, &old->entry);
	/*
	 * Now check if we can merge with the preceding and/or
	 * following ranges.
	 */
	merge_lpi_ranges(old, new);
	merge_lpi_ranges(new, list_next_entry(new, entry));

	mutex_unlock(&lpi_range_lock);
	return 0;
}

static int __init its_lpi_init(u32 id_bits)
{
	u32 lpis = (1UL << id_bits) - 8192;
	u32 numlpis;
	int err;

	numlpis = 1UL << GICD_TYPER_NUM_LPIS(gic_rdists->gicd_typer);

	if (numlpis > 2 && !WARN_ON(numlpis > lpis)) {
		lpis = numlpis;
		pr_info("ITS: Using hypervisor restricted LPI range [%u]\n",
			lpis);
	}

	/*
	 * Initializing the allocator is just the same as freeing the
	 * full range of LPIs.
	 */
	err = free_lpi_range(8192, lpis);
	pr_debug("ITS: Allocator initialized for %u LPIs\n", lpis);
	return err;
}

static unsigned long *its_lpi_alloc(int nr_irqs, u32 *base, int *nr_ids)
{
	unsigned long *bitmap = NULL;
	int err = 0;

	do {
		err = alloc_lpi_range(nr_irqs, base);
		if (!err)
			break;

		nr_irqs /= 2;
	} while (nr_irqs > 0);

	if (!nr_irqs)
		err = -ENOSPC;

	if (err)
		goto out;

	bitmap = kcalloc(BITS_TO_LONGS(nr_irqs), sizeof (long), GFP_ATOMIC);
	if (!bitmap)
		goto out;

	*nr_ids = nr_irqs;

out:
	if (!bitmap)
		*base = *nr_ids = 0;

	return bitmap;
}

static void its_lpi_free(unsigned long *bitmap, u32 base, u32 nr_ids)
{
	WARN_ON(free_lpi_range(base, nr_ids));
	kfree(bitmap);
}

static void gic_reset_prop_table(void *va)
{
	/* Priority 0xa0, Group-1, disabled */
	memset(va, LPI_PROP_DEFAULT_PRIO | LPI_PROP_GROUP1, LPI_PROPBASE_SZ);

	/* Make sure the GIC will observe the written configuration */
	gic_flush_dcache_to_poc(va, LPI_PROPBASE_SZ);
}

static struct page *its_allocate_prop_table(gfp_t gfp_flags)
{
	struct page *prop_page;

	if (of_machine_is_compatible("rockchip,rk3568") || of_machine_is_compatible("rockchip,rk3566"))
		gfp_flags |= GFP_DMA32;
	prop_page = alloc_pages(gfp_flags, get_order(LPI_PROPBASE_SZ));
	if (!prop_page)
		return NULL;

	gic_reset_prop_table(page_address(prop_page));

	return prop_page;
}

static void its_free_prop_table(struct page *prop_page)
{
	free_pages((unsigned long)page_address(prop_page),
		   get_order(LPI_PROPBASE_SZ));
}

static bool gic_check_reserved_range(phys_addr_t addr, unsigned long size)
{
	phys_addr_t start, end, addr_end;
	u64 i;

	/*
	 * We don't bother checking for a kdump kernel as by
	 * construction, the LPI tables are out of this kernel's
	 * memory map.
	 */
	if (is_kdump_kernel())
		return true;

	addr_end = addr + size - 1;

	for_each_reserved_mem_range(i, &start, &end) {
		if (addr >= start && addr_end <= end)
			return true;
	}

	/* Not found, not a good sign... */
	pr_warn("GICv3: Expected reserved range [%pa:%pa], not found\n",
		&addr, &addr_end);
	add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);
	return false;
}

static int gic_reserve_range(phys_addr_t addr, unsigned long size)
{
	if (efi_enabled(EFI_CONFIG_TABLES))
		return efi_mem_reserve_persistent(addr, size);

	return 0;
}

static int __init its_setup_lpi_prop_table(void)
{
	if (gic_rdists->flags & RDIST_FLAGS_RD_TABLES_PREALLOCATED) {
		u64 val;

		val = gicr_read_propbaser(gic_data_rdist_rd_base() + GICR_PROPBASER);
		lpi_id_bits = (val & GICR_PROPBASER_IDBITS_MASK) + 1;

		gic_rdists->prop_table_pa = val & GENMASK_ULL(51, 12);
		gic_rdists->prop_table_va = memremap(gic_rdists->prop_table_pa,
						     LPI_PROPBASE_SZ,
						     MEMREMAP_WB);
		gic_reset_prop_table(gic_rdists->prop_table_va);
	} else {
		struct page *page;

		lpi_id_bits = min_t(u32,
				    GICD_TYPER_ID_BITS(gic_rdists->gicd_typer),
				    ITS_MAX_LPI_NRBITS);
		page = its_allocate_prop_table(GFP_NOWAIT);
		if (!page) {
			pr_err("Failed to allocate PROPBASE\n");
			return -ENOMEM;
		}

		gic_rdists->prop_table_pa = page_to_phys(page);
		gic_rdists->prop_table_va = page_address(page);
		WARN_ON(gic_reserve_range(gic_rdists->prop_table_pa,
					  LPI_PROPBASE_SZ));
	}

	pr_info("GICv3: using LPI property table @%pa\n",
		&gic_rdists->prop_table_pa);

	return its_lpi_init(lpi_id_bits);
}

static const char *its_base_type_string[] = {
	[GITS_BASER_TYPE_DEVICE]	= "Devices",
	[GITS_BASER_TYPE_VCPU]		= "Virtual CPUs",
	[GITS_BASER_TYPE_RESERVED3]	= "Reserved (3)",
	[GITS_BASER_TYPE_COLLECTION]	= "Interrupt Collections",
	[GITS_BASER_TYPE_RESERVED5] 	= "Reserved (5)",
	[GITS_BASER_TYPE_RESERVED6] 	= "Reserved (6)",
	[GITS_BASER_TYPE_RESERVED7] 	= "Reserved (7)",
};

static u64 its_read_baser(struct its_node *its, struct its_baser *baser)
{
	u32 idx = baser - its->tables;

	return gits_read_baser(its->base + GITS_BASER + (idx << 3));
}

static void its_write_baser(struct its_node *its, struct its_baser *baser,
			    u64 val)
{
	u32 idx = baser - its->tables;

	gits_write_baser(val, its->base + GITS_BASER + (idx << 3));
	baser->val = its_read_baser(its, baser);
}

static int its_setup_baser(struct its_node *its, struct its_baser *baser,
			   u64 cache, u64 shr, u32 order, bool indirect)
{
	u64 val = its_read_baser(its, baser);
	u64 esz = GITS_BASER_ENTRY_SIZE(val);
	u64 type = GITS_BASER_TYPE(val);
	u64 baser_phys, tmp;
	u32 alloc_pages, psz;
	struct page *page;
	void *base;
	gfp_t gfp_flags;

	psz = baser->psz;
	alloc_pages = (PAGE_ORDER_TO_SIZE(order) / psz);
	if (alloc_pages > GITS_BASER_PAGES_MAX) {
		pr_warn("ITS@%pa: %s too large, reduce ITS pages %u->%u\n",
			&its->phys_base, its_base_type_string[type],
			alloc_pages, GITS_BASER_PAGES_MAX);
		alloc_pages = GITS_BASER_PAGES_MAX;
		order = get_order(GITS_BASER_PAGES_MAX * psz);
	}

	gfp_flags = GFP_KERNEL | __GFP_ZERO;
	if (of_machine_is_compatible("rockchip,rk3568") || of_machine_is_compatible("rockchip,rk3566"))
		gfp_flags |= GFP_DMA32;
	page = alloc_pages_node(its->numa_node, gfp_flags, order);
	if (!page)
		return -ENOMEM;

	base = (void *)page_address(page);
	baser_phys = virt_to_phys(base);

	/* Check if the physical address of the memory is above 48bits */
	if (IS_ENABLED(CONFIG_ARM64_64K_PAGES) && (baser_phys >> 48)) {

		/* 52bit PA is supported only when PageSize=64K */
		if (psz != SZ_64K) {
			pr_err("ITS: no 52bit PA support when psz=%d\n", psz);
			free_pages((unsigned long)base, order);
			return -ENXIO;
		}

		/* Convert 52bit PA to 48bit field */
		baser_phys = GITS_BASER_PHYS_52_to_48(baser_phys);
	}

retry_baser:
	val = (baser_phys					 |
		(type << GITS_BASER_TYPE_SHIFT)			 |
		((esz - 1) << GITS_BASER_ENTRY_SIZE_SHIFT)	 |
		((alloc_pages - 1) << GITS_BASER_PAGES_SHIFT)	 |
		cache						 |
		shr						 |
		GITS_BASER_VALID);

	val |=	indirect ? GITS_BASER_INDIRECT : 0x0;

	switch (psz) {
	case SZ_4K:
		val |= GITS_BASER_PAGE_SIZE_4K;
		break;
	case SZ_16K:
		val |= GITS_BASER_PAGE_SIZE_16K;
		break;
	case SZ_64K:
		val |= GITS_BASER_PAGE_SIZE_64K;
		break;
	}

	its_write_baser(its, baser, val);
	tmp = baser->val;

	if (of_machine_is_compatible("rockchip,rk3568") ||
	    of_machine_is_compatible("rockchip,rk3566")) {
		if (tmp & GITS_BASER_SHAREABILITY_MASK)
			tmp &= ~GITS_BASER_SHAREABILITY_MASK;
		else
			gic_flush_dcache_to_poc(base, PAGE_ORDER_TO_SIZE(order));
	}

	if ((val ^ tmp) & GITS_BASER_SHAREABILITY_MASK) {
		/*
		 * Shareability didn't stick. Just use
		 * whatever the read reported, which is likely
		 * to be the only thing this redistributor
		 * supports. If that's zero, make it
		 * non-cacheable as well.
		 */
		shr = tmp & GITS_BASER_SHAREABILITY_MASK;
		if (!shr) {
			cache = GITS_BASER_nC;
			gic_flush_dcache_to_poc(base, PAGE_ORDER_TO_SIZE(order));
		}
		goto retry_baser;
	}

	if (val != tmp) {
		pr_err("ITS@%pa: %s doesn't stick: %llx %llx\n",
		       &its->phys_base, its_base_type_string[type],
		       val, tmp);
		free_pages((unsigned long)base, order);
		return -ENXIO;
	}

	baser->order = order;
	baser->base = base;
	baser->psz = psz;
	tmp = indirect ? GITS_LVL1_ENTRY_SIZE : esz;

	pr_info("ITS@%pa: allocated %d %s @%lx (%s, esz %d, psz %dK, shr %d)\n",
		&its->phys_base, (int)(PAGE_ORDER_TO_SIZE(order) / (int)tmp),
		its_base_type_string[type],
		(unsigned long)virt_to_phys(base),
		indirect ? "indirect" : "flat", (int)esz,
		psz / SZ_1K, (int)shr >> GITS_BASER_SHAREABILITY_SHIFT);

	return 0;
}

static bool its_parse_indirect_baser(struct its_node *its,
				     struct its_baser *baser,
				     u32 *order, u32 ids)
{
	u64 tmp = its_read_baser(its, baser);
	u64 type = GITS_BASER_TYPE(tmp);
	u64 esz = GITS_BASER_ENTRY_SIZE(tmp);
	u64 val = GITS_BASER_InnerShareable | GITS_BASER_RaWaWb;
	u32 new_order = *order;
	u32 psz = baser->psz;
	bool indirect = false;

	/* No need to enable Indirection if memory requirement < (psz*2)bytes */
	if ((esz << ids) > (psz * 2)) {
		/*
		 * Find out whether hw supports a single or two-level table by
		 * table by reading bit at offset '62' after writing '1' to it.
		 */
		its_write_baser(its, baser, val | GITS_BASER_INDIRECT);
		indirect = !!(baser->val & GITS_BASER_INDIRECT);

		if (indirect) {
			/*
			 * The size of the lvl2 table is equal to ITS page size
			 * which is 'psz'. For computing lvl1 table size,
			 * subtract ID bits that sparse lvl2 table from 'ids'
			 * which is reported by ITS hardware times lvl1 table
			 * entry size.
			 */
			ids -= ilog2(psz / (int)esz);
			esz = GITS_LVL1_ENTRY_SIZE;
		}
	}

	/*
	 * Allocate as many entries as required to fit the
	 * range of device IDs that the ITS can grok... The ID
	 * space being incredibly sparse, this results in a
	 * massive waste of memory if two-level device table
	 * feature is not supported by hardware.
	 */
	new_order = max_t(u32, get_order(esz << ids), new_order);
	if (new_order >= MAX_ORDER) {
		new_order = MAX_ORDER - 1;
		ids = ilog2(PAGE_ORDER_TO_SIZE(new_order) / (int)esz);
		pr_warn("ITS@%pa: %s Table too large, reduce ids %llu->%u\n",
			&its->phys_base, its_base_type_string[type],
			device_ids(its), ids);
	}

	*order = new_order;

	return indirect;
}

static u32 compute_common_aff(u64 val)
{
	u32 aff, clpiaff;

	aff = FIELD_GET(GICR_TYPER_AFFINITY, val);
	clpiaff = FIELD_GET(GICR_TYPER_COMMON_LPI_AFF, val);

	return aff & ~(GENMASK(31, 0) >> (clpiaff * 8));
}

static u32 compute_its_aff(struct its_node *its)
{
	u64 val;
	u32 svpet;

	/*
	 * Reencode the ITS SVPET and MPIDR as a GICR_TYPER, and compute
	 * the resulting affinity. We then use that to see if this match
	 * our own affinity.
	 */
	svpet = FIELD_GET(GITS_TYPER_SVPET, its->typer);
	val  = FIELD_PREP(GICR_TYPER_COMMON_LPI_AFF, svpet);
	val |= FIELD_PREP(GICR_TYPER_AFFINITY, its->mpidr);
	return compute_common_aff(val);
}

static struct its_node *find_sibling_its(struct its_node *cur_its)
{
	struct its_node *its;
	u32 aff;

	if (!FIELD_GET(GITS_TYPER_SVPET, cur_its->typer))
		return NULL;

	aff = compute_its_aff(cur_its);

	list_for_each_entry(its, &its_nodes, entry) {
		u64 baser;

		if (!is_v4_1(its) || its == cur_its)
			continue;

		if (!FIELD_GET(GITS_TYPER_SVPET, its->typer))
			continue;

		if (aff != compute_its_aff(its))
			continue;

		/* GICv4.1 guarantees that the vPE table is GITS_BASER2 */
		baser = its->tables[2].val;
		if (!(baser & GITS_BASER_VALID))
			continue;

		return its;
	}

	return NULL;
}

static void its_free_tables(struct its_node *its)
{
	int i;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		if (its->tables[i].base) {
			free_pages((unsigned long)its->tables[i].base,
				   its->tables[i].order);
			its->tables[i].base = NULL;
		}
	}
}

static int its_probe_baser_psz(struct its_node *its, struct its_baser *baser)
{
	u64 psz = SZ_64K;

	while (psz) {
		u64 val, gpsz;

		val = its_read_baser(its, baser);
		val &= ~GITS_BASER_PAGE_SIZE_MASK;

		switch (psz) {
		case SZ_64K:
			gpsz = GITS_BASER_PAGE_SIZE_64K;
			break;
		case SZ_16K:
			gpsz = GITS_BASER_PAGE_SIZE_16K;
			break;
		case SZ_4K:
		default:
			gpsz = GITS_BASER_PAGE_SIZE_4K;
			break;
		}

		gpsz >>= GITS_BASER_PAGE_SIZE_SHIFT;

		val |= FIELD_PREP(GITS_BASER_PAGE_SIZE_MASK, gpsz);
		its_write_baser(its, baser, val);

		if (FIELD_GET(GITS_BASER_PAGE_SIZE_MASK, baser->val) == gpsz)
			break;

		switch (psz) {
		case SZ_64K:
			psz = SZ_16K;
			break;
		case SZ_16K:
			psz = SZ_4K;
			break;
		case SZ_4K:
		default:
			return -1;
		}
	}

	baser->psz = psz;
	return 0;
}

static int its_alloc_tables(struct its_node *its)
{
	u64 shr = GITS_BASER_InnerShareable;
	u64 cache = GITS_BASER_RaWaWb;
	int err, i;

	if (its->flags & ITS_FLAGS_WORKAROUND_CAVIUM_22375)
		/* erratum 24313: ignore memory access type */
		cache = GITS_BASER_nCnB;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		struct its_baser *baser = its->tables + i;
		u64 val = its_read_baser(its, baser);
		u64 type = GITS_BASER_TYPE(val);
		bool indirect = false;
		u32 order;

		if (type == GITS_BASER_TYPE_NONE)
			continue;

		if (its_probe_baser_psz(its, baser)) {
			its_free_tables(its);
			return -ENXIO;
		}

		order = get_order(baser->psz);

		switch (type) {
		case GITS_BASER_TYPE_DEVICE:
			indirect = its_parse_indirect_baser(its, baser, &order,
							    device_ids(its));
			break;

		case GITS_BASER_TYPE_VCPU:
			if (is_v4_1(its)) {
				struct its_node *sibling;

				WARN_ON(i != 2);
				if ((sibling = find_sibling_its(its))) {
					*baser = sibling->tables[2];
					its_write_baser(its, baser, baser->val);
					continue;
				}
			}

			indirect = its_parse_indirect_baser(its, baser, &order,
							    ITS_MAX_VPEID_BITS);
			break;
		}

		err = its_setup_baser(its, baser, cache, shr, order, indirect);
		if (err < 0) {
			its_free_tables(its);
			return err;
		}

		/* Update settings which will be used for next BASERn */
		cache = baser->val & GITS_BASER_CACHEABILITY_MASK;
		shr = baser->val & GITS_BASER_SHAREABILITY_MASK;
	}

	return 0;
}

static u64 inherit_vpe_l1_table_from_its(void)
{
	struct its_node *its;
	u64 val;
	u32 aff;

	val = gic_read_typer(gic_data_rdist_rd_base() + GICR_TYPER);
	aff = compute_common_aff(val);

	list_for_each_entry(its, &its_nodes, entry) {
		u64 baser, addr;

		if (!is_v4_1(its))
			continue;

		if (!FIELD_GET(GITS_TYPER_SVPET, its->typer))
			continue;

		if (aff != compute_its_aff(its))
			continue;

		/* GICv4.1 guarantees that the vPE table is GITS_BASER2 */
		baser = its->tables[2].val;
		if (!(baser & GITS_BASER_VALID))
			continue;

		/* We have a winner! */
		gic_data_rdist()->vpe_l1_base = its->tables[2].base;

		val  = GICR_VPROPBASER_4_1_VALID;
		if (baser & GITS_BASER_INDIRECT)
			val |= GICR_VPROPBASER_4_1_INDIRECT;
		val |= FIELD_PREP(GICR_VPROPBASER_4_1_PAGE_SIZE,
				  FIELD_GET(GITS_BASER_PAGE_SIZE_MASK, baser));
		switch (FIELD_GET(GITS_BASER_PAGE_SIZE_MASK, baser)) {
		case GIC_PAGE_SIZE_64K:
			addr = GITS_BASER_ADDR_48_to_52(baser);
			break;
		default:
			addr = baser & GENMASK_ULL(47, 12);
			break;
		}
		val |= FIELD_PREP(GICR_VPROPBASER_4_1_ADDR, addr >> 12);
		val |= FIELD_PREP(GICR_VPROPBASER_SHAREABILITY_MASK,
				  FIELD_GET(GITS_BASER_SHAREABILITY_MASK, baser));
		val |= FIELD_PREP(GICR_VPROPBASER_INNER_CACHEABILITY_MASK,
				  FIELD_GET(GITS_BASER_INNER_CACHEABILITY_MASK, baser));
		val |= FIELD_PREP(GICR_VPROPBASER_4_1_SIZE, GITS_BASER_NR_PAGES(baser) - 1);

		return val;
	}

	return 0;
}

static u64 inherit_vpe_l1_table_from_rd(cpumask_t **mask)
{
	u32 aff;
	u64 val;
	int cpu;

	val = gic_read_typer(gic_data_rdist_rd_base() + GICR_TYPER);
	aff = compute_common_aff(val);

	for_each_possible_cpu(cpu) {
		void __iomem *base = gic_data_rdist_cpu(cpu)->rd_base;

		if (!base || cpu == smp_processor_id())
			continue;

		val = gic_read_typer(base + GICR_TYPER);
		if (aff != compute_common_aff(val))
			continue;

		/*
		 * At this point, we have a victim. This particular CPU
		 * has already booted, and has an affinity that matches
		 * ours wrt CommonLPIAff. Let's use its own VPROPBASER.
		 * Make sure we don't write the Z bit in that case.
		 */
		val = gicr_read_vpropbaser(base + SZ_128K + GICR_VPROPBASER);
		val &= ~GICR_VPROPBASER_4_1_Z;

		gic_data_rdist()->vpe_l1_base = gic_data_rdist_cpu(cpu)->vpe_l1_base;
		*mask = gic_data_rdist_cpu(cpu)->vpe_table_mask;

		return val;
	}

	return 0;
}

static bool allocate_vpe_l2_table(int cpu, u32 id)
{
	void __iomem *base = gic_data_rdist_cpu(cpu)->rd_base;
	unsigned int psz, esz, idx, npg, gpsz;
	u64 val;
	struct page *page;
	__le64 *table;

	if (!gic_rdists->has_rvpeid)
		return true;

	/* Skip non-present CPUs */
	if (!base)
		return true;

	val  = gicr_read_vpropbaser(base + SZ_128K + GICR_VPROPBASER);

	esz  = FIELD_GET(GICR_VPROPBASER_4_1_ENTRY_SIZE, val) + 1;
	gpsz = FIELD_GET(GICR_VPROPBASER_4_1_PAGE_SIZE, val);
	npg  = FIELD_GET(GICR_VPROPBASER_4_1_SIZE, val) + 1;

	switch (gpsz) {
	default:
		WARN_ON(1);
		fallthrough;
	case GIC_PAGE_SIZE_4K:
		psz = SZ_4K;
		break;
	case GIC_PAGE_SIZE_16K:
		psz = SZ_16K;
		break;
	case GIC_PAGE_SIZE_64K:
		psz = SZ_64K;
		break;
	}

	/* Don't allow vpe_id that exceeds single, flat table limit */
	if (!(val & GICR_VPROPBASER_4_1_INDIRECT))
		return (id < (npg * psz / (esz * SZ_8)));

	/* Compute 1st level table index & check if that exceeds table limit */
	idx = id >> ilog2(psz / (esz * SZ_8));
	if (idx >= (npg * psz / GITS_LVL1_ENTRY_SIZE))
		return false;

	table = gic_data_rdist_cpu(cpu)->vpe_l1_base;

	/* Allocate memory for 2nd level table */
	if (!table[idx]) {
		page = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(psz));
		if (!page)
			return false;

		/* Flush Lvl2 table to PoC if hw doesn't support coherency */
		if (!(val & GICR_VPROPBASER_SHAREABILITY_MASK))
			gic_flush_dcache_to_poc(page_address(page), psz);

		table[idx] = cpu_to_le64(page_to_phys(page) | GITS_BASER_VALID);

		/* Flush Lvl1 entry to PoC if hw doesn't support coherency */
		if (!(val & GICR_VPROPBASER_SHAREABILITY_MASK))
			gic_flush_dcache_to_poc(table + idx, GITS_LVL1_ENTRY_SIZE);

		/* Ensure updated table contents are visible to RD hardware */
		dsb(sy);
	}

	return true;
}

static int allocate_vpe_l1_table(void)
{
	void __iomem *vlpi_base = gic_data_rdist_vlpi_base();
	u64 val, gpsz, npg, pa;
	unsigned int psz = SZ_64K;
	unsigned int np, epp, esz;
	struct page *page;

	if (!gic_rdists->has_rvpeid)
		return 0;

	/*
	 * if VPENDBASER.Valid is set, disable any previously programmed
	 * VPE by setting PendingLast while clearing Valid. This has the
	 * effect of making sure no doorbell will be generated and we can
	 * then safely clear VPROPBASER.Valid.
	 */
	if (gicr_read_vpendbaser(vlpi_base + GICR_VPENDBASER) & GICR_VPENDBASER_Valid)
		gicr_write_vpendbaser(GICR_VPENDBASER_PendingLast,
				      vlpi_base + GICR_VPENDBASER);

	/*
	 * If we can inherit the configuration from another RD, let's do
	 * so. Otherwise, we have to go through the allocation process. We
	 * assume that all RDs have the exact same requirements, as
	 * nothing will work otherwise.
	 */
	val = inherit_vpe_l1_table_from_rd(&gic_data_rdist()->vpe_table_mask);
	if (val & GICR_VPROPBASER_4_1_VALID)
		goto out;

	gic_data_rdist()->vpe_table_mask = kzalloc(sizeof(cpumask_t), GFP_ATOMIC);
	if (!gic_data_rdist()->vpe_table_mask)
		return -ENOMEM;

	val = inherit_vpe_l1_table_from_its();
	if (val & GICR_VPROPBASER_4_1_VALID)
		goto out;

	/* First probe the page size */
	val = FIELD_PREP(GICR_VPROPBASER_4_1_PAGE_SIZE, GIC_PAGE_SIZE_64K);
	gicr_write_vpropbaser(val, vlpi_base + GICR_VPROPBASER);
	val = gicr_read_vpropbaser(vlpi_base + GICR_VPROPBASER);
	gpsz = FIELD_GET(GICR_VPROPBASER_4_1_PAGE_SIZE, val);
	esz = FIELD_GET(GICR_VPROPBASER_4_1_ENTRY_SIZE, val);

	switch (gpsz) {
	default:
		gpsz = GIC_PAGE_SIZE_4K;
		fallthrough;
	case GIC_PAGE_SIZE_4K:
		psz = SZ_4K;
		break;
	case GIC_PAGE_SIZE_16K:
		psz = SZ_16K;
		break;
	case GIC_PAGE_SIZE_64K:
		psz = SZ_64K;
		break;
	}

	/*
	 * Start populating the register from scratch, including RO fields
	 * (which we want to print in debug cases...)
	 */
	val = 0;
	val |= FIELD_PREP(GICR_VPROPBASER_4_1_PAGE_SIZE, gpsz);
	val |= FIELD_PREP(GICR_VPROPBASER_4_1_ENTRY_SIZE, esz);

	/* How many entries per GIC page? */
	esz++;
	epp = psz / (esz * SZ_8);

	/*
	 * If we need more than just a single L1 page, flag the table
	 * as indirect and compute the number of required L1 pages.
	 */
	if (epp < ITS_MAX_VPEID) {
		int nl2;

		val |= GICR_VPROPBASER_4_1_INDIRECT;

		/* Number of L2 pages required to cover the VPEID space */
		nl2 = DIV_ROUND_UP(ITS_MAX_VPEID, epp);

		/* Number of L1 pages to point to the L2 pages */
		npg = DIV_ROUND_UP(nl2 * SZ_8, psz);
	} else {
		npg = 1;
	}

	val |= FIELD_PREP(GICR_VPROPBASER_4_1_SIZE, npg - 1);

	/* Right, that's the number of CPU pages we need for L1 */
	np = DIV_ROUND_UP(npg * psz, PAGE_SIZE);

	pr_debug("np = %d, npg = %lld, psz = %d, epp = %d, esz = %d\n",
		 np, npg, psz, epp, esz);
	page = alloc_pages(GFP_ATOMIC | __GFP_ZERO, get_order(np * PAGE_SIZE));
	if (!page)
		return -ENOMEM;

	gic_data_rdist()->vpe_l1_base = page_address(page);
	pa = virt_to_phys(page_address(page));
	WARN_ON(!IS_ALIGNED(pa, psz));

	val |= FIELD_PREP(GICR_VPROPBASER_4_1_ADDR, pa >> 12);
	val |= GICR_VPROPBASER_RaWb;
	val |= GICR_VPROPBASER_InnerShareable;
	val |= GICR_VPROPBASER_4_1_Z;
	val |= GICR_VPROPBASER_4_1_VALID;

out:
	gicr_write_vpropbaser(val, vlpi_base + GICR_VPROPBASER);
	cpumask_set_cpu(smp_processor_id(), gic_data_rdist()->vpe_table_mask);

	pr_debug("CPU%d: VPROPBASER = %llx %*pbl\n",
		 smp_processor_id(), val,
		 cpumask_pr_args(gic_data_rdist()->vpe_table_mask));

	return 0;
}

static int its_alloc_collections(struct its_node *its)
{
	int i;

	its->collections = kcalloc(nr_cpu_ids, sizeof(*its->collections),
				   GFP_KERNEL);
	if (!its->collections)
		return -ENOMEM;

	for (i = 0; i < nr_cpu_ids; i++)
		its->collections[i].target_address = ~0ULL;

	return 0;
}

static struct page *its_allocate_pending_table(gfp_t gfp_flags)
{
	struct page *pend_page;

	if (of_machine_is_compatible("rockchip,rk3568") || of_machine_is_compatible("rockchip,rk3566"))
		gfp_flags |= GFP_DMA32;
	pend_page = alloc_pages(gfp_flags | __GFP_ZERO,
				get_order(LPI_PENDBASE_SZ));
	if (!pend_page)
		return NULL;

	/* Make sure the GIC will observe the zero-ed page */
	gic_flush_dcache_to_poc(page_address(pend_page), LPI_PENDBASE_SZ);

	return pend_page;
}

static void its_free_pending_table(struct page *pt)
{
	free_pages((unsigned long)page_address(pt), get_order(LPI_PENDBASE_SZ));
}

/*
 * Booting with kdump and LPIs enabled is generally fine. Any other
 * case is wrong in the absence of firmware/EFI support.
 */
static bool enabled_lpis_allowed(void)
{
	phys_addr_t addr;
	u64 val;

	/* Check whether the property table is in a reserved region */
	val = gicr_read_propbaser(gic_data_rdist_rd_base() + GICR_PROPBASER);
	addr = val & GENMASK_ULL(51, 12);

	return gic_check_reserved_range(addr, LPI_PROPBASE_SZ);
}

static int __init allocate_lpi_tables(void)
{
	u64 val;
	int err, cpu;

	/*
	 * If LPIs are enabled while we run this from the boot CPU,
	 * flag the RD tables as pre-allocated if the stars do align.
	 */
	val = readl_relaxed(gic_data_rdist_rd_base() + GICR_CTLR);
	if ((val & GICR_CTLR_ENABLE_LPIS) && enabled_lpis_allowed()) {
		gic_rdists->flags |= (RDIST_FLAGS_RD_TABLES_PREALLOCATED |
				      RDIST_FLAGS_PROPBASE_NEEDS_FLUSHING);
		pr_info("GICv3: Using preallocated redistributor tables\n");
	}

	err = its_setup_lpi_prop_table();
	if (err)
		return err;

	/*
	 * We allocate all the pending tables anyway, as we may have a
	 * mix of RDs that have had LPIs enabled, and some that
	 * don't. We'll free the unused ones as each CPU comes online.
	 */
	for_each_possible_cpu(cpu) {
		struct page *pend_page;

		pend_page = its_allocate_pending_table(GFP_NOWAIT);
		if (!pend_page) {
			pr_err("Failed to allocate PENDBASE for CPU%d\n", cpu);
			return -ENOMEM;
		}

		gic_data_rdist_cpu(cpu)->pend_page = pend_page;
	}

	return 0;
}

static u64 its_clear_vpend_valid(void __iomem *vlpi_base, u64 clr, u64 set)
{
	u32 count = 1000000;	/* 1s! */
	bool clean;
	u64 val;

	val = gicr_read_vpendbaser(vlpi_base + GICR_VPENDBASER);
	val &= ~GICR_VPENDBASER_Valid;
	val &= ~clr;
	val |= set;
	gicr_write_vpendbaser(val, vlpi_base + GICR_VPENDBASER);

	do {
		val = gicr_read_vpendbaser(vlpi_base + GICR_VPENDBASER);
		clean = !(val & GICR_VPENDBASER_Dirty);
		if (!clean) {
			count--;
			cpu_relax();
			udelay(1);
		}
	} while (!clean && count);

	if (unlikely(val & GICR_VPENDBASER_Dirty)) {
		pr_err_ratelimited("ITS virtual pending table not cleaning\n");
		val |= GICR_VPENDBASER_PendingLast;
	}

	return val;
}

static void its_cpu_init_lpis(void)
{
	void __iomem *rbase = gic_data_rdist_rd_base();
	struct page *pend_page;
	phys_addr_t paddr;
	u64 val, tmp;

	if (gic_data_rdist()->lpi_enabled)
		return;

	val = readl_relaxed(rbase + GICR_CTLR);
	if ((gic_rdists->flags & RDIST_FLAGS_RD_TABLES_PREALLOCATED) &&
	    (val & GICR_CTLR_ENABLE_LPIS)) {
		/*
		 * Check that we get the same property table on all
		 * RDs. If we don't, this is hopeless.
		 */
		paddr = gicr_read_propbaser(rbase + GICR_PROPBASER);
		paddr &= GENMASK_ULL(51, 12);
		if (WARN_ON(gic_rdists->prop_table_pa != paddr))
			add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);

		paddr = gicr_read_pendbaser(rbase + GICR_PENDBASER);
		paddr &= GENMASK_ULL(51, 16);

		WARN_ON(!gic_check_reserved_range(paddr, LPI_PENDBASE_SZ));
		its_free_pending_table(gic_data_rdist()->pend_page);
		gic_data_rdist()->pend_page = NULL;

		goto out;
	}

	pend_page = gic_data_rdist()->pend_page;
	paddr = page_to_phys(pend_page);
	WARN_ON(gic_reserve_range(paddr, LPI_PENDBASE_SZ));

	/* set PROPBASE */
	val = (gic_rdists->prop_table_pa |
	       GICR_PROPBASER_InnerShareable |
	       GICR_PROPBASER_RaWaWb |
	       ((LPI_NRBITS - 1) & GICR_PROPBASER_IDBITS_MASK));

	gicr_write_propbaser(val, rbase + GICR_PROPBASER);
	tmp = gicr_read_propbaser(rbase + GICR_PROPBASER);

	if (of_machine_is_compatible("rockchip,rk3568") ||
	    of_machine_is_compatible("rockchip,rk3566"))
		tmp &= ~GICR_PROPBASER_SHAREABILITY_MASK;

	if ((tmp ^ val) & GICR_PROPBASER_SHAREABILITY_MASK) {
		if (!(tmp & GICR_PROPBASER_SHAREABILITY_MASK)) {
			/*
			 * The HW reports non-shareable, we must
			 * remove the cacheability attributes as
			 * well.
			 */
			val &= ~(GICR_PROPBASER_SHAREABILITY_MASK |
				 GICR_PROPBASER_CACHEABILITY_MASK);
			val |= GICR_PROPBASER_nC;
			gicr_write_propbaser(val, rbase + GICR_PROPBASER);
		}
		pr_info_once("GIC: using cache flushing for LPI property table\n");
		gic_rdists->flags |= RDIST_FLAGS_PROPBASE_NEEDS_FLUSHING;
	}

	/* set PENDBASE */
	val = (page_to_phys(pend_page) |
	       GICR_PENDBASER_InnerShareable |
	       GICR_PENDBASER_RaWaWb);

	gicr_write_pendbaser(val, rbase + GICR_PENDBASER);
	tmp = gicr_read_pendbaser(rbase + GICR_PENDBASER);

	if (of_machine_is_compatible("rockchip,rk3568") ||
	    of_machine_is_compatible("rockchip,rk3566"))
		tmp &= ~GICR_PENDBASER_SHAREABILITY_MASK;

	if (!(tmp & GICR_PENDBASER_SHAREABILITY_MASK)) {
		/*
		 * The HW reports non-shareable, we must remove the
		 * cacheability attributes as well.
		 */
		val &= ~(GICR_PENDBASER_SHAREABILITY_MASK |
			 GICR_PENDBASER_CACHEABILITY_MASK);
		val |= GICR_PENDBASER_nC;
		gicr_write_pendbaser(val, rbase + GICR_PENDBASER);
	}

	/* Enable LPIs */
	val = readl_relaxed(rbase + GICR_CTLR);
	val |= GICR_CTLR_ENABLE_LPIS;
	writel_relaxed(val, rbase + GICR_CTLR);

	if (gic_rdists->has_vlpis && !gic_rdists->has_rvpeid) {
		void __iomem *vlpi_base = gic_data_rdist_vlpi_base();

		/*
		 * It's possible for CPU to receive VLPIs before it is
		 * sheduled as a vPE, especially for the first CPU, and the
		 * VLPI with INTID larger than 2^(IDbits+1) will be considered
		 * as out of range and dropped by GIC.
		 * So we initialize IDbits to known value to avoid VLPI drop.
		 */
		val = (LPI_NRBITS - 1) & GICR_VPROPBASER_IDBITS_MASK;
		pr_debug("GICv4: CPU%d: Init IDbits to 0x%llx for GICR_VPROPBASER\n",
			smp_processor_id(), val);
		gicr_write_vpropbaser(val, vlpi_base + GICR_VPROPBASER);

		/*
		 * Also clear Valid bit of GICR_VPENDBASER, in case some
		 * ancient programming gets left in and has possibility of
		 * corrupting memory.
		 */
		val = its_clear_vpend_valid(vlpi_base, 0, 0);
	}

	if (allocate_vpe_l1_table()) {
		/*
		 * If the allocation has failed, we're in massive trouble.
		 * Disable direct injection, and pray that no VM was
		 * already running...
		 */
		gic_rdists->has_rvpeid = false;
		gic_rdists->has_vlpis = false;
	}

	/* Make sure the GIC has seen the above */
	dsb(sy);
out:
	gic_data_rdist()->lpi_enabled = true;
	pr_info("GICv3: CPU%d: using %s LPI pending table @%pa\n",
		smp_processor_id(),
		gic_data_rdist()->pend_page ? "allocated" : "reserved",
		&paddr);
}

static void its_cpu_init_collection(struct its_node *its)
{
	int cpu = smp_processor_id();
	u64 target;

	/* avoid cross node collections and its mapping */

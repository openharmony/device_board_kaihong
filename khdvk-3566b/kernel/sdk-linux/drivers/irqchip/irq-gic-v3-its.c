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


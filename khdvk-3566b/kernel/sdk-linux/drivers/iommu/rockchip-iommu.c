// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU API for Rockchip
 *
 * Module Authors:	Simon Xue <xxm@rock-chips.com>
 *			Daniel Kurtz <djkurtz@chromium.org>
 */

#include <linux/clk.h>
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <soc/rockchip/rockchip_iommu.h>

/** MMU register offsets */
#define RK_MMU_DTE_ADDR		0x00	/* Directory table address */
#define RK_MMU_STATUS		0x04
#define RK_MMU_COMMAND		0x08
#define RK_MMU_PAGE_FAULT_ADDR	0x0C	/* IOVA of last page fault */
#define RK_MMU_ZAP_ONE_LINE	0x10	/* Shootdown one IOTLB entry */
#define RK_MMU_INT_RAWSTAT	0x14	/* IRQ status ignoring mask */
#define RK_MMU_INT_CLEAR	0x18	/* Acknowledge and re-arm irq */
#define RK_MMU_INT_MASK		0x1C	/* IRQ enable */
#define RK_MMU_INT_STATUS	0x20	/* IRQ status after masking */
#define RK_MMU_AUTO_GATING	0x24

#define DTE_ADDR_DUMMY		0xCAFEBABE

#define RK_MMU_POLL_PERIOD_US		100
#define RK_MMU_FORCE_RESET_TIMEOUT_US	100000
#define RK_MMU_POLL_TIMEOUT_US		1000

/* RK_MMU_STATUS fields */
#define RK_MMU_STATUS_PAGING_ENABLED       BIT(0)
#define RK_MMU_STATUS_PAGE_FAULT_ACTIVE    BIT(1)
#define RK_MMU_STATUS_STALL_ACTIVE         BIT(2)
#define RK_MMU_STATUS_IDLE                 BIT(3)
#define RK_MMU_STATUS_REPLAY_BUFFER_EMPTY  BIT(4)
#define RK_MMU_STATUS_PAGE_FAULT_IS_WRITE  BIT(5)
#define RK_MMU_STATUS_STALL_NOT_ACTIVE     BIT(31)

/* RK_MMU_COMMAND command values */
#define RK_MMU_CMD_ENABLE_PAGING    0  /* Enable memory translation */
#define RK_MMU_CMD_DISABLE_PAGING   1  /* Disable memory translation */
#define RK_MMU_CMD_ENABLE_STALL     2  /* Stall paging to allow other cmds */
#define RK_MMU_CMD_DISABLE_STALL    3  /* Stop stall re-enables paging */
#define RK_MMU_CMD_ZAP_CACHE        4  /* Shoot down entire IOTLB */
#define RK_MMU_CMD_PAGE_FAULT_DONE  5  /* Clear page fault */
#define RK_MMU_CMD_FORCE_RESET      6  /* Reset all registers */

/* RK_MMU_INT_* register fields */
#define RK_MMU_IRQ_PAGE_FAULT    0x01  /* page fault */
#define RK_MMU_IRQ_BUS_ERROR     0x02  /* bus read error */
#define RK_MMU_IRQ_MASK          (RK_MMU_IRQ_PAGE_FAULT | RK_MMU_IRQ_BUS_ERROR)

#define NUM_DT_ENTRIES 1024
#define NUM_PT_ENTRIES 1024

#define SPAGE_ORDER 12
#define SPAGE_SIZE (1 << SPAGE_ORDER)

#define DISABLE_FETCH_DTE_TIME_LIMIT BIT(31)

#define CMD_RETRY_COUNT 10

 /*
  * Support mapping any size that fits in one page table:
  *   4 KiB to 4 MiB
  */
#define RK_IOMMU_PGSIZE_BITMAP 0x007ff000

#define DT_LO_MASK 0xfffff000
#define DT_HI_MASK GENMASK_ULL(39, 32)
#define DT_SHIFT   28

#define DTE_BASE_HI_MASK GENMASK(11, 4)

#define PAGE_DESC_LO_MASK   0xfffff000
#define PAGE_DESC_HI1_LOWER 32
#define PAGE_DESC_HI1_UPPER 35
#define PAGE_DESC_HI2_LOWER 36
#define PAGE_DESC_HI2_UPPER 39
#define PAGE_DESC_HI_MASK1  GENMASK_ULL(PAGE_DESC_HI1_UPPER, PAGE_DESC_HI1_LOWER)
#define PAGE_DESC_HI_MASK2  GENMASK_ULL(PAGE_DESC_HI2_UPPER, PAGE_DESC_HI2_LOWER)

#define DTE_HI1_LOWER 8
#define DTE_HI1_UPPER 11
#define DTE_HI2_LOWER 4
#define DTE_HI2_UPPER 7
#define DTE_HI_MASK1  GENMASK(DTE_HI1_UPPER, DTE_HI1_LOWER)
#define DTE_HI_MASK2  GENMASK(DTE_HI2_UPPER, DTE_HI2_LOWER)

#define PAGE_DESC_HI_SHIFT1 (PAGE_DESC_HI1_LOWER - DTE_HI1_LOWER)
#define PAGE_DESC_HI_SHIFT2 (PAGE_DESC_HI2_LOWER - DTE_HI2_LOWER)

struct rk_iommu_domain {
	struct list_head iommus;
	u32 *dt; /* page directory table */
	dma_addr_t dt_dma;
	spinlock_t iommus_lock; /* lock for iommus list */
	spinlock_t dt_lock; /* lock for modifying page directory table */
	bool shootdown_entire;

	struct iommu_domain domain;
};

struct rockchip_iommu_data {
	u32 version;
};

struct rk_iommu {
	struct device *dev;
	void __iomem **bases;
	int num_mmu;
	int num_irq;
	struct clk_bulk_data *clocks;
	int num_clocks;
	bool reset_disabled;
	bool skip_read; /* rk3126/rk3128 can't read vop iommu registers */
	bool dlr_disable; /* avoid access iommu when runtime ops called */
	bool cmd_retry;
	struct iommu_device iommu;
	struct list_head node; /* entry in rk_iommu_domain.iommus */
	struct iommu_domain *domain; /* domain to which iommu is attached */
	struct iommu_group *group;
	u32 version;
	bool shootdown_entire;
};

struct rk_iommudata {
	struct device_link *link; /* runtime PM link from IOMMU to master */
	struct rk_iommu *iommu;
	bool defer_attach;
};

static struct device *dma_dev;

static inline void rk_table_flush(struct rk_iommu_domain *dom, dma_addr_t dma,
				  unsigned int count)
{
	size_t size = count * sizeof(u32); /* count of u32 entry */

	dma_sync_single_for_device(dma_dev, dma, size, DMA_TO_DEVICE);
}

static struct rk_iommu_domain *to_rk_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct rk_iommu_domain, domain);
}

/*
 * The Rockchip rk3288 iommu uses a 2-level page table.
 * The first level is the "Directory Table" (DT).
 * The DT consists of 1024 4-byte Directory Table Entries (DTEs), each pointing
 * to a "Page Table".
 * The second level is the 1024 Page Tables (PT).
 * Each PT consists of 1024 4-byte Page Table Entries (PTEs), each pointing to
 * a 4 KB page of physical memory.
 *
 * The DT and each PT fits in a single 4 KB page (4-bytes * 1024 entries).
 * Each iommu device has a MMU_DTE_ADDR register that contains the physical
 * address of the start of the DT page.
 *
 * The structure of the page table is as follows:
 *
 *                   DT
 * MMU_DTE_ADDR -> +-----+
 *                 |     |
 *                 +-----+     PT
 *                 | DTE | -> +-----+
 *                 +-----+    |     |     Memory
 *                 |     |    +-----+     Page
 *                 |     |    | PTE | -> +-----+
 *                 +-----+    +-----+    |     |
 *                            |     |    |     |
 *                            |     |    |     |
 *                            +-----+    |     |
 *                                       |     |
 *                                       |     |
 *                                       +-----+
 */

/*
 * Each DTE has a PT address and a valid bit:
 * +---------------------+-----------+-+
 * | PT address          | Reserved  |V|
 * +---------------------+-----------+-+
 *  31:12 - PT address (PTs always starts on a 4 KB boundary)
 *  11: 1 - Reserved
 *      0 - 1 if PT @ PT address is valid
 */
#define RK_DTE_PT_ADDRESS_MASK    0xfffff000
#define RK_DTE_PT_VALID           BIT(0)

/*
 * In v2:
 * 31:12 - PT address bit 31:0
 * 11: 8 - PT address bit 35:32
 *  7: 4 - PT address bit 39:36
 *  3: 1 - Reserved
 *     0 - 1 if PT @ PT address is valid
 */
#define RK_DTE_PT_ADDRESS_MASK_V2 0xfffffff0

static inline phys_addr_t rk_dte_pt_address(u32 dte)
{
	return (phys_addr_t)dte & RK_DTE_PT_ADDRESS_MASK;
}

static inline phys_addr_t rk_dte_pt_address_v2(u32 dte)
{
	u64 dte_v2 = dte;

	dte_v2 = ((dte_v2 & DTE_HI_MASK2) << PAGE_DESC_HI_SHIFT2) |
		 ((dte_v2 & DTE_HI_MASK1) << PAGE_DESC_HI_SHIFT1) |
		 (dte_v2 & PAGE_DESC_LO_MASK);

	return (phys_addr_t)dte_v2;
}

static inline bool rk_dte_is_pt_valid(u32 dte)
{
	return dte & RK_DTE_PT_VALID;
}

static inline u32 rk_mk_dte(dma_addr_t pt_dma)
{
	return (pt_dma & RK_DTE_PT_ADDRESS_MASK) | RK_DTE_PT_VALID;
}

static inline u32 rk_mk_dte_v2(dma_addr_t pt_dma)
{
	pt_dma = (pt_dma & PAGE_DESC_LO_MASK) |
		 ((pt_dma & PAGE_DESC_HI_MASK1) >> PAGE_DESC_HI_SHIFT1) |
		 (pt_dma & PAGE_DESC_HI_MASK2) >> PAGE_DESC_HI_SHIFT2;

	return (pt_dma & RK_DTE_PT_ADDRESS_MASK_V2) | RK_DTE_PT_VALID;
}

/*
 * Each PTE has a Page address, some flags and a valid bit:
 * +---------------------+---+-------+-+
 * | Page address        |Rsv| Flags |V|
 * +---------------------+---+-------+-+
 *  31:12 - Page address (Pages always start on a 4 KB boundary)
 *  11: 9 - Reserved
 *   8: 1 - Flags
 *      8 - Read allocate - allocate cache space on read misses
 *      7 - Read cache - enable cache & prefetch of data
 *      6 - Write buffer - enable delaying writes on their way to memory
 *      5 - Write allocate - allocate cache space on write misses
 *      4 - Write cache - different writes can be merged together
 *      3 - Override cache attributes
 *          if 1, bits 4-8 control cache attributes
 *          if 0, the system bus defaults are used
 *      2 - Writable
 *      1 - Readable
 *      0 - 1 if Page @ Page address is valid
 */
#define RK_PTE_PAGE_ADDRESS_MASK  0xfffff000
#define RK_PTE_PAGE_FLAGS_MASK    0x000001fe
#define RK_PTE_PAGE_WRITABLE      BIT(2)
#define RK_PTE_PAGE_READABLE      BIT(1)
#define RK_PTE_PAGE_VALID         BIT(0)

/*
 * In v2:
 * 31:12 - Page address bit 31:0
 *  11:9 - Page address bit 34:32
 *   8:4 - Page address bit 39:35
 *     3 - Security
 *     2 - Writable
 *     1 - Readable
 *     0 - 1 if Page @ Page address is valid
 */
#define RK_PTE_PAGE_ADDRESS_MASK_V2  0xfffffff0
#define RK_PTE_PAGE_FLAGS_MASK_V2    0x0000000e
#define RK_PTE_PAGE_READABLE_V2      BIT(1)
#define RK_PTE_PAGE_WRITABLE_V2      BIT(2)

static inline phys_addr_t rk_pte_page_address(u32 pte)
{
	return (phys_addr_t)pte & RK_PTE_PAGE_ADDRESS_MASK;
}

static inline phys_addr_t rk_pte_page_address_v2(u32 pte)
{
	u64 pte_v2 = pte;

	pte_v2 = ((pte_v2 & DTE_HI_MASK2) << PAGE_DESC_HI_SHIFT2) |
		 ((pte_v2 & DTE_HI_MASK1) << PAGE_DESC_HI_SHIFT1) |
		 (pte_v2 & PAGE_DESC_LO_MASK);

	return (phys_addr_t)pte_v2;
}

static inline bool rk_pte_is_page_valid(u32 pte)
{
	return pte & RK_PTE_PAGE_VALID;
}

/* TODO: set cache flags per prot IOMMU_CACHE */
static u32 rk_mk_pte(phys_addr_t page, int prot)
{
	u32 flags = 0;
	flags |= (prot & IOMMU_READ) ? RK_PTE_PAGE_READABLE : 0;
	flags |= (prot & IOMMU_WRITE) ? RK_PTE_PAGE_WRITABLE : 0;
	page &= RK_PTE_PAGE_ADDRESS_MASK;
	return page | flags | RK_PTE_PAGE_VALID;
}

static u32 rk_mk_pte_v2(phys_addr_t page, int prot)
{
	u32 flags = 0;

	flags |= (prot & IOMMU_READ) ? RK_PTE_PAGE_READABLE_V2 : 0;
	flags |= (prot & IOMMU_WRITE) ? RK_PTE_PAGE_WRITABLE_V2 : 0;
	page = (page & PAGE_DESC_LO_MASK) |
	       ((page & PAGE_DESC_HI_MASK1) >> PAGE_DESC_HI_SHIFT1) |
	       (page & PAGE_DESC_HI_MASK2) >> PAGE_DESC_HI_SHIFT2;
	page &= RK_PTE_PAGE_ADDRESS_MASK_V2;

	return page | flags | RK_PTE_PAGE_VALID;
}

static u32 rk_mk_pte_invalid(u32 pte)
{
	return pte & ~RK_PTE_PAGE_VALID;
}

/*
 * rk3288 iova (IOMMU Virtual Address) format
 *  31       22.21       12.11          0
 * +-----------+-----------+-------------+
 * | DTE index | PTE index | Page offset |
 * +-----------+-----------+-------------+
 *  31:22 - DTE index   - index of DTE in DT
 *  21:12 - PTE index   - index of PTE in PT @ DTE.pt_address
 *  11: 0 - Page offset - offset into page @ PTE.page_address
 */
#define RK_IOVA_DTE_MASK    0xffc00000
#define RK_IOVA_DTE_SHIFT   22
#define RK_IOVA_PTE_MASK    0x003ff000
#define RK_IOVA_PTE_SHIFT   12
#define RK_IOVA_PAGE_MASK   0x00000fff
#define RK_IOVA_PAGE_SHIFT  0

static u32 rk_iova_dte_index(dma_addr_t iova)
{
	return (u32)(iova & RK_IOVA_DTE_MASK) >> RK_IOVA_DTE_SHIFT;
}

static u32 rk_iova_pte_index(dma_addr_t iova)
{
	return (u32)(iova & RK_IOVA_PTE_MASK) >> RK_IOVA_PTE_SHIFT;
}

static u32 rk_iova_page_offset(dma_addr_t iova)
{
	return (u32)(iova & RK_IOVA_PAGE_MASK) >> RK_IOVA_PAGE_SHIFT;
}

static u32 rk_iommu_read(void __iomem *base, u32 offset)
{
	return readl(base + offset);
}

static void rk_iommu_write(void __iomem *base, u32 offset, u32 value)
{
	writel(value, base + offset);
}

static void rk_iommu_command(struct rk_iommu *iommu, u32 command)
{
	int i;

	for (i = 0; i < iommu->num_mmu; i++)
		writel(command, iommu->bases[i] + RK_MMU_COMMAND);
}

static void rk_iommu_base_command(void __iomem *base, u32 command)

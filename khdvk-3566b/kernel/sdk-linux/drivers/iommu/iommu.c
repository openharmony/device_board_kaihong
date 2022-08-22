// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#define pr_fmt(fmt)    "iommu: " fmt

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/iommu.h>
#include <linux/idr.h>
#include <linux/notifier.h>
#include <linux/err.h>
#include <linux/pci.h>
#include <linux/bitops.h>
#include <linux/property.h>
#include <linux/fsl/mc.h>
#include <linux/module.h>
#include <trace/events/iommu.h>

static struct kset *iommu_group_kset;
static DEFINE_IDA(iommu_group_ida);

static unsigned int iommu_def_domain_type __read_mostly;
static bool iommu_dma_strict __read_mostly = true;
static u32 iommu_cmd_line __read_mostly;

struct iommu_group {
	struct kobject kobj;
	struct kobject *devices_kobj;
	struct list_head devices;
	struct mutex mutex;
	struct blocking_notifier_head notifier;
	void *iommu_data;
	void (*iommu_data_release)(void *iommu_data);
	char *name;
	int id;
	struct iommu_domain *default_domain;
	struct iommu_domain *domain;
	struct list_head entry;
};

struct group_device {
	struct list_head list;
	struct device *dev;
	char *name;
};

struct iommu_group_attribute {
	struct attribute attr;
	ssize_t (*show)(struct iommu_group *group, char *buf);
	ssize_t (*store)(struct iommu_group *group,
			 const char *buf, size_t count);
};

static const char * const iommu_group_resv_type_string[] = {
	[IOMMU_RESV_DIRECT]			= "direct",
	[IOMMU_RESV_DIRECT_RELAXABLE]		= "direct-relaxable",
	[IOMMU_RESV_RESERVED]			= "reserved",
	[IOMMU_RESV_MSI]			= "msi",
	[IOMMU_RESV_SW_MSI]			= "msi",
};

#define IOMMU_CMD_LINE_DMA_API		BIT(0)

static void iommu_set_cmd_line_dma_api(void)
{
	iommu_cmd_line |= IOMMU_CMD_LINE_DMA_API;
}

static bool iommu_cmd_line_dma_api(void)
{
	return !!(iommu_cmd_line & IOMMU_CMD_LINE_DMA_API);
}

static int iommu_alloc_default_domain(struct iommu_group *group,
				      struct device *dev);
static struct iommu_domain *__iommu_domain_alloc(struct bus_type *bus,
						 unsigned type);
static int __iommu_attach_device(struct iommu_domain *domain,
				 struct device *dev);
static int __iommu_attach_group(struct iommu_domain *domain,
				struct iommu_group *group);
static void __iommu_detach_group(struct iommu_domain *domain,
				 struct iommu_group *group);
static int iommu_create_device_direct_mappings(struct iommu_group *group,
					       struct device *dev);
static struct iommu_group *iommu_group_get_for_dev(struct device *dev);

#define IOMMU_GROUP_ATTR(_name, _mode, _show, _store)		\
struct iommu_group_attribute iommu_group_attr_##_name =		\
	__ATTR(_name, _mode, _show, _store)

#define to_iommu_group_attr(_attr)	\
	container_of(_attr, struct iommu_group_attribute, attr)
#define to_iommu_group(_kobj)		\
	container_of(_kobj, struct iommu_group, kobj)

static LIST_HEAD(iommu_device_list);
static DEFINE_SPINLOCK(iommu_device_lock);

/*
 * Use a function instead of an array here because the domain-type is a
 * bit-field, so an array would waste memory.
 */
static const char *iommu_domain_type_str(unsigned int t)
{
	switch (t) {
	case IOMMU_DOMAIN_BLOCKED:
		return "Blocked";
	case IOMMU_DOMAIN_IDENTITY:
		return "Passthrough";
	case IOMMU_DOMAIN_UNMANAGED:
		return "Unmanaged";
	case IOMMU_DOMAIN_DMA:
		return "Translated";
	default:
		return "Unknown";
	}
}

static int __init iommu_subsys_init(void)
{
	bool cmd_line = iommu_cmd_line_dma_api();

	if (!cmd_line) {
		if (IS_ENABLED(CONFIG_IOMMU_DEFAULT_PASSTHROUGH))
			iommu_set_default_passthrough(false);
		else
			iommu_set_default_translated(false);

		if (iommu_default_passthrough() && mem_encrypt_active()) {
			pr_info("Memory encryption detected - Disabling default IOMMU Passthrough\n");
			iommu_set_default_translated(false);
		}
	}

	pr_info("Default domain type: %s %s\n",
		iommu_domain_type_str(iommu_def_domain_type),
		cmd_line ? "(set via kernel command line)" : "");

	return 0;
}
subsys_initcall(iommu_subsys_init);

int iommu_device_register(struct iommu_device *iommu)
{
	spin_lock(&iommu_device_lock);
	list_add_tail(&iommu->list, &iommu_device_list);
	spin_unlock(&iommu_device_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(iommu_device_register);

void iommu_device_unregister(struct iommu_device *iommu)
{
	spin_lock(&iommu_device_lock);
	list_del(&iommu->list);
	spin_unlock(&iommu_device_lock);
}
EXPORT_SYMBOL_GPL(iommu_device_unregister);

static struct dev_iommu *dev_iommu_get(struct device *dev)
{
	struct dev_iommu *param = dev->iommu;

	if (param)
		return param;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		return NULL;

	mutex_init(&param->lock);
	dev->iommu = param;
	return param;
}

static void dev_iommu_free(struct device *dev)
{
	iommu_fwspec_free(dev);
	kfree(dev->iommu);
	dev->iommu = NULL;
}

static int __iommu_probe_device(struct device *dev, struct list_head *group_list)
{
	const struct iommu_ops *ops = dev->bus->iommu_ops;
	struct iommu_device *iommu_dev;
	struct iommu_group *group;
	int ret;

	if (!ops)
		return -ENODEV;

	if (!dev_iommu_get(dev))
		return -ENOMEM;

	if (!try_module_get(ops->owner)) {
		ret = -EINVAL;
		goto err_free;
	}

	iommu_dev = ops->probe_device(dev);
	if (IS_ERR(iommu_dev)) {
		ret = PTR_ERR(iommu_dev);
		goto out_module_put;
	}

	dev->iommu->iommu_dev = iommu_dev;

	group = iommu_group_get_for_dev(dev);
	if (IS_ERR(group)) {
		ret = PTR_ERR(group);
		goto out_release;
	}
	iommu_group_put(group);

	if (group_list && !group->default_domain && list_empty(&group->entry))
		list_add_tail(&group->entry, group_list);

	iommu_device_link(iommu_dev, dev);

	return 0;

out_release:
	ops->release_device(dev);

out_module_put:
	module_put(ops->owner);

err_free:
	dev_iommu_free(dev);

	return ret;
}

int iommu_probe_device(struct device *dev)
{
	const struct iommu_ops *ops = dev->bus->iommu_ops;
	struct iommu_group *group;
	int ret;

	ret = __iommu_probe_device(dev, NULL);
	if (ret)
		goto err_out;

	group = iommu_group_get(dev);
	if (!group)
		goto err_release;

	/*
	 * Try to allocate a default domain - needs support from the
	 * IOMMU driver. There are still some drivers which don't
	 * support default domains, so the return value is not yet
	 * checked.
	 */
	iommu_alloc_default_domain(group, dev);

	if (group->default_domain) {
		ret = __iommu_attach_device(group->default_domain, dev);
		if (ret) {
			iommu_group_put(group);
			goto err_release;
		}
	}

	iommu_create_device_direct_mappings(group, dev);

	iommu_group_put(group);

	if (ops->probe_finalize)
		ops->probe_finalize(dev);

	return 0;

err_release:
	iommu_release_device(dev);

err_out:
	return ret;

}

void iommu_release_device(struct device *dev)
{
	const struct iommu_ops *ops = dev->bus->iommu_ops;

	if (!dev->iommu)
		return;

	iommu_device_unlink(dev->iommu->iommu_dev, dev);

	ops->release_device(dev);

	iommu_group_remove_device(dev);
	module_put(ops->owner);
	dev_iommu_free(dev);
}

static int __init iommu_set_def_domain_type(char *str)
{
	bool pt;
	int ret;

	ret = kstrtobool(str, &pt);
	if (ret)
		return ret;

	if (pt)
		iommu_set_default_passthrough(true);
	else
		iommu_set_default_translated(true);

	return 0;
}
early_param("iommu.passthrough", iommu_set_def_domain_type);

static int __init iommu_dma_setup(char *str)
{
	return kstrtobool(str, &iommu_dma_strict);
}
early_param("iommu.strict", iommu_dma_setup);

static ssize_t iommu_group_attr_show(struct kobject *kobj,
				     struct attribute *__attr, char *buf)
{
	struct iommu_group_attribute *attr = to_iommu_group_attr(__attr);
	struct iommu_group *group = to_iommu_group(kobj);
	ssize_t ret = -EIO;

	if (attr->show)
		ret = attr->show(group, buf);
	return ret;
}

static ssize_t iommu_group_attr_store(struct kobject *kobj,
				      struct attribute *__attr,
				      const char *buf, size_t count)
{
	struct iommu_group_attribute *attr = to_iommu_group_attr(__attr);
	struct iommu_group *group = to_iommu_group(kobj);
	ssize_t ret = -EIO;

	if (attr->store)
		ret = attr->store(group, buf, count);
	return ret;
}

static const struct sysfs_ops iommu_group_sysfs_ops = {
	.show = iommu_group_attr_show,
	.store = iommu_group_attr_store,
};

static int iommu_group_create_file(struct iommu_group *group,
				   struct iommu_group_attribute *attr)
{
	return sysfs_create_file(&group->kobj, &attr->attr);
}

static void iommu_group_remove_file(struct iommu_group *group,
				    struct iommu_group_attribute *attr)
{
	sysfs_remove_file(&group->kobj, &attr->attr);
}

static ssize_t iommu_group_show_name(struct iommu_group *group, char *buf)
{
	return sprintf(buf, "%s\n", group->name);
}

/**
 * iommu_insert_resv_region - Insert a new region in the
 * list of reserved regions.
 * @new: new region to insert
 * @regions: list of regions
 *
 * Elements are sorted by start address and overlapping segments
 * of the same type are merged.
 */
static int iommu_insert_resv_region(struct iommu_resv_region *new,
				    struct list_head *regions)
{
	struct iommu_resv_region *iter, *tmp, *nr, *top;

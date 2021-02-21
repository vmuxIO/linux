// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kvm_host.h>
#include <linux/fs.h>
#include <kvm/iodev.h>
#include "eventfd.h"

void
kvm_ioregionfd_init(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->ioregions_fast_mmio);
	INIT_LIST_HEAD(&kvm->ioregions_mmio);
	INIT_LIST_HEAD(&kvm->ioregions_pio);
}

struct ioregion {
	struct list_head     list;
	u64                  paddr;  /* guest physical address */
	u64                  size;   /* size in bytes */
	struct file         *rf;
	struct file         *wf;
	u64                  user_data; /* opaque token used by userspace */
	struct kvm_io_device dev;
	bool                 posted_writes;
};

static inline struct ioregion *
to_ioregion(struct kvm_io_device *dev)
{
	return container_of(dev, struct ioregion, dev);
}

/* assumes kvm->slots_lock held */
static void
ioregion_release(struct ioregion *p)
{
	if (p->rf)
		fput(p->rf);
	fput(p->wf);
	list_del(&p->list);
	kfree(p);
}

static int
ioregion_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this, gpa_t addr,
	      int len, void *val)
{
	return -EOPNOTSUPP;
}

static int
ioregion_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this, gpa_t addr,
		int len, const void *val)
{
	return -EOPNOTSUPP;
}

/*
 * This function is called as KVM is completely shutting down.  We do not
 * need to worry about locking just nuke anything we have as quickly as possible
 */
static void
ioregion_destructor(struct kvm_io_device *this)
{
	struct ioregion *p = to_ioregion(this);

	ioregion_release(p);
}

static const struct kvm_io_device_ops ioregion_ops = {
	.read       = ioregion_read,
	.write      = ioregion_write,
	.destructor = ioregion_destructor,
};

static inline struct list_head *
get_ioregion_list(struct kvm *kvm, enum kvm_bus bus_idx)
{
	if (bus_idx == KVM_FAST_MMIO_BUS)
		return &kvm->ioregions_fast_mmio;
	if (bus_idx == KVM_MMIO_BUS)
		return &kvm->ioregions_mmio;
	BUG_ON(bus_idx != KVM_PIO_BUS);
	return &kvm->ioregions_pio;
}

/* check for not overlapping case and reverse */
inline bool
overlap(u64 start1, u64 size1, u64 start2, u64 size2)
{
	u64 end1 = start1 + size1 - 1;
	u64 end2 = start2 + size2 - 1;

	return !(end1 < start2 || start1 >= end2);
}

/* assumes kvm->slots_lock held */
bool
kvm_ioregion_collides(struct kvm *kvm, int bus_idx,
		      u64 start, u64 size)
{
	struct ioregion *p;
	struct list_head *ioregions = get_ioregion_list(kvm, bus_idx);

	list_for_each_entry(p, ioregions, list)
		if (overlap(start, size, p->paddr, !p->size ? 8 : p->size))
			return true;

	return false;
}

/* assumes kvm->slots_lock held */
static bool
ioregion_collision(struct kvm *kvm, struct ioregion *p, enum kvm_bus bus_idx)
{
	if (kvm_ioregion_collides(kvm, bus_idx, p->paddr, !p->size ? 8 : p->size) ||
	    kvm_eventfd_collides(kvm, bus_idx, p->paddr, !p->size ? 8 : p->size))
		return true;

	return false;
}

static enum kvm_bus
get_bus_from_flags(__u32 flags)
{
	if (flags & KVM_IOREGION_PIO)
		return KVM_PIO_BUS;
	return KVM_MMIO_BUS;
}

int
kvm_set_ioregion_idx(struct kvm *kvm, struct kvm_ioregion *args, enum kvm_bus bus_idx)
{
	struct ioregion *p;
	struct file *rfile = NULL, *wfile;
	int ret = 0;

	wfile = fget(args->write_fd);
	if (!wfile)
		return -EBADF;
	if (args->memory_size) {
		rfile = fget(args->read_fd);
		if (!rfile) {
			fput(wfile);
			return -EBADF;
		}
	}
	p = kzalloc(sizeof(*p), GFP_KERNEL_ACCOUNT);
	if (!p) {
		ret = -ENOMEM;
		goto fail;
	}

	INIT_LIST_HEAD(&p->list);
	p->paddr = args->guest_paddr;
	p->size = args->memory_size;
	p->user_data = args->user_data;
	p->rf = rfile;
	p->wf = wfile;
	p->posted_writes = args->flags & KVM_IOREGION_POSTED_WRITES;

	mutex_lock(&kvm->slots_lock);

	if (ioregion_collision(kvm, p, bus_idx)) {
		ret = -EEXIST;
		goto unlock_fail;
	}
	kvm_iodevice_init(&p->dev, &ioregion_ops);
	ret = kvm_io_bus_register_dev(kvm, bus_idx, p->paddr, p->size,
				      &p->dev);
	if (ret < 0)
		goto unlock_fail;
	list_add_tail(&p->list, get_ioregion_list(kvm, bus_idx));

	mutex_unlock(&kvm->slots_lock);

	return 0;

unlock_fail:
	mutex_unlock(&kvm->slots_lock);
	kfree(p);
fail:
	if (rfile)
		fput(rfile);
	fput(wfile);

	return ret;
}

static int
kvm_rm_ioregion_idx(struct kvm *kvm, struct kvm_ioregion *args, enum kvm_bus bus_idx)
{
	struct ioregion *p, *tmp;
	int ret = -ENOENT;

	struct list_head *ioregions = get_ioregion_list(kvm, bus_idx);

	mutex_lock(&kvm->slots_lock);

	list_for_each_entry_safe(p, tmp, ioregions, list) {
		if (p->paddr == args->guest_paddr  &&
		    p->size == args->memory_size) {
			kvm_io_bus_unregister_dev(kvm, bus_idx, &p->dev);
			ioregion_release(p);
			ret = 0;
			break;
		}
	}

	mutex_unlock(&kvm->slots_lock);

	return ret;
}

static int
kvm_set_ioregion(struct kvm *kvm, struct kvm_ioregion *args)
{
	int ret;

	enum kvm_bus bus_idx = get_bus_from_flags(args->flags);

	/* check for range overflow */
	if (args->guest_paddr + args->memory_size < args->guest_paddr)
		return -EINVAL;
	/* If size is ignored only posted writes are allowed */
	if (!args->memory_size && !(args->flags & KVM_IOREGION_POSTED_WRITES))
		return -EINVAL;

	ret = kvm_set_ioregion_idx(kvm, args, bus_idx);
	if (ret)
		return ret;

	/* If size is ignored, MMIO is also put on a FAST_MMIO bus */
	if (!args->memory_size && bus_idx == KVM_MMIO_BUS)
		ret = kvm_set_ioregion_idx(kvm, args, KVM_FAST_MMIO_BUS);
	if (ret) {
		kvm_rm_ioregion_idx(kvm, args, bus_idx);
		return ret;
	}

	return 0;
}

static int
kvm_rm_ioregion(struct kvm *kvm, struct kvm_ioregion *args)
{
	enum kvm_bus bus_idx = get_bus_from_flags(args->flags);
	int ret = kvm_rm_ioregion_idx(kvm, args, bus_idx);

	if (!args->memory_size && bus_idx == KVM_MMIO_BUS)
		kvm_rm_ioregion_idx(kvm, args, KVM_FAST_MMIO_BUS);

	return ret;
}

int
kvm_ioregionfd(struct kvm *kvm, struct kvm_ioregion *args)
{
	if (args->flags & ~KVM_IOREGION_VALID_FLAG_MASK)
		return -EINVAL;

	if (args->flags & KVM_IOREGION_DEASSIGN)
		return kvm_rm_ioregion(kvm, args);

	return kvm_set_ioregion(kvm, args);
}

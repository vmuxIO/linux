// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kvm_host.h>
#include <linux/wait.h>
#include <kvm/iodev.h>
#include "eventfd.h"
#include <uapi/linux/ioregion.h>

/* ioregions that share the same rfd are serialized so that only one vCPU
 * thread sends a struct ioregionfd_cmd to userspace at a time. This
 * ensures that the struct ioregionfd_resp received from userspace will
 * be processed by the one and only vCPU thread that sent it.
 *
 * A waitqueue is used to wake up waiting vCPU threads in order. Most of
 * the time the waitqueue is unused and the lock is not contended.
 * For best performance userspace should set up ioregionfds so that there
 * is no contention (e.g. dedicated ioregionfds for queue doorbell
 * registers on multi-queue devices).
 */
struct ioregionfd {
	wait_queue_head_t	  wq;
	struct file		 *rf;
	struct kref		  kref;
	bool			  busy;
};

struct ioregion {
	struct list_head	  list;
	u64			  paddr;   /* guest physical address */
	u64			  size;    /* size in bytes */
	struct file		 *wf;
	u64			  user_data; /* opaque token used by userspace */
	struct kvm_io_device	  dev;
	bool			  posted_writes;
	struct ioregionfd	 *ctx;
};

void
kvm_ioregionfd_init(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->ioregions_fast_mmio);
	INIT_LIST_HEAD(&kvm->ioregions_mmio);
	INIT_LIST_HEAD(&kvm->ioregions_pio);
}

static inline struct ioregion *
to_ioregion(struct kvm_io_device *dev)
{
	return container_of(dev, struct ioregion, dev);
}

/* assumes kvm->slots_lock held */
static void ctx_free(struct kref *kref)
{
	struct ioregionfd *ctx = container_of(kref, struct ioregionfd, kref);

	kfree(ctx);
}

/* assumes kvm->slots_lock held */
static void
ioregion_release(struct ioregion *p)
{
	if (p->ctx) {
		fput(p->ctx->rf);
		kref_put(&p->ctx->kref, ctx_free);
	}
	fput(p->wf);
	list_del(&p->list);
	kfree(p);
}

static bool
pack_cmd(struct ioregionfd_cmd *cmd, u64 offset, u64 len, u8 opt, u8 resp,
	 u64 user_data, const void *val)
{
	switch (len) {
	case 0:
		break;
	case 1:
		cmd->size_exponent = IOREGIONFD_SIZE_8BIT;
		break;
	case 2:
		cmd->size_exponent = IOREGIONFD_SIZE_16BIT;
		break;
	case 4:
		cmd->size_exponent = IOREGIONFD_SIZE_32BIT;
		break;
	case 8:
		cmd->size_exponent = IOREGIONFD_SIZE_64BIT;
		break;
	default:
		return false;
	}

	if (val)
		memcpy(&cmd->data, val, len);
	cmd->user_data = user_data;
	cmd->offset = offset;
	cmd->cmd = opt;
	cmd->resp = resp;

	return true;
}

enum {
	SEND_CMD,
	GET_REPLY,
	COMPLETE
};

static void
ioregion_save_ctx(struct kvm_vcpu *vcpu, bool in, gpa_t addr, u8 state, void *val)
{
	vcpu->ioregion_ctx.is_interrupted = true;
	vcpu->ioregion_ctx.val = val;
	vcpu->ioregion_ctx.state = state;
	vcpu->ioregion_ctx.addr = addr;
	vcpu->ioregion_ctx.in = in;
}

static inline void
ioregion_lock_ctx(struct ioregionfd *ctx)
{
	if (!ctx)
		return;

	spin_lock(&ctx->wq.lock);
	wait_event_interruptible_exclusive_locked(ctx->wq, !ctx->busy);
	ctx->busy = true;
	spin_unlock(&ctx->wq.lock);
}

static inline void
ioregion_unlock_ctx(struct ioregionfd *ctx)
{
	if (!ctx)
		return;

	spin_lock(&ctx->wq.lock);
	ctx->busy = false;
	wake_up_locked(&ctx->wq);
	spin_unlock(&ctx->wq.lock);
}

static int
ioregion_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this, gpa_t addr,
	      int len, void *val)
{
	struct ioregion *p = to_ioregion(this);
	union {
		struct ioregionfd_cmd cmd;
		struct ioregionfd_resp resp;
	} buf;
	int ret = 0;
	int state = SEND_CMD;

	if (unlikely(vcpu->ioregion_ctx.is_interrupted)) {
		vcpu->ioregion_ctx.is_interrupted = false;

		switch (vcpu->ioregion_ctx.state) {
		case SEND_CMD:
			goto send_cmd;
		case GET_REPLY:
			goto get_repl;
		default:
			return -EINVAL;
		}
	}

	ioregion_lock_ctx(p->ctx);

send_cmd:
	memset(&buf, 0, sizeof(buf));
	if (!pack_cmd(&buf.cmd, addr - p->paddr, len, IOREGIONFD_CMD_READ,
		      1, p->user_data, NULL)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = kernel_write(p->wf, &buf.cmd, sizeof(buf.cmd), 0);
	state = (ret == sizeof(buf.cmd)) ? GET_REPLY : SEND_CMD;
	if (signal_pending(current) && state == SEND_CMD) {
		ioregion_save_ctx(vcpu, 1, addr, state, val);
		return -EINTR;
	}
	if (ret != sizeof(buf.cmd)) {
		ret = (ret < 0) ? ret : -EIO;
		ret = (ret == -EAGAIN || ret == -EWOULDBLOCK) ? -EINVAL : ret;
		goto out;
	}
	if (!p->ctx)
		return 0;

get_repl:
	memset(&buf, 0, sizeof(buf));
	ret = kernel_read(p->ctx->rf, &buf.resp, sizeof(buf.resp), 0);
	state = (ret == sizeof(buf.resp)) ? COMPLETE : GET_REPLY;
	if (signal_pending(current) && state == GET_REPLY) {
		ioregion_save_ctx(vcpu, 1, addr, state, val);
		return -EINTR;
	}
	if (ret != sizeof(buf.resp)) {
		ret = (ret < 0) ? ret : -EIO;
		ret = (ret == -EAGAIN || ret == -EWOULDBLOCK) ? -EINVAL : ret;
		goto out;
	}

	memcpy(val, &buf.resp.data, len);
	ret = 0;

out:
	ioregion_unlock_ctx(p->ctx);

	return ret;
}

static int
ioregion_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this, gpa_t addr,
		int len, const void *val)
{
	struct ioregion *p = to_ioregion(this);
	union {
		struct ioregionfd_cmd cmd;
		struct ioregionfd_resp resp;
	} buf;
	int ret = 0;
	int state = SEND_CMD;

	if (unlikely(vcpu->ioregion_ctx.is_interrupted)) {
		vcpu->ioregion_ctx.is_interrupted = false;

		switch (vcpu->ioregion_ctx.state) {
		case SEND_CMD:
			goto send_cmd;
		case GET_REPLY:
			goto get_repl;
		default:
			return -EINVAL;
		}
	}

	ioregion_lock_ctx(p->ctx);

send_cmd:
	memset(&buf, 0, sizeof(buf));
	if (!pack_cmd(&buf.cmd, addr - p->paddr, len, IOREGIONFD_CMD_WRITE,
		      p->posted_writes ? 0 : 1, p->user_data, val)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = kernel_write(p->wf, &buf.cmd, sizeof(buf.cmd), 0);
	state = (ret == sizeof(buf.cmd)) ? GET_REPLY : SEND_CMD;
	if (signal_pending(current) && state == SEND_CMD) {
		ioregion_save_ctx(vcpu, 0, addr, state, (void *)val);
		return -EINTR;
	}
	if (ret != sizeof(buf.cmd)) {
		ret = (ret < 0) ? ret : -EIO;
		ret = (ret == -EAGAIN || ret == -EWOULDBLOCK) ? -EINVAL : ret;
		goto out;
	}

get_repl:
	if (!p->posted_writes) {
		memset(&buf, 0, sizeof(buf));
		ret = kernel_read(p->ctx->rf, &buf.resp, sizeof(buf.resp), 0);
		state = (ret == sizeof(buf.resp)) ? COMPLETE : GET_REPLY;
		if (signal_pending(current) && state == GET_REPLY) {
			ioregion_save_ctx(vcpu, 0, addr, state, (void *)val);
			return -EINTR;
		}
		if (ret != sizeof(buf.resp)) {
			ret = (ret < 0) ? ret : -EIO;
			ret = (ret == -EAGAIN || ret == -EWOULDBLOCK) ? -EINVAL : ret;
			goto out;
		}
	}
	ret = 0;

out:
	ioregion_unlock_ctx(p->ctx);

	return ret;
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
	if (bus_idx == KVM_PIO_BUS)
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

/* assumes kvm->slots_lock held */
static bool
ioregion_get_ctx(struct kvm *kvm, struct ioregion *p, struct file *rf, int bus_idx)
{
	struct ioregion *_p;
	struct list_head *ioregions;

	ioregions = get_ioregion_list(kvm, bus_idx);
	list_for_each_entry(_p, ioregions, list)
		if (file_inode(_p->ctx->rf)->i_ino == file_inode(rf)->i_ino) {
			p->ctx = _p->ctx;
			kref_get(&p->ctx->kref);
			return true;
		}

	p->ctx = kzalloc(sizeof(*p->ctx), GFP_KERNEL_ACCOUNT);
	if (!p->ctx)
		return false;

	p->ctx->rf = rf;
	p->ctx->busy = false;
	init_waitqueue_head(&p->ctx->wq);
	kref_get(&p->ctx->kref);

	return true;
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
	p->wf = wfile;
	p->paddr = args->guest_paddr;
	p->size = args->memory_size;
	p->user_data = args->user_data;
	p->posted_writes = args->flags & KVM_IOREGION_POSTED_WRITES;

	mutex_lock(&kvm->slots_lock);

	if (ioregion_collision(kvm, p, bus_idx)) {
		ret = -EEXIST;
		goto unlock_fail;
	}

	if (rfile && !ioregion_get_ctx(kvm, p, rfile, bus_idx)) {
		ret = -ENOMEM;
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
	if (p->ctx)
		kref_put(&p->ctx->kref, ctx_free);
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

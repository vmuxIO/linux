// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/list.h>
#include <kvm/iodev.h>

/* Wire protocol */
struct ioregionfd_cmd {
	__u32 info;
	__u32 padding;
	__u64 user_data;
	__u64 offset;
	__u64 data;
};

struct ioregionfd_resp {
	__u64 data;
	__u8 pad[24];
};

#define IOREGIONFD_CMD_READ    0
#define IOREGIONFD_CMD_WRITE   1

#define IOREGIONFD_SIZE_8BIT   0
#define IOREGIONFD_SIZE_16BIT  1
#define IOREGIONFD_SIZE_32BIT  2
#define IOREGIONFD_SIZE_64BIT  3

#define IOREGIONFD_SIZE_OFFSET 4
#define IOREGIONFD_RESP_OFFSET 6
#define IOREGIONFD_SIZE(x) ((x) << IOREGIONFD_SIZE_OFFSET)
#define IOREGIONFD_RESP(x) ((x) << IOREGIONFD_RESP_OFFSET)

void
kvm_ioregionfd_init(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->ioregions_mmio);
	INIT_LIST_HEAD(&kvm->ioregions_pio);
}

/* serialize ioregionfd cmds/replies in case
 * different ioregions use same rfd
 */
struct ioregionfd {
	struct file          *rd;
	struct mutex         mutex;
	struct kref          kref;
};

struct ioregion {
	struct list_head     list;
	u64                  paddr;
	u64                  size;
	struct file          *wf;
	u64                  user_data;
	struct kvm_io_device dev;
	bool                 posted_writes;
	struct ioregionfd    *ctx;
};

static inline struct list_head *
get_ioregion_list(struct kvm *kvm, enum kvm_bus bus_idx)
{
	return (bus_idx == KVM_MMIO_BUS) ?
		&kvm->ioregions_mmio : &kvm->ioregions_pio;
}

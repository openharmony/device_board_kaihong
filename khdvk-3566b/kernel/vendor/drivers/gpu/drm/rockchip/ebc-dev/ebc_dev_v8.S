// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Rockchip Electronics Co. Ltd.
 *
 * Author: Zorro Liu <zorro.liu@rock-chips.com>
 */

	.arch armv8-a
	.file	"ebc_dev.c"
	.text
.Ltext0:
	.cfi_sections	.debug_frame
#APP
	.section	".initcall6s.init", "a"	
__initcall_ebc_init6s:			
.long	ebc_init - .			
.previous					

#NO_APP
	.align	2
	.p2align 3,,7
	.type	get_auto_image, %function
get_auto_image:
.LFB2810:
	.file 1 "drivers/gpu/drm/rockchip/ebc-dev/ebc_dev.c"
	.loc 1 363 0
	.cfi_startproc
.LVL0:
	.loc 1 364 0
	adrp	x5, .LANCHOR0
	.loc 1 372 0
	ldrb	w13, [x4, 36]
.LVL1:
	.loc 1 364 0
	ldr	x16, [x5, #:lo12:.LANCHOR0]
	.loc 1 376 0
	add	x16, x16, 24
	ldr	w18, [x16, 156]
	.loc 1 379 0
	ldp	w10, w17, [x16, 84]
	.loc 1 381 0
	str	wzr, [x4, 40]
.LVL2:
	.loc 1 387 0
	cmp	w17, 0
	ble	.L69
	lsr	w10, w10, 4
.LVL3:
	.loc 1 363 0
	stp	x29, x30, [sp, -80]!
	.cfi_def_cfa_offset 80
	.cfi_offset 29, -80
	.cfi_offset 30, -72
	sub	w15, w10, #1
	.loc 1 387 0
	mov	w14, 0
.LVL4:
	add	x15, x15, 1
	.loc 1 363 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	lsl	x15, x15, 3
	stp	x19, x20, [sp, 16]
	.loc 1 397 0
	mov	w12, 1
	.loc 1 363 0
	stp	x21, x22, [sp, 32]
	.loc 1 400 0
	mov	x11, 72340172838076673
	.loc 1 363 0
	stp	x23, x24, [sp, 48]
.LBB803:
.LBB804:
	.loc 1 144 0
	mov	w9, 3
.LBE804:
.LBE803:
	.loc 1 363 0
	str	x25, [sp, 64]
	.cfi_offset 19, -64
	.cfi_offset 20, -56
	.cfi_offset 21, -48
	.cfi_offset 22, -40
	.cfi_offset 23, -32
	.cfi_offset 24, -24
	.cfi_offset 25, -16
.LVL5:
	.p2align 2
.L31:
	.loc 1 388 0
	cbz	w18, .L3
	.loc 1 389 0
	ldp	w5, w8, [x16, 84]
.LVL6:
	sub	w8, w8, #1
	sub	w8, w8, w14
	mul	w8, w8, w5
	lsr	w8, w8, 2
	add	x8, x0, x8
.LVL7:
.L6:
	add	x8, x8, 4
.LVL8:
	add	x20, x3, 8
	.loc 1 393 0 discriminator 1
	mov	x19, 0
	cbnz	w10, .L65
	b	.L5
	.p2align 3
.L75:
	.loc 1 397 0
	str	w12, [x4, 40]
	.loc 1 399 0
	ldr	x7, [x4, 112]
.LVL9:
	.loc 1 398 0
	ldr	x22, [x20, -8]
.LVL10:
	.loc 1 400 0
	add	x21, x22, x11
	.loc 1 399 0
	ubfiz	x22, x22, 16, 8
	.loc 1 401 0
	cmp	w13, w21, uxtb
	.loc 1 399 0
	add	x7, x7, x22
.LVL11:
	.loc 1 401 0
	beq	.L73
.L8:
	.loc 1 406 0
	and	w23, w6, 65535
	and	w22, w5, 65535
.LBB806:
.LBB807:
	.loc 1 142 0
	mov	w30, 0
	.loc 1 141 0
	cmp	w23, w22
	beq	.L9
	.loc 1 139 0
	eor	w24, w23, w22
.LVL12:
	.loc 1 152 0
	ubfiz	w25, w23, 8, 8
	.loc 1 153 0
	and	w23, w23, 65280
	.loc 1 152 0
	add	w25, w25, w22, uxtb
	.loc 1 144 0
	tst	x24, 15
	.loc 1 153 0
	add	w22, w23, w22, lsr 8
	.loc 1 144 0
	csel	w30, wzr, w9, eq
	.loc 1 146 0
	tst	w24, 240
	orr	w23, w30, 12
	.loc 1 152 0
	ldrb	w25, [x7, w25, sxtw]
	.loc 1 146 0
	csel	w30, w23, w30, ne
	.loc 1 148 0
	tst	w24, 3840
	orr	w23, w30, 48
	.loc 1 153 0
	ldrb	w22, [x7, w22, sxtw]
	.loc 1 148 0
	csel	w30, w23, w30, ne
	.loc 1 150 0
	tst	w24, 61440
	orr	w23, w30, -64
	and	w23, w23, 255
	.loc 1 152 0
	orr	w22, w25, w22, lsl 4
	.loc 1 150 0
	csel	w30, w23, w30, ne
	.loc 1 152 0
	and	w30, w22, w30
	and	w30, w30, 255
.LVL13:
.L9:
.LBE807:
.LBE806:
	.loc 1 406 0
	strb	w30, [x8, -4]
	.loc 1 407 0
	lsr	w23, w6, 16
	lsr	w22, w5, 16
.LBB808:
.LBB809:
	.loc 1 142 0
	mov	w30, 0
	.loc 1 141 0
	cmp	w23, w22
	beq	.L14
	.loc 1 139 0
	eor	w24, w23, w22
.LVL14:
	.loc 1 152 0
	ubfiz	w25, w23, 8, 8
	.loc 1 153 0
	and	w23, w23, 65280
	.loc 1 152 0
	add	w25, w25, w22, uxtb
	.loc 1 144 0
	tst	x24, 15
	.loc 1 153 0
	add	w22, w23, w22, lsr 8
	.loc 1 144 0
	csel	w30, wzr, w9, eq
	.loc 1 146 0
	tst	w24, 240
	orr	w23, w30, 12
	.loc 1 152 0
	ldrb	w25, [x7, w25, sxtw]
	.loc 1 146 0
	csel	w30, w23, w30, ne
	.loc 1 148 0
	tst	w24, 3840
	orr	w23, w30, 48
	.loc 1 153 0
	ldrb	w22, [x7, w22, sxtw]
	.loc 1 148 0
	csel	w30, w23, w30, ne
	.loc 1 150 0
	tst	w24, 61440
	orr	w23, w30, -64
	and	w23, w23, 255
	.loc 1 152 0
	orr	w22, w25, w22, lsl 4
	.loc 1 150 0
	csel	w30, w23, w30, ne
	.loc 1 152 0
	and	w30, w22, w30
	and	w30, w30, 255
.LVL15:
.L14:
.LBE809:
.LBE808:
	.loc 1 407 0
	strb	w30, [x8, -3]
	.loc 1 408 0
	ubfx	x23, x6, 32, 16
	ubfx	x22, x5, 32, 16
.LBB810:
.LBB811:
	.loc 1 142 0
	mov	w30, 0
	.loc 1 141 0
	cmp	w23, w22
	beq	.L19
	.loc 1 139 0
	eor	w24, w23, w22
.LVL16:
	.loc 1 152 0
	ubfiz	w25, w23, 8, 8
	.loc 1 153 0
	and	w23, w23, 65280
	.loc 1 152 0
	add	w25, w25, w22, uxtb
	.loc 1 144 0
	tst	x24, 15
	.loc 1 153 0
	add	w22, w23, w22, lsr 8
	.loc 1 144 0
	csel	w30, wzr, w9, eq
	.loc 1 146 0
	tst	w24, 240
	orr	w23, w30, 12
	.loc 1 152 0
	ldrb	w25, [x7, w25, sxtw]
	.loc 1 146 0
	csel	w30, w23, w30, ne
	.loc 1 148 0
	tst	w24, 3840
	orr	w23, w30, 48
	.loc 1 153 0
	ldrb	w22, [x7, w22, sxtw]
	.loc 1 148 0
	csel	w30, w23, w30, ne
	.loc 1 150 0
	tst	w24, 61440
	orr	w23, w30, -64
	and	w23, w23, 255
	.loc 1 152 0
	orr	w22, w25, w22, lsl 4
	.loc 1 150 0
	csel	w30, w23, w30, ne
	.loc 1 152 0
	and	w30, w22, w30
	and	w30, w30, 255
.LVL17:
.L19:
.LBE811:
.LBE810:
	.loc 1 408 0
	strb	w30, [x8, -2]
	.loc 1 409 0
	lsr	x6, x6, 48
.LVL18:
	lsr	x5, x5, 48
.LVL19:
.LBB812:
.LBB805:
	.loc 1 142 0
	mov	w30, 0
	.loc 1 141 0
	cmp	w6, w5
	beq	.L24
	.loc 1 139 0
	eor	w22, w6, w5
.LVL20:
	.loc 1 152 0
	ubfiz	w23, w6, 8, 8
	.loc 1 153 0
	and	w6, w6, 65280
	.loc 1 152 0
	add	w23, w23, w5, uxtb
	.loc 1 144 0
	tst	x22, 15
	.loc 1 153 0
	add	w5, w6, w5, lsr 8
	.loc 1 144 0
	csel	w6, wzr, w9, eq
	.loc 1 146 0
	tst	w22, 240
	orr	w24, w6, 12
.LVL21:
	.loc 1 152 0
	ldrb	w23, [x7, w23, sxtw]
	.loc 1 146 0
	csel	w6, w24, w6, ne
	.loc 1 148 0
	tst	w22, 3840
	orr	w24, w6, 48
	.loc 1 153 0
	ldrb	w30, [x7, w5, sxtw]
	.loc 1 148 0
	csel	w6, w24, w6, ne
	.loc 1 150 0
	tst	w22, 61440
	orr	w5, w6, -64
	and	w5, w5, 255
	.loc 1 152 0
	orr	w30, w23, w30, lsl 4
	.loc 1 150 0
	csel	w6, w5, w6, ne
	.loc 1 152 0
	and	w6, w30, w6
	and	w30, w6, 255
.LVL22:
.L24:
.LBE805:
.LBE812:
	.loc 1 409 0
	strb	w30, [x8, -1]
	add	x19, x19, 1
	.loc 1 410 0
	str	x21, [x20, -8]
	add	x8, x8, 4
	add	x20, x20, 8
	.loc 1 393 0
	cmp	w10, w19
	ble	.L74
.LVL23:
.L65:
	.loc 1 394 0
	ldr	x5, [x1, x19, lsl 3]
	.loc 1 395 0
	ldr	x6, [x2, x19, lsl 3]
	.loc 1 396 0
	cmp	x5, x6
	bne	.L75
	.loc 1 413 0
	str	wzr, [x8, -4]
	add	x19, x19, 1
	add	x8, x8, 4
	add	x20, x20, 8
	.loc 1 393 0
	cmp	w10, w19
	bgt	.L65
.L74:
	add	x3, x3, x15
.LVL24:
	add	x2, x2, x15
.LVL25:
	add	x1, x1, x15
.LVL26:
.L5:
	.loc 1 387 0 discriminator 2
	add	w14, w14, 1
	cmp	w17, w14
	bne	.L31
	.loc 1 421 0
	ldp	x19, x20, [sp, 16]
	ldp	x21, x22, [sp, 32]
.LVL27:
	ldp	x23, x24, [sp, 48]
.LVL28:
	ldr	x25, [sp, 64]
	ldp	x29, x30, [sp], 80
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 25
	.cfi_restore 23
	.cfi_restore 24
	.cfi_restore 21
	.cfi_restore 22
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL29:
	.p2align 3
.L73:
	.cfi_restore_state
	.loc 1 403 0
	str	x5, [x2, x19, lsl 3]
	.loc 1 402 0
	mov	x21, 0
	b	.L8
.LVL30:
	.p2align 3
.L3:
	.loc 1 391 0
	ldr	w8, [x16, 84]
	mul	w8, w14, w8
	lsr	w8, w8, 2
	add	x8, x0, x8
.LVL31:
	b	.L6
.LVL32:
.L69:
	.cfi_def_cfa 31, 0
	.cfi_restore 19
	.cfi_restore 20
	.cfi_restore 21
	.cfi_restore 22
	.cfi_restore 23
	.cfi_restore 24
	.cfi_restore 25
	.cfi_restore 29
	.cfi_restore 30
	ret
	.cfi_endproc
.LFE2810:
	.size	get_auto_image, .-get_auto_image
	.align	2
	.p2align 3,,7
	.type	ebc_open, %function
ebc_open:
.LFB2827:
	.loc 1 1322 0
	.cfi_startproc
.LVL33:
	.loc 1 1326 0
	mov	w0, 0
.LVL34:
	.loc 1 1323 0
	str	xzr, [x1, 104]
	.loc 1 1326 0
	ret
	.cfi_endproc
.LFE2827:
	.size	ebc_open, .-ebc_open
	.section	.exit.text,"ax",@progbits
	.align	2
	.type	ebc_exit, %function
ebc_exit:
.LFB2846:
	.loc 1 1874 0
	.cfi_startproc
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	.loc 1 1875 0
	adrp	x0, .LANCHOR1
	add	x0, x0, :lo12:.LANCHOR1
	.loc 1 1874 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1875 0
	bl	platform_driver_unregister
.LVL35:
	.loc 1 1876 0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2846:
	.size	ebc_exit, .-ebc_exit
	.text
	.align	2
	.p2align 3,,7
	.type	ebc_resume, %function
ebc_resume:
.LFB2844:
	.loc 1 1836 0
	.cfi_startproc
.LVL36:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	str	x19, [sp, 16]
	.cfi_offset 19, -16
.LBB813:
.LBB814:
	.file 2 "./include/linux/device.h"
	.loc 2 1181 0
	ldr	x19, [x0, 184]
.LBE814:
.LBE813:
	.loc 1 1840 0
	ldr	x1, [x19, 16]
.LBB815:
.LBB816:
	.file 3 "drivers/gpu/drm/rockchip/ebc-dev/pmic/ebc_pmic.h"
	.loc 3 45 0
	mov	x0, x1
.LVL37:
	ldr	x1, [x1, 48]
	blr	x1
.LVL38:
.LBE816:
.LBE815:
	.loc 1 1841 0
	str	wzr, [x19, 780]
	.loc 1 1842 0
	ldr	x0, [x19, 272]
	adrp	x1, .LC0
	add	x1, x1, :lo12:.LC0
	bl	_dev_info
.LVL39:
	.loc 1 1845 0
	ldr	x19, [sp, 16]
	mov	w0, 0
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2844:
	.size	ebc_resume, .-ebc_resume
	.align	2
	.p2align 3,,7
	.type	ebc_vdd_power_timeout, %function
ebc_vdd_power_timeout:
.LFB2822:
	.loc 1 1076 0
	.cfi_startproc
.LVL40:
	.loc 1 1077 0
	adrp	x0, .LANCHOR0
.LVL41:
	ldr	x0, [x0, #:lo12:.LANCHOR0]
	.loc 1 1079 0
	ldr	w2, [x0, 608]
	cbnz	w2, .L90
	ret
	.p2align 3
.L90:
	.loc 1 1076 0
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
.LBB817:
.LBB818:
	.file 4 "./include/linux/wakelock.h"
	.loc 4 68 0
	add	x0, x0, 400
.LBE818:
.LBE817:
	.loc 1 1076 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1080 0
	str	wzr, [x0, 208]
.LBB820:
.LBB819:
	.loc 4 68 0
	bl	__pm_relax
.LVL42:
.LBE819:
.LBE820:
	.loc 1 1085 0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2822:
	.size	ebc_vdd_power_timeout, .-ebc_vdd_power_timeout
	.align	2
	.p2align 3,,7
	.type	ebc_remove, %function
ebc_remove:
.LFB2842:
	.loc 1 1812 0
	.cfi_startproc
.LVL43:
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	.loc 1 1813 0
	adrp	x0, .LANCHOR1
.LVL44:
	add	x0, x0, :lo12:.LANCHOR1
	.loc 1 1812 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1813 0
	add	x0, x0, 224
	.loc 1 1812 0
	.loc 1 1813 0
	bl	misc_deregister
.LVL45:
	.loc 1 1816 0
	mov	w0, 0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2842:
	.size	ebc_remove, .-ebc_remove
	.align	2
	.p2align 3,,7
	.type	ebc_mmap, %function
ebc_mmap:
.LFB2826:
	.loc 1 1306 0
	.cfi_startproc
.LVL46:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	str	x19, [sp, 16]
	.cfi_offset 19, -16
	.loc 1 1306 0
	mov	x19, x1
	.loc 1 1309 0
	bl	ebc_phy_buf_base_get
.LVL47:
	.loc 1 1313 0
	lsr	x2, x0, 12
	.loc 1 1310 0
	mov	x7, -29
	.loc 1 1311 0
	mov	x6, 16384
	ldp	x4, x5, [x19, 72]
	.loc 1 1310 0
	movk	x7, 0xff9f, lsl 48
	.loc 1 1313 0
	ldp	x1, x3, [x19]
	.loc 1 1311 0
	movk	x6, 0x404, lsl 16
	.loc 1 1310 0
	and	x4, x4, x7
	.loc 1 1311 0
	orr	x5, x5, x6
	.loc 1 1310 0
	orr	x4, x4, 27021597764222976
	.loc 1 1311 0
	stp	x4, x5, [x19, 72]
	.loc 1 1313 0
	sub	x3, x3, x1
	mov	x0, x19
	bl	remap_pfn_range
.LVL48:
	.loc 1 1316 0
	cmp	w0, 0
	mov	w1, -11
	.loc 1 1319 0
	ldr	x19, [sp, 16]
.LVL49:
	csel	w0, w0, w1, eq
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2826:
	.size	ebc_mmap, .-ebc_mmap
	.align	2
	.p2align 3,,7
	.type	ebc_io_ctl, %function
ebc_io_ctl:
.LFB2825:
	.loc 1 1161 0
	.cfi_startproc
.LVL50:
	stp	x29, x30, [sp, -160]!
	.cfi_def_cfa_offset 160
	.cfi_offset 29, -160
	.cfi_offset 30, -152
	.loc 1 1171 0
	cmp	w1, 28672
	.loc 1 1161 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -144
	.cfi_offset 20, -136
	adrp	x19, __stack_chk_guard
	stp	x21, x22, [sp, 32]
	add	x0, x19, :lo12:__stack_chk_guard
.LVL51:
	str	x23, [sp, 48]
	.cfi_offset 21, -128
	.cfi_offset 22, -120
	.cfi_offset 23, -112
	.loc 1 1161 0
	mov	x21, x2
	ldr	x3, [x0]
	str	x3, [x29, 152]
	mov	x3,0
	.loc 1 1163 0
	adrp	x0, .LANCHOR0
	ldr	x20, [x0, #:lo12:.LANCHOR0]
	.loc 1 1171 0
	bcc	.L98
	mov	w0, 28675
	cmp	w1, w0
	bls	.L99
	mov	w0, -28678
	add	w0, w1, w0
	cmp	w0, 1
	bls	.L99
.L98:
	.loc 1 1187 0
	mov	w0, 28675
	cmp	w1, w0
	beq	.L102
	bls	.L176
	mov	w0, 28677
	cmp	w1, w0
	beq	.L107
	bcc	.L108
	mov	w0, 28678
	cmp	w1, w0
	beq	.L109
	mov	w0, 28679
	cmp	w1, w0
	bne	.L101
.LBB821:
.LBB822:
.LBB823:
.LBB824:
.LBB825:
.LBB826:
.LBB827:
	.file 5 "./arch/arm64/include/asm/current.h"
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x0, sp_el0
// 0 "" 2
.LVL52:
#NO_APP
.LBE827:
.LBE826:
	.file 6 "./arch/arm64/include/asm/uaccess.h"
	.loc 6 85 0
	ldr	w2, [x0, 52]
	.loc 6 77 0
	ldr	x1, [x0, 8]
.LVL53:
	.loc 6 84 0
	tbnz	x2, 21, .L133
.LBB828:
.LBB829:
.LBB830:
	.file 7 "./include/asm-generic/bitops/non-atomic.h"
	.loc 7 106 0
	ldr	x2, [x0]
.LBE830:
.LBE829:
.LBE828:
.LBE825:
.LBE824:
.LBE823:
.LBE822:
.LBE821:
	.loc 1 1162 0
	mov	x0, x21
.LVL54:
.LBB850:
.LBB848:
.LBB846:
.LBB836:
.LBB834:
	.loc 6 84 0
	tbnz	x2, 26, .L133
.L134:
.LVL55:
	.loc 6 89 0
#APP
// 89 "./arch/arm64/include/asm/uaccess.h" 1
		adds	x0, x0, 44
	csel	x1, xzr, x1, hi
	csinv	x0, x0, xzr, cc
	sbcs	xzr, x0, x1
	cset	x0, ls

// 0 "" 2
.LVL56:
#NO_APP
.LBE834:
.LBE836:
	.file 8 "./include/linux/uaccess.h"
	.loc 8 114 0
	cbz	x0, .L175
.LBB837:
.LBB838:
.LBB839:
.LBB840:
.LBB841:
	.file 9 "./include/linux/bitops.h"
	.loc 9 157 0
	sbfx	x0, x21, 0, 56
.LVL57:
.LBE841:
.LBE840:
.LBE839:
.LBB842:
.LBB843:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x1, sp_el0
// 0 "" 2
.LVL58:
#NO_APP
.LBE843:
.LBE842:
.LBB844:
	.loc 6 254 0
	and	x0, x0, x21
.LVL59:
.LBE844:
	.loc 6 249 0
	ldr	x2, [x1, 8]
#APP
// 249 "./arch/arm64/include/asm/uaccess.h" 1
		bics	xzr, x0, x2
	csel	x1, x21, xzr, eq

// 0 "" 2
.LVL60:
	.loc 6 257 0
// 257 "./arch/arm64/include/asm/uaccess.h" 1
	hint #20
// 0 "" 2
#NO_APP
.LBE838:
.LBE837:
	.loc 8 116 0
	mov	x2, 44
	add	x0, x29, 104
.LVL61:
	bl	__arch_copy_from_user
.LVL62:
	.loc 8 118 0
	cbnz	x0, .L175
.LBE846:
.LBE848:
.LBE850:
	.loc 1 1252 0
	bl	ebc_osd_buf_clone
.LVL63:
	mov	x1, x0
	.loc 1 1253 0
	cbz	x0, .L174
	.loc 1 1254 0
	ldr	w6, [x29, 108]
	.loc 1 1263 0
	add	x20, x20, 184
	.loc 1 1258 0
	ldp	w5, w3, [x29, 124]
	.loc 1 1254 0
	str	w6, [x1, 40]
	.loc 1 1259 0
	ldp	w4, w2, [x29, 132]
	.loc 1 1258 0
	stp	w5, w3, [x1, 48]
	.loc 1 1259 0
	stp	w4, w2, [x1, 56]
	.loc 1 1261 0
	bl	ebc_add_to_dsp_buf_list
.LVL64:
	.loc 1 1263 0
	ldr	w0, [x20, 80]
	cbz	w0, .L177
.LVL65:
	.p2align 2
.L174:
	.loc 1 1284 0
	mov	x0, 0
.LVL66:
.L97:
	.loc 1 1303 0
	add	x19, x19, :lo12:__stack_chk_guard
	ldr	x2, [x29, 152]
	ldr	x1, [x19]
	eor	x1, x2, x1
.LVL67:
	cbnz	x1, .L178
	ldp	x19, x20, [sp, 16]
	ldp	x21, x22, [sp, 32]
.LVL68:
	ldr	x23, [sp, 48]
	ldp	x29, x30, [sp], 160
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 23
	.cfi_restore 21
	.cfi_restore 22
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL69:
	.p2align 3
.L99:
	.cfi_restore_state
	.loc 1 1178 0
	cbnz	x21, .L98
	.loc 1 1179 0
	ldr	x0, [x20, 272]
	adrp	x2, .LANCHOR2
	adrp	x1, .LC1
.LVL70:
	add	x2, x2, :lo12:.LANCHOR2
	add	x1, x1, :lo12:.LC1
	bl	_dev_err
.LVL71:
	.loc 1 1180 0
	mov	x0, -14
	b	.L97
.LVL72:
	.p2align 3
.L176:
	.loc 1 1187 0
	mov	w0, 28673
	cmp	w1, w0
	beq	.L104
	bhi	.L105
	cmp	w1, 28672
	bne	.L101
	.loc 1 1203 0
	bl	ebc_empty_buf_get
.LVL73:
	mov	x23, x0
	.loc 1 1204 0
	cbz	x0, .L116
	.loc 1 1207 0
	ldr	x22, [x0, 8]
	bl	ebc_phy_buf_base_get
.LVL74:
.LBB851:
.LBB852:
.LBB853:
.LBB854:
.LBB855:
.LBB856:
.LBB857:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x2, sp_el0
// 0 "" 2
.LVL75:
#NO_APP
.LBE857:
.LBE856:
	.loc 6 85 0
	ldr	w3, [x2, 52]
.LBE855:
.LBE854:
.LBE853:
.LBE852:
.LBE851:
	.loc 1 1207 0
	sub	w0, w22, w0
	.loc 1 1212 0
	ldr	w1, [x20, 176]
	.loc 1 1211 0
	ldp	w5, w4, [x20, 108]
	.loc 1 1210 0
	stp	w4, w5, [x29, 112]
	.loc 1 1212 0
	str	w1, [x29, 120]
	.loc 1 1209 0
	str	w0, [x29, 104]
.LBB886:
.LBB882:
.LBB878:
.LBB867:
.LBB864:
	.loc 6 77 0
	ldr	x1, [x2, 8]
.LVL76:
	.loc 6 84 0
	tbnz	x3, 21, .L117
.LBB858:
.LBB859:
.LBB860:
	.loc 7 106 0
	ldr	x2, [x2]
.LVL77:
.LBE860:
.LBE859:
.LBE858:
.LBE864:
.LBE867:
.LBE878:
.LBE882:
.LBE886:
	.loc 1 1162 0
	mov	x0, x21
.LVL78:
.LBB887:
.LBB883:
.LBB879:
.LBB868:
.LBB865:
	.loc 6 84 0
	tbnz	x2, 26, .L117
.LVL79:
.L118:
	.loc 6 89 0
#APP
// 89 "./arch/arm64/include/asm/uaccess.h" 1
		adds	x0, x0, 44
	csel	x1, xzr, x1, hi
	csinv	x0, x0, xzr, cc
	sbcs	xzr, x0, x1
	cset	x0, ls

// 0 "" 2
.LVL80:
#NO_APP
.LBE865:
.LBE868:
	.loc 8 132 0
	cbnz	x0, .L119
.L120:
.LBE879:
.LBE883:
.LBE887:
	.loc 1 1216 0
	mov	x0, x23
.LVL81:
	bl	ebc_buf_release
.LVL82:
	.loc 1 1217 0
	mov	x0, -14
	b	.L97
.LVL83:
	.p2align 3
.L105:
.LBB888:
.LBB889:
.LBB890:
.LBB891:
.LBB892:
.LBB893:
.LBB894:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x2, sp_el0
// 0 "" 2
.LVL84:
#NO_APP
.LBE894:
.LBE893:
	.loc 6 85 0
	ldr	w3, [x2, 52]
.LBE892:
.LBE891:
.LBE890:
.LBE889:
.LBE888:
	.loc 1 1290 0
	ldp	w1, w0, [x20, 116]
.LVL85:
	stp	w1, w0, [x29, 140]
	.loc 1 1287 0
	ldp	w6, w5, [x20, 108]
	.loc 1 1286 0
	stp	w5, w6, [x29, 112]
	.loc 1 1288 0
	ldr	w4, [x20, 176]
	str	w4, [x29, 120]
.LBB923:
.LBB919:
.LBB915:
.LBB904:
.LBB901:
	.loc 6 77 0
	ldr	x1, [x2, 8]
.LVL86:
	.loc 6 84 0
	tbnz	x3, 21, .L140
.LBB895:
.LBB896:
.LBB897:
	.loc 7 106 0
	ldr	x2, [x2]
.LVL87:
.LBE897:
.LBE896:
.LBE895:
.LBE901:
.LBE904:
.LBE915:
.LBE919:
.LBE923:
	.loc 1 1162 0
	mov	x0, x21
.LVL88:
.LBB924:
.LBB920:
.LBB916:
.LBB905:
.LBB902:
	.loc 6 84 0
	tbnz	x2, 26, .L140
.LVL89:
.L141:
	.loc 6 89 0
#APP
// 89 "./arch/arm64/include/asm/uaccess.h" 1
		adds	x0, x0, 44
	csel	x1, xzr, x1, hi
	csinv	x0, x0, xzr, cc
	sbcs	xzr, x0, x1
	cset	x0, ls

// 0 "" 2
.LVL90:
#NO_APP
.LBE902:
.LBE905:
	.loc 8 132 0
	cbnz	x0, .L142
.L143:
.LBE916:
.LBE920:
.LBE924:
	.loc 1 1293 0
	ldr	x0, [x20, 272]
.LVL91:
	adrp	x1, .LC5
.LVL92:
	add	x1, x1, :lo12:.LC5
	bl	_dev_err
.LVL93:
.L175:
	.loc 1 1294 0
	mov	x0, -14
.LVL94:
	b	.L97
.LVL95:
	.p2align 3
.L109:
	.loc 1 1189 0
	bl	ebc_osd_buf_get
.LVL96:
	.loc 1 1190 0
	cbz	x0, .L116
	.loc 1 1193 0
	ldr	x22, [x0, 8]
	bl	ebc_phy_buf_base_get
.LVL97:
.LBB925:
.LBB926:
.LBB927:
.LBB928:
.LBB929:
.LBB930:
.LBB931:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x1, sp_el0
// 0 "" 2
.LVL98:
#NO_APP
.LBE931:
.LBE930:
	.loc 6 85 0
	ldr	w2, [x1, 52]
.LBE929:
.LBE928:
.LBE927:
.LBE926:
.LBE925:
	.loc 1 1193 0
	sub	w0, w22, w0
	.loc 1 1197 0
	ldp	w5, w4, [x20, 108]
	.loc 1 1195 0
	str	w0, [x29, 104]
	.loc 1 1198 0
	ldr	w3, [x20, 176]
	.loc 1 1196 0
	stp	w4, w5, [x29, 112]
	.loc 1 1198 0
	str	w3, [x29, 120]
.LBB954:
.LBB952:
.LBB950:
.LBB940:
.LBB938:
	.loc 6 77 0
	ldr	x0, [x1, 8]
.LVL99:
	.loc 6 84 0
	tbnz	x2, 21, .L112
.LBB932:
.LBB933:
.LBB934:
	.loc 7 106 0
	ldr	x2, [x1]
.LBE934:
.LBE933:
.LBE932:
.LBE938:
.LBE940:
.LBE950:
.LBE952:
.LBE954:
	.loc 1 1162 0
	mov	x1, x21
.LVL100:
.LBB955:
.LBB953:
.LBB951:
.LBB941:
.LBB939:
	.loc 6 84 0
	tbz	x2, 26, .L113
.LVL101:
.L112:
.LBB935:
.LBB936:
.LBB937:
	.loc 9 157 0
	sbfx	x1, x21, 0, 56
.LVL102:
.LBE937:
.LBE936:
	.loc 6 86 0
	and	x1, x1, x21
.LVL103:
.L113:
.LBE935:
	.loc 6 89 0
#APP
// 89 "./arch/arm64/include/asm/uaccess.h" 1
		adds	x1, x1, 44
	csel	x0, xzr, x0, hi
	csinv	x1, x1, xzr, cc
	sbcs	xzr, x1, x0
	cset	x1, ls

// 0 "" 2
.LVL104:
#NO_APP
.LBE939:
.LBE941:
	.loc 8 132 0
	mov	x0, 44
.LVL105:
	cbz	x1, .L97
.LBB942:
.LBB943:
.LBB944:
.LBB945:
.LBB946:
	.loc 9 157 0
	sbfx	x1, x21, 0, 56
.LVL106:
.LBE946:
.LBE945:
.LBE944:
.LBB947:
.LBB948:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x2, sp_el0
// 0 "" 2
.LVL107:
#NO_APP
.LBE948:
.LBE947:
.LBB949:
	.loc 6 254 0
	and	x1, x1, x21
.LVL108:
.LBE949:
	.loc 6 249 0
	ldr	x2, [x2, 8]
.LVL109:
#APP
// 249 "./arch/arm64/include/asm/uaccess.h" 1
		bics	xzr, x1, x2
	csel	x3, x21, xzr, eq

// 0 "" 2
.LVL110:
	.loc 6 257 0
// 257 "./arch/arm64/include/asm/uaccess.h" 1
	hint #20
// 0 "" 2
#NO_APP
.LBE943:
.LBE942:
	.loc 8 134 0
	mov	x2, x0
	add	x1, x29, 104
.LVL111:
	mov	x0, x3
	bl	__arch_copy_to_user
.LVL112:
	sxtw	x0, w0
	b	.L97
.LVL113:
	.p2align 3
.L140:
.LBE951:
.LBE953:
.LBE955:
.LBB956:
.LBB921:
.LBB917:
.LBB906:
.LBB903:
.LBB898:
.LBB899:
.LBB900:
	.loc 9 157 0
	sbfx	x0, x21, 0, 56
.LVL114:
.LBE900:
.LBE899:
	.loc 6 86 0
	and	x0, x0, x21
.LVL115:
	b	.L141
.LVL116:
	.p2align 3
.L133:
.LBE898:
.LBE903:
.LBE906:
.LBE917:
.LBE921:
.LBE956:
.LBB957:
.LBB849:
.LBB847:
.LBB845:
.LBB835:
.LBB831:
.LBB832:
.LBB833:
	.loc 9 157 0
	sbfx	x0, x21, 0, 56
.LVL117:
.LBE833:
.LBE832:
	.loc 6 86 0
	and	x0, x0, x21
.LVL118:
	b	.L134
.LVL119:
	.p2align 3
.L117:
.LBE831:
.LBE835:
.LBE845:
.LBE847:
.LBE849:
.LBE957:
.LBB958:
.LBB884:
.LBB880:
.LBB869:
.LBB866:
.LBB861:
.LBB862:
.LBB863:
	.loc 9 157 0
	sbfx	x0, x21, 0, 56
.LVL120:
.LBE863:
.LBE862:
	.loc 6 86 0
	and	x0, x0, x21
.LVL121:
	b	.L118
.LVL122:
	.p2align 3
.L102:
.LBE861:
.LBE866:
.LBE869:
.LBE880:
.LBE884:
.LBE958:
.LBB959:
.LBB960:
.LBB961:
.LBB962:
.LBB963:
.LBB964:
.LBB965:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x0, sp_el0
// 0 "" 2
.LVL123:
#NO_APP
.LBE965:
.LBE964:
	.loc 6 85 0
	ldr	w2, [x0, 52]
.LBE963:
.LBE962:
.LBE961:
.LBE960:
.LBE959:
	.loc 1 1279 0
	add	x22, x20, 236
.LBB994:
.LBB990:
.LBB986:
.LBB975:
.LBB972:
	.loc 6 77 0
	ldr	x1, [x0, 8]
.LVL124:
	.loc 6 84 0
	tbnz	x2, 21, .L136
.LBB966:
.LBB967:
.LBB968:
	.loc 7 106 0
	ldr	x2, [x0]
.LBE968:
.LBE967:
.LBE966:
.LBE972:
.LBE975:
.LBE986:
.LBE990:
.LBE994:
	.loc 1 1162 0
	mov	x0, x21
.LVL125:
.LBB995:
.LBB991:
.LBB987:
.LBB976:
.LBB973:
	.loc 6 84 0
	tbnz	x2, 26, .L136
.L137:
.LVL126:
	.loc 6 89 0
#APP
// 89 "./arch/arm64/include/asm/uaccess.h" 1
		adds	x0, x0, 4
	csel	x1, xzr, x1, hi
	csinv	x0, x0, xzr, cc
	sbcs	xzr, x0, x1
	cset	x0, ls

// 0 "" 2
.LVL127:
#NO_APP
	mov	x3, x0
.LBE973:
.LBE976:
	.loc 8 114 0
	cbz	x0, .L153
.LBB977:
.LBB978:
.LBB979:
.LBB980:
.LBB981:
	.loc 9 157 0
	sbfx	x0, x21, 0, 56
.LBE981:
.LBE980:
.LBE979:
.LBB982:
.LBB983:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x1, sp_el0
// 0 "" 2
.LVL128:
#NO_APP
.LBE983:
.LBE982:
.LBB984:
	.loc 6 254 0
	and	x0, x0, x21
.LVL129:
.LBE984:
	.loc 6 249 0
	ldr	x2, [x1, 8]
#APP
// 249 "./arch/arm64/include/asm/uaccess.h" 1
		bics	xzr, x0, x2
	csel	x1, x21, xzr, eq

// 0 "" 2
.LVL130:
	.loc 6 257 0
// 257 "./arch/arm64/include/asm/uaccess.h" 1
	hint #20
// 0 "" 2
#NO_APP
.LBE978:
.LBE977:
	.loc 8 116 0
	mov	x2, 4
	mov	x0, x22
.LVL131:
	bl	__arch_copy_from_user
.LVL132:
	.loc 8 118 0
	cbnz	x0, .L179
.LBE987:
.LBE991:
.LBE995:
	.loc 1 1283 0
	add	x20, x20, 184
	ldr	w2, [x20, 52]
	ldr	x0, [x20, 88]
.LVL133:
	adrp	x1, .LC7
	add	x1, x1, :lo12:.LC7
	bl	_dev_info
.LVL134:
	b	.L174
.LVL135:
	.p2align 3
.L136:
.LBB996:
.LBB992:
.LBB988:
.LBB985:
.LBB974:
.LBB969:
.LBB970:
.LBB971:
	.loc 9 157 0
	sbfx	x0, x21, 0, 56
.LVL136:
.LBE971:
.LBE970:
	.loc 6 86 0
	and	x0, x0, x21
.LVL137:
	b	.L137
.LVL138:
	.p2align 3
.L104:
.LBE969:
.LBE974:
.LBE985:
.LBE988:
.LBE992:
.LBE996:
.LBB997:
.LBB998:
.LBB999:
.LBB1000:
.LBB1001:
.LBB1002:
.LBB1003:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x0, sp_el0
// 0 "" 2
.LVL139:
#NO_APP
.LBE1003:
.LBE1002:
	.loc 6 85 0
	ldr	w2, [x0, 52]
	.loc 6 77 0
	ldr	x1, [x0, 8]
.LVL140:
	.loc 6 84 0
	tbnz	x2, 21, .L121
.LBB1004:
.LBB1005:
.LBB1006:
	.loc 7 106 0
	ldr	x2, [x0]
.LBE1006:
.LBE1005:
.LBE1004:
.LBE1001:
.LBE1000:
.LBE999:
.LBE998:
.LBE997:
	.loc 1 1162 0
	mov	x0, x21
.LVL141:
.LBB1026:
.LBB1024:
.LBB1022:
.LBB1012:
.LBB1010:
	.loc 6 84 0
	tbnz	x2, 26, .L121
.L122:
.LVL142:
	.loc 6 89 0
#APP
// 89 "./arch/arm64/include/asm/uaccess.h" 1
		adds	x0, x0, 44
	csel	x1, xzr, x1, hi
	csinv	x0, x0, xzr, cc
	sbcs	xzr, x0, x1
	cset	x0, ls

// 0 "" 2
.LVL143:
#NO_APP
.LBE1010:
.LBE1012:
	.loc 8 114 0
	cbz	x0, .L175
.LBB1013:
.LBB1014:
.LBB1015:
.LBB1016:
.LBB1017:
	.loc 9 157 0
	sbfx	x0, x21, 0, 56
.LVL144:
.LBE1017:
.LBE1016:
.LBE1015:
.LBB1018:
.LBB1019:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x1, sp_el0
// 0 "" 2
.LVL145:
#NO_APP
.LBE1019:
.LBE1018:
.LBB1020:
	.loc 6 254 0
	and	x0, x0, x21
.LVL146:
.LBE1020:
	.loc 6 249 0
	ldr	x2, [x1, 8]
#APP
// 249 "./arch/arm64/include/asm/uaccess.h" 1
		bics	xzr, x0, x2
	csel	x1, x21, xzr, eq

// 0 "" 2
.LVL147:
	.loc 6 257 0
// 257 "./arch/arm64/include/asm/uaccess.h" 1
	hint #20
// 0 "" 2
#NO_APP
.LBE1014:
.LBE1013:
	.loc 8 116 0
	mov	x2, 44
	add	x0, x29, 104
.LVL148:
	bl	__arch_copy_from_user
.LVL149:
	.loc 8 118 0
	cbnz	x0, .L175
.LBE1022:
.LBE1024:
.LBE1026:
	.loc 1 1225 0
	bl	ebc_phy_buf_base_get
.LVL150:
	ldrsw	x1, [x29, 104]
	.loc 1 1226 0
	add	x0, x1, x0
	bl	ebc_find_buf_by_phy_addr
.LVL151:
	mov	x21, x0
.LVL152:
	.loc 1 1227 0
	cbz	x0, .L174
	.loc 1 1228 0
	ldr	w5, [x29, 108]
	.loc 1 1237 0
	add	x20, x20, 184
	.loc 1 1232 0
	ldp	w4, w2, [x29, 124]
	.loc 1 1228 0
	str	w5, [x21, 40]
	.loc 1 1233 0
	ldp	w3, w1, [x29, 132]
	.loc 1 1232 0
	stp	w4, w2, [x21, 48]
	.loc 1 1233 0
	stp	w3, w1, [x21, 56]
	.loc 1 1235 0
	bl	ebc_add_to_dsp_buf_list
.LVL153:
	.loc 1 1237 0
	ldr	w0, [x20, 80]
	cbz	w0, .L180
.L126:
	.loc 1 1241 0
	ldr	w0, [x21, 40]
	cmp	w0, 15
	beq	.L181
	.loc 1 1241 0 is_stmt 0 discriminator 3
	cmp	w0, 17
	bne	.L174
.L128:
	.loc 1 1242 0 is_stmt 1
	mov	w0, 1
	str	w0, [x20, 188]
.LBB1027:
.LBB1028:
	.loc 1 1243 0
	mov	w1, 0
	add	x0, x29, 64
	bl	init_wait_entry
.LVL154:
	adrp	x0, .LANCHOR1
.LBB1029:
	add	x0, x0, :lo12:.LANCHOR1
	add	x21, x0, 328
	b	.L132
	.p2align 3
.L182:
.LVL155:
	.loc 1 1243 0 is_stmt 0 discriminator 5
	cbnz	x0, .L174
	.loc 1 1243 0 discriminator 7
	bl	schedule
.LVL156:
.L132:
	.loc 1 1243 0 discriminator 9
	add	x1, x29, 64
	mov	w2, 1
	mov	x0, x21
	bl	prepare_to_wait_event
.LVL157:
	ldr	w1, [x20, 188]
	cbnz	w1, .L182
.L131:
.LBE1029:
	.loc 1 1243 0 discriminator 4
	add	x1, x29, 64
	mov	x0, x21
	bl	finish_wait
.LVL158:
	b	.L174
.LVL159:
	.p2align 3
.L121:
.LBE1028:
.LBE1027:
.LBB1030:
.LBB1025:
.LBB1023:
.LBB1021:
.LBB1011:
.LBB1007:
.LBB1008:
.LBB1009:
	.loc 9 157 0 is_stmt 1
	sbfx	x0, x21, 0, 56
.LVL160:
.LBE1009:
.LBE1008:
	.loc 6 86 0
	and	x0, x0, x21
.LVL161:
	b	.L122
.LVL162:
	.p2align 3
.L101:
.LBE1007:
.LBE1011:
.LBE1021:
.LBE1023:
.LBE1025:
.LBE1030:
	.loc 1 1298 0
	ldr	x0, [x20, 272]
	adrp	x2, .LANCHOR2
	adrp	x1, .LC6
.LVL163:
	add	x2, x2, :lo12:.LANCHOR2
	add	x1, x1, :lo12:.LC6
	bl	_dev_err
.LVL164:
	.loc 1 1299 0
	mov	x0, 0
	.loc 1 1302 0
	b	.L97
.LVL165:
	.p2align 3
.L108:
	.loc 1 1271 0
	ldr	x0, [x20, 272]
	.loc 1 1270 0
	mov	w2, 1
	str	w2, [x20, 788]
	.loc 1 1271 0
	adrp	x1, .LC2
.LVL166:
	add	x1, x1, :lo12:.LC2
	bl	_dev_info
.LVL167:
	.loc 1 1272 0
	mov	x0, 0
	b	.L97
.LVL168:
	.p2align 3
.L107:
	.loc 1 1276 0
	ldr	x0, [x20, 272]
	adrp	x1, .LC3
.LVL169:
	.loc 1 1274 0
	str	wzr, [x20, 788]
	.loc 1 1276 0
	add	x1, x1, :lo12:.LC3
	.loc 1 1275 0
	str	wzr, [x20, 792]
	.loc 1 1276 0
	bl	_dev_info
.LVL170:
	.loc 1 1277 0
	mov	x0, 0
	b	.L97
	.p2align 3
.L177:
	.loc 1 1264 0
	mov	w2, 1
	str	w2, [x20, 80]
	.loc 1 1265 0
	adrp	x0, .LANCHOR1
	add	x0, x0, :lo12:.LANCHOR1
	add	x0, x0, 304
	mov	w1, w2
	bl	__wake_up_sync
.LVL171:
	mov	x0, 0
	b	.L97
.LVL172:
	.p2align 3
.L180:
	.loc 1 1238 0
	mov	w2, 1
	str	w2, [x20, 80]
	.loc 1 1239 0
	adrp	x0, .LANCHOR1
	add	x0, x0, :lo12:.LANCHOR1
	mov	w1, w2
	add	x0, x0, 304
	bl	__wake_up_sync
.LVL173:
	b	.L126
.LVL174:
	.p2align 3
.L142:
.LBB1031:
.LBB922:
.LBB918:
.LBB907:
.LBB908:
.LBB909:
.LBB910:
.LBB911:
	.loc 9 157 0
	sbfx	x1, x21, 0, 56
.LVL175:
.LBE911:
.LBE910:
.LBE909:
.LBB912:
.LBB913:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x0, sp_el0
// 0 "" 2
.LVL176:
#NO_APP
.LBE913:
.LBE912:
.LBB914:
	.loc 6 254 0
	and	x1, x1, x21
.LVL177:
.LBE914:
	.loc 6 249 0
	ldr	x2, [x0, 8]
.LVL178:
#APP
// 249 "./arch/arm64/include/asm/uaccess.h" 1
		bics	xzr, x1, x2
	csel	x0, x21, xzr, eq

// 0 "" 2
.LVL179:
	.loc 6 257 0
// 257 "./arch/arm64/include/asm/uaccess.h" 1
	hint #20
// 0 "" 2
#NO_APP
.LBE908:
.LBE907:
	.loc 8 134 0
	mov	x2, 44
	add	x1, x29, 104
.LVL180:
	bl	__arch_copy_to_user
.LVL181:
.LBE918:
.LBE922:
.LBE1031:
	.loc 1 1292 0
	cbz	x0, .L174
	b	.L143
.LVL182:
	.p2align 3
.L119:
.LBB1032:
.LBB885:
.LBB881:
.LBB870:
.LBB871:
.LBB872:
.LBB873:
.LBB874:
	.loc 9 157 0
	sbfx	x1, x21, 0, 56
.LVL183:
.LBE874:
.LBE873:
.LBE872:
.LBB875:
.LBB876:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x0, sp_el0
// 0 "" 2
.LVL184:
#NO_APP
.LBE876:
.LBE875:
.LBB877:
	.loc 6 254 0
	and	x1, x1, x21
.LVL185:
.LBE877:
	.loc 6 249 0
	ldr	x2, [x0, 8]
.LVL186:
#APP
// 249 "./arch/arm64/include/asm/uaccess.h" 1
		bics	xzr, x1, x2
	csel	x0, x21, xzr, eq

// 0 "" 2
.LVL187:
	.loc 6 257 0
// 257 "./arch/arm64/include/asm/uaccess.h" 1
	hint #20
// 0 "" 2
#NO_APP
.LBE871:
.LBE870:
	.loc 8 134 0
	mov	x2, 44
	add	x1, x29, 104
.LVL188:
	bl	__arch_copy_to_user
.LVL189:
.LBE881:
.LBE885:
.LBE1032:
	.loc 1 1215 0
	cbz	w0, .L174
	b	.L120
.LVL190:
	.p2align 3
.L181:
	.loc 1 1241 0 discriminator 1
	ldr	w0, [x20, 592]
	cbz	w0, .L128
	b	.L174
.LVL191:
.L153:
.LBB1033:
.LBB993:
.LBB989:
	.loc 8 112 0
	mov	x0, 4
.LVL192:
.L138:
	.loc 8 119 0
	mov	x2, x0
	mov	w1, 0
.LVL193:
	add	x0, x22, x3
.LVL194:
	bl	memset
.LVL195:
.LBE989:
.LBE993:
.LBE1033:
	.loc 1 1280 0
	ldr	x0, [x20, 272]
	adrp	x1, .LC4
	add	x1, x1, :lo12:.LC4
	bl	_dev_err
.LVL196:
	.loc 1 1281 0
	mov	x0, -14
	b	.L97
.L116:
	.loc 1 1191 0
	mov	x0, -1
	b	.L97
.L178:
	.loc 1 1303 0
	bl	__stack_chk_fail
.LVL197:
.L179:
	mov	x3, 4
	sub	x3, x3, x0
.LVL198:
	b	.L138
	.cfi_endproc
.LFE2825:
	.size	ebc_io_ctl, .-ebc_io_ctl
	.align	2
	.p2align 3,,7
	.type	frame_done_callback, %function
frame_done_callback:
.LFB2817:
	.loc 1 636 0
	.cfi_startproc
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	.loc 1 637 0
	adrp	x0, .LANCHOR0
	add	x1, x0, :lo12:.LANCHOR0
	.loc 1 636 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -32
	.cfi_offset 20, -24
	.loc 1 637 0
	ldr	x20, [x0, #:lo12:.LANCHOR0]
	.loc 1 636 0
	str	x21, [sp, 32]
	.cfi_offset 21, -16
	.loc 1 639 0
	add	x19, x20, 184
	ldr	x0, [x19, 208]
	ldr	w0, [x0, 40]
	cmp	w0, 1
	bhi	.L184
	.loc 1 642 0
	ldr	w0, [x19, 40]
	cbz	w0, .L186
	.loc 1 643 0
	ldr	x0, [x1, 8]
	bl	wake_up_process
.LVL199:
	.loc 1 669 0
	ldr	x21, [sp, 32]
	ldp	x19, x20, [sp, 16]
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 20
	.cfi_restore 19
	.cfi_restore 21
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
	.p2align 3
.L184:
	.cfi_restore_state
	.loc 1 657 0
	ldr	w0, [x19, 44]
	cbnz	w0, .L190
	.loc 1 663 0
	ldr	x0, [x19, 88]
	.loc 1 662 0
	mov	w20, 1
	.loc 1 661 0
	str	wzr, [x19, 28]
	.loc 1 663 0
	adrp	x1, .LC9
	.loc 1 662 0
	str	w20, [x19, 76]
	.loc 1 663 0
	add	x1, x1, :lo12:.LC9
	.loc 1 664 0
	adrp	x19, .LANCHOR1
	add	x19, x19, :lo12:.LANCHOR1
	.loc 1 663 0
	bl	_dev_info
.LVL200:
	.loc 1 664 0
	mov	w2, w20
	add	x0, x19, 352
	mov	w1, w20
	bl	__wake_up_sync
.LVL201:
	.loc 1 665 0
	mov	w2, w20
	mov	w1, w20
	add	x0, x19, 304
	bl	__wake_up_sync
.LVL202:
	.loc 1 669 0
	ldp	x19, x20, [sp, 16]
	ldr	x21, [sp, 32]
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 21
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
	.p2align 3
.L186:
	.cfi_restore_state
	.loc 1 646 0
	ldr	x0, [x19, 88]
	adrp	x1, .LC8
	add	x1, x1, :lo12:.LC8
	.loc 1 651 0
	mov	w21, 1
	.loc 1 646 0
	bl	_dev_info
.LVL203:
	.loc 1 648 0
	ldrsw	x2, [x19, 20]
	mov	w1, 0
	ldr	x0, [x19, 152]
	bl	memset
.LVL204:
	.loc 1 649 0
	adrp	x2, jiffies
	add	x0, x20, 672
	mov	x1, 402653184
	ldr	x2, [x2, #:lo12:jiffies]
	add	x1, x2, x1
	bl	mod_timer
.LVL205:
	.loc 1 651 0
	str	w21, [x19, 76]
	.loc 1 650 0
	str	wzr, [x19, 28]
	.loc 1 652 0
	adrp	x19, .LANCHOR1
	add	x19, x19, :lo12:.LANCHOR1
	mov	w2, w21
	mov	w1, w21
	add	x0, x19, 352
	bl	__wake_up_sync
.LVL206:
	.loc 1 653 0
	mov	w2, w21
	mov	w1, w21
	add	x0, x19, 304
	bl	__wake_up_sync
.LVL207:
	.loc 1 669 0
	ldp	x19, x20, [sp, 16]
	ldr	x21, [sp, 32]
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 20
	.cfi_restore 19
	.cfi_restore 21
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
	.p2align 3
.L190:
	.cfi_restore_state
	.loc 1 659 0
	ldr	x0, [x1, 8]
	.loc 1 658 0
	mov	w1, 1
	str	w1, [x19, 28]
	.loc 1 659 0
	bl	wake_up_process
.LVL208:
	.loc 1 669 0
	ldr	x21, [sp, 32]
	ldp	x19, x20, [sp, 16]
	ldp	x29, x30, [sp], 48
	.cfi_restore 20
	.cfi_restore 19
	.cfi_restore 21
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2817:
	.size	frame_done_callback, .-frame_done_callback
	.align	2
	.p2align 3,,7
	.type	ebc_frame_timeout, %function
ebc_frame_timeout:
.LFB2823:
	.loc 1 1088 0
	.cfi_startproc
.LVL209:
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1089 0
	bl	frame_done_callback
.LVL210:
	.loc 1 1091 0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2823:
	.size	ebc_frame_timeout, .-ebc_frame_timeout
	.align	2
	.p2align 3,,7
	.type	ebc_lut_update, %function
ebc_lut_update:
.LFB2818:
	.loc 1 672 0
	.cfi_startproc
.LVL211:
	stp	x29, x30, [sp, -64]!
	.cfi_def_cfa_offset 64
	.cfi_offset 29, -64
	.cfi_offset 30, -56
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -48
	.cfi_offset 20, -40
	mov	x20, x0
	str	x21, [sp, 32]
	.cfi_offset 21, -32
	.loc 1 672 0
	adrp	x19, __stack_chk_guard
	add	x0, x19, :lo12:__stack_chk_guard
.LVL212:
.LBB1034:
.LBB1035:
	.loc 3 50 0
	add	x1, x29, 52
.LBE1035:
.LBE1034:
	.loc 1 672 0
	ldr	x2, [x0]
	str	x2, [x29, 56]
	mov	x2,0
	add	x21, x20, 184
	.loc 1 678 0
	ldr	x2, [x20, 16]
.LBB1037:
.LBB1036:
	.loc 3 50 0
	mov	x0, x2
	ldr	x2, [x2, 56]
	blr	x2
.LVL213:
.LBE1036:
.LBE1037:
	.loc 1 679 0
	ldr	w2, [x29, 52]
	cmp	w2, 50
	bhi	.L214
.L194:
	.loc 1 683 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC11
	add	x1, x1, :lo12:.LC11
	bl	_dev_info
.LVL214:
	.loc 1 686 0
	ldr	x0, [x21, 208]
	ldr	w0, [x0, 40]
	cmp	w0, 17
	bls	.L215
	.loc 1 733 0
	ldr	w2, [x29, 52]
.L213:
	mov	w1, 7
	add	x0, x20, 280
	bl	epd_lut_get
.LVL215:
	cbnz	w0, .L206
.L208:
	.loc 1 743 0
	mov	w0, 0
.L193:
	.loc 1 744 0
	add	x19, x19, :lo12:__stack_chk_guard
	ldr	x2, [x29, 56]
	ldr	x1, [x19]
	eor	x1, x2, x1
	cbnz	x1, .L216
	ldp	x19, x20, [sp, 16]
.LVL216:
	ldr	x21, [sp, 32]
	ldp	x29, x30, [sp], 64
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 21
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL217:
	.p2align 3
.L215:
	.cfi_restore_state
	.loc 1 686 0
	adrp	x1, .L197
	.loc 1 688 0
	ldr	w2, [x29, 52]
	.loc 1 686 0
	add	x1, x1, :lo12:.L197
	ldrb	w0, [x1,w0,uxtw]
	adr	x1, .Lrtx197
	add	x0, x1, w0, sxtb #2
	br	x0
.Lrtx197:
	.section	.rodata
	.align	0
	.align	2
.L197:
	.byte	(.L196 - .Lrtx197) / 4
	.byte	(.L196 - .Lrtx197) / 4
	.byte	(.L213 - .Lrtx197) / 4
	.byte	(.L199 - .Lrtx197) / 4
	.byte	(.L200 - .Lrtx197) / 4
	.byte	(.L201 - .Lrtx197) / 4
	.byte	(.L202 - .Lrtx197) / 4
	.byte	(.L213 - .Lrtx197) / 4
	.byte	(.L199 - .Lrtx197) / 4
	.byte	(.L200 - .Lrtx197) / 4
	.byte	(.L201 - .Lrtx197) / 4
	.byte	(.L202 - .Lrtx197) / 4
	.byte	(.L203 - .Lrtx197) / 4
	.byte	(.L204 - .Lrtx197) / 4
	.byte	(.L205 - .Lrtx197) / 4
	.byte	(.L213 - .Lrtx197) / 4
	.byte	(.L213 - .Lrtx197) / 4
	.byte	(.L213 - .Lrtx197) / 4
	.text
	.p2align 3
.L205:
	.loc 1 688 0
	mov	w1, 1
	add	x0, x20, 280
	bl	epd_lut_get
.LVL218:
	cbz	w0, .L208
	.p2align 2
.L206:
	.loc 1 739 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC12
	add	x1, x1, :lo12:.LC12
	bl	_dev_err
.LVL219:
	.loc 1 740 0
	mov	w0, -1
	b	.L193
	.p2align 3
.L214:
	.loc 1 680 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC10
	add	x1, x1, :lo12:.LC10
	bl	_dev_err
.LVL220:
	.loc 1 681 0
	mov	w0, 25
	mov	w2, w0
	str	w0, [x29, 52]
	b	.L194
	.p2align 3
.L204:
	.loc 1 709 0
	mov	w1, 4
	add	x0, x20, 280
	bl	epd_lut_get
.LVL221:
	cbnz	w0, .L206
	b	.L208
	.p2align 3
.L196:
	.loc 1 701 0
	mov	w1, 5
	add	x0, x20, 280
	bl	epd_lut_get
.LVL222:
	cbnz	w0, .L206
	b	.L208
	.p2align 3
.L199:
	.loc 1 714 0
	mov	w1, 8
	add	x0, x20, 280
	bl	epd_lut_get
.LVL223:
	cbnz	w0, .L206
	b	.L208
	.p2align 3
.L200:
	.loc 1 719 0
	mov	w1, 9
	add	x0, x20, 280
	bl	epd_lut_get
.LVL224:
	cbnz	w0, .L206
	b	.L208
	.p2align 3
.L201:
	.loc 1 724 0
	mov	w1, 10
	add	x0, x20, 280
	bl	epd_lut_get
.LVL225:
	cbnz	w0, .L206
	b	.L208
	.p2align 3
.L202:
	.loc 1 729 0
	mov	w1, 11
	add	x0, x20, 280
	bl	epd_lut_get
.LVL226:
	cbnz	w0, .L206
	b	.L208
	.p2align 3
.L203:
	.loc 1 705 0
	mov	w1, 6
	add	x0, x20, 280
	bl	epd_lut_get
.LVL227:
	cbnz	w0, .L206
	b	.L208
.L216:
	.loc 1 744 0
	bl	__stack_chk_fail
.LVL228:
	.cfi_endproc
.LFE2818:
	.size	ebc_lut_update, .-ebc_lut_update
	.align	2
	.p2align 3,,7
	.type	ebc_state_read, %function
ebc_state_read:
.LFB2834:
	.loc 1 1428 0
	.cfi_startproc
.LVL229:
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	.loc 1 1429 0
	adrp	x3, .LANCHOR0
	.loc 1 1428 0
	mov	x0, x2
.LVL230:
	.loc 1 1429 0
	adrp	x1, .LC13
.LVL231:
	.loc 1 1428 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1429 0
	ldr	x2, [x3, #:lo12:.LANCHOR0]
.LVL232:
	add	x1, x1, :lo12:.LC13
	ldr	w2, [x2, 608]
	bl	sprintf
.LVL233:
	.loc 1 1430 0
	sxtw	x0, w0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2834:
	.size	ebc_state_read, .-ebc_state_read
	.align	2
	.p2align 3,,7
	.type	ebc_version_read, %function
ebc_version_read:
.LFB2833:
	.loc 1 1419 0
	.cfi_startproc
.LVL234:
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	mov	x0, x2
.LVL235:
	.loc 1 1420 0
	adrp	x1, .LC15
.LVL236:
	adrp	x2, .LC14
.LVL237:
	.loc 1 1419 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1420 0
	add	x2, x2, :lo12:.LC14
	.loc 1 1419 0
	.loc 1 1420 0
	add	x1, x1, :lo12:.LC15
	bl	sprintf
.LVL238:
	.loc 1 1421 0
	sxtw	x0, w0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2833:
	.size	ebc_version_read, .-ebc_version_read
	.align	2
	.p2align 3,,7
	.type	pmic_vcom_read, %function
pmic_vcom_read:
.LFB2831:
	.loc 1 1383 0
	.cfi_startproc
.LVL239:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	.loc 1 1384 0
	adrp	x0, .LANCHOR0
.LVL240:
	.loc 1 1383 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1387 0
	ldr	x0, [x0, #:lo12:.LANCHOR0]
	.loc 1 1383 0
	str	x19, [sp, 16]
	.cfi_offset 19, -16
	.loc 1 1383 0
	mov	x19, x2
	.loc 1 1387 0
	ldr	x1, [x0, 16]
.LVL241:
.LBB1038:
.LBB1039:
	.loc 3 55 0
	mov	x0, x1
	ldr	x1, [x1, 64]
	blr	x1
.LVL242:
.LBE1039:
.LBE1038:
	.loc 1 1389 0
	mov	w2, w0
	adrp	x1, .LC13
	mov	x0, x19
	add	x1, x1, :lo12:.LC13
	bl	sprintf
.LVL243:
	.loc 1 1390 0
	sxtw	x0, w0
	ldr	x19, [sp, 16]
.LVL244:
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2831:
	.size	pmic_vcom_read, .-pmic_vcom_read
	.align	2
	.p2align 3,,7
	.type	pmic_temp_read, %function
pmic_temp_read:
.LFB2830:
	.loc 1 1369 0
	.cfi_startproc
.LVL245:
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	.loc 1 1370 0
	adrp	x0, .LANCHOR0
.LVL246:
	.loc 1 1369 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1373 0
	ldr	x0, [x0, #:lo12:.LANCHOR0]
.LBB1040:
.LBB1041:
	.loc 3 50 0
	add	x1, x29, 36
.LVL247:
.LBE1041:
.LBE1040:
	.loc 1 1369 0
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -32
	.cfi_offset 20, -24
	.loc 1 1369 0
	adrp	x19, __stack_chk_guard
	add	x19, x19, :lo12:__stack_chk_guard
	mov	x20, x2
	ldr	x2, [x19]
	str	x2, [x29, 40]
	mov	x2,0
.LVL248:
	.loc 1 1373 0
	ldr	x2, [x0, 16]
.LBB1043:
.LBB1042:
	.loc 3 50 0
	mov	x0, x2
	ldr	x2, [x2, 56]
	blr	x2
.LVL249:
.LBE1042:
.LBE1043:
	.loc 1 1375 0
	ldr	w2, [x29, 36]
	adrp	x1, .LC13
	mov	x0, x20
	add	x1, x1, :lo12:.LC13
	bl	sprintf
.LVL250:
	.loc 1 1376 0
	ldr	x2, [x29, 40]
	ldr	x1, [x19]
	eor	x1, x2, x1
	cbnz	x1, .L226
	ldp	x19, x20, [sp, 16]
.LVL251:
	sxtw	x0, w0
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL252:
.L226:
	.cfi_restore_state
	bl	__stack_chk_fail
.LVL253:
	.cfi_endproc
.LFE2830:
	.size	pmic_temp_read, .-pmic_temp_read
	.align	2
	.p2align 3,,7
	.type	pmic_name_read, %function
pmic_name_read:
.LFB2829:
	.loc 1 1358 0
	.cfi_startproc
.LVL254:
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	.loc 1 1359 0
	adrp	x3, .LANCHOR0
	.loc 1 1358 0
	mov	x0, x2
.LVL255:
	.loc 1 1361 0
	adrp	x1, .LC15
.LVL256:
	.loc 1 1358 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1361 0
	ldr	x2, [x3, #:lo12:.LANCHOR0]
.LVL257:
	add	x1, x1, :lo12:.LC15
	ldr	x2, [x2, 16]
	add	x2, x2, 8
	bl	sprintf
.LVL258:
	.loc 1 1362 0
	sxtw	x0, w0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2829:
	.size	pmic_name_read, .-pmic_name_read
	.align	2
	.p2align 3,,7
	.type	pmic_vcom_write, %function
pmic_vcom_write:
.LFB2832:
	.loc 1 1395 0
	.cfi_startproc
.LVL259:
	stp	x29, x30, [sp, -64]!
	.cfi_def_cfa_offset 64
	.cfi_offset 29, -64
	.cfi_offset 30, -56
	.loc 1 1396 0
	adrp	x0, .LANCHOR0
.LVL260:
	.loc 1 1395 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -48
	.cfi_offset 20, -40
	adrp	x19, __stack_chk_guard
	stp	x21, x22, [sp, 32]
	.cfi_offset 21, -32
	.cfi_offset 22, -24
	.loc 1 1395 0
	add	x1, x19, :lo12:__stack_chk_guard
.LVL261:
	mov	x21, x2
	.loc 1 1396 0
	ldr	x22, [x0, #:lo12:.LANCHOR0]
.LVL262:
	.loc 1 1395 0
	ldr	x2, [x1]
	str	x2, [x29, 56]
	mov	x2,0
.LVL263:
	mov	x20, x3
	.loc 1 1399 0
	add	x2, x29, 52
	mov	w1, 0
	mov	x0, x21
	bl	kstrtouint
.LVL264:
	.loc 1 1400 0
	cbnz	w0, .L236
.LVL265:
	.loc 1 1404 0
	ldr	w1, [x29, 52]
	ldr	x0, [x22, 16]
	bl	ebc_pmic_set_vcom
.LVL266:
	.loc 1 1405 0
	cbnz	w0, .L237
.L229:
	.loc 1 1411 0
	add	x19, x19, :lo12:__stack_chk_guard
	mov	x0, x20
.LVL267:
	ldr	x2, [x29, 56]
	ldr	x1, [x19]
	eor	x1, x2, x1
	cbnz	x1, .L238
	ldp	x19, x20, [sp, 16]
	ldp	x21, x22, [sp, 32]
.LVL268:
	ldp	x29, x30, [sp], 64
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 21
	.cfi_restore 22
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL269:
	.p2align 3
.L236:
	.cfi_restore_state
	.loc 1 1401 0
	ldr	x0, [x22]
	adrp	x1, .LC16
	mov	x2, x21
	add	x1, x1, :lo12:.LC16
	.loc 1 1402 0
	mov	x20, -1
.LVL270:
	.loc 1 1401 0
	bl	_dev_err
.LVL271:
	.loc 1 1402 0
	b	.L229
.LVL272:
	.p2align 3
.L237:
	.loc 1 1406 0
	ldr	x0, [x22]
	adrp	x1, .LC17
	.loc 1 1407 0
	mov	x20, -1
.LVL273:
	.loc 1 1406 0
	add	x1, x1, :lo12:.LC17
	bl	_dev_err
.LVL274:
	.loc 1 1407 0
	b	.L229
.L238:
	.loc 1 1411 0
	bl	__stack_chk_fail
.LVL275:
	.cfi_endproc
.LFE2832:
	.size	pmic_vcom_write, .-pmic_vcom_write
	.align	2
	.p2align 3,,7
	.type	waveform_version_read, %function
waveform_version_read:
.LFB2828:
	.loc 1 1347 0
	.cfi_startproc
.LVL276:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	str	x19, [sp, 16]
	.cfi_offset 19, -16
	.loc 1 1347 0
	mov	x19, x2
	.loc 1 1348 0
	bl	epd_lut_get_wf_version
.LVL277:
	.loc 1 1350 0
	mov	x2, x0
	adrp	x1, .LC15
	mov	x0, x19
	add	x1, x1, :lo12:.LC15
	bl	sprintf
.LVL278:
	.loc 1 1351 0
	sxtw	x0, w0
	ldr	x19, [sp, 16]
.LVL279:
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2828:
	.size	waveform_version_read, .-waveform_version_read
	.section	.init.text,"ax",@progbits
	.align	2
	.type	ebc_init, %function
ebc_init:
.LFB2845:
	.loc 1 1869 0
	.cfi_startproc
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	.loc 1 1870 0
	mov	x1, 0
	adrp	x0, .LANCHOR1
	add	x0, x0, :lo12:.LANCHOR1
	.loc 1 1869 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1870 0
	bl	__platform_driver_register
.LVL280:
	.loc 1 1871 0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2845:
	.size	ebc_init, .-ebc_init
	.text
	.align	2
	.p2align 3,,7
	.type	direct_mode_data_change.isra.0, %function
direct_mode_data_change.isra.0:
.LFB2847:
	.loc 1 423 0
	.cfi_startproc
.LVL281:
	.loc 1 427 0
	adrp	x6, .LANCHOR0
	.loc 1 423 0
	and	w3, w3, 255
	.loc 1 433 0
	sub	w3, w3, w4
.LVL282:
	.loc 1 427 0
	ldr	x13, [x6, #:lo12:.LANCHOR0]
	.loc 1 434 0
	lsl	w3, w3, 16
.LVL283:
	add	x5, x5, x3, sxtw
.LVL284:
	.loc 1 435 0
	add	x13, x13, 24
	ldr	w16, [x13, 156]
	.loc 1 438 0
	ldp	w3, w15, [x13, 84]
.LVL285:
	.loc 1 443 0
	cmp	w15, 0
	ble	.L255
	lsr	w14, w3, 4
	mov	w12, 0
.LVL286:
	sub	w11, w14, #1
	add	x11, x11, 1
	lsl	x11, x11, 3
	.loc 1 444 0
	cbz	w16, .L258
.LVL287:
.L269:
	.loc 1 445 0
	ldr	w6, [x13, 88]
.LVL288:
	sub	w6, w6, #1
	sub	w6, w6, w12
	mul	w6, w6, w3
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL289:
.L259:
	.loc 1 449 0
	cbz	w14, .L267
	.loc 1 423 0
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	add	x29, sp, 0
	.cfi_def_cfa_register 29
.LVL290:
	.p2align 2
.L260:
	.loc 1 449 0
	mov	x7, 0
	.p2align 2
.L249:
	.loc 1 451 0
	ldr	x4, [x2, x7]
.LVL291:
	add	x6, x6, 4
	.loc 1 450 0
	ldr	x3, [x1, x7]
.LVL292:
	add	x7, x7, 8
	.loc 1 453 0
	and	w9, w4, 65535
	.loc 1 449 0
	cmp	x11, x7
	.loc 1 453 0
	and	w8, w3, 65535
.LBB1044:
.LBB1045:
	.loc 1 132 0
	ubfiz	w30, w9, 8, 8
	.loc 1 133 0
	and	w9, w9, 65280
	.loc 1 132 0
	add	w30, w30, w8, uxtb
	.loc 1 133 0
	add	w9, w9, w8, lsr 8
.LBE1045:
.LBE1044:
	.loc 1 454 0
	lsr	w10, w4, 16
	lsr	w8, w3, 16
.LBB1049:
.LBB1050:
	.loc 1 132 0
	ubfiz	w18, w10, 8, 8
.LBE1050:
.LBE1049:
.LBB1056:
.LBB1046:
	ldrb	w30, [x5, w30, sxtw]
.LBE1046:
.LBE1056:
.LBB1057:
.LBB1051:
	.loc 1 133 0
	and	w10, w10, 65280
.LBE1051:
.LBE1057:
.LBB1058:
.LBB1047:
	ldrb	w17, [x5, w9, sxtw]
.LBE1047:
.LBE1058:
.LBB1059:
.LBB1052:
	.loc 1 132 0
	add	w18, w18, w8, uxtb
	.loc 1 133 0
	add	w10, w10, w8, lsr 8
.LBE1052:
.LBE1059:
	.loc 1 455 0
	ubfx	x9, x4, 32, 16
	ubfx	x8, x3, 32, 16
	.loc 1 456 0
	lsr	x4, x4, 48
.LVL293:
.LBB1060:
.LBB1048:
	.loc 1 132 0
	orr	w17, w30, w17, lsl 4
.LBE1048:
.LBE1060:
	.loc 1 453 0
	strb	w17, [x6, -4]
.LBB1061:
.LBB1062:
	.loc 1 132 0
	ubfiz	w17, w9, 8, 8
	.loc 1 133 0
	and	w9, w9, 65280
.LBE1062:
.LBE1061:
.LBB1068:
.LBB1053:
	ldrb	w10, [x5, w10, sxtw]
.LBE1053:
.LBE1068:
.LBB1069:
.LBB1063:
	.loc 1 132 0
	add	w17, w17, w8, uxtb
.LBE1063:
.LBE1069:
.LBB1070:
.LBB1054:
	ldrb	w18, [x5, w18, sxtw]
.LBE1054:
.LBE1070:
.LBB1071:
.LBB1064:
	.loc 1 133 0
	add	w8, w9, w8, lsr 8
.LBE1064:
.LBE1071:
	.loc 1 456 0
	lsr	x3, x3, 48
.LVL294:
.LBB1072:
.LBB1055:
	.loc 1 132 0
	orr	w9, w18, w10, lsl 4
.LBE1055:
.LBE1072:
	.loc 1 454 0
	strb	w9, [x6, -3]
.LBB1073:
.LBB1074:
	.loc 1 132 0
	ubfiz	w9, w4, 8, 8
	.loc 1 133 0
	and	w4, w4, 65280
.LBE1074:
.LBE1073:
.LBB1078:
.LBB1065:
	ldrb	w10, [x5, w8, sxtw]
.LBE1065:
.LBE1078:
.LBB1079:
.LBB1075:
	.loc 1 132 0
	add	w8, w9, w3, uxtb
.LBE1075:
.LBE1079:
.LBB1080:
.LBB1066:
	ldrb	w17, [x5, w17, sxtw]
.LBE1066:
.LBE1080:
.LBB1081:
.LBB1076:
	.loc 1 133 0
	add	w3, w4, w3, lsr 8
.LBE1076:
.LBE1081:
.LBB1082:
.LBB1067:
	.loc 1 132 0
	orr	w4, w17, w10, lsl 4
.LBE1067:
.LBE1082:
	.loc 1 455 0
	strb	w4, [x6, -2]
.LBB1083:
.LBB1077:
	.loc 1 133 0
	ldrb	w3, [x5, w3, sxtw]
	.loc 1 132 0
	ldrb	w4, [x5, w8, sxtw]
	orr	w3, w4, w3, lsl 4
.LBE1077:
.LBE1083:
	.loc 1 456 0
	strb	w3, [x6, -1]
	.loc 1 449 0
	bne	.L249
	.loc 1 443 0
	add	w12, w12, 1
	add	x1, x1, x11
.LVL295:
	add	x2, x2, x11
.LVL296:
	cmp	w15, w12
	beq	.L243
.L268:
	ldr	w3, [x13, 84]
	.loc 1 444 0
	cbz	w16, .L246
	.loc 1 445 0
	ldr	w6, [x13, 88]
.LVL297:
	sub	w6, w6, #1
	sub	w6, w6, w12
	mul	w6, w6, w3
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL298:
	.loc 1 449 0
	cbnz	w14, .L260
.L266:
	.loc 1 443 0
	add	w12, w12, 1
	cmp	w15, w12
	bne	.L268
.L243:
	.loc 1 459 0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
.LVL299:
.L258:
	.loc 1 447 0
	mul	w6, w12, w3
.LVL300:
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL301:
	b	.L259
.LVL302:
	.p2align 3
.L246:
	.cfi_def_cfa 29, 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	mul	w6, w12, w3
.LVL303:
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL304:
	.loc 1 449 0
	cbnz	w14, .L260
	b	.L266
.LVL305:
.L267:
	.cfi_def_cfa 31, 0
	.cfi_restore 29
	.cfi_restore 30
	.loc 1 443 0
	add	w12, w12, 1
	cmp	w15, w12
	beq	.L255
	ldr	w3, [x13, 84]
	.loc 1 444 0
	cbz	w16, .L258
	b	.L269
.L255:
	ret
	.cfi_endproc
.LFE2847:
	.size	direct_mode_data_change.isra.0, .-direct_mode_data_change.isra.0
	.align	2
	.p2align 3,,7
	.type	direct_mode_data_change_part.isra.1, %function
direct_mode_data_change_part.isra.1:
.LFB2848:
	.loc 1 461 0
	.cfi_startproc
.LVL306:
	.loc 1 465 0
	adrp	x6, .LANCHOR0
	.loc 1 461 0
	and	w3, w3, 255
	.loc 1 470 0
	sub	w3, w3, w4
.LVL307:
	.loc 1 465 0
	ldr	x14, [x6, #:lo12:.LANCHOR0]
	.loc 1 471 0
	lsl	w3, w3, 16
.LVL308:
	add	x5, x5, x3, sxtw
.LVL309:
	.loc 1 472 0
	add	x14, x14, 24
	ldr	w16, [x14, 156]
	.loc 1 475 0
	ldp	w3, w15, [x14, 84]
.LVL310:
	.loc 1 480 0
	cmp	w15, 0
	ble	.L336
	lsr	w11, w3, 4
.LVL311:
	mov	w12, 0
.LVL312:
	sub	w13, w11, #1
.LBB1084:
.LBB1085:
	.loc 1 138 0
	mov	w10, 3
	add	x13, x13, 1
	lsl	x13, x13, 3
.LBE1085:
.LBE1084:
	.loc 1 481 0
	cbz	w16, .L339
.LVL313:
.L354:
	.loc 1 482 0
	ldr	w6, [x14, 88]
.LVL314:
	sub	w6, w6, #1
	sub	w6, w6, w12
	mul	w6, w6, w3
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL315:
.L340:
	.loc 1 486 0
	cbz	w11, .L342
	add	x6, x6, 4
.LVL316:
	mov	x8, 0
.LVL317:
.L343:
	.loc 1 487 0
	ldr	x3, [x1, x8, lsl 3]
	.loc 1 488 0
	ldr	x4, [x2, x8, lsl 3]
	.loc 1 489 0
	cmp	x3, x4
	beq	.L352
	.loc 1 461 0
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	add	x29, sp, 0
	.cfi_def_cfa_register 29
.LVL318:
.L344:
	.loc 1 490 0
	and	w17, w4, 65535
	and	w9, w3, 65535
.LVL319:
.LBB1087:
.LBB1088:
	.loc 1 142 0
	mov	w7, 0
	.loc 1 141 0
	cmp	w17, w9
	beq	.L277
	.loc 1 139 0
	eor	w18, w17, w9
.LVL320:
	.loc 1 152 0
	ubfiz	w30, w17, 8, 8
	.loc 1 153 0
	and	w17, w17, 65280
	.loc 1 152 0
	add	w30, w30, w9, uxtb
	.loc 1 138 0
	tst	x18, 15
	.loc 1 153 0
	add	w9, w17, w9, lsr 8
	.loc 1 138 0
	csel	w7, w10, wzr, ne
	.loc 1 146 0
	tst	w18, 240
	orr	w17, w7, 12
	.loc 1 152 0
	ldrb	w30, [x5, w30, sxtw]
	.loc 1 146 0
	csel	w7, w17, w7, ne
	.loc 1 148 0
	tst	w18, 3840
	orr	w17, w7, 48
	.loc 1 153 0
	ldrb	w9, [x5, w9, sxtw]
	.loc 1 148 0
	csel	w7, w17, w7, ne
	.loc 1 150 0
	tst	w18, 61440
	orr	w17, w7, -64
	and	w17, w17, 255
	.loc 1 152 0
	orr	w9, w30, w9, lsl 4
	.loc 1 150 0
	csel	w7, w17, w7, ne
	.loc 1 152 0
	and	w7, w9, w7
	and	w7, w7, 255
.LVL321:
.L277:
.LBE1088:
.LBE1087:
	.loc 1 490 0
	strb	w7, [x6, -4]
	.loc 1 491 0
	lsr	w17, w4, 16
	lsr	w9, w3, 16
.LBB1089:
.LBB1090:
	.loc 1 142 0
	mov	w7, 0
	.loc 1 141 0
	cmp	w17, w9
	beq	.L282
	.loc 1 139 0
	eor	w18, w17, w9
.LVL322:
	.loc 1 152 0
	ubfiz	w30, w17, 8, 8
	.loc 1 153 0
	and	w17, w17, 65280
	.loc 1 152 0
	add	w30, w30, w9, uxtb
	.loc 1 138 0
	tst	x18, 15
	.loc 1 153 0
	add	w9, w17, w9, lsr 8
	.loc 1 138 0
	csel	w7, w10, wzr, ne
	.loc 1 146 0
	tst	w18, 240
	orr	w17, w7, 12
	.loc 1 152 0
	ldrb	w30, [x5, w30, sxtw]
	.loc 1 146 0
	csel	w7, w17, w7, ne
	.loc 1 148 0
	tst	w18, 3840
	orr	w17, w7, 48
	.loc 1 153 0
	ldrb	w9, [x5, w9, sxtw]
	.loc 1 148 0
	csel	w7, w17, w7, ne
	.loc 1 150 0
	tst	w18, 61440
	orr	w17, w7, -64
	and	w17, w17, 255
	.loc 1 152 0
	orr	w9, w30, w9, lsl 4
	.loc 1 150 0
	csel	w7, w17, w7, ne
	.loc 1 152 0
	and	w7, w9, w7
	and	w7, w7, 255
.LVL323:
.L282:
.LBE1090:
.LBE1089:
	.loc 1 491 0
	strb	w7, [x6, -3]
	.loc 1 492 0
	ubfx	x17, x4, 32, 16
	ubfx	x9, x3, 32, 16
.LBB1091:
.LBB1092:
	.loc 1 142 0
	mov	w7, 0
	.loc 1 141 0
	cmp	w17, w9
	beq	.L287
	.loc 1 139 0
	eor	w18, w17, w9
.LVL324:
	.loc 1 152 0
	ubfiz	w30, w17, 8, 8
	.loc 1 153 0
	and	w17, w17, 65280
	.loc 1 152 0
	add	w30, w30, w9, uxtb
	.loc 1 138 0
	tst	x18, 15
	.loc 1 153 0
	add	w9, w17, w9, lsr 8
	.loc 1 138 0
	csel	w7, w10, wzr, ne
	.loc 1 146 0
	tst	w18, 240
	orr	w17, w7, 12
	.loc 1 152 0
	ldrb	w30, [x5, w30, sxtw]
	.loc 1 146 0
	csel	w7, w17, w7, ne
	.loc 1 148 0
	tst	w18, 3840
	orr	w17, w7, 48
	.loc 1 153 0
	ldrb	w9, [x5, w9, sxtw]
	.loc 1 148 0
	csel	w7, w17, w7, ne
	.loc 1 150 0
	tst	w18, 61440
	orr	w17, w7, -64
	and	w17, w17, 255
	.loc 1 152 0
	orr	w9, w30, w9, lsl 4
	.loc 1 150 0
	csel	w7, w17, w7, ne
	.loc 1 152 0
	and	w7, w9, w7
	and	w7, w7, 255
.LVL325:
.L287:
.LBE1092:
.LBE1091:
	.loc 1 492 0
	strb	w7, [x6, -2]
	.loc 1 493 0
	lsr	x4, x4, 48
.LVL326:
	lsr	x3, x3, 48
.LVL327:
.LBB1093:
.LBB1086:
	.loc 1 142 0
	mov	w7, 0
	.loc 1 141 0
	cmp	w4, w3
	beq	.L292
	.loc 1 139 0
	eor	w9, w4, w3
.LVL328:
	.loc 1 152 0
	ubfiz	w7, w4, 8, 8
	.loc 1 153 0
	and	w4, w4, 65280
	.loc 1 152 0
	add	w7, w7, w3, uxtb
	.loc 1 138 0
	tst	x9, 15
	.loc 1 153 0
	add	w3, w4, w3, lsr 8
	.loc 1 138 0
	csel	w4, w10, wzr, ne
	.loc 1 146 0
	tst	w9, 240
	orr	w18, w4, 12
.LVL329:
	.loc 1 152 0
	ldrb	w17, [x5, w7, sxtw]
	.loc 1 146 0
	csel	w4, w18, w4, ne
	.loc 1 148 0
	tst	w9, 3840
	orr	w18, w4, 48
	.loc 1 153 0
	ldrb	w7, [x5, w3, sxtw]
	.loc 1 148 0
	csel	w4, w18, w4, ne
	.loc 1 150 0
	tst	w9, 61440
	orr	w3, w4, -64
	and	w3, w3, 255
	.loc 1 152 0
	orr	w7, w17, w7, lsl 4
	.loc 1 150 0
	csel	w4, w3, w4, ne
	.loc 1 152 0
	and	w4, w7, w4
	and	w7, w4, 255
.LVL330:
.L292:
.LBE1086:
.LBE1093:
	.loc 1 493 0
	strb	w7, [x6, -1]
	add	x8, x8, 1
	add	x6, x6, 4
	.loc 1 486 0
	cmp	w11, w8
	ble	.L353
.LVL331:
.L298:
	.loc 1 487 0
	ldr	x3, [x1, x8, lsl 3]
	.loc 1 488 0
	ldr	x4, [x2, x8, lsl 3]
	.loc 1 489 0
	cmp	x3, x4
	bne	.L344
	.loc 1 496 0
	str	wzr, [x6, -4]
	add	x8, x8, 1
	add	x6, x6, 4
	.loc 1 486 0
	cmp	w11, w8
	bgt	.L298
.L353:
	add	x1, x1, x13
.LVL332:
	add	x2, x2, x13
.LVL333:
.L275:
	.loc 1 480 0
	add	w12, w12, 1
	cmp	w15, w12
	beq	.L270
	ldr	w3, [x14, 84]
.LVL334:
	.loc 1 481 0
	cbz	w16, .L273
	.loc 1 482 0
	ldr	w6, [x14, 88]
.LVL335:
	sub	w6, w6, #1
	sub	w6, w6, w12
	mul	w6, w6, w3
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL336:
.L274:
	.loc 1 486 0
	cbz	w11, .L275
	add	x6, x6, 4
.LVL337:
	mov	x8, 0
	b	.L298
.LVL338:
	.p2align 3
.L352:
	.cfi_def_cfa 31, 0
	.cfi_restore 29
	.cfi_restore 30
	.loc 1 496 0
	str	wzr, [x6, -4]
	add	x8, x8, 1
	.loc 1 486 0
	cmp	w11, w8
	add	x6, x6, 4
	bgt	.L343
	add	x1, x1, x13
.LVL339:
	add	x2, x2, x13
.LVL340:
.L342:
	.loc 1 480 0
	add	w12, w12, 1
	cmp	w15, w12
	beq	.L336
	ldr	w3, [x14, 84]
.LVL341:
	.loc 1 481 0
	cbnz	w16, .L354
.L339:
	.loc 1 484 0
	mul	w6, w12, w3
.LVL342:
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL343:
	b	.L340
.LVL344:
	.p2align 3
.L273:
	.cfi_def_cfa 29, 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	mul	w6, w12, w3
.LVL345:
	lsr	w6, w6, 2
	add	x6, x0, x6
.LVL346:
	b	.L274
.LVL347:
.L270:
	.loc 1 501 0
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
.LVL348:
.L336:
	ret
	.cfi_endproc
.LFE2848:
	.size	direct_mode_data_change_part.isra.1, .-direct_mode_data_change_part.isra.1
	.align	2
	.p2align 3,,7
	.type	flip.isra.2, %function
flip.isra.2:
.LFB2849:
	.loc 1 503 0
	.cfi_startproc
.LVL349:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	.loc 1 507 0
	sxtw	x2, w1
	.loc 1 503 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -16
	.cfi_offset 20, -8
	.loc 1 503 0
	mov	x20, x0
	.loc 1 505 0
	ldr	w19, [x0, 72]
	.loc 1 507 0
	ldr	x0, [x0]
.LVL350:
.LBB1094:
.LBB1095:
.LBB1096:
.LBB1097:
	.file 10 "./include/linux/dma-mapping.h"
	.loc 10 266 0
	cbz	x0, .L358
	ldr	x3, [x0, 648]
	.loc 10 268 0
	adrp	x4, dummy_dma_ops
	add	x4, x4, :lo12:dummy_dma_ops
	cmp	x3, 0
	csel	x3, x4, x3, eq
.L356:
.LBE1097:
.LBE1096:
	.loc 10 434 0
	ldr	x5, [x3, 88]
	sxtw	x19, w19
	cbz	x5, .L357
.LBE1095:
.LBE1094:
	.loc 1 507 0
	add	x4, x19, x19, lsl 1
.LBB1103:
.LBB1100:
	.loc 10 435 0
	mov	w3, 1
.LBE1100:
.LBE1103:
	.loc 1 507 0
	add	x4, x20, x4, lsl 3
.LBB1104:
.LBB1101:
	.loc 10 435 0
	ldr	x1, [x4, 32]
	blr	x5
.LVL351:
.L357:
.LBE1101:
.LBE1104:
	.loc 1 508 0
	ldr	x5, [x20, 8]
.LBB1105:
.LBB1106:
	.file 11 "drivers/gpu/drm/rockchip/ebc-dev/tcon/ebc_tcon.h"
	.loc 11 57 0
	mov	w4, 0
	mov	w3, 0
	mov	w2, 0
	mov	x0, x5
	mov	w1, 0
.LBE1106:
.LBE1105:
	.loc 1 509 0
	add	x19, x19, x19, lsl 1
.LBB1109:
.LBB1107:
	.loc 11 57 0
	ldr	x5, [x5, 64]
.LBE1107:
.LBE1109:
	.loc 1 509 0
	add	x19, x20, x19, lsl 3
.LBB1110:
.LBB1108:
	.loc 11 57 0
	blr	x5
.LVL352:
.LBE1108:
.LBE1110:
	.loc 1 509 0
	ldr	x1, [x20, 8]
.LBB1111:
.LBB1112:
	.loc 11 62 0
	mov	w2, 0
	mov	x0, x1
	ldr	x3, [x1, 72]
	ldr	w1, [x19, 32]
	blr	x3
.LVL353:
.LBE1112:
.LBE1111:
	.loc 1 510 0
	ldr	x2, [x20, 8]
.LBB1113:
.LBB1114:
	.loc 11 77 0
	mov	w1, 1
	mov	x0, x2
	ldr	x2, [x2, 96]
	blr	x2
.LVL354:
.LBE1114:
.LBE1113:
	.loc 1 511 0
	ldr	w1, [x20, 72]
	mov	w0, 1
	sub	w0, w0, w1
	str	w0, [x20, 72]
	.loc 1 512 0
	ldp	x19, x20, [sp, 16]
.LVL355:
	ldp	x29, x30, [sp], 32
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL356:
	.p2align 3
.L358:
	.cfi_restore_state
.LBB1115:
.LBB1102:
.LBB1099:
.LBB1098:
	.loc 10 268 0
	adrp	x3, dummy_dma_ops
	add	x3, x3, :lo12:dummy_dma_ops
	b	.L356
.LBE1098:
.LBE1099:
.LBE1102:
.LBE1115:
	.cfi_endproc
.LFE2849:
	.size	flip.isra.2, .-flip.isra.2
	.align	2
	.p2align 3,,7
	.type	ebc_auto_tast_function, %function
ebc_auto_tast_function:
.LFB2816:
	.loc 1 576 0
	.cfi_startproc
.LVL357:
	stp	x29, x30, [sp, -96]!
	.cfi_def_cfa_offset 96
	.cfi_offset 29, -96
	.cfi_offset 30, -88
	.loc 1 577 0
	adrp	x1, .LANCHOR0
	.loc 1 576 0
	adrp	x0, __stack_chk_guard
.LVL358:
	add	x0, x0, :lo12:__stack_chk_guard
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -80
	.cfi_offset 20, -72
	adrp	x20, .LANCHOR1
	stp	x21, x22, [sp, 32]
	.loc 1 582 0
	add	x20, x20, :lo12:.LANCHOR1
	.cfi_offset 21, -64
	.cfi_offset 22, -56
	.loc 1 577 0
	ldr	x22, [x1, #:lo12:.LANCHOR0]
.LVL359:
	.loc 1 582 0
	add	x20, x20, 376
	.loc 1 576 0
	stp	x23, x24, [sp, 48]
	.cfi_offset 23, -48
	.cfi_offset 24, -40
.LBB1116:
.LBB1117:
.LBB1118:
	.file 12 "./include/linux/compiler.h"
	.loc 12 234 0
	mov	x24, 2
.LBE1118:
.LBE1117:
.LBE1116:
	.loc 1 576 0
	stp	x25, x26, [sp, 64]
	.cfi_offset 25, -32
	.cfi_offset 26, -24
	.loc 1 578 0
	add	x21, x22, 24
	.loc 1 579 0
	add	x19, x22, 184
	add	x26, x22, 728
	.loc 1 576 0
	ldr	x1, [x0]
	str	x1, [x29, 88]
	mov	x1,0
	adrp	x25, system_wq
.LBB1123:
.LBB1120:
.LBB1121:
	.loc 5 19 0
#APP
// 19 "./arch/arm64/include/asm/current.h" 1
	mrs x23, sp_el0
// 0 "" 2
.LVL360:
#NO_APP
	b	.L371
	.p2align 3
.L380:
.LBE1121:
.LBE1120:
.LBE1123:
	.loc 1 587 0
	sub	w0, w0, #7
	cmp	w0, 4
	bhi	.L364
	.loc 1 602 0
	ldr	w1, [x19, 44]
	.loc 1 603 0
	mov	x0, x21
	.loc 1 602 0
	sub	w1, w1, #1
	str	w1, [x19, 44]
	.loc 1 603 0
	ldr	w1, [x22, 208]
	bl	flip.isra.2
.LVL361:
	.loc 1 604 0
	ldr	w4, [x19, 44]
	cbnz	w4, .L378
.L367:
	.loc 1 624 0
	ldr	x0, [x19, 208]
	ldr	w0, [x0, 40]
	cmp	w0, 1
	bls	.L379
.L370:
	.loc 1 628 0
	mov	x0, x20
	bl	up
.LVL362:
	.loc 1 629 0
	bl	schedule
.LVL363:
.L371:
	.loc 1 582 0
	mov	x0, x20
	bl	down
.LVL364:
.LBB1124:
.LBB1122:
.LBB1119:
	.loc 12 234 0
	str	x24, [x23, 32]
.LBE1119:
.LBE1122:
.LBE1124:
	.loc 1 586 0
#APP
// 586 "drivers/gpu/drm/rockchip/ebc-dev/ebc_dev.c" 1
	dmb ish
// 0 "" 2
	.loc 1 587 0
#NO_APP
	ldr	x0, [x19, 208]
	ldr	w0, [x0, 40]
	tbnz	w0, #31, .L364
	cmp	w0, 1
	bgt	.L380
	.loc 1 590 0
	ldrsw	x0, [x21, 72]
	mov	x4, x19
	ldp	x1, x2, [x19, 128]
	add	x0, x19, x0, lsl 3
	ldr	x3, [x19, 152]
	ldr	x0, [x0, 168]
	bl	get_auto_image
.LVL365:
	.loc 1 595 0
	ldr	w1, [x22, 208]
	mov	x0, x21
	bl	flip.isra.2
.LVL366:
	.loc 1 624 0
	ldr	x0, [x19, 208]
	ldr	w0, [x0, 40]
	cmp	w0, 1
	bhi	.L370
.L379:
.LBB1125:
.LBB1126:
.LBB1127:
.LBB1128:
	.file 13 "./include/linux/workqueue.h"
	.loc 13 518 0
	ldr	x1, [x25, #:lo12:system_wq]
	mov	x2, x26
	mov	w0, 8
	bl	queue_work_on
.LVL367:
	b	.L370
	.p2align 3
.L364:
.LBE1128:
.LBE1127:
.LBE1126:
.LBE1125:
	.loc 1 612 0
	ldr	w1, [x19, 44]
	.loc 1 613 0
	mov	x0, x21
	.loc 1 612 0
	sub	w1, w1, #1
	str	w1, [x19, 44]
	.loc 1 613 0
	ldr	w1, [x22, 208]
	bl	flip.isra.2
.LVL368:
	.loc 1 614 0
	ldr	w4, [x19, 44]
	cbz	w4, .L367
	.loc 1 616 0
	ldrsw	x0, [x21, 72]
	.loc 1 617 0
	ldp	x2, x1, [x19, 200]
	.loc 1 616 0
	add	x0, x19, x0, lsl 3
	ldrb	w3, [x22, 220]
	ldr	x5, [x22, 296]
	ldr	x1, [x1, 16]
	ldr	x0, [x0, 168]
	ldr	x2, [x2, 16]
	bl	direct_mode_data_change.isra.0
.LVL369:
	.loc 1 620 0
	b	.L367
	.p2align 3
.L378:
	.loc 1 606 0
	ldrsw	x0, [x21, 72]
	.loc 1 607 0
	ldp	x2, x1, [x19, 200]
	.loc 1 606 0
	add	x0, x19, x0, lsl 3
	ldrb	w3, [x22, 220]
	ldr	x5, [x22, 296]
	ldr	x1, [x1, 16]
	ldr	x0, [x0, 168]
	ldr	x2, [x2, 16]
	bl	direct_mode_data_change_part.isra.1
.LVL370:
	.loc 1 610 0
	b	.L367
	.cfi_endproc
.LFE2816:
	.size	ebc_auto_tast_function, .-ebc_auto_tast_function
	.align	2
	.p2align 3,,7
	.type	ebc_frame_start, %function
ebc_frame_start:
.LFB2815:
	.loc 1 521 0
	.cfi_startproc
.LVL371:
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -32
	.cfi_offset 20, -24
	.loc 1 525 0
	add	x19, x0, 184
	.loc 1 521 0
	str	x21, [sp, 32]
	.cfi_offset 21, -16
	.loc 1 521 0
	mov	x20, x0
	.loc 1 522 0
	add	x21, x0, 24
	.loc 1 525 0
	ldr	x1, [x19, 208]
	ldr	w0, [x1, 40]
.LVL372:
	tbnz	w0, #31, .L382
	cmp	w0, 1
	ble	.L383
	sub	w0, w0, #7
	cmp	w0, 4
	bhi	.L382
	.loc 1 548 0
	ldr	x2, [x19, 200]
	.loc 1 545 0
	ldrb	w4, [x19, 36]
	str	w4, [x19, 44]
	.loc 1 546 0
	ldr	x0, [x19, 168]
	mov	w3, w4
	ldr	x2, [x2, 16]
	ldr	x5, [x20, 296]
	ldr	x1, [x1, 16]
	bl	direct_mode_data_change_part.isra.1
.LVL373:
.LBB1129:
.LBB1130:
	.loc 1 516 0
	str	wzr, [x21, 72]
	.loc 1 517 0
	mov	x0, x21
	ldr	w1, [x20, 208]
	bl	flip.isra.2
.LVL374:
.LBE1130:
.LBE1129:
	.loc 1 551 0
	ldr	w4, [x19, 44]
	.loc 1 553 0
	ldp	x2, x1, [x19, 200]
	.loc 1 551 0
	sub	w4, w4, #1
	str	w4, [x19, 44]
	.loc 1 552 0
	ldr	x0, [x19, 176]
	ldrb	w3, [x20, 220]
	ldr	x1, [x1, 16]
	ldr	x2, [x2, 16]
	ldr	x5, [x20, 296]
	bl	direct_mode_data_change_part.isra.1
.LVL375:
.L381:
	.loc 1 573 0
	ldp	x19, x20, [sp, 16]
.LVL376:
	ldr	x21, [sp, 32]
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 21
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL377:
	.p2align 3
.L382:
	.cfi_restore_state
	.loc 1 561 0
	ldr	x2, [x19, 200]
	.loc 1 558 0
	ldrb	w4, [x19, 36]
	str	w4, [x19, 44]
	.loc 1 559 0
	ldr	x0, [x19, 168]
	mov	w3, w4
	ldr	x5, [x20, 296]
	ldr	x2, [x2, 16]
	ldr	x1, [x1, 16]
	bl	direct_mode_data_change.isra.0
.LVL378:
.LBB1131:
.LBB1132:
	.loc 1 516 0
	str	wzr, [x21, 72]
	.loc 1 517 0
	mov	x0, x21
	ldr	w1, [x20, 208]
	bl	flip.isra.2
.LVL379:
.LBE1132:
.LBE1131:
	.loc 1 564 0
	ldr	w4, [x19, 44]
	.loc 1 566 0
	ldp	x2, x1, [x19, 200]
	.loc 1 564 0
	sub	w4, w4, #1
	str	w4, [x19, 44]
	.loc 1 565 0
	ldr	x0, [x19, 176]
	ldrb	w3, [x20, 220]
	ldr	x5, [x20, 296]
	ldr	x1, [x1, 16]
	ldr	x2, [x2, 16]
	bl	direct_mode_data_change.isra.0
.LVL380:
	.loc 1 573 0
	ldr	x21, [sp, 32]
	ldp	x19, x20, [sp, 16]
.LVL381:
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 20
	.cfi_restore 19
	.cfi_restore 21
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
.LVL382:
	.p2align 3
.L383:
	.cfi_restore_state
	.loc 1 528 0
	ldr	x0, [x19, 168]
	mov	x4, x19
	ldp	x1, x2, [x19, 128]
	ldr	x3, [x19, 152]
	bl	get_auto_image
.LVL383:
	.loc 1 533 0
	ldr	w0, [x19, 40]
	cbz	w0, .L385
.LBB1133:
.LBB1134:
	.loc 1 516 0
	str	wzr, [x21, 72]
	.loc 1 517 0
	mov	x0, x21
	ldr	w1, [x20, 208]
	bl	flip.isra.2
.LVL384:
.LBE1134:
.LBE1133:
	.loc 1 573 0
	ldr	x21, [sp, 32]
	ldp	x19, x20, [sp, 16]
.LVL385:
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 20
	.cfi_restore 19
	.cfi_restore 21
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
.LVL386:
.L385:
	.cfi_restore_state
	.loc 1 536 0
	adrp	x1, .LANCHOR3
	adrp	x0, .LC18
	add	x1, x1, :lo12:.LANCHOR3
	add	x0, x0, :lo12:.LC18
	bl	printk
.LVL387:
	.loc 1 537 0
	str	wzr, [x19, 28]
	b	.L381
	.cfi_endproc
.LFE2815:
	.size	ebc_frame_start, .-ebc_frame_start
	.align	2
	.p2align 3,,7
	.type	ebc_power_set.part.3, %function
ebc_power_set.part.3:
.LFB2850:
	.loc 1 182 0
	.cfi_startproc
.LVL388:
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -32
	.cfi_offset 20, -24
	.loc 1 188 0
	add	x20, x0, 184
	.loc 1 182 0
	str	x21, [sp, 32]
	.cfi_offset 21, -16
	.loc 1 182 0
	mov	x19, x0
	mov	w21, w1
	.loc 1 187 0
	mov	x0, 1
.LVL389:
	bl	ebc_notify
.LVL390:
	.loc 1 188 0
	ldr	w0, [x20, 424]
	cbnz	w0, .L390
	.loc 1 189 0
	mov	w0, 1
	str	w0, [x20, 424]
.LBB1135:
.LBB1136:
	.loc 4 58 0
	add	x0, x19, 400
	bl	__pm_stay_awake
.LVL391:
.L390:
.LBE1136:
.LBE1135:
	.loc 1 192 0
	str	w21, [x20, 184]
.LBB1137:
.LBB1138:
	.loc 11 46 0
	add	x1, x19, 24
.LBE1138:
.LBE1137:
	.loc 1 193 0
	ldr	x2, [x19, 8]
.LBB1140:
.LBB1139:
	.loc 11 46 0
	mov	x0, x2
	ldr	x2, [x2, 48]
	blr	x2
.LVL392:
.LBE1139:
.LBE1140:
	.loc 1 194 0
	ldr	x2, [x19, 16]
.LBB1141:
.LBB1142:
	.loc 3 30 0
	mov	w1, 1
	mov	x0, x2
	ldr	x2, [x2, 32]
	blr	x2
.LVL393:
.LBE1142:
.LBE1141:
	.loc 1 195 0
	ldr	x0, [x19]
	adrp	x1, .LC19
	add	x1, x1, :lo12:.LC19
	bl	_dev_info
.LVL394:
	.loc 1 210 0
	ldr	x21, [sp, 32]
.LVL395:
	ldp	x19, x20, [sp, 16]
.LVL396:
	ldp	x29, x30, [sp], 48
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 21
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2850:
	.size	ebc_power_set.part.3, .-ebc_power_set.part.3
	.align	2
	.p2align 3,,7
	.type	ebc_probe, %function
ebc_probe:
.LFB2841:
	.loc 1 1704 0
	.cfi_startproc
.LVL397:
	stp	x29, x30, [sp, -208]!
	.cfi_def_cfa_offset 208
	.cfi_offset 29, -208
	.cfi_offset 30, -200
.LBB1292:
.LBB1293:
	.loc 2 711 0
	mov	w2, 32960
	movk	w2, 0x60, lsl 16
.LBE1293:
.LBE1292:
	.loc 1 1704 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -192
	.cfi_offset 20, -184
	.loc 1 1705 0
	add	x20, x0, 16
	.loc 1 1704 0
	stp	x23, x24, [sp, 48]
	.cfi_offset 23, -160
	.cfi_offset 24, -152
	adrp	x23, __stack_chk_guard
	stp	x21, x22, [sp, 32]
	add	x0, x23, :lo12:__stack_chk_guard
.LVL398:
	stp	x25, x26, [sp, 64]
	stp	x27, x28, [sp, 80]
	.cfi_offset 21, -176
	.cfi_offset 22, -168
	.cfi_offset 25, -144
	.cfi_offset 26, -136
	.cfi_offset 27, -128
	.cfi_offset 28, -120
	.loc 1 1704 0
	ldr	x1, [x0]
	str	x1, [x29, 200]
	mov	x1,0
.LBB1295:
.LBB1294:
	.loc 2 711 0
	mov	x0, x20
	mov	x1, 800
	bl	devm_kmalloc
.LVL399:
.LBE1294:
.LBE1295:
	.loc 1 1716 0
	cbz	x0, .L438
	.loc 1 1720 0
	adrp	x25, .LANCHOR0
	mov	x19, x0
	.loc 1 1722 0
	adrp	x1, .LC20
	mov	w2, 0
	.loc 1 1720 0
	str	x0, [x25, #:lo12:.LANCHOR0]
	.loc 1 1722 0
	add	x1, x1, :lo12:.LC20
	ldr	x0, [x20, 752]
	.loc 1 1719 0
	str	x20, [x19]
	.loc 1 1722 0
	bl	of_parse_phandle
.LVL400:
	.loc 1 1723 0
	cbz	x0, .L478
	.loc 1 1728 0
	bl	of_find_device_by_node
.LVL401:
	.loc 1 1730 0
	cbz	x0, .L396
.LBB1296:
.LBB1297:
.LBB1298:
	.loc 2 1181 0
	ldr	x0, [x0, 200]
.LVL402:
.LBE1298:
.LBE1297:
.LBE1296:
	.loc 1 1733 0
	str	x0, [x19, 8]
	.loc 1 1734 0
	cbz	x0, .L396
	.loc 1 1736 0
	adrp	x1, frame_done_callback
	add	x1, x1, :lo12:frame_done_callback
	str	x1, [x0, 104]
	.loc 1 1738 0
	mov	w2, 0
	adrp	x1, .LC22
	add	x1, x1, :lo12:.LC22
	ldr	x0, [x20, 752]
	bl	of_parse_phandle
.LVL403:
	.loc 1 1739 0
	cbz	x0, .L479
	.loc 1 1744 0
	bl	of_find_i2c_device_by_node
.LVL404:
	.loc 1 1746 0
	cbz	x0, .L480
.LBB1299:
.LBB1300:
.LBB1301:
	.loc 2 1181 0
	ldr	x0, [x0, 216]
.LVL405:
.LBE1301:
.LBE1300:
.LBE1299:
	.loc 1 1750 0
	str	x0, [x19, 16]
	.loc 1 1751 0
	cbz	x0, .L481
	.loc 1 1757 0
	add	x21, x19, 184
.LVL406:
	.loc 1 1759 0
	add	x22, x19, 24
	.loc 1 1757 0
	str	x20, [x21, 88]
.LBB1302:
.LBB1303:
.LBB1304:
.LBB1305:
.LBB1306:
	.file 14 "./include/linux/of.h"
	.loc 14 499 0
	adrp	x1, .LC26
.LBE1306:
.LBE1305:
.LBE1304:
.LBE1303:
.LBE1302:
	.loc 1 1759 0
	str	x20, [x19, 24]
.LBB1401:
.LBB1397:
.LBB1313:
.LBB1310:
.LBB1307:
	.loc 14 499 0
	mov	x4, 0
.LBE1307:
.LBE1310:
.LBE1313:
.LBE1397:
.LBE1401:
	.loc 1 1760 0
	ldr	x2, [x19, 8]
.LBB1402:
.LBB1398:
.LBB1314:
.LBB1311:
.LBB1308:
	.loc 14 499 0
	add	x1, x1, :lo12:.LC26
.LBE1308:
.LBE1311:
.LBE1314:
.LBE1398:
.LBE1402:
	.loc 1 1761 0
	stp	x2, x0, [x22, 8]
.LBB1403:
.LBB1399:
.LBB1315:
.LBB1312:
.LBB1309:
	.loc 14 499 0
	mov	x3, 1
	ldr	x0, [x20, 752]
	add	x2, x19, 100
	bl	of_property_read_variable_u32_array
.LVL407:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1309:
.LBE1312:
.LBE1315:
.LBB1316:
.LBB1317:
.LBB1318:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC52
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 104
	add	x1, x1, :lo12:.LC52
	bl	of_property_read_variable_u32_array
.LVL408:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1318:
.LBE1317:
.LBE1316:
.LBB1319:
.LBB1320:
.LBB1321:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC53
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 108
	add	x1, x1, :lo12:.LC53
	bl	of_property_read_variable_u32_array
.LVL409:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1321:
.LBE1320:
.LBE1319:
.LBB1322:
.LBB1323:
.LBB1324:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC54
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 112
	add	x1, x1, :lo12:.LC54
	bl	of_property_read_variable_u32_array
.LVL410:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1324:
.LBE1323:
.LBE1322:
.LBB1325:
.LBB1326:
.LBB1327:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC55
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 128
	add	x1, x1, :lo12:.LC55
	bl	of_property_read_variable_u32_array
.LVL411:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1327:
.LBE1326:
.LBE1325:
.LBB1328:
.LBB1329:
.LBB1330:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC56
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 132
	add	x1, x1, :lo12:.LC56
	bl	of_property_read_variable_u32_array
.LVL412:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1330:
.LBE1329:
.LBE1328:
.LBB1331:
.LBB1332:
.LBB1333:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC57
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 136
	add	x1, x1, :lo12:.LC57
	bl	of_property_read_variable_u32_array
.LVL413:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1333:
.LBE1332:
.LBE1331:
.LBB1334:
.LBB1335:
.LBB1336:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC58
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 140
	add	x1, x1, :lo12:.LC58
	bl	of_property_read_variable_u32_array
.LVL414:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1336:
.LBE1335:
.LBE1334:
.LBB1337:
.LBB1338:
.LBB1339:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC59
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 144
	add	x1, x1, :lo12:.LC59
	bl	of_property_read_variable_u32_array
.LVL415:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1339:
.LBE1338:
.LBE1337:
.LBB1340:
.LBB1341:
.LBB1342:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC60
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 148
	add	x1, x1, :lo12:.LC60
	bl	of_property_read_variable_u32_array
.LVL416:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1342:
.LBE1341:
.LBE1340:
.LBB1343:
.LBB1344:
.LBB1345:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC61
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 152
	add	x1, x1, :lo12:.LC61
	bl	of_property_read_variable_u32_array
.LVL417:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1345:
.LBE1344:
.LBE1343:
.LBB1346:
.LBB1347:
.LBB1348:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC62
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 156
	add	x1, x1, :lo12:.LC62
	bl	of_property_read_variable_u32_array
.LVL418:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1348:
.LBE1347:
.LBE1346:
.LBB1349:
.LBB1350:
.LBB1351:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC63
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 160
	add	x1, x1, :lo12:.LC63
	bl	of_property_read_variable_u32_array
.LVL419:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1351:
.LBE1350:
.LBE1349:
.LBB1352:
.LBB1353:
.LBB1354:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC64
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 164
	add	x1, x1, :lo12:.LC64
	bl	of_property_read_variable_u32_array
.LVL420:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1354:
.LBE1353:
.LBE1352:
.LBB1355:
.LBB1356:
.LBB1357:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC65
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 168
	add	x1, x1, :lo12:.LC65
	bl	of_property_read_variable_u32_array
.LVL421:
	.loc 14 501 0
	tbnz	w0, #31, .L401
.LBE1357:
.LBE1356:
.LBE1355:
.LBB1358:
.LBB1359:
.LBB1360:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC66
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 172
	add	x1, x1, :lo12:.LC66
	bl	of_property_read_variable_u32_array
.LVL422:
	.loc 14 501 0
	tbnz	w0, #31, .L482
.LBE1360:
.LBE1359:
.LBE1358:
.LBB1361:
.LBB1362:
.LBB1363:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC27
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 176
	add	x1, x1, :lo12:.LC27
	bl	of_property_read_variable_u32_array
.LVL423:
	.loc 14 501 0
	tbnz	w0, #31, .L402
.L429:
.LBE1363:
.LBE1362:
.LBE1361:
.LBB1368:
.LBB1369:
.LBB1370:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC28
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 180
	add	x1, x1, :lo12:.LC28
	bl	of_property_read_variable_u32_array
.LVL424:
	.loc 14 501 0
	tbnz	w0, #31, .L403
.L430:
.LBE1370:
.LBE1369:
.LBE1368:
.LBB1375:
.LBB1376:
.LBB1377:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC29
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 116
	add	x1, x1, :lo12:.LC29
	bl	of_property_read_variable_u32_array
.LVL425:
	.loc 14 501 0
	tbnz	w0, #31, .L404
.L431:
.LBE1377:
.LBE1376:
.LBE1375:
.LBB1382:
.LBB1383:
.LBB1384:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC30
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 120
	add	x1, x1, :lo12:.LC30
	bl	of_property_read_variable_u32_array
.LVL426:
	.loc 14 501 0
	tbnz	w0, #31, .L405
.L432:
.LBE1384:
.LBE1383:
.LBE1382:
.LBE1399:
.LBE1403:
	.loc 1 1769 0
	ldr	w0, [x22, 88]
.LBB1404:
.LBB1405:
	.loc 1 1500 0
	mov	w2, 0
.LBE1405:
.LBE1404:
	.loc 1 1769 0
	str	w0, [x21, 56]
	.loc 1 1770 0
	ldr	w1, [x22, 84]
	str	w1, [x21, 60]
	.loc 1 1771 0
	mul	w0, w0, w1
.LBB1429:
.LBB1424:
	.loc 1 1500 0
	adrp	x1, .LC31
	add	x1, x1, :lo12:.LC31
.LBE1424:
.LBE1429:
	.loc 1 1771 0
	lsr	w3, w0, 1
	.loc 1 1772 0
	lsr	w0, w0, 2
	stp	w3, w0, [x21, 20]
.LBB1430:
.LBB1425:
	.loc 1 1491 0
	ldr	x26, [x19]
.LVL427:
	.loc 1 1500 0
	ldr	x0, [x26, 752]
	bl	of_parse_phandle
.LVL428:
	.loc 1 1501 0
	cbz	x0, .L439
	.loc 1 1504 0
	add	x2, x29, 104
	mov	w1, 0
	bl	of_address_to_resource
.LVL429:
	mov	w24, w0
	.loc 1 1506 0
	cbnz	w0, .L483
.LBB1406:
.LBB1407:
	.file 15 "./include/linux/ioport.h"
	.loc 15 204 0
	ldp	x1, x2, [x29, 104]
.LBE1407:
.LBE1406:
	.loc 1 1511 0
	str	x1, [x19, 184]
	.loc 1 1514 0
	mov	x3, 1
	mov	x0, x26
.LBB1409:
.LBB1408:
	.loc 15 204 0
	add	x2, x2, 1
	sub	x2, x2, x1
.LBE1408:
.LBE1409:
	.loc 1 1512 0
	str	w2, [x21, 16]
	.loc 1 1514 0
	sxtw	x2, w2
	bl	devm_memremap
.LVL430:
	str	x0, [x21, 8]
	.loc 1 1516 0
	cbz	x0, .L409
	.loc 1 1524 0
	mov	x1, x0
	ldr	w2, [x21, 16]
	ldr	x0, [x19, 184]
	mov	w4, 4
	mov	w3, 2097152
	bl	ebc_buf_init
.LVL431:
	.loc 1 1525 0
	cbnz	w0, .L409
	.loc 1 1530 0
	ldr	x0, [x21, 8]
	.loc 1 1531 0
	mov	x5, 1048576
	str	x5, [x22, 40]
.LBB1410:
.LBB1411:
	.loc 2 711 0
	mov	w2, 32960
.LBE1411:
.LBE1410:
	.loc 1 1530 0
	add	x6, x0, 10485760
	str	x6, [x22, 24]
	add	x4, x0, 11534336
	.loc 1 1536 0
	add	x1, x0, 12582912
	.loc 1 1532 0
	ldr	x3, [x19, 184]
.LBB1415:
.LBB1412:
	.loc 2 711 0
	movk	w2, 0x60, lsl 16
	mov	x0, x26
.LBE1412:
.LBE1415:
	.loc 1 1532 0
	add	x7, x3, 10485760
	str	x7, [x22, 32]
	.loc 1 1533 0
	str	x6, [x21, 168]
	.loc 1 1532 0
	add	x3, x3, 11534336
	.loc 1 1531 0
	str	x5, [x22, 64]
	.loc 1 1532 0
	stp	x4, x3, [x22, 48]
	.loc 1 1536 0
	str	x1, [x21, 112]
.LBB1416:
.LBB1413:
	.loc 2 711 0
	ldrsw	x1, [x21, 20]
.LBE1413:
.LBE1416:
	.loc 1 1533 0
	str	x4, [x21, 176]
.LBB1417:
.LBB1414:
	.loc 2 711 0
	bl	devm_kmalloc
.LVL432:
.LBE1414:
.LBE1417:
	.loc 1 1539 0
	str	x0, [x21, 128]
	.loc 1 1540 0
	cbz	x0, .L409
.LBB1418:
.LBB1419:
	.loc 2 711 0
	ldrsw	x1, [x21, 20]
	mov	w2, 32960
	movk	w2, 0x60, lsl 16
	mov	x0, x26
	bl	devm_kmalloc
.LVL433:
.LBE1419:
.LBE1418:
	.loc 1 1542 0
	str	x0, [x21, 136]
	.loc 1 1543 0
	ldr	x1, [x21, 128]
	cbz	x1, .L409
.LBB1420:
.LBB1421:
	.loc 2 711 0
	ldrsw	x1, [x21, 20]
	mov	w2, 32960
	movk	w2, 0x60, lsl 16
	mov	x0, x26
	bl	devm_kmalloc
.LVL434:
.LBE1421:
.LBE1420:
	.loc 1 1545 0
	str	x0, [x21, 144]
	.loc 1 1546 0
	ldr	x1, [x21, 128]
	cbz	x1, .L409
.LBB1422:
.LBB1423:
	.loc 2 711 0
	ldrsw	x1, [x21, 20]
	mov	w2, 32960
	movk	w2, 0x60, lsl 16
	mov	x0, x26
	bl	devm_kmalloc
.LVL435:
.LBE1423:
.LBE1422:
	.loc 1 1550 0
	str	x0, [x21, 152]
	.loc 1 1551 0
	ldr	x1, [x21, 128]
	cbz	x1, .L409
	.loc 1 1553 0
	ldrsw	x24, [x21, 20]
	mov	w1, 0
	mov	x2, x24
	bl	memset
.LVL436:
	.loc 1 1554 0
	ldr	x0, [x21, 144]
	mov	x2, x24
	mov	w1, 255
	bl	memset
.LVL437:
.LBE1425:
.LBE1430:
.LBB1431:
.LBB1432:
	.loc 1 1451 0
	ldr	x26, [x19, 272]
.LVL438:
	.loc 1 1457 0
	adrp	x1, .LC33
	mov	w2, 0
	add	x1, x1, :lo12:.LC33
	ldr	x0, [x26, 752]
	bl	of_parse_phandle
.LVL439:
	.loc 1 1458 0
	cbz	x0, .L440
	.loc 1 1461 0
	add	x2, x29, 104
	mov	w1, 0
	bl	of_address_to_resource
.LVL440:
	mov	w24, w0
	.loc 1 1463 0
	cbz	w0, .L484
.L410:
.LBE1432:
.LBE1431:
	.loc 1 1784 0
	adrp	x1, .LC68
	mov	x0, x20
	add	x1, x1, :lo12:.LC68
	bl	_dev_err
.LVL441:
	.loc 1 1785 0
	b	.L392
.LVL442:
	.p2align 3
.L401:
	.loc 1 1767 0
	mov	w24, -22
	.loc 1 1766 0
	adrp	x1, .LC72
	mov	w2, w24
	add	x1, x1, :lo12:.LC72
	mov	x0, x20
	bl	_dev_err
.LVL443:
.L392:
	.loc 1 1809 0
	add	x23, x23, :lo12:__stack_chk_guard
	mov	w0, w24
.LVL444:
	ldr	x2, [x29, 200]
	ldr	x1, [x23]
	eor	x1, x2, x1
	cbnz	x1, .L485
	ldp	x19, x20, [sp, 16]
	ldp	x21, x22, [sp, 32]
.LVL445:
	ldp	x23, x24, [sp, 48]
	ldp	x25, x26, [sp, 64]
.LVL446:
	ldp	x27, x28, [sp, 80]
.LVL447:
	ldp	x29, x30, [sp], 208
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 27
	.cfi_restore 28
	.cfi_restore 25
	.cfi_restore 26
	.cfi_restore 23
	.cfi_restore 24
	.cfi_restore 21
	.cfi_restore 22
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL448:
	.p2align 3
.L483:
	.cfi_restore_state
.LBB1439:
.LBB1426:
	.loc 1 1507 0
	adrp	x1, .LC32
	mov	x0, x26
	add	x1, x1, :lo12:.LC32
	bl	_dev_err
.LVL449:
.L406:
.LBE1426:
.LBE1439:
	.loc 1 1777 0
	adrp	x1, .LC67
	mov	x0, x20
	add	x1, x1, :lo12:.LC67
	bl	_dev_err
.LVL450:
	.loc 1 1778 0
	b	.L392
.LVL451:
	.p2align 3
.L405:
.LBB1440:
.LBB1400:
	.loc 1 1155 0
	str	wzr, [x22, 96]
	b	.L432
	.p2align 3
.L404:
.LBB1389:
.LBB1387:
.LBB1385:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC30
.LBE1385:
.LBE1387:
.LBE1389:
	.loc 1 1152 0
	str	wzr, [x22, 92]
.LBB1390:
.LBB1388:
.LBB1386:
	.loc 14 499 0
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 120
	add	x1, x1, :lo12:.LC30
	bl	of_property_read_variable_u32_array
.LVL452:
	.loc 14 501 0
	tbz	w0, #31, .L432
	b	.L405
	.p2align 3
.L403:
.LBE1386:
.LBE1388:
.LBE1390:
.LBB1391:
.LBB1380:
.LBB1378:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC29
.LBE1378:
.LBE1380:
.LBE1391:
	.loc 1 1149 0
	str	wzr, [x22, 156]
.LBB1392:
.LBB1381:
.LBB1379:
	.loc 14 499 0
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 116
	add	x1, x1, :lo12:.LC29
	bl	of_property_read_variable_u32_array
.LVL453:
	.loc 14 501 0
	tbz	w0, #31, .L431
	b	.L404
	.p2align 3
.L402:
.LBE1379:
.LBE1381:
.LBE1392:
.LBB1393:
.LBB1373:
.LBB1371:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC28
.LBE1371:
.LBE1373:
.LBE1393:
	.loc 1 1146 0
	str	wzr, [x22, 152]
.LBB1394:
.LBB1374:
.LBB1372:
	.loc 14 499 0
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 180
	add	x1, x1, :lo12:.LC28
	bl	of_property_read_variable_u32_array
.LVL454:
	.loc 14 501 0
	tbz	w0, #31, .L430
	b	.L403
	.p2align 3
.L482:
.LBE1372:
.LBE1374:
.LBE1394:
.LBB1395:
.LBB1366:
.LBB1364:
	.loc 14 499 0
	ldr	x0, [x20, 752]
	adrp	x1, .LC27
.LBE1364:
.LBE1366:
.LBE1395:
	.loc 1 1143 0
	str	wzr, [x22, 148]
.LBB1396:
.LBB1367:
.LBB1365:
	.loc 14 499 0
	mov	x4, 0
	mov	x3, 1
	add	x2, x19, 176
	add	x1, x1, :lo12:.LC27
	bl	of_property_read_variable_u32_array
.LVL455:
	.loc 14 501 0
	tbz	w0, #31, .L429
	b	.L402
.LVL456:
	.p2align 3
.L484:
.LBE1365:
.LBE1367:
.LBE1396:
.LBE1400:
.LBE1440:
.LBB1441:
.LBB1435:
	.loc 1 1469 0
	mov	x0, x26
	mov	x3, 1
.LBB1433:
.LBB1434:
	.loc 15 204 0
	ldp	x1, x26, [x29, 104]
.LVL457:
	add	x26, x26, 1
	sub	x26, x26, x1
.LBE1434:
.LBE1433:
	.loc 1 1469 0
	sxtw	x2, w26
	bl	devm_memremap
.LVL458:
	str	x0, [x19, 376]
	.loc 1 1471 0
	cbz	x0, .L486
	.loc 1 1476 0
	bl	epd_lut_from_mem_init
.LVL459:
	.loc 1 1477 0
	tbnz	w0, #31, .L487
.L412:
.LBE1435:
.LBE1441:
.LBB1442:
.LBB1443:
	.loc 1 1563 0
	add	x0, x19, 736
	mov	x1, 68719476704
	str	x1, [x21, 544]
	.loc 1 1565 0
	add	x25, x25, :lo12:.LANCHOR0
.LBB1444:
.LBB1445:
.LBB1446:
.LBB1447:
.LBB1448:
	.loc 12 234 0
	str	x0, [x19, 736]
.LBE1448:
.LBE1447:
.LBE1446:
.LBE1445:
.LBE1444:
	.loc 1 1561 0
	mov	w26, 99
.LBB1450:
.LBB1449:
	.file 16 "./include/linux/list.h"
	.loc 16 29 0
	str	x0, [x0, 8]
.LBE1449:
.LBE1450:
	.loc 1 1563 0
	adrp	x0, new_buffer_refresh
	add	x0, x0, :lo12:new_buffer_refresh
	str	x0, [x21, 568]
	.loc 1 1565 0
	adrp	x3, .LC69
	mov	w2, -1
	add	x3, x3, :lo12:.LC69
	mov	x1, x21
	adrp	x0, ebc_auto_tast_function
	.loc 1 1561 0
	str	w26, [x29, 104]
	.loc 1 1565 0
	add	x0, x0, :lo12:ebc_auto_tast_function
	bl	kthread_create_on_node
.LVL460:
	str	x0, [x25, 8]
	.loc 1 1566 0
	cmn	x0, #4096
	bhi	.L488
	.loc 1 1570 0
	add	x2, x29, 104
	mov	w1, 1
	bl	sched_setscheduler_nocheck
.LVL461:
	.loc 1 1571 0
	ldr	x2, [x25, 8]
.LBB1451:
.LBB1452:
	.file 17 "./arch/arm64/include/asm/atomic_lse.h"
	.loc 17 47 0
	mov	w0, 1
.LVL462:
	add	x1, x2, 48
.LVL463:
#APP
// 47 "./arch/arm64/include/asm/atomic_lse.h" 1
	.arch_extension lse
.if 1 == 1
661:
	bl	__ll_sc_atomic_add

662:
.pushsection .altinstructions,"a"
 .word 661b - .
 .word 663f - .
 .hword 5
 .byte 662b-661b
 .byte 664f-663f
.popsection
.pushsection .altinstr_replacement, "a"
663:
	.arch_extension lse
	stadd	w0, [x1]

664:
	.popsection
	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
.endif

// 0 "" 2
.LVL464:
#NO_APP
.LBE1452:
.LBE1451:
	.loc 1 1573 0
	adrp	x3, .LC38
	adrp	x0, ebc_refresh_tast_function
.LVL465:
	add	x3, x3, :lo12:.LC38
	add	x0, x0, :lo12:ebc_refresh_tast_function
	mov	w2, -1
	mov	x1, x21
	bl	kthread_create_on_node
.LVL466:
	str	x0, [x25, 16]
	.loc 1 1574 0
	cmn	x0, #4096
	bhi	.L489
	.loc 1 1578 0
	add	x2, x29, 104
	mov	w1, 1
	bl	sched_setscheduler_nocheck
.LVL467:
	.loc 1 1579 0
	ldr	x2, [x25, 16]
.LBB1453:
.LBB1454:
	.loc 17 47 0
	mov	w0, 1
.LVL468:
	add	x1, x2, 48
.LVL469:
#APP
// 47 "./arch/arm64/include/asm/atomic_lse.h" 1
	.arch_extension lse
.if 1 == 1
661:
	bl	__ll_sc_atomic_add

662:
.pushsection .altinstructions,"a"
 .word 661b - .
 .word 663f - .
 .hword 5
 .byte 662b-661b
 .byte 664f-663f
.popsection
.pushsection .altinstr_replacement, "a"
663:
	.arch_extension lse
	stadd	w0, [x1]

664:
	.popsection
	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
.endif

// 0 "" 2
.LVL470:
#NO_APP
.LBE1454:
.LBE1453:
.LBB1455:
	.loc 1 1582 0
	adrp	x3, .LC40
	adrp	x0, ebc_thread
.LVL471:
	add	x3, x3, :lo12:.LC40
	mov	w2, -1
	add	x0, x0, :lo12:ebc_thread
	mov	x1, x21
.LBE1455:
	.loc 1 1581 0
	str	w26, [x29, 104]
.LBB1456:
	.loc 1 1582 0
	bl	kthread_create_on_node
.LVL472:
	mov	x25, x0
.LVL473:
	cmn	x0, #4096
	bhi	.L415
	bl	wake_up_process
.LVL474:
.LBE1456:
	str	x25, [x21, 120]
	.loc 1 1587 0
	add	x2, x29, 104
	mov	w1, 1
	mov	x0, x25
	bl	sched_setscheduler_nocheck
.LVL475:
	.loc 1 1588 0
	ldr	x2, [x21, 120]
.LBB1457:
.LBB1458:
	.loc 17 47 0
	mov	w0, 1
.LVL476:
	add	x1, x2, 48
.LVL477:
#APP
// 47 "./arch/arm64/include/asm/atomic_lse.h" 1
	.arch_extension lse
.if 1 == 1
661:
	bl	__ll_sc_atomic_add

662:
.pushsection .altinstructions,"a"
 .word 661b - .
 .word 663f - .
 .hword 5
 .byte 662b-661b
 .byte 664f-663f
.popsection
.pushsection .altinstr_replacement, "a"
663:
	.arch_extension lse
	stadd	w0, [x1]

664:
	.popsection
	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
.endif

// 0 "" 2
.LVL478:
#NO_APP
.LBE1458:
.LBE1457:
.LBE1443:
.LBE1442:
.LBB1462:
.LBB1463:
	.loc 1 1597 0
	mov	w0, -1
.LVL479:
	str	w0, [x21, 52]
.LBB1464:
.LBB1465:
	.loc 4 39 0
	add	x0, x19, 400
.LVL480:
.LBE1465:
.LBE1464:
	.loc 1 1600 0
	stp	wzr, wzr, [x21, 28]
	.loc 1 1601 0
	str	wzr, [x21, 80]
.LBB1470:
.LBB1466:
	.loc 4 43 0
	adrp	x1, .LC41
.LBE1466:
.LBE1470:
	.loc 1 1596 0
	str	wzr, [x21, 184]
.LBB1471:
.LBB1467:
	.loc 4 43 0
	add	x1, x1, :lo12:.LC41
.LBE1467:
.LBE1471:
	.loc 1 1598 0
	str	wzr, [x21, 592]
	.loc 1 1609 0
	add	x25, x19, 616
.LVL481:
	.loc 1 1599 0
	str	wzr, [x21, 596]
	.loc 1 1610 0
	adrp	x26, jiffies
.LBB1472:
.LBB1468:
	.loc 4 42 0
	stp	xzr, xzr, [x0]
.LBE1468:
.LBE1472:
	.loc 1 1610 0
	mov	x27, 268435455
.LBB1473:
.LBB1469:
	.loc 4 42 0
	stp	xzr, xzr, [x0, 16]
	stp	xzr, xzr, [x0, 32]
	stp	xzr, xzr, [x0, 48]
	stp	xzr, xzr, [x0, 64]
	stp	xzr, xzr, [x0, 80]
	stp	xzr, xzr, [x0, 96]
	stp	xzr, xzr, [x0, 112]
	stp	xzr, xzr, [x0, 128]
	stp	xzr, xzr, [x0, 144]
	stp	xzr, xzr, [x0, 160]
	stp	xzr, xzr, [x0, 176]
	stp	xzr, xzr, [x0, 192]
	.loc 4 43 0
	str	x1, [x19, 400]
	.loc 4 45 0
	bl	wakeup_source_add
.LVL482:
.LBE1469:
.LBE1473:
	.loc 1 1606 0
	str	wzr, [x21, 424]
	.loc 1 1609 0
	mov	x4, 0
	mov	x3, 0
	mov	w2, 0
	mov	x0, x25
	adrp	x1, ebc_vdd_power_timeout
	add	x1, x1, :lo12:ebc_vdd_power_timeout
	bl	init_timer_key
.LVL483:
	.loc 1 1610 0
	ldr	x1, [x26, #:lo12:jiffies]
	mov	x0, x25
	.loc 1 1613 0
	add	x25, x19, 672
	.loc 1 1610 0
	add	x1, x1, x27
	bl	mod_timer
.LVL484:
	.loc 1 1613 0
	mov	x4, 0
	mov	x3, 0
	mov	w2, 0
	mov	x0, x25
	adrp	x1, ebc_frame_timeout
	add	x1, x1, :lo12:ebc_frame_timeout
	bl	init_timer_key
.LVL485:
	.loc 1 1614 0
	ldr	x1, [x26, #:lo12:jiffies]
	mov	x0, x25
	add	x1, x1, x27
	bl	mod_timer
.LVL486:
.LBE1463:
.LBE1462:
.LBB1474:
.LBB1475:
	.loc 1 1624 0
	adrp	x0, saved_command_line
	adrp	x1, .LC42
	.loc 1 1621 0
	stp	wzr, wzr, [x29, 100]
.LVL487:
	.loc 1 1624 0
	add	x1, x1, :lo12:.LC42
	ldr	x25, [x0, #:lo12:saved_command_line]
	mov	x0, x25
	bl	strstr
.LVL488:
	.loc 1 1625 0
	adrp	x1, .LC43
	.loc 1 1624 0
	mov	x26, x0
.LVL489:
	.loc 1 1625 0
	add	x1, x1, :lo12:.LC43
	mov	x0, x25
	bl	strstr
.LVL490:
	mov	x28, x0
.LVL491:
	.loc 1 1630 0
	cbz	x26, .L416
	.loc 1 1631 0
	add	x2, x29, 100
	adrp	x1, .LC44
	mov	x0, x26
	add	x1, x1, :lo12:.LC44
	bl	sscanf
.LVL492:
	.loc 1 1632 0
	ldr	w2, [x29, 100]
	ldr	x0, [x19, 184]
	cmp	x0, x2, uxtw
	bls	.L490
.L416:
	.loc 1 1644 0
	mov	w25, 0
.LVL493:
	mov	x27, 0
.LVL494:
	.loc 1 1628 0
	mov	x26, 0
.LVL495:
	.loc 1 1644 0
	cbz	x28, .L436
.LVL496:
.L435:
	.loc 1 1645 0
	add	x2, x29, 104
	mov	x0, x28
	adrp	x1, .LC47
	add	x1, x1, :lo12:.LC47
	bl	sscanf
.LVL497:
	.loc 1 1623 0
	mov	w28, 0
.LVL498:
	.loc 1 1646 0
	ldr	w2, [x29, 104]
	.loc 1 1628 0
	mov	x26, 0
.LVL499:
	.loc 1 1646 0
	ldr	x0, [x19, 184]
	cmp	x0, x2, uxtw
	bls	.L491
.L420:
	.loc 1 1658 0
	cbnz	w25, .L419
.LVL500:
.L436:
	.loc 1 1659 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC50
	add	x1, x1, :lo12:.LC50
	bl	_dev_info
.LVL501:
	.loc 1 1660 0
	ldr	x0, [x19, 16]
	bl	ebc_pmic_verity_vcom
.LVL502:
.LBB1476:
.LBB1477:
	.loc 1 1063 0
	bl	ebc_empty_buf_get
.LVL503:
	mov	x25, x0
.LVL504:
	.loc 1 1064 0
	ldp	w2, w0, [x19, 108]
	mov	w1, 255
	mul	w2, w2, w0
	ldr	x0, [x25, 16]
	lsr	w2, w2, 1
	bl	memset
.LVL505:
	.loc 1 1067 0
	stp	wzr, wzr, [x25, 48]
	.loc 1 1065 0
	mov	w0, 14
	str	w0, [x25, 40]
	.loc 1 1070 0
	mov	x0, x25
	.loc 1 1068 0
	ldr	w1, [x19, 108]
	str	w1, [x25, 56]
	.loc 1 1069 0
	ldr	w1, [x19, 112]
	str	w1, [x25, 60]
	.loc 1 1070 0
	bl	ebc_add_to_dsp_buf_list
.LVL506:
.L422:
.LBE1477:
.LBE1476:
	.loc 1 1677 0
	cbnz	w28, .L492
.L424:
	.loc 1 1690 0
	ldr	w0, [x21, 80]
	adrp	x22, .LANCHOR1
	cbz	w0, .L493
.L426:
	.loc 1 1695 0
	cbz	x27, .L427
	.loc 1 1696 0
	mov	x0, x27
	bl	kfree
.LVL507:
.L427:
	.loc 1 1697 0
	cbz	x26, .L418
	.loc 1 1698 0
	mov	x0, x26
	bl	kfree
.LVL508:
.L418:
.LBE1475:
.LBE1474:
.LBB1487:
.LBB1488:
.LBB1489:
	.loc 2 1186 0
	str	x19, [x20, 184]
.LBE1489:
.LBE1488:
.LBE1487:
.LBB1490:
.LBB1491:
	.loc 1 1436 0
	add	x22, x22, :lo12:.LANCHOR1
	add	x0, x22, 224
	bl	misc_register
.LVL509:
	.loc 1 1438 0
	ldr	x0, [x19, 272]
	add	x1, x22, 400
	bl	device_create_file
.LVL510:
	.loc 1 1439 0
	ldr	x0, [x19, 272]
	add	x1, x22, 432
	bl	device_create_file
.LVL511:
	.loc 1 1440 0
	ldr	x0, [x19, 272]
	add	x1, x22, 464
	bl	device_create_file
.LVL512:
	.loc 1 1441 0
	ldr	x0, [x19, 272]
	add	x1, x22, 496
	bl	device_create_file
.LVL513:
	.loc 1 1442 0
	ldr	x0, [x19, 272]
	add	x1, x22, 528
	bl	device_create_file
.LVL514:
	.loc 1 1443 0
	ldr	x0, [x19, 272]
	add	x1, x22, 560
	bl	device_create_file
.LVL515:
.LBE1491:
.LBE1490:
	.loc 1 1806 0
	ldr	x0, [x21, 88]
	adrp	x2, .LC14
	adrp	x1, .LC51
	add	x2, x2, :lo12:.LC14
	add	x1, x1, :lo12:.LC51
	bl	_dev_info
.LVL516:
	.loc 1 1808 0
	b	.L392
.LVL517:
	.p2align 3
.L490:
.LBB1492:
.LBB1484:
	.loc 1 1634 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC45
	add	x1, x1, :lo12:.LC45
	bl	_dev_info
.LVL518:
	.loc 1 1635 0
	ldp	w0, w1, [x22, 84]
	mul	w0, w0, w1
.LBB1478:
.LBB1479:
.LBB1480:
	.file 18 "./include/linux/slab.h"
	.loc 18 553 0
	mov	w1, 32960
	movk	w1, 0x60, lsl 16
	lsr	w0, w0, 1
	bl	__kmalloc
.LVL519:
	mov	x27, x0
.LVL520:
.LBE1480:
.LBE1479:
.LBE1478:
	.loc 1 1636 0
	cbz	x0, .L494
	.loc 1 1640 0
	ldp	w2, w1, [x22, 84]
	ldr	x3, [x19, 184]
	mul	w2, w2, w1
	ldr	w1, [x29, 100]
.LVL521:
	sub	x1, x1, x3
.LVL522:
	ldr	x3, [x21, 8]
	lsr	w2, w2, 1
	add	x1, x3, x1
	bl	memcpy
.LVL523:
	.loc 1 1644 0
	cbnz	x28, .L495
	.loc 1 1623 0
	mov	w28, 0
.LVL524:
	.loc 1 1628 0
	mov	x26, 0
.LVL525:
.L419:
	.loc 1 1665 0
	bl	ebc_empty_buf_get
.LVL526:
	mov	x25, x0
.LVL527:
	.loc 1 1666 0
	cbz	x0, .L422
	.loc 1 1667 0
	ldp	w2, w0, [x22, 84]
	mov	x1, x27
	mul	w2, w2, w0
	ldr	x0, [x25, 16]
	lsr	w2, w2, 1
	bl	memcpy
.LVL528:
	.loc 1 1670 0
	stp	wzr, wzr, [x25, 48]
	.loc 1 1668 0
	mov	w0, 7
	str	w0, [x25, 40]
	.loc 1 1673 0
	mov	x0, x25
	.loc 1 1671 0
	ldr	w1, [x22, 84]
	str	w1, [x25, 56]
	.loc 1 1672 0
	ldr	w1, [x22, 88]
	str	w1, [x25, 60]
	.loc 1 1673 0
	bl	ebc_add_to_dsp_buf_list
.LVL529:
	b	.L422
.LVL530:
	.p2align 3
.L493:
	.loc 1 1691 0
	mov	w2, 1
	str	w2, [x21, 80]
	.loc 1 1692 0
	add	x0, x22, :lo12:.LANCHOR1
	mov	w1, w2
	add	x0, x0, 304
	bl	__wake_up_sync
.LVL531:
	b	.L426
.LVL532:
	.p2align 3
.L491:
	.loc 1 1648 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC48
	add	x1, x1, :lo12:.LC48
	bl	_dev_info
.LVL533:
	.loc 1 1649 0
	ldp	w0, w1, [x22, 84]
	mul	w0, w0, w1
.LBB1481:
.LBB1482:
.LBB1483:
	.loc 18 553 0
	mov	w1, 32960
	movk	w1, 0x60, lsl 16
	lsr	w0, w0, 1
	bl	__kmalloc
.LVL534:
	mov	x26, x0
.LBE1483:
.LBE1482:
.LBE1481:
	.loc 1 1650 0
	cbz	x0, .L496
	.loc 1 1654 0
	ldp	w2, w1, [x22, 84]
	.loc 1 1647 0
	mov	w28, 1
	.loc 1 1654 0
	ldr	x3, [x19, 184]
	mul	w2, w2, w1
	ldr	w1, [x29, 104]
.LVL535:
	sub	x1, x1, x3
.LVL536:
	ldr	x3, [x21, 8]
	lsr	w2, w2, 1
	add	x1, x3, x1
	bl	memcpy
.LVL537:
	b	.L420
.LVL538:
	.p2align 3
.L409:
.LBE1484:
.LBE1492:
.LBB1493:
.LBB1427:
	.loc 1 1517 0
	mov	w24, -12
	b	.L406
.LVL539:
	.p2align 3
.L492:
.LBE1427:
.LBE1493:
.LBB1494:
.LBB1485:
	.loc 1 1678 0
	bl	ebc_empty_buf_get
.LVL540:
	mov	x25, x0
.LVL541:
	.loc 1 1679 0
	cbz	x0, .L424
	.loc 1 1680 0
	ldp	w2, w0, [x22, 84]
	mov	x1, x26
	mul	w2, w2, w0
	ldr	x0, [x25, 16]
	lsr	w2, w2, 1
	bl	memcpy
.LVL542:
	.loc 1 1683 0
	stp	wzr, wzr, [x25, 48]
	.loc 1 1681 0
	mov	w0, 7
	str	w0, [x25, 40]
	.loc 1 1684 0
	ldr	w0, [x22, 84]
	str	w0, [x25, 56]
	.loc 1 1686 0
	mov	x0, x25
	.loc 1 1685 0
	ldr	w1, [x22, 88]
	str	w1, [x25, 60]
	.loc 1 1686 0
	bl	ebc_add_to_dsp_buf_list
.LVL543:
	b	.L424
.LVL544:
	.p2align 3
.L487:
.LBE1485:
.LBE1494:
.LBB1495:
.LBB1436:
	.loc 1 1478 0
	ldr	x0, [x19, 272]
	adrp	x1, .LC35
	add	x1, x1, :lo12:.LC35
	bl	_dev_err
.LVL545:
	.loc 1 1479 0
	ldr	x0, [x19, 272]
	mov	w2, w26
	ldr	x1, [x19, 376]
	bl	epd_lut_from_file_init
.LVL546:
	.loc 1 1480 0
	tbz	w0, #31, .L412
	.loc 1 1481 0
	ldr	x0, [x19, 272]
	adrp	x1, .LC36
	.loc 1 1482 0
	mov	w24, -1
	.loc 1 1481 0
	add	x1, x1, :lo12:.LC36
	bl	_dev_err
.LVL547:
	b	.L410
.LVL548:
	.p2align 3
.L396:
.LBE1436:
.LBE1495:
	.loc 1 1731 0
	mov	w24, -517
	b	.L392
.LVL549:
	.p2align 3
.L488:
.LBB1496:
.LBB1459:
	.loc 1 1567 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC37
	add	x1, x1, :lo12:.LC37
	bl	_dev_err
.LVL550:
.L413:
.LBE1459:
.LBE1496:
	.loc 1 1791 0
	adrp	x1, .LC71
	mov	x0, x20
	add	x1, x1, :lo12:.LC71
	.loc 1 1792 0
	mov	w24, -1
	.loc 1 1791 0
	bl	_dev_err
.LVL551:
	.loc 1 1792 0
	b	.L392
.LVL552:
	.p2align 3
.L489:
.LBB1497:
.LBB1460:
	.loc 1 1575 0
	ldr	x0, [x21, 88]
	adrp	x1, .LC39
	add	x1, x1, :lo12:.LC39
	bl	_dev_err
.LVL553:
	b	.L413
.LVL554:
	.p2align 3
.L438:
.LBE1460:
.LBE1497:
	.loc 1 1717 0
	mov	w24, -12
	b	.L392
.LVL555:
	.p2align 3
.L415:
.LBB1498:
.LBB1461:
	.loc 1 1584 0
	ldr	x0, [x21, 88]
.LVL556:
	adrp	x1, .LC70
	.loc 1 1582 0
	str	x25, [x21, 120]
	.loc 1 1584 0
	add	x1, x1, :lo12:.LC70
	bl	_dev_err
.LVL557:
	b	.L413
.LVL558:
	.p2align 3
.L439:
.LBE1461:
.LBE1498:
.LBB1499:
.LBB1428:
	.loc 1 1502 0
	mov	w24, -19
	b	.L406
.LVL559:
.L478:
.LBE1428:
.LBE1499:
	.loc 1 1724 0
	adrp	x1, .LC21
	mov	x0, x20
	add	x1, x1, :lo12:.LC21
	.loc 1 1725 0
	mov	w24, -19
	.loc 1 1724 0
	bl	_dev_err
.LVL560:
	.loc 1 1725 0
	b	.L392
.L481:
	.loc 1 1752 0
	adrp	x1, .LC25
	mov	x0, x20
	add	x1, x1, :lo12:.LC25
	.loc 1 1753 0
	mov	w24, -517
	.loc 1 1752 0
	bl	_dev_err
.LVL561:
	.loc 1 1753 0
	b	.L392
.L479:
	.loc 1 1740 0
	adrp	x1, .LC23
	mov	x0, x20
	add	x1, x1, :lo12:.LC23
	.loc 1 1741 0
	mov	w24, -19
	.loc 1 1740 0
	bl	_dev_err
.LVL562:
	.loc 1 1741 0
	b	.L392
.LVL563:
.L440:
.LBB1500:
.LBB1437:
	.loc 1 1459 0
	mov	w24, -19
	b	.L410
.LVL564:
.L480:
.LBE1437:
.LBE1500:
	.loc 1 1747 0
	adrp	x1, .LC24
	mov	x0, x20
.LVL565:
	add	x1, x1, :lo12:.LC24
	.loc 1 1748 0
	mov	w24, -517
	.loc 1 1747 0
	bl	_dev_err
.LVL566:
	.loc 1 1748 0
	b	.L392
.LVL567:
.L486:
.LBB1501:
.LBB1438:
	.loc 1 1472 0
	ldr	x0, [x19, 272]
	adrp	x2, .LANCHOR3
	add	x2, x2, :lo12:.LANCHOR3
	adrp	x1, .LC34
	mov	w3, 1472
	add	x2, x2, 16
	add	x1, x1, :lo12:.LC34
	.loc 1 1473 0
	mov	w24, -12
	.loc 1 1472 0
	bl	_dev_err
.LVL568:
	b	.L410
.LVL569:
.L485:
.LBE1438:
.LBE1501:
	.loc 1 1809 0
	bl	__stack_chk_fail
.LVL570:
.L496:
.LBB1502:
.LBB1486:
	.loc 1 1651 0
	ldr	x0, [x21, 88]
.LVL571:
	adrp	x1, .LC49
	adrp	x22, .LANCHOR1
	add	x1, x1, :lo12:.LC49
	bl	_dev_err
.LVL572:
	b	.L418
.LVL573:
.L494:
	.loc 1 1637 0
	ldr	x0, [x21, 88]
.LVL574:
	adrp	x1, .LC46
	adrp	x22, .LANCHOR1
	add	x1, x1, :lo12:.LC46
	bl	_dev_err
.LVL575:
	b	.L418
.LVL576:
.L495:
	.loc 1 1633 0
	mov	w25, 1
.LVL577:
	b	.L435
.LBE1486:
.LBE1502:
	.cfi_endproc
.LFE2841:
	.size	ebc_probe, .-ebc_probe
	.align	2
	.p2align 3,,7
	.type	ebc_power_set.constprop.7, %function
ebc_power_set.constprop.7:
.LFB2854:
	.loc 1 182 0
	.cfi_startproc
.LVL578:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -16
	.cfi_offset 20, -8
	.loc 1 182 0
	mov	x19, x0
	.loc 1 198 0
	mov	x0, 0
.LVL579:
	bl	ebc_notify
.LVL580:
.LBB1503:
.LBB1504:
	.loc 3 35 0
	mov	w1, 0
.LBE1504:
.LBE1503:
	.loc 1 200 0
	ldr	x2, [x19, 16]
	.loc 1 199 0
	str	wzr, [x19, 368]
.LBB1506:
.LBB1505:
	.loc 3 35 0
	mov	x0, x2
	ldr	x2, [x2, 32]
	blr	x2
.LVL581:
.LBE1505:
.LBE1506:
	.loc 1 201 0
	ldr	x1, [x19, 8]
.LBB1507:
.LBB1508:
	.loc 11 51 0
	mov	x0, x1
	ldr	x1, [x1, 56]
	blr	x1
.LVL582:
.LBE1508:
.LBE1507:
	.loc 1 202 0
	ldr	w0, [x19, 608]
	cbnz	w0, .L503
	.loc 1 206 0
	ldr	x0, [x19]
	adrp	x1, .LC73
	add	x1, x1, :lo12:.LC73
	bl	_dev_info
.LVL583:
	.loc 1 210 0
	mov	w0, 0
	ldp	x19, x20, [sp, 16]
.LVL584:
	ldp	x29, x30, [sp], 32
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL585:
	.p2align 3
.L503:
	.cfi_restore_state
	.loc 1 203 0
	str	wzr, [x19, 608]
.LBB1509:
.LBB1510:
	.loc 4 68 0
	add	x0, x19, 400
	bl	__pm_relax
.LVL586:
.LBE1510:
.LBE1509:
	.loc 1 206 0
	ldr	x0, [x19]
	adrp	x1, .LC73
	add	x1, x1, :lo12:.LC73
	bl	_dev_info
.LVL587:
	.loc 1 210 0
	mov	w0, 0
	ldp	x19, x20, [sp, 16]
.LVL588:
	ldp	x29, x30, [sp], 32
	.cfi_restore 20
	.cfi_restore 19
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2854:
	.size	ebc_power_set.constprop.7, .-ebc_power_set.constprop.7
	.align	2
	.p2align 3,,7
	.type	ebc_suspend, %function
ebc_suspend:
.LFB2843:
	.loc 1 1819 0
	.cfi_startproc
.LVL589:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -16
	.cfi_offset 20, -8
.LBB1511:
.LBB1512:
	.loc 2 1181 0
	ldr	x20, [x0, 184]
.LBE1512:
.LBE1511:
	.loc 1 1823 0
	add	x19, x20, 184
	ldr	w0, [x19, 184]
.LVL590:
	cmp	w0, 1
	beq	.L507
.L505:
	.loc 1 1827 0
	mov	w0, 1
	str	w0, [x19, 596]
	.loc 1 1829 0
	ldr	x1, [x20, 16]
.LBB1513:
.LBB1514:
	.loc 3 40 0
	mov	x0, x1
	ldr	x1, [x1, 40]
	blr	x1
.LVL591:
.LBE1514:
.LBE1513:
	.loc 1 1830 0
	ldr	x0, [x19, 88]
	adrp	x1, .LC75
	add	x1, x1, :lo12:.LC75
	bl	_dev_info
.LVL592:
	.loc 1 1833 0
	mov	w0, 0
	ldp	x19, x20, [sp, 16]
	ldp	x29, x30, [sp], 32
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
	.p2align 3
.L507:
	.cfi_restore_state
	.loc 1 1824 0
	ldr	x0, [x19, 88]
	adrp	x2, .LANCHOR3
	add	x2, x2, :lo12:.LANCHOR3
	adrp	x1, .LC74
	add	x2, x2, 40
	add	x1, x1, :lo12:.LC74
	bl	_dev_info
.LVL593:
	.loc 1 1825 0
	mov	x0, x20
	bl	ebc_power_set.constprop.7
.LVL594:
	b	.L505
	.cfi_endproc
.LFE2843:
	.size	ebc_suspend, .-ebc_suspend
	.align	2
	.p2align 3,,7
	.global	refresh_new_image2
	.type	refresh_new_image2, %function
refresh_new_image2:
.LFB2806:
	.loc 1 214 0
	.cfi_startproc
.LVL595:
	.loc 1 222 0
	ldp	w13, w6, [x4, 56]
	cmp	w6, 0
	add	w10, w6, 15
	csel	w10, w10, w6, lt
.LVL596:
	.loc 1 229 0
	cmp	w13, 0
	.loc 1 222 0
	asr	w10, w10, 4
.LVL597:
	.loc 1 229 0
	ble	.L508
	sub	w11, w10, #1
	mov	w12, 0
.LVL598:
	add	x11, x11, 1
	lsl	x11, x11, 3
.LVL599:
	.p2align 2
.L510:
	.loc 1 230 0 discriminator 1
	mov	x4, 0
.LVL600:
	cmp	w10, 0
	ble	.L515
	.p2align 2
.L517:
	.loc 1 231 0
	ldr	x9, [x3, x4, lsl 3]
	.loc 1 235 0
	mov	x6, -1
.LVL601:
	.loc 1 232 0
	ldr	x8, [x1, x4, lsl 3]
	.loc 1 233 0
	ldr	x7, [x0, x4, lsl 3]
	.loc 1 245 0
	cmp	x9, 0
	.loc 1 234 0
	cbz	w5, .L511
	.loc 1 237 0
	ldr	x6, [x2]
.LVL602:
	add	x2, x2, 8
.LVL603:
.L511:
	.loc 1 245 0
	and	x6, x6, x8
.LVL604:
	csel	x7, x6, x7, eq
	.loc 1 255 0
	str	x7, [x0, x4, lsl 3]
	add	x4, x4, 1
	.loc 1 230 0
	cmp	w10, w4
	bgt	.L517
	add	x3, x3, x11
.LVL605:
	add	x1, x1, x11
.LVL606:
	add	x0, x0, x11
.LVL607:
.L515:
	.loc 1 229 0 discriminator 2
	add	w12, w12, 1
	cmp	w13, w12
	bne	.L510
.LVL608:
.L508:
	ret
	.cfi_endproc
.LFE2806:
	.size	refresh_new_image2, .-refresh_new_image2
	.align	2
	.p2align 3,,7
	.global	new_buffer_refresh
	.type	new_buffer_refresh, %function
new_buffer_refresh:
.LFB2808:
	.loc 1 284 0
	.cfi_startproc
.LVL609:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	.loc 1 285 0
	adrp	x0, .LANCHOR0
.LVL610:
	.loc 1 284 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -16
	.cfi_offset 20, -8
	.loc 1 288 0
	adrp	x19, .LANCHOR1
	add	x19, x19, :lo12:.LANCHOR1
	.loc 1 285 0
	ldr	x20, [x0, #:lo12:.LANCHOR0]
.LVL611:
	.loc 1 288 0
	add	x19, x19, 592
	mov	x0, x19
	bl	down
.LVL612:
	.loc 1 290 0
	add	x4, x20, 184
	ldr	x1, [x4, 208]
	.loc 1 289 0
	ldr	x0, [x4, 128]
	ldp	x2, x3, [x4, 144]
	ldr	w5, [x1, 40]
	ldr	x1, [x1, 16]
	bl	refresh_new_image2
.LVL613:
	.loc 1 294 0
	mov	x0, x19
	bl	up
.LVL614:
	.loc 1 295 0
	ldp	x19, x20, [sp, 16]
.LVL615:
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
	.cfi_endproc
.LFE2808:
	.size	new_buffer_refresh, .-new_buffer_refresh
	.align	2
	.p2align 3,,7
	.type	ebc_thread, %function
ebc_thread:
.LFB2820:
	.loc 1 781 0
	.cfi_startproc
.LVL616:
	stp	x29, x30, [sp, -160]!
	.cfi_def_cfa_offset 160
	.cfi_offset 29, -160
	.cfi_offset 30, -152
	.loc 1 782 0
	adrp	x1, .LANCHOR0
	.loc 1 781 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	stp	x23, x24, [sp, 48]
	.cfi_offset 19, -144
	.cfi_offset 20, -136
	.cfi_offset 23, -112
	.cfi_offset 24, -104
	adrp	x24, __stack_chk_guard
	stp	x25, x26, [sp, 64]
	add	x0, x24, :lo12:__stack_chk_guard
.LVL617:
	stp	x21, x22, [sp, 32]
	.cfi_offset 25, -96
	.cfi_offset 26, -88
	.cfi_offset 21, -128
	.cfi_offset 22, -120
	adrp	x22, .LANCHOR1
	stp	x27, x28, [sp, 80]
	.cfi_offset 27, -80
	.cfi_offset 28, -72
.LBB1543:
.LBB1544:
.LBB1545:
	.loc 1 1051 0
	add	x22, x22, :lo12:.LANCHOR1
.LBE1545:
.LBE1544:
.LBE1543:
	.loc 1 782 0
	ldr	x20, [x1, #:lo12:.LANCHOR0]
.LVL618:
.LBB1552:
.LBB1549:
.LBB1546:
	.loc 1 1051 0
	add	x19, x22, 304
.LBE1546:
.LBE1549:
.LBE1552:
	.loc 1 781 0
	ldr	x1, [x0]
	str	x1, [x29, 152]
	mov	x1,0
	.loc 1 787 0
	mov	w26, 0
.LVL619:
	.loc 1 784 0
	add	x27, x20, 184
	.loc 1 786 0
	mov	w23, 0
.LVL620:
.LBB1553:
.LBB1550:
.LBB1547:
	.loc 1 1051 0
	mov	w25, 1
.LVL621:
	.p2align 2
.L523:
.LBE1547:
.LBE1550:
.LBE1553:
	.loc 1 790 0
	ldr	w0, [x27, 600]
.LVL622:
	cbnz	w0, .L653
.L524:
	.loc 1 796 0
	bl	ebc_dsp_buf_get
.LVL623:
	mov	x28, x0
	.loc 1 798 0
	cbz	x0, .L526
	.loc 1 798 0 is_stmt 0 discriminator 1
	ldr	x1, [x0, 8]
	cbz	x1, .L526
	.loc 1 799 0 is_stmt 1
	ldr	w1, [x0, 40]
	cmp	w1, 17
	beq	.L654
	.loc 1 803 0
	ldr	x2, [x27, 592]
	cbz	x2, .L529
	.loc 1 804 0
	cmp	w1, 16
	beq	.L655
	.loc 1 810 0
	bl	ebc_remove_from_dsp_buf_list
.LVL624:
	.loc 1 811 0
	mov	x0, x28
	bl	ebc_buf_release
.LVL625:
	.loc 1 790 0
	ldr	w0, [x27, 600]
	cbz	w0, .L524
	.p2align 2
.L653:
	.loc 1 791 0
	ldr	w0, [x27, 184]
	cmp	w0, 1
	beq	.L656
.L525:
	.loc 1 1057 0
	add	x24, x24, :lo12:__stack_chk_guard
	mov	w0, 0
	ldr	x2, [x29, 152]
	ldr	x1, [x24]
	eor	x1, x2, x1
	cbnz	x1, .L657
	ldp	x19, x20, [sp, 16]
.LVL626:
	ldp	x21, x22, [sp, 32]
	ldp	x23, x24, [sp, 48]
.LVL627:
	ldp	x25, x26, [sp, 64]
.LVL628:
	ldp	x27, x28, [sp, 80]
.LVL629:
	ldp	x29, x30, [sp], 160
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 27
	.cfi_restore 28
	.cfi_restore 25
	.cfi_restore 26
	.cfi_restore 23
	.cfi_restore 24
	.cfi_restore 21
	.cfi_restore 22
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL630:
	.p2align 3
.L526:
	.cfi_restore_state
	.loc 1 1038 0
	ldr	w0, [x27, 28]
.LVL631:
	cmp	w0, 1
	beq	.L658
	.loc 1 1047 0
	ldr	w0, [x27, 184]
	cmp	w0, 1
	beq	.L659
.LVL632:
.L650:
	ldr	w0, [x27, 80]
.LVL633:
	.loc 1 1050 0
	cbz	w0, .L660
.L604:
.LVL634:
.L594:
	.loc 1 1052 0
	str	wzr, [x27, 80]
	b	.L523
.LVL635:
	.p2align 3
.L660:
.LBB1554:
.LBB1551:
	.loc 1 1051 0 discriminator 1
	mov	w1, 0
	add	x0, x29, 112
	bl	init_wait_entry
.LVL636:
	b	.L605
	.p2align 3
.L661:
.LVL637:
.LBB1548:
	.loc 1 1051 0 is_stmt 0 discriminator 5
	cbnz	x0, .L594
	.loc 1 1051 0 discriminator 7
	bl	schedule
.LVL638:
.L605:

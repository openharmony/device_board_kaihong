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

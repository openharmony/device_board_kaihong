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

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Rockchip Electronics Co. Ltd.
 *
 * Author: Zorro Liu <zorro.liu@rock-chips.com>
 */

	.arch armv8-a
	.file	"pvi_waveform.c"
	.text
.Ltext0:
	.cfi_sections	.debug_frame
	.align	2
	.p2align 3,,7
	.type	get_wf_mode_index, %function
get_wf_mode_index:
.LFB1548:
	.file 1 "drivers/gpu/drm/rockchip/ebc-dev/epdlut/pvi_waveform.c"
	.loc 1 383 0
	.cfi_startproc
.LVL0:
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -16
	.cfi_offset 20, -8
	.loc 1 384 0
	adrp	x19, .LANCHOR0
	add	x1, x19, :lo12:.LANCHOR0
	.loc 1 383 0
	mov	w20, w0
	.loc 1 384 0
	ldr	x3, [x1, 40]
.LVL1:
.LBB7:
.LBB8:
	.loc 1 284 0
	ldrb	w0, [x3, 16]
.LVL2:
	cmp	w0, 25
	beq	.L3
	bhi	.L4
	cmp	w0, 18
	beq	.L5
	bls	.L45
	cmp	w0, 22
	bne	.L46
	.loc 1 298 0
	mov	w2, 1
	.loc 1 302 0
	mov	w0, 4
	.loc 1 300 0
	mov	w6, 2
	.loc 1 301 0
	mov	w5, 3
	.loc 1 304 0
	mov	w4, 5
	.loc 1 305 0
	mov	w3, 6
.LVL3:
	.loc 1 297 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
.LBE8:
.LBE7:
	.loc 1 390 0
	cmp	w20, 5
.LBB13:
.LBB9:
	.loc 1 299 0
	stp	w2, w2, [x1, 4]
	.loc 1 301 0
	stp	w6, w5, [x1, 12]
	.loc 1 303 0
	stp	w0, w0, [x1, 20]
	.loc 1 304 0
	stp	w3, w4, [x1, 28]
.LBE9:
.LBE13:
	.loc 1 390 0
	bne	.L47
	.p2align 2
.L26:
	add	x19, x19, :lo12:.LANCHOR0
	add	x19, x19, 12
	.loc 1 426 0
	ldr	w0, [x19]
.L50:
	.loc 1 427 0
	ldp	x19, x20, [sp, 16]
.LVL4:
	ldp	x29, x30, [sp], 32
	.cfi_remember_state
	.cfi_restore 20
	.cfi_restore 19
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
.LVL5:
	.p2align 3
.L4:
	.cfi_restore_state
.LBB14:
.LBB10:
	.loc 1 284 0
	cmp	w0, 35
	beq	.L10
	bls	.L48
	cmp	w0, 67
	beq	.L3
	cmp	w0, 84
	bne	.L2
	.loc 1 325 0
	mov	w0, 4
	.loc 1 321 0
	mov	w2, 1
	.loc 1 323 0
	mov	w5, 2
	.loc 1 324 0
	mov	w4, 3
	.loc 1 327 0
	mov	w3, 5
.LVL6:
	.loc 1 320 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
	.loc 1 322 0
	stp	w2, w2, [x1, 4]
	.loc 1 324 0
	stp	w5, w4, [x1, 12]
	.loc 1 326 0
	stp	w0, w0, [x1, 20]
	.loc 1 328 0
	stp	w3, w0, [x1, 28]
	.p2align 2
.L13:
.LBE10:
.LBE14:
	.loc 1 390 0
	cmp	w20, 5
	beq	.L26
.L47:
	.loc 1 393 0
	cmp	w20, 2
	beq	.L26
	.loc 1 396 0
	cmp	w20, 6
	beq	.L16
	bhi	.L17
	cmp	w20, 3
	beq	.L18
	cmp	w20, 4
	beq	.L19
	cmp	w20, 1
	beq	.L49
.L15:
	.loc 1 422 0
	adrp	x0, .LC1
	add	x0, x0, :lo12:.LC1
	bl	printk
.LVL7:
	.loc 1 423 0
	mov	w0, -1
	.loc 1 427 0
	ldp	x19, x20, [sp, 16]
.LVL8:
	ldp	x29, x30, [sp], 32
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL9:
	.p2align 3
.L5:
	.cfi_restore_state
.LBB15:
.LBB11:
	.loc 1 348 0
	mov	w0, 5
	.loc 1 346 0
	mov	w2, 3
	.loc 1 344 0
	mov	w6, 1
	.loc 1 345 0
	mov	w5, 7
	.loc 1 349 0
	mov	w4, 6
	.loc 1 350 0
	mov	w3, 4
.LVL10:
	.loc 1 343 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
	.loc 1 345 0
	stp	w6, w5, [x1, 4]
	.loc 1 347 0
	stp	w2, w2, [x1, 12]
	.loc 1 349 0
	stp	w0, w4, [x1, 20]
	.loc 1 351 0
	stp	w3, w0, [x1, 28]
	b	.L13
.LVL11:
	.p2align 3
.L46:
	.loc 1 284 0
	cmp	w0, 24
	bne	.L2
.L9:
	.loc 1 309 0
	add	x0, x19, :lo12:.LANCHOR0
	.loc 1 314 0
	mov	w1, 4
	.loc 1 310 0
	mov	w2, 1
	.loc 1 312 0
	mov	w6, 2
	.loc 1 313 0
	mov	w5, 3
	.loc 1 315 0
	mov	w4, 5
	.loc 1 316 0
	mov	w3, 6
.LVL12:
	.loc 1 309 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
	.loc 1 311 0
	stp	w2, w2, [x0, 4]
	.loc 1 313 0
	stp	w6, w5, [x0, 12]
	.loc 1 315 0
	stp	w1, w4, [x0, 20]
	.loc 1 317 0
	stp	w3, w1, [x0, 28]
	b	.L13
.LVL13:
	.p2align 3
.L3:
	.loc 1 332 0
	add	x0, x19, :lo12:.LANCHOR0
	.loc 1 337 0
	mov	w1, 4
	.loc 1 333 0
	mov	w7, 1
	.loc 1 334 0
	mov	w6, 7
	.loc 1 335 0
	mov	w5, 2
	.loc 1 336 0
	mov	w4, 3
	.loc 1 338 0
	mov	w3, 5
.LVL14:
	.loc 1 339 0
	mov	w2, 6
	.loc 1 332 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
	.loc 1 334 0
	stp	w7, w6, [x0, 4]
	.loc 1 336 0
	stp	w5, w4, [x0, 12]
	.loc 1 338 0
	stp	w1, w3, [x0, 20]
	.loc 1 340 0
	stp	w2, w1, [x0, 28]
	b	.L13
	.p2align 3
.L49:
.LBE11:
.LBE15:
	.loc 1 396 0
	add	x19, x19, :lo12:.LANCHOR0
	.loc 1 426 0
	ldr	w0, [x19]
	b	.L50
	.p2align 3
.L17:
	.loc 1 396 0
	cmp	w20, 8
	beq	.L27
	bcc	.L26
	.loc 1 411 0
	add	x19, x19, :lo12:.LANCHOR0
	.loc 1 396 0
	cmp	w20, 9
	beq	.L22
	cmp	w20, 10
	.loc 1 414 0
	add	x19, x19, 24
	.loc 1 396 0
	bne	.L15
	.loc 1 426 0
	ldr	w0, [x19]
	b	.L50
.LVL15:
	.p2align 3
.L45:
.LBB16:
.LBB12:
	.loc 1 284 0
	cmp	w0, 9
	bne	.L2
	.loc 1 290 0
	mov	w0, 3
	.loc 1 287 0
	mov	w2, 1
	.loc 1 289 0
	mov	w4, 2
	.loc 1 294 0
	mov	w3, 4
.LVL16:
	.loc 1 286 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
	.loc 1 288 0
	stp	w2, w2, [x1, 4]
	.loc 1 290 0
	stp	w4, w0, [x1, 12]
	.loc 1 292 0
	stp	w0, w0, [x1, 20]
	.loc 1 293 0
	stp	w3, w0, [x1, 28]
	b	.L13
.LVL17:
	.p2align 3
.L48:
	.loc 1 284 0
	cmp	w0, 32
	beq	.L9
.L2:
	.loc 1 365 0
	add	x0, x19, :lo12:.LANCHOR0
	.loc 1 370 0
	mov	w1, 4
	.loc 1 366 0
	mov	w2, 1
	.loc 1 365 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
	.loc 1 368 0
	mov	w5, 2
	.loc 1 369 0
	mov	w4, 3
	.loc 1 367 0
	stp	w2, w2, [x0, 4]
	.loc 1 371 0
	mov	w2, 5
	.loc 1 369 0
	stp	w5, w4, [x0, 12]
	.loc 1 370 0
	str	w1, [x0, 20]
	.loc 1 373 0
	str	w1, [x0, 32]
	.loc 1 372 0
	mov	w1, 6
	stp	w2, w1, [x0, 24]
	.loc 1 374 0
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	ldrb	w2, [x3, 22]
	ldrb	w1, [x3, 16]
	bl	printk
.LVL18:
	b	.L13
.LVL19:
	.p2align 3
.L10:
	.loc 1 358 0
	mov	w0, 3
	.loc 1 355 0
	mov	w5, 1
	.loc 1 356 0
	mov	w4, 5
	.loc 1 357 0
	mov	w3, 2
.LVL20:
	.loc 1 361 0
	mov	w2, 4
	.loc 1 354 0
	str	wzr, [x19, #:lo12:.LANCHOR0]
	.loc 1 356 0
	stp	w5, w4, [x1, 4]
	.loc 1 358 0
	stp	w3, w0, [x1, 12]
	.loc 1 360 0
	stp	w0, w0, [x1, 20]
	.loc 1 362 0
	stp	w2, w0, [x1, 28]
	b	.L13
	.p2align 3
.L22:
.LBE12:
.LBE16:
	.loc 1 411 0
	add	x19, x19, 20
	.loc 1 426 0
	ldr	w0, [x19]
	b	.L50
	.p2align 3
.L19:
	.loc 1 420 0
	add	x19, x19, :lo12:.LANCHOR0
	add	x19, x19, 4
	.loc 1 426 0
	ldr	w0, [x19]
	b	.L50
	.p2align 3
.L18:
	.loc 1 417 0
	add	x19, x19, :lo12:.LANCHOR0
	add	x19, x19, 8
	.loc 1 426 0
	ldr	w0, [x19]
	b	.L50
	.p2align 3
.L27:
	.loc 1 396 0
	add	x19, x19, :lo12:.LANCHOR0
	add	x19, x19, 16
	.loc 1 426 0
	ldr	w0, [x19]
	b	.L50
	.p2align 3
.L16:
	.loc 1 396 0
	add	x19, x19, :lo12:.LANCHOR0
	add	x19, x19, 28
	.loc 1 426 0
	ldr	w0, [x19]
	b	.L50
	.cfi_endproc
.LFE1548:
	.size	get_wf_mode_index, .-get_wf_mode_index
	.align	2
	.p2align 3,,7
	.global	decodewaveform
	.type	decodewaveform, %function
decodewaveform:
.LFB1546:
	.loc 1 64 0
	.cfi_startproc
.LVL21:
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -32
	.cfi_offset 20, -24
	.loc 1 72 0
	adrp	x20, .LANCHOR0
	add	x2, x20, :lo12:.LANCHOR0
	.loc 1 64 0
	str	x21, [sp, 32]
	.cfi_offset 21, -16
	.loc 1 72 0
	ldr	x5, [x2, 48]
	cbz	x5, .L89
	.loc 1 76 0
	sub	w2, w1, #16
	mov	w21, w1
	tst	w2, -17
	bne	.L71
	mov	w7, 1
.LVL22:
	mov	w15, 0
	mov	w19, 0
.LVL23:
	mov	w3, 0
	mov	w6, 0
	.p2align 2
.L55:
	.loc 1 86 0
	ldrb	w2, [x0, w15, uxtw]
	cmp	w2, 255
	beq	.L58
	.loc 1 91 0
	cmp	w2, 252
	beq	.L90
.L59:
	.loc 1 98 0
	lsl	w4, w19, 16
	.loc 1 96 0
	cbz	w7, .L60
	.loc 1 98 0
	add	w10, w4, w3, lsl 8
	add	w9, w3, 1
	add	w4, w4, w6
	add	w10, w10, w6
	.loc 1 99 0
	add	w8, w3, 2
	add	w9, w4, w9, lsl 8
	.loc 1 100 0
	add	w7, w3, 3
.LVL24:
	add	w8, w4, w8, lsl 8
	.loc 1 98 0
	and	w11, w2, 3
	.loc 1 101 0
	add	w4, w4, w7, lsl 8
	.loc 1 98 0
	strb	w11, [x5, w10, uxtw]
	.loc 1 99 0
	ubfx	x12, x2, 2, 2
	strb	w12, [x5, w9, uxtw]
	.loc 1 100 0
	ubfx	x13, x2, 4, 2
	strb	w13, [x5, w8, uxtw]
	.loc 1 101 0
	lsr	w14, w2, 6
	strb	w14, [x5, w4, uxtw]
	add	w3, w3, 4
	.loc 1 102 0
	add	w2, w15, 1
	.loc 1 104 0
	cmp	w21, w3
	bhi	.L61
	.loc 1 106 0
	add	w6, w6, 1
	.loc 1 105 0
	mov	w3, 0
	.loc 1 106 0
	cmp	w21, w6
	bhi	.L61
	.loc 1 108 0
	add	w19, w19, 1
	.loc 1 107 0
	mov	w6, 0
.L61:
	.loc 1 112 0
	ldrb	w4, [x0, w2, uxtw]
	.loc 1 113 0
	cbz	w4, .L62
	.p2align 2
.L64:
	.loc 1 114 0
	lsl	w2, w19, 16
	add	w9, w3, 1
	add	w10, w2, w3, lsl 8
	add	w2, w2, w6
	add	w10, w10, w6
	.loc 1 115 0
	add	w8, w3, 2
	add	w9, w2, w9, lsl 8
	.loc 1 116 0
	add	w7, w3, 3
	add	w8, w2, w8, lsl 8
	.loc 1 117 0
	add	w2, w2, w7, lsl 8
	.loc 1 114 0
	strb	w11, [x5, w10, uxtw]
	.loc 1 117 0
	add	w3, w3, 4
	.loc 1 115 0
	strb	w12, [x5, w9, uxtw]
	.loc 1 113 0
	sub	w4, w4, #1
	.loc 1 116 0
	strb	w13, [x5, w8, uxtw]
	.loc 1 118 0
	cmp	w21, w3
	.loc 1 117 0
	strb	w14, [x5, w2, uxtw]
	.loc 1 118 0
	bhi	.L63
	.loc 1 120 0
	add	w6, w6, 1
	.loc 1 119 0
	mov	w3, 0
	.loc 1 120 0
	cmp	w21, w6
	bhi	.L63
	.loc 1 122 0
	add	w19, w19, 1
	.loc 1 121 0
	mov	w6, 0
.L63:
	.loc 1 113 0
	ands	w4, w4, 255
	bne	.L64
.L62:
	.loc 1 127 0
	add	w15, w15, 2
	mov	w7, 1
.LVL25:
.L65:
	.loc 1 81 0
	cmp	w19, 255
	bls	.L55
	.loc 1 82 0
	adrp	x0, .LC3
.LVL26:
	add	x0, x0, :lo12:.LC3
	bl	printk
.LVL27:
	.loc 1 147 0
	cmp	w21, 32
	beq	.L56
.LVL28:
.L57:
	.loc 1 164 0
	mov	w0, w19
.LVL29:
.L51:
	.loc 1 165 0
	ldp	x19, x20, [sp, 16]
.LVL30:
	ldr	x21, [sp, 32]
.LVL31:
	ldp	x29, x30, [sp], 48
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 21
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa 31, 0
	ret
.LVL32:
	.p2align 3
.L60:
	.cfi_restore_state
	.loc 1 131 0
	add	w11, w4, w3, lsl 8
	add	w10, w3, 1
	add	w4, w4, w6
	add	w11, w11, w6
	.loc 1 132 0
	add	w9, w3, 2
	add	w10, w4, w10, lsl 8
	.loc 1 133 0
	add	w8, w3, 3
	add	w9, w4, w9, lsl 8
	.loc 1 131 0
	and	w12, w2, 3
	.loc 1 134 0
	add	w4, w4, w8, lsl 8
	.loc 1 131 0
	strb	w12, [x5, w11, uxtw]
	.loc 1 132 0
	ubfx	x8, x2, 2, 2
	strb	w8, [x5, w10, uxtw]
	.loc 1 133 0
	ubfx	x8, x2, 4, 2
	strb	w8, [x5, w9, uxtw]
	.loc 1 134 0
	lsr	w2, w2, 6
	strb	w2, [x5, w4, uxtw]
	add	w3, w3, 4
	.loc 1 135 0
	add	w15, w15, 1
	.loc 1 137 0
	cmp	w21, w3
	bhi	.L65
	.loc 1 139 0
	add	w6, w6, 1
	.loc 1 138 0
	mov	w3, 0
	.loc 1 139 0
	cmp	w21, w6
	bhi	.L65
	.loc 1 141 0
	add	w19, w19, 1
	.loc 1 138 0
	mov	w3, w7
	.loc 1 140 0
	mov	w6, 0
	b	.L65
.L90:
	.loc 1 93 0
	add	w15, w15, 1
	.loc 1 92 0
	eor	w7, w7, 1
	ldrb	w2, [x0, w15, uxtw]
	b	.L59
.L58:
	.loc 1 147 0
	cmp	w21, 32
	bne	.L57
	.loc 1 149 0 discriminator 1
	cbz	w19, .L57
.L56:
	add	x20, x20, :lo12:.LANCHOR0
	.loc 1 121 0
	mov	w8, 0
	ldr	x1, [x20, 48]
.LVL33:
.L70:
	lsl	w7, w8, 16
.LVL34:
	mov	w6, 0
	mov	w5, w7
	.p2align 2
.L68:
	lsr	w4, w6, 1
	mov	w0, 0
.LVL35:
	add	w4, w7, w4, lsl 8
	.p2align 2
.L67:
	.loc 1 156 0 discriminator 3
	add	w3, w0, w5
.LVL36:
	.loc 1 157 0 discriminator 3
	add	w2, w4, w0, lsr 1
	.loc 1 151 0 discriminator 3
	add	w0, w0, 2
	cmp	w0, 32
	.loc 1 156 0 discriminator 3
	ldrb	w3, [x1, w3, uxtw]
.LVL37:
	.loc 1 157 0 discriminator 3
	strb	w3, [x1, w2, uxtw]
	.loc 1 151 0 discriminator 3
	bne	.L67
	.loc 1 150 0 discriminator 2
	add	w6, w6, 2
	add	w5, w5, 512
	cmp	w6, 32
	bne	.L68
	.loc 1 149 0 discriminator 2
	add	w8, w8, 1
	and	w8, w8, 255
	cmp	w19, w8
	bhi	.L70
	b	.L57
.LVL38:
.L71:
	.loc 1 77 0
	mov	w0, -22
.LVL39:
	.loc 1 165 0
	ldr	x21, [sp, 32]
.LVL40:
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
.LVL41:
.L89:
	.cfi_restore_state
	.loc 1 73 0
	adrp	x0, .LC2
.LVL42:
	add	x0, x0, :lo12:.LC2
	bl	printk
.LVL43:
	.loc 1 74 0
	mov	w0, -22
	b	.L51
	.cfi_endproc
.LFE1546:
	.size	decodewaveform, .-decodewaveform
	.align	2
	.p2align 3,,7
	.type	get_wf_frm_num, %function
get_wf_frm_num:
.LFB1550:
	.loc 1 450 0
	.cfi_startproc
.LVL44:
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	.loc 1 451 0
	adrp	x2, .LANCHOR0+40
	.loc 1 450 0
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 451 0
	ldr	x2, [x2, #:lo12:.LANCHOR0+40]
.LVL45:
	.loc 1 456 0
	ldrb	w3, [x2, 32]
	add	w0, w3, w0, lsl 2
.LVL46:
	.loc 1 459 0
	add	x4, x2, x0, sxtw
	.loc 1 458 0
	ldrb	w5, [x2, w0, sxtw]
	.loc 1 460 0
	ldrb	w3, [x4, 2]
	.loc 1 459 0
	ldrb	w0, [x4, 1]
	.loc 1 461 0
	ldrb	w6, [x4, 3]
	.loc 1 462 0
	add	w4, w0, w3
	add	w4, w4, w5
	cmp	w6, w4, uxtb
	bne	.L109
	.loc 1 467 0
	lsl	w3, w3, 16
	orr	w0, w3, w0, lsl 8
	orr	w0, w0, w5
	.loc 1 469 0
	add	w0, w0, w1, lsl 2
	.loc 1 472 0
	add	x3, x2, x0, sxtw
	.loc 1 471 0
	ldrb	w4, [x2, w0, sxtw]
	.loc 1 473 0
	ldrb	w1, [x3, 2]
.LVL47:
	.loc 1 472 0
	ldrb	w0, [x3, 1]
	.loc 1 474 0
	ldrb	w5, [x3, 3]
	.loc 1 476 0
	add	w3, w0, w1
	add	w3, w3, w4
	cmp	w5, w3, uxtb
	bne	.L110
	.loc 1 481 0
	lsl	w1, w1, 16
	.loc 1 483 0
	ldrb	w3, [x2, 16]
	.loc 1 481 0
	orr	w0, w1, w0, lsl 8
	orr	w0, w0, w4
	.loc 1 483 0
	cmp	w3, 25
	bhi	.L96
	cmp	w3, 24
	bcs	.L97
	cmp	w3, 22
	beq	.L97
.L95:
	.loc 1 492 0
	mov	w1, 16
	add	x0, x2, x0
	bl	decodewaveform
.LVL48:
.L91:
	.loc 1 497 0
	ldp	x29, x30, [sp], 16
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
.LVL49:
	.p2align 3
.L96:
	.cfi_restore_state
	.loc 1 483 0
	cmp	w3, 32
	beq	.L97
	cmp	w3, 67
	bne	.L95
.L97:
	.loc 1 489 0
	mov	w1, 32
	add	x0, x2, x0
	bl	decodewaveform
.LVL50:
	.loc 1 497 0
	ldp	x29, x30, [sp], 16
	.cfi_remember_state
	.cfi_restore 29
	.cfi_restore 30
	.cfi_def_cfa 31, 0
	ret
.LVL51:
.L110:
	.cfi_restore_state
	.loc 1 477 0
	adrp	x1, .LANCHOR1
	adrp	x0, .LC4
	mov	w2, 477
.LVL52:
	add	x1, x1, :lo12:.LANCHOR1
	add	x0, x0, :lo12:.LC4
	bl	printk
.LVL53:
	.loc 1 478 0
	mov	w0, -22
	b	.L91
.LVL54:
.L109:
	.loc 1 463 0
	adrp	x1, .LANCHOR1
.LVL55:
	adrp	x0, .LC4
	mov	w2, 463
.LVL56:
	add	x1, x1, :lo12:.LANCHOR1
	add	x0, x0, :lo12:.LC4
	bl	printk
.LVL57:
	.loc 1 464 0
	mov	w0, -22
	b	.L91
	.cfi_endproc
.LFE1550:
	.size	get_wf_frm_num, .-get_wf_frm_num
	.align	2
	.p2align 3,,7
	.global	pvi_wf_get_lut
	.type	pvi_wf_get_lut, %function
pvi_wf_get_lut:
.LFB1552:
	.loc 1 937 0
	.cfi_startproc
.LVL58:
	stp	x29, x30, [sp, -64]!
	.cfi_def_cfa_offset 64
	.cfi_offset 29, -64
	.cfi_offset 30, -56
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	str	x23, [sp, 48]
	.cfi_offset 23, -16
	.loc 1 943 0
	adrp	x23, .LANCHOR0
	add	x3, x23, :lo12:.LANCHOR0
	.loc 1 937 0
	stp	x19, x20, [sp, 16]
	stp	x21, x22, [sp, 32]
	.cfi_offset 19, -48
	.cfi_offset 20, -40
	.cfi_offset 21, -32
	.cfi_offset 22, -24
	.loc 1 943 0
	ldr	x5, [x3, 40]
	cbz	x5, .L133
	.loc 1 946 0
	cbz	x0, .L150
.L113:
	.loc 1 951 0
	adrp	x6, .LANCHOR2
	mov	w3, 21846
	movk	w3, 0x5555, lsl 16
	add	x8, x6, :lo12:.LANCHOR2
	ldr	w7, [x6, #:lo12:.LANCHOR2]
	smull	x4, w2, w3
	smull	x3, w7, w3
	lsr	x4, x4, 32
	sub	w4, w4, w2, asr 31
	lsr	x3, x3, 32
	sub	w3, w3, w7, asr 31
	cmp	w4, w3
	beq	.L151
.L114:
	.loc 1 954 0
	add	x4, x6, :lo12:.LANCHOR2
.LBB22:
.LBB23:
	.loc 1 432 0
	ldrb	w3, [x5, 38]
.LVL59:
.LBE23:
.LBE22:
	.loc 1 954 0
	str	w2, [x6, #:lo12:.LANCHOR2]
	.loc 1 955 0
	str	w1, [x4, 4]
.LBB26:
.LBB24:
	.loc 1 436 0
	cbz	w3, .L115
	.loc 1 437 0
	ldrb	w4, [x5, 48]
	.loc 1 436 0
	mov	w20, 0
.LVL60:
	.loc 1 437 0
	cmp	w2, w4
	bge	.L117
	b	.L132
	.p2align 3
.L118:
	ldrb	w4, [x5, w4, sxtw]
	cmp	w2, w4
	blt	.L132
.L117:
	.loc 1 436 0
	add	w20, w20, 1
	.loc 1 437 0
	add	w4, w20, 48
	.loc 1 436 0
	cmp	w3, w20
	bne	.L118
.L115:
	.loc 1 444 0
	sub	w20, w3, #1
.L132:
	mov	x21, x0
.LBE24:
.LBE26:
	.loc 1 958 0
	add	x0, x23, :lo12:.LANCHOR0
.LVL61:
	mov	w19, w1
	.loc 1 962 0
	cmp	w1, 3
	.loc 1 958 0
	ldr	x1, [x21, 16]
.LVL62:
	str	x1, [x0, 48]
	.loc 1 962 0
	beq	.L119
	bhi	.L120
	cbnz	w19, .L121
.L136:
	.loc 1 981 0
	mov	w0, -1
	b	.L111
.LVL63:
.L133:
	.loc 1 944 0
	mov	w0, -19
.LVL64:
.L111:
	.loc 1 985 0
	ldp	x19, x20, [sp, 16]
.LVL65:
	ldp	x21, x22, [sp, 32]
.LVL66:
	ldr	x23, [sp, 48]
	ldp	x29, x30, [sp], 64
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
.LVL67:
.L120:
	.cfi_restore_state
	.loc 1 962 0
	cmp	w19, 11
	bhi	.L136
.L121:
.LBB27:
.LBB28:
	.loc 1 902 0
	mov	w0, w19
	bl	get_wf_mode_index
.LVL68:
	.loc 1 903 0
	mov	w1, w20
	bl	get_wf_frm_num
.LVL69:
	mov	w22, w0
.LVL70:
	.loc 1 904 0
	tbnz	w0, #31, .L152
	.loc 1 908 0
	str	w0, [x21]
	.loc 1 910 0
	cmp	w19, 5
	beq	.L153
.L124:
	.loc 1 917 0
	cbz	w22, .L148
	add	x23, x23, :lo12:.LANCHOR0
	mov	w10, 0
	mov	w11, 0
.LVL71:
	ldr	x4, [x23, 48]
.LVL72:
.L131:
	mov	w8, w10
	mov	w9, 0
	.p2align 2
.L129:
	and	w0, w9, 65535
.LBE28:
.LBE27:
.LBB33:
.LBB25:
	.loc 1 437 0
	mov	w2, 0
	ubfiz	w7, w0, 8, 4
	and	w0, w0, 240
	add	w7, w7, w10
	add	w6, w10, w0, lsl 4
	.p2align 2
.L128:
.LBE25:
.LBE33:
.LBB34:
.LBB31:
.LBB29:
	.loc 1 922 0
	and	w0, w2, 65535
	.loc 1 929 0
	add	w5, w2, w8
	.loc 1 928 0
	add	w1, w6, w0, lsr 4
	.loc 1 927 0
	and	w0, w0, 15
	add	w0, w0, w7
.LBE29:
	.loc 1 919 0
	add	w2, w2, 1
	cmp	w2, 256
.LBB30:
	.loc 1 928 0
	ldrb	w1, [x4, w1, sxtw]
	.loc 1 927 0
	ldrb	w3, [x4, w0, sxtw]
	.loc 1 929 0
	ubfiz	w0, w1, 2, 2
	.loc 1 927 0
	and	w1, w3, 3
	.loc 1 929 0
	orr	w0, w0, w1
	strb	w0, [x4, w5, sxtw]
.LBE30:
	.loc 1 919 0
	bne	.L128
	.loc 1 918 0
	add	w9, w9, 1
	add	w8, w8, 256
	cmp	w9, 256
	bne	.L129
	.loc 1 917 0
	add	w11, w11, 1
	add	w10, w10, 65536
	cmp	w22, w11
	bne	.L131
.LVL73:
.L148:
.LBE31:
.LBE34:
	.loc 1 984 0
	mov	w0, 0
	.loc 1 979 0
	b	.L111
.LVL74:
.L153:
.LBB35:
.LBB32:
	.loc 1 911 0
	mov	w0, 4
.LVL75:
	bl	get_wf_mode_index
.LVL76:
	.loc 1 912 0
	mov	w1, w20
	bl	get_wf_frm_num
.LVL77:
	.loc 1 913 0
	cmp	w0, 0
	bgt	.L124
	.loc 1 914 0
	adrp	x0, .LC6
	add	x0, x0, :lo12:.LC6
	bl	printk
.LVL78:
	b	.L124
.LVL79:
.L152:
	.loc 1 905 0
	adrp	x0, .LC5
.LVL80:
	add	x0, x0, :lo12:.LC5
	bl	printk
.LVL81:
.LBE32:
.LBE35:
	.loc 1 975 0
	mov	w0, -1
	b	.L111
.LVL82:
.L119:
	.loc 1 978 0
	adrp	x0, .LC7
	add	x0, x0, :lo12:.LC7
	bl	printk
.LVL83:
	b	.L148
.LVL84:
.L151:
	.loc 1 951 0 discriminator 1
	ldr	w3, [x8, 4]
	cmp	w3, w1
	bne	.L114
	b	.L148
.L150:
	.loc 1 946 0 discriminator 1
	ldr	x3, [x0, 16]
	cbnz	x3, .L113
	.loc 1 947 0
	mov	w0, -22
.LVL85:
	b	.L111
	.cfi_endproc
.LFE1552:
	.size	pvi_wf_get_lut, .-pvi_wf_get_lut
	.align	2
	.p2align 3,,7
	.global	pvi_wf_input
	.type	pvi_wf_input, %function
pvi_wf_input:
.LFB1553:
	.loc 1 994 0
	.cfi_startproc
.LVL86:
	.loc 1 997 0
	adrp	x2, .LANCHOR0
	add	x1, x2, :lo12:.LANCHOR0
	ldr	x1, [x1, 40]
	cbnz	x1, .L160
	.loc 1 1001 0
	ldrb	w1, [x0, 16]
	cmp	w1, 25
	bls	.L185
	cmp	w1, 35
	beq	.L158
	bls	.L186
	cmp	w1, 67
	beq	.L158
	cmp	w1, 84
	bne	.L156
.L158:
	.loc 1 1018 0
	add	x2, x2, :lo12:.LANCHOR0
	.loc 1 1020 0
	mov	w1, 0
	.loc 1 1018 0
	str	x0, [x2, 40]
	.loc 1 1021 0
	mov	w0, w1
.LVL87:
	ret
.LVL88:
	.p2align 3
.L185:
	.loc 1 1001 0
	cmp	w1, 24
	bcs	.L158
	cmp	w1, 18
	beq	.L158
	cmp	w1, 22
	beq	.L158
	cmp	w1, 9
	beq	.L158
.L156:
	.loc 1 994 0
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	add	x29, sp, 0
	.cfi_def_cfa_register 29
	.loc 1 1013 0
	ldrb	w2, [x0, 22]
	adrp	x0, .LC8
.LVL89:
	add	x0, x0, :lo12:.LC8
	bl	printk
.LVL90:
	.loc 1 1015 0
	mov	w1, -8
	.loc 1 1021 0
	mov	w0, w1
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa 31, 0
	ret
.LVL91:
	.p2align 3
.L160:
	.loc 1 998 0
	mov	w1, -16
	.loc 1 1021 0
	mov	w0, w1
.LVL92:
	ret
.LVL93:
	.p2align 3
.L186:
	.loc 1 1001 0
	cmp	w1, 32
	beq	.L158
	b	.L156
	.cfi_endproc
.LFE1553:
	.size	pvi_wf_input, .-pvi_wf_input
	.align	2
	.p2align 3,,7
	.global	pvi_wf_get_version
	.type	pvi_wf_get_version, %function
pvi_wf_get_version:
.LFB1554:
	.loc 1 1030 0
	.cfi_startproc
	.loc 1 1031 0
	adrp	x0, .LANCHOR0
	add	x0, x0, :lo12:.LANCHOR0
	ldr	x3, [x0, 40]
.LVL94:
	.loc 1 1035 0
	cbz	x3, .L190
	.loc 1 1039 0 discriminator 3
	add	x0, x0, 56
	mov	x1, 0
	.p2align 2
.L189:
	add	x2, x3, x1
	ldrb	w2, [x2, 65]
	strb	w2, [x1, x0]
	add	x1, x1, 1
	.loc 1 1038 0 discriminator 3
	cmp	x1, 31
	bne	.L189
	.loc 1 1041 0
	strb	wzr, [x0, 31]
	.loc 1 1043 0
	ret
.L190:
	.loc 1 1036 0
	mov	x0, 0
	.loc 1 1044 0
	ret
	.cfi_endproc
.LFE1554:
	.size	pvi_wf_get_version, .-pvi_wf_get_version
	.section	.rodata
	.align	3
	.set	.LANCHOR1,. + 0
	.type	__func__.16854, %object
	.size	__func__.16854, 15
__func__.16854:
	.string	"get_wf_frm_num"
	.data
	.align	2
	.set	.LANCHOR2,. + 0
	.type	sftemp.16894, %object
	.size	sftemp.16894, 4
sftemp.16894:
	.word	-1
	.type	stype.16893, %object
	.size	stype.16893, 4
stype.16893:
	.word	12
	.bss
	.align	3
	.set	.LANCHOR0,. + 0
	.type	pvi_modes.16805, %object
	.size	pvi_modes.16805, 36
pvi_modes.16805:
	.zero	36
	.zero	4
	.type	global_waveform, %object
	.size	global_waveform, 8
global_waveform:
	.zero	8
	.type	waveformdata, %object
	.size	waveformdata, 8
waveformdata:
	.zero	8
	.type	spi_id_buffer.16929, %object
	.size	spi_id_buffer.16929, 32
spi_id_buffer.16929:
	.zero	32
	.section	.rodata.str1.8,"aMS",@progbits,1
	.align	3
.LC0:
	.string	"pvi : Unknow waveform version %x,%x\n"
	.zero	3
.LC1:
	.string	"pvi: unspport PVI waveform type"
.LC2:
	.string	"waveformdata is NULL\n"
	.zero	2
.LC3:
	.string	"pvi: decodec waveform 19 error\n"
.LC4:
	.string	"pvi: %s %d check error\n"
.LC5:
	.string	"pvi waveform get frame number failed\n"
	.zero	2
.LC6:
	.string	"Get GRAY2 waveform data failed during AUTO mode\n"
	.zero	7
.LC7:
	.string	"pvi: unsupport WF GRAY4n"
	.zero	7
.LC8:
	.string	"pvi : Unknow waveform version %x,%x, may be wrong waveform file\n"
	.text
.Letext0:
	.file 2 "./include/uapi/asm-generic/int-ll64.h"
	.file 3 "./include/asm-generic/int-ll64.h"
	.file 4 "./include/uapi/asm-generic/posix_types.h"
	.file 5 "./include/uapi/linux/types.h"
	.file 6 "./include/linux/types.h"
	.file 7 "./include/linux/ioport.h"
	.file 8 "./arch/arm64/include/asm/insn.h"
	.file 9 "./include/linux/init.h"
	.file 10 "./arch/arm64/include/asm/alternative.h"
	.file 11 "./include/asm-generic/atomic-long.h"
	.file 12 "./arch/arm64/include/asm/cache.h"
	.file 13 "./include/linux/printk.h"
	.file 14 "./include/linux/kernel.h"
	.file 15 "./include/linux/notifier.h"
	.file 16 "./include/asm-generic/qspinlock_types.h"
	.file 17 "./include/linux/lockdep.h"
	.file 18 "./include/linux/spinlock_types.h"
	.file 19 "./arch/arm64/include/asm/hwcap.h"
	.file 20 "./include/linux/jump_label.h"
	.file 21 "./arch/arm64/include/asm/jump_label.h"
	.file 22 "./arch/arm64/include/asm/cpufeature.h"
	.file 23 "./arch/arm64/include/uapi/asm/ptrace.h"
	.file 24 "./include/asm-generic/sections.h"
	.file 25 "./arch/arm64/include/asm/sections.h"
	.file 26 "./arch/arm64/include/asm/virt.h"
	.file 27 "./arch/arm64/include/asm/memory.h"
	.file 28 "./arch/arm64/include/asm/processor.h"
	.file 29 "./arch/arm64/include/asm/fpsimd.h"
	.file 30 "./include/linux/osq_lock.h"
	.file 31 "./include/linux/debug_locks.h"
	.file 32 "./include/linux/mutex.h"
	.file 33 "./include/linux/sched.h"
	.file 34 "./include/uapi/linux/time.h"
	.file 35 "./include/linux/restart_block.h"
	.file 36 "./include/linux/compat_time.h"
	.file 37 "./arch/arm64/include/asm/stack_pointer.h"
	.file 38 "./arch/arm64/include/asm/thread_info.h"
	.file 39 "./include/linux/cpumask.h"
	.file 40 "./include/linux/rcupdate.h"
	.file 41 "./include/linux/radix-tree.h"
	.file 42 "./include/linux/sched/debug.h"
	.file 43 "./include/linux/wait.h"
	.file 44 "./include/linux/seqlock.h"
	.file 45 "./include/linux/nodemask.h"
	.file 46 "./include/linux/stddef.h"
	.file 47 "./include/uapi/linux/personality.h"
	.file 48 "./include/linux/mmzone.h"
	.file 49 "./include/linux/rwsem.h"
	.file 50 "./include/linux/time.h"
	.file 51 "./include/linux/llist.h"
	.file 52 "./include/linux/smp.h"
	.file 53 "./include/asm-generic/percpu.h"
	.file 54 "./arch/arm64/include/asm/smp.h"
	.file 55 "./include/clocksource/arm_arch_timer.h"
	.file 56 "./arch/arm64/include/asm/arch_timer.h"
	.file 57 "./include/linux/timex.h"
	.file 58 "./include/linux/jiffies.h"
	.file 59 "./include/linux/ktime.h"
	.file 60 "./include/linux/timekeeping.h"
	.file 61 "./include/linux/timer.h"
	.file 62 "./include/linux/workqueue.h"
	.file 63 "./include/linux/completion.h"
	.file 64 "./include/linux/percpu.h"
	.file 65 "./arch/arm64/include/asm/topology.h"
	.file 66 "./include/linux/arch_topology.h"
	.file 67 "./include/linux/gfp.h"
	.file 68 "./include/linux/idr.h"
	.file 69 "./include/linux/rbtree.h"
	.file 70 "./include/linux/highuid.h"
	.file 71 "./include/linux/uidgid.h"
	.file 72 "./include/linux/kernfs.h"
	.file 73 "./include/linux/kobject_ns.h"
	.file 74 "./include/linux/pid.h"
	.file 75 "./include/linux/refcount.h"
	.file 76 "./include/linux/plist.h"
	.file 77 "./include/linux/timerqueue.h"
	.file 78 "./include/linux/hrtimer.h"
	.file 79 "./include/linux/seccomp.h"
	.file 80 "./include/uapi/asm-generic/signal.h"
	.file 81 "./include/uapi/asm-generic/siginfo.h"
	.file 82 "./include/linux/signal_types.h"
	.file 83 "./include/linux/mm_types_task.h"
	.file 84 "./include/linux/task_io_accounting.h"
	.file 85 "./include/uapi/linux/rseq.h"
	.file 86 "./include/linux/sysfs.h"
	.file 87 "./include/linux/kobject.h"
	.file 88 "./include/linux/kref.h"
	.file 89 "./include/linux/klist.h"
	.file 90 "./include/linux/pm.h"
	.file 91 "./include/linux/device.h"
	.file 92 "./include/linux/pm_wakeup.h"
	.file 93 "./include/linux/ratelimit.h"
	.file 94 "./arch/arm64/include/asm/device.h"
	.file 95 "./include/linux/slab.h"
	.file 96 "drivers/gpu/drm/rockchip/ebc-dev/epdlut/epd_lut.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x6831
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.4byte	.LASF1511
	.byte	0x1
	.4byte	.LASF1512
	.4byte	.LASF1513
	.8byte	.Ltext0
	.8byte	.Letext0-.Ltext0
	.4byte	.Ldebug_line0
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	.LASF0
	.uleb128 0x3
	.4byte	0x2d
	.uleb128 0x4
	.4byte	0x2d
	.uleb128 0x5
	.4byte	0x2d
	.4byte	0x4e
	.uleb128 0x6
	.4byte	0x4e
	.byte	0x1
	.byte	0
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	.LASF1
	.uleb128 0x7
	.byte	0x8
	.4byte	0x67
	.uleb128 0x3
	.4byte	0x55
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF2
	.uleb128 0x3
	.4byte	0x60
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	.LASF3
	.uleb128 0x8
	.4byte	.LASF5
	.byte	0x2
	.byte	0x14
	.4byte	0x7e
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	.LASF4
	.uleb128 0x8
	.4byte	.LASF6
	.byte	0x2
	.byte	0x15
	.4byte	0x90
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF7
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	.LASF8
	.uleb128 0x8
	.4byte	.LASF9
	.byte	0x2
	.byte	0x18
	.4byte	0xa9
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	.LASF10
	.uleb128 0x8
	.4byte	.LASF11
	.byte	0x2
	.byte	0x1a
	.4byte	0xbb
	.uleb128 0x9
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.4byte	0xbb
	.uleb128 0x8
	.4byte	.LASF12
	.byte	0x2
	.byte	0x1b
	.4byte	0x6c
	.uleb128 0x8
	.4byte	.LASF13
	.byte	0x2
	.byte	0x1e
	.4byte	0xdd
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF14
	.uleb128 0x8
	.4byte	.LASF15
	.byte	0x2
	.byte	0x1f
	.4byte	0xef
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	.LASF16
	.uleb128 0xa
	.string	"s8"
	.byte	0x3
	.byte	0x10
	.4byte	0x73
	.uleb128 0xa
	.string	"u8"
	.byte	0x3
	.byte	0x11
	.4byte	0x85
	.uleb128 0xa
	.string	"u16"
	.byte	0x3
	.byte	0x13
	.4byte	0x9e
	.uleb128 0xa
	.string	"s32"
	.byte	0x3
	.byte	0x14
	.4byte	0xb0
	.uleb128 0xa
	.string	"u32"
	.byte	0x3
	.byte	0x15
	.4byte	0xc7
	.uleb128 0xa
	.string	"s64"
	.byte	0x3
	.byte	0x16
	.4byte	0xd2
	.uleb128 0xa
	.string	"u64"
	.byte	0x3
	.byte	0x17
	.4byte	0xe4
	.uleb128 0xb
	.byte	0x4
	.4byte	0x6c
	.byte	0x2e
	.byte	0xa
	.4byte	0x15a
	.uleb128 0xc
	.4byte	.LASF17
	.byte	0
	.uleb128 0xc
	.4byte	.LASF18
	.byte	0x1
	.byte	0
	.uleb128 0x5
	.4byte	0x2d
	.4byte	0x16a
	.uleb128 0x6
	.4byte	0x4e
	.byte	0xf
	.byte	0
	.uleb128 0x8
	.4byte	.LASF19
	.byte	0x4
	.byte	0xf
	.4byte	0x175
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF20
	.uleb128 0x4
	.4byte	0x175
	.uleb128 0x8
	.4byte	.LASF21
	.byte	0x4
	.byte	0x10
	.4byte	0x2d
	.uleb128 0x8
	.4byte	.LASF22
	.byte	0x4
	.byte	0x1c
	.4byte	0xbb
	.uleb128 0x8
	.4byte	.LASF23
	.byte	0x4
	.byte	0x31
	.4byte	0x6c
	.uleb128 0x8
	.4byte	.LASF24
	.byte	0x4
	.byte	0x32
	.4byte	0x6c
	.uleb128 0x8
	.4byte	.LASF25
	.byte	0x4
	.byte	0x48
	.4byte	0x181
	.uleb128 0x8
	.4byte	.LASF26
	.byte	0x4
	.byte	0x49
	.4byte	0x16a
	.uleb128 0x8
	.4byte	.LASF27
	.byte	0x4
	.byte	0x58
	.4byte	0xdd
	.uleb128 0x8
	.4byte	.LASF28
	.byte	0x4
	.byte	0x59
	.4byte	0x16a
	.uleb128 0x8
	.4byte	.LASF29
	.byte	0x4
	.byte	0x5b
	.4byte	0x16a
	.uleb128 0x8
	.4byte	.LASF30
	.byte	0x4
	.byte	0x5c
	.4byte	0xbb
	.uleb128 0x8
	.4byte	.LASF31
	.byte	0x4
	.byte	0x5d
	.4byte	0xbb
	.uleb128 0x7
	.byte	0x8
	.4byte	0x60
	.uleb128 0x3
	.4byte	0x1fa
	.uleb128 0x8
	.4byte	.LASF32
	.byte	0x5
	.byte	0x34
	.4byte	0x6c
	.uleb128 0x8
	.4byte	.LASF33
	.byte	0x6
	.byte	0xd
	.4byte	0x120
	.uleb128 0x8
	.4byte	.LASF34
	.byte	0x6
	.byte	0x10
	.4byte	0x210
	.uleb128 0x8
	.4byte	.LASF35
	.byte	0x6
	.byte	0x13
	.4byte	0xa9
	.uleb128 0x8
	.4byte	.LASF36
	.byte	0x6
	.byte	0x16
	.4byte	0x18c
	.uleb128 0x8
	.4byte	.LASF37
	.byte	0x6
	.byte	0x1b
	.4byte	0x1ef
	.uleb128 0x8
	.4byte	.LASF38
	.byte	0x6
	.byte	0x1e
	.4byte	0x252
	.uleb128 0x2
	.byte	0x1
	.byte	0x2
	.4byte	.LASF39
	.uleb128 0x8
	.4byte	.LASF40
	.byte	0x6
	.byte	0x20
	.4byte	0x197
	.uleb128 0x8
	.4byte	.LASF41
	.byte	0x6
	.byte	0x21
	.4byte	0x1a2
	.uleb128 0x8
	.4byte	.LASF42
	.byte	0x6
	.byte	0x2e
	.4byte	0x1c3
	.uleb128 0x8
	.4byte	.LASF43
	.byte	0x6
	.byte	0x37
	.4byte	0x1ad
	.uleb128 0x8
	.4byte	.LASF44
	.byte	0x6
	.byte	0x3c
	.4byte	0x1b8
	.uleb128 0x8
	.4byte	.LASF45
	.byte	0x6
	.byte	0x9e
	.4byte	0x6c
	.uleb128 0x8
	.4byte	.LASF46
	.byte	0x6
	.byte	0xa3
	.4byte	0x136
	.uleb128 0x8
	.4byte	.LASF47
	.byte	0x6
	.byte	0xa8
	.4byte	0x29b
	.uleb128 0xd
	.byte	0x4
	.byte	0x6
	.byte	0xb0
	.4byte	0x2c6
	.uleb128 0xe
	.4byte	.LASF49
	.byte	0x6
	.byte	0xb1
	.4byte	0xbb
	.byte	0
	.byte	0
	.uleb128 0x8
	.4byte	.LASF48
	.byte	0x6
	.byte	0xb2
	.4byte	0x2b1
	.uleb128 0xd
	.byte	0x8
	.byte	0x6
	.byte	0xb5
	.4byte	0x2e6
	.uleb128 0xe
	.4byte	.LASF49
	.byte	0x6
	.byte	0xb6
	.4byte	0x175
	.byte	0
	.byte	0
	.uleb128 0x8
	.4byte	.LASF50
	.byte	0x6
	.byte	0xb7
	.4byte	0x2d1
	.uleb128 0xf
	.4byte	.LASF53
	.byte	0x10
	.byte	0x6
	.byte	0xba
	.4byte	0x316
	.uleb128 0xe
	.4byte	.LASF51
	.byte	0x6
	.byte	0xbb
	.4byte	0x316
	.byte	0
	.uleb128 0xe
	.4byte	.LASF52
	.byte	0x6
	.byte	0xbb
	.4byte	0x316
	.byte	0x8
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.4byte	0x2f1
	.uleb128 0xf
	.4byte	.LASF54
	.byte	0x8
	.byte	0x6
	.byte	0xbe
	.4byte	0x335
	.uleb128 0xe
	.4byte	.LASF55
	.byte	0x6
	.byte	0xbf
	.4byte	0x35a
	.byte	0
	.byte	0
	.uleb128 0xf
	.4byte	.LASF56
	.byte	0x10
	.byte	0x6
	.byte	0xc2
	.4byte	0x35a
	.uleb128 0xe
	.4byte	.LASF51
	.byte	0x6
	.byte	0xc3
	.4byte	0x35a
	.byte	0
	.uleb128 0xe
	.4byte	.LASF57

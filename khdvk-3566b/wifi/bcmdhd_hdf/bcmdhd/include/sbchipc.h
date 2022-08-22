/*
 * SiliconBackplane Chipcommon core hardware definitions.
 *
 * The chipcommon core provides chip identification, SB control,
 * JTAG, 0/1/2 UARTs, clock frequency control, a watchdog interrupt timer,
 * GPIO interface, extbus, and support for serial and parallel flashes.
 *
 * $Id: sbchipc.h 825481 2019-06-14 10:06:03Z $
 *
 * Copyright (C) 2022 Broadcom.
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 */

#ifndef	_SBCHIPC_H
#define	_SBCHIPC_H

#if !defined(_LANGUAGE_ASSEMBLY) && !defined(__ASSEMBLY__)

/* cpp contortions to concatenate w/arg prescan */
#ifndef PAD
#define	_PADLINE(line)	pad ## line
#define	_XSTR(line)	_PADLINE(line)
#define	PAD		_XSTR(__LINE__)
#endif	/* PAD */

#define BCM_MASK32(msb, lsb)	((~0u >> (32u - (msb) - 1u)) & (~0u << (lsb)))

/**
 * In chipcommon rev 49 the pmu registers have been moved from chipc to the pmu core if the
 * 'AOBPresent' bit of 'CoreCapabilitiesExt' is set. If this field is set, the traditional chipc to
 * [pmu|gci|sreng] register interface is deprecated and removed. These register blocks would instead
 * be assigned their respective chipc-specific address space and connected to the Always On
 * Backplane via the APB interface.
 */
typedef volatile struct {
	uint32  PAD[384];
	uint32  pmucontrol;             /* 0x600 */
	uint32  pmucapabilities;        /* 0x604 */
	uint32  pmustatus;              /* 0x608 */
	uint32  res_state;              /* 0x60C */
	uint32  res_pending;            /* 0x610 */
	uint32  pmutimer;               /* 0x614 */
	uint32  min_res_mask;           /* 0x618 */
	uint32  max_res_mask;           /* 0x61C */
	uint32  res_table_sel;          /* 0x620 */
	uint32  res_dep_mask;
	uint32  res_updn_timer;
	uint32  res_timer;
	uint32  clkstretch;
	uint32  pmuwatchdog;
	uint32  gpiosel;                /* 0x638, rev >= 1 */
	uint32  gpioenable;             /* 0x63c, rev >= 1 */
	uint32  res_req_timer_sel;      /* 0x640 */
	uint32  res_req_timer;          /* 0x644 */
	uint32  res_req_mask;           /* 0x648 */
	uint32	core_cap_ext;           /* 0x64C */
	uint32  chipcontrol_addr;       /* 0x650 */
	uint32  chipcontrol_data;       /* 0x654 */
	uint32  regcontrol_addr;
	uint32  regcontrol_data;
	uint32  pllcontrol_addr;
	uint32  pllcontrol_data;
	uint32  pmustrapopt;            /* 0x668, corerev >= 28 */
	uint32  pmu_xtalfreq;           /* 0x66C, pmurev >= 10 */
	uint32  retention_ctl;          /* 0x670 */
	uint32  ILPPeriod;              /* 0x674 */
	uint32  PAD[2];
	uint32  retention_grpidx;       /* 0x680 */
	uint32  retention_grpctl;       /* 0x684 */
	uint32  mac_res_req_timer;      /* 0x688 */
	uint32  mac_res_req_mask;       /* 0x68c */
	uint32  PAD[18];
	uint32  pmucontrol_ext;         /* 0x6d8 */
	uint32  slowclkperiod;          /* 0x6dc */
	uint32	pmu_statstimer_addr;	/* 0x6e0 */
	uint32	pmu_statstimer_ctrl;	/* 0x6e4 */
	uint32	pmu_statstimer_N;		/* 0x6e8 */
	uint32	PAD[1];
	uint32  mac_res_req_timer1;	/* 0x6f0 */
	uint32  mac_res_req_mask1;	/* 0x6f4 */
	uint32	PAD[2];
	uint32  pmuintmask0;            /* 0x700 */
	uint32  pmuintmask1;            /* 0x704 */
	uint32  PAD[14];
	uint32  pmuintstatus;           /* 0x740 */
	uint32  extwakeupstatus;        /* 0x744 */
	uint32  watchdog_res_mask;      /* 0x748 */
	uint32  PAD[1];                 /* 0x74C */
	uint32  swscratch;              /* 0x750 */
	uint32  PAD[3];                 /* 0x754-0x75C */
	uint32	extwakemask0; /* 0x760 */
	uint32	extwakemask1; /* 0x764 */
	uint32  PAD[2];                 /* 0x768-0x76C */
	uint32  extwakereqmask[2];      /* 0x770-0x774 */
	uint32  PAD[2];                 /* 0x778-0x77C */
	uint32  pmuintctrl0;            /* 0x780 */
	uint32  pmuintctrl1;            /* 0x784 */
	uint32  PAD[2];
	uint32  extwakectrl[2];         /* 0x790 */
	uint32  PAD[7];
	uint32  fis_ctrl_status;        /* 0x7b4 */
	uint32  fis_min_res_mask;       /* 0x7b8 */
	uint32  PAD[1];
	uint32	PrecisionTmrCtrlStatus;	/* 0x7c0 */
} pmuregs_t;

typedef struct eci_prerev35 {
	uint32	eci_output;
	uint32	eci_control;
	uint32	eci_inputlo;
	uint32	eci_inputmi;
	uint32	eci_inputhi;
	uint32	eci_inputintpolaritylo;
	uint32	eci_inputintpolaritymi;
	uint32	eci_inputintpolarityhi;
	uint32	eci_intmasklo;
	uint32	eci_intmaskmi;
	uint32	eci_intmaskhi;
	uint32	eci_eventlo;
	uint32	eci_eventmi;
	uint32	eci_eventhi;
	uint32	eci_eventmasklo;
	uint32	eci_eventmaskmi;
	uint32	eci_eventmaskhi;
	uint32	PAD[3];
} eci_prerev35_t;

typedef struct eci_rev35 {
	uint32	eci_outputlo;
	uint32	eci_outputhi;
	uint32	eci_controllo;
	uint32	eci_controlhi;
	uint32	eci_inputlo;
	uint32	eci_inputhi;
	uint32	eci_inputintpolaritylo;
	uint32	eci_inputintpolarityhi;
	uint32	eci_intmasklo;
	uint32	eci_intmaskhi;
	uint32	eci_eventlo;
	uint32	eci_eventhi;
	uint32	eci_eventmasklo;
	uint32	eci_eventmaskhi;
	uint32	eci_auxtx;
	uint32	eci_auxrx;
	uint32	eci_datatag;
	uint32	eci_uartescvalue;
	uint32	eci_autobaudctr;
	uint32	eci_uartfifolevel;
} eci_rev35_t;

typedef struct flash_config {
	uint32	PAD[19];
	/* Flash struct configuration registers (0x18c) for BCM4706 (corerev = 31) */
	uint32 flashstrconfig;
} flash_config_t;

typedef volatile struct {
	uint32	chipid;			/* 0x0 */
	uint32	capabilities;
	uint32	corecontrol;		/* corerev >= 1 */
	uint32	bist;

	/* OTP */
	uint32	otpstatus;		/* 0x10, corerev >= 10 */
	uint32	otpcontrol;
	uint32	otpprog;
	uint32	otplayout;		/* corerev >= 23 */

	/* Interrupt control */
	uint32	intstatus;		/* 0x20 */
	uint32	intmask;

	/* Chip specific regs */
	uint32	chipcontrol;		/* 0x28, rev >= 11 */
	uint32	chipstatus;		/* 0x2c, rev >= 11 */

	/* Jtag Master */
	uint32	jtagcmd;		/* 0x30, rev >= 10 */
	uint32	jtagir;
	uint32	jtagdr;
	uint32	jtagctrl;

	/* serial flash interface registers */
	uint32	flashcontrol;		/* 0x40 */
	uint32	flashaddress;
	uint32	flashdata;
	uint32	otplayoutextension;	/* rev >= 35 */

	/* Silicon backplane configuration broadcast control */
	uint32	broadcastaddress;	/* 0x50 */
	uint32	broadcastdata;

	/* gpio - cleared only by power-on-reset */
	uint32	gpiopullup;		/* 0x58, corerev >= 20 */
	uint32	gpiopulldown;		/* 0x5c, corerev >= 20 */
	uint32	gpioin;			/* 0x60 */
	uint32	gpioout;		/* 0x64 */
	uint32	gpioouten;		/* 0x68 */
	uint32	gpiocontrol;		/* 0x6C */
	uint32	gpiointpolarity;	/* 0x70 */
	uint32	gpiointmask;		/* 0x74 */

	/* GPIO events corerev >= 11 */
	uint32	gpioevent;
	uint32	gpioeventintmask;

	/* Watchdog timer */
	uint32	watchdog;		/* 0x80 */

	/* GPIO events corerev >= 11 */
	uint32	gpioeventintpolarity;

	/* GPIO based LED powersave registers corerev >= 16 */
	uint32  gpiotimerval;		/* 0x88 */
	uint32  gpiotimeroutmask;

	/* clock control */
	uint32	clockcontrol_n;		/* 0x90 */
	uint32	clockcontrol_sb;	/* aka m0 */
	uint32	clockcontrol_pci;	/* aka m1 */
	uint32	clockcontrol_m2;	/* mii/uart/mipsref */
	uint32	clockcontrol_m3;	/* cpu */
	uint32	clkdiv;			/* corerev >= 3 */
	uint32	gpiodebugsel;		/* corerev >= 28 */
	uint32	capabilities_ext;               	/* 0xac  */

	/* pll delay registers (corerev >= 4) */
	uint32	pll_on_delay;		/* 0xb0 */
	uint32	fref_sel_delay;
	uint32	slow_clk_ctl;		/* 5 < corerev < 10 */
	uint32	PAD;

	/* Instaclock registers (corerev >= 10) */
	uint32	system_clk_ctl;		/* 0xc0 */
	uint32	clkstatestretch;
	uint32	PAD[2];

	/* Indirect backplane access (corerev >= 22) */
	uint32	bp_addrlow;		/* 0xd0 */
	uint32	bp_addrhigh;
	uint32	bp_data;
	uint32	PAD;
	uint32	bp_indaccess;
	/* SPI registers, corerev >= 37 */
	uint32	gsioctrl;
	uint32	gsioaddress;
	uint32	gsiodata;

	/* More clock dividers (corerev >= 32) */
	uint32	clkdiv2;
	/* FAB ID (corerev >= 40) */
	uint32	otpcontrol1;
	uint32	fabid;			/* 0xf8 */

	/* In AI chips, pointer to erom */
	uint32	eromptr;		/* 0xfc */

	/* ExtBus control registers (corerev >= 3) */
	uint32	pcmcia_config;		/* 0x100 */
	uint32	pcmcia_memwait;
	uint32	pcmcia_attrwait;
	uint32	pcmcia_iowait;
	uint32	ide_config;
	uint32	ide_memwait;
	uint32	ide_attrwait;
	uint32	ide_iowait;
	uint32	prog_config;
	uint32	prog_waitcount;
	uint32	flash_config;
	uint32	flash_waitcount;
	uint32  SECI_config;		/* 0x130 SECI configuration */
	uint32	SECI_status;
	uint32	SECI_statusmask;
	uint32	SECI_rxnibchanged;

	uint32	PAD[20];

	/* SROM interface (corerev >= 32) */
	uint32	sromcontrol;		/* 0x190 */
	uint32	sromaddress;
	uint32	sromdata;
	uint32	PAD[1];				/* 0x19C */
	/* NAND flash registers for BCM4706 (corerev = 31) */
	uint32  nflashctrl;         /* 0x1a0 */
	uint32  nflashconf;
	uint32  nflashcoladdr;
	uint32  nflashrowaddr;
	uint32  nflashdata;
	uint32  nflashwaitcnt0;		/* 0x1b4 */
	uint32  PAD[2];

	uint32  seci_uart_data;		/* 0x1C0 */
	uint32  seci_uart_bauddiv;
	uint32  seci_uart_fcr;
	uint32  seci_uart_lcr;
	uint32  seci_uart_mcr;
	uint32  seci_uart_lsr;
	uint32  seci_uart_msr;
	uint32  seci_uart_baudadj;
	/* Clock control and hardware workarounds (corerev >= 20) */
	uint32	clk_ctl_st;		/* 0x1e0 */
	uint32	hw_war;
	uint32  powerctl;		/* 0x1e8 */
	uint32  PAD[69];

	/* UARTs */
	uint8	uart0data;		/* 0x300 */
	uint8	uart0imr;
	uint8	uart0fcr;
	uint8	uart0lcr;
	uint8	uart0mcr;
	uint8	uart0lsr;
	uint8	uart0msr;
	uint8	uart0scratch;
	uint8	PAD[248];		/* corerev >= 1 */

	uint8	uart1data;		/* 0x400 */
	uint8	uart1imr;
	uint8	uart1fcr;
	uint8	uart1lcr;
	uint8	uart1mcr;
	uint8	uart1lsr;
	uint8	uart1msr;
	uint8	uart1scratch;		/* 0x407 */
	uint32	PAD[50];
	uint32	sr_memrw_addr;		/* 0x4d0 */
	uint32	sr_memrw_data;		/* 0x4d4 */
	uint32	PAD[10];

	/* save/restore, corerev >= 48 */
	uint32	sr_capability;		/* 0x500 */
	uint32	sr_control0;		/* 0x504 */
	uint32	sr_control1;		/* 0x508 */
	uint32  gpio_control;		/* 0x50C */
	uint32	PAD[29];
	/* 2 SR engines case */
	uint32	sr1_control0;		/* 0x584 */
	uint32	sr1_control1;		/* 0x588 */
	uint32	PAD[29];
	/* PMU registers (corerev >= 20) */
	/* Note: all timers driven by ILP clock are updated asynchronously to HT/ALP.
	 * The CPU must read them twice, compare, and retry if different.
	 */
	uint32	pmucontrol;		/* 0x600 */
	uint32	pmucapabilities;
	uint32	pmustatus;
	uint32	res_state;
	uint32	res_pending;
	uint32	pmutimer;
	uint32	min_res_mask;
	uint32	max_res_mask;
	uint32	res_table_sel;
	uint32	res_dep_mask;
	uint32	res_updn_timer;
	uint32	res_timer;
	uint32	clkstretch;
	uint32	pmuwatchdog;
	uint32	gpiosel;		/* 0x638, rev >= 1 */
	uint32	gpioenable;		/* 0x63c, rev >= 1 */
	uint32	res_req_timer_sel;
	uint32	res_req_timer;
	uint32	res_req_mask;
	uint32	core_cap_ext;		/* 0x64c */
	uint32	chipcontrol_addr;	/* 0x650 */
	uint32	chipcontrol_data;	/* 0x654 */
	uint32	regcontrol_addr;
	uint32	regcontrol_data;
	uint32	pllcontrol_addr;
	uint32	pllcontrol_data;
	uint32	pmustrapopt;		/* 0x668, corerev >= 28 */
	uint32	pmu_xtalfreq;		/* 0x66C, pmurev >= 10 */
	uint32  retention_ctl;		/* 0x670 */
	uint32	ILPPeriod;		/* 0x674 */
	uint32  PAD[2];
	uint32  retention_grpidx;	/* 0x680 */
	uint32  retention_grpctl;	/* 0x684 */
	uint32  mac_res_req_timer;	/* 0x688 */
	uint32  mac_res_req_mask;	/* 0x68c */
	uint32  PAD[18];
	uint32	pmucontrol_ext;		/* 0x6d8 */
	uint32	slowclkperiod;		/* 0x6dc */
	uint32	pmu_statstimer_addr;	/* 0x6e0 */
	uint32	pmu_statstimer_ctrl;	/* 0x6e4 */
	uint32	pmu_statstimer_N;		/* 0x6e8 */
	uint32	PAD[1];
	uint32  mac_res_req_timer1;	/* 0x6f0 */
	uint32  mac_res_req_mask1;	/* 0x6f4 */
	uint32	PAD[2];
	uint32	pmuintmask0;		/* 0x700 */
	uint32	pmuintmask1;		/* 0x704 */
	uint32  PAD[14];
	uint32  pmuintstatus;		/* 0x740 */
	uint32  extwakeupstatus;	/* 0x744 */
	uint32	PAD[6];
	uint32  extwakemask0;		/* 0x760 */
	uint32	extwakemask1; /* 0x764 */
	uint32	PAD[2];		/* 0x768-0x76C */
	uint32	extwakereqmask[2]; /* 0x770-0x774 */
	uint32	PAD[2];		/* 0x778-0x77C */
	uint32  pmuintctrl0;		/* 0x780 */
	uint32  PAD[3];			/* 0x784 - 0x78c */
	uint32  extwakectrl[1];		/* 0x790 */
	uint32  PAD[8];
	uint32  fis_ctrl_status;        /* 0x7b4 */
	uint32  fis_min_res_mask;       /* 0x7b8 */
	uint32  PAD[17];
	uint16	sromotp[512];		/* 0x800 */
#ifdef CCNFLASH_SUPPORT
	/* Nand flash MLC controller registers (corerev >= 38) */
	uint32	nand_revision;		/* 0xC00 */
	uint32	nand_cmd_start;
	uint32	nand_cmd_addr_x;
	uint32	nand_cmd_addr;
	uint32	nand_cmd_end_addr;
	uint32	nand_cs_nand_select;
	uint32	nand_cs_nand_xor;
	uint32	PAD;
	uint32	nand_spare_rd0;
	uint32	nand_spare_rd4;
	uint32	nand_spare_rd8;
	uint32	nand_spare_rd12;
	uint32	nand_spare_wr0;
	uint32	nand_spare_wr4;
	uint32	nand_spare_wr8;
	uint32	nand_spare_wr12;
	uint32	nand_acc_control;
	uint32	PAD;
	uint32	nand_config;
	uint32	PAD;
	uint32	nand_timing_1;
	uint32	nand_timing_2;
	uint32	nand_semaphore;
	uint32	PAD;
	uint32	nand_devid;
	uint32	nand_devid_x;
	uint32	nand_block_lock_status;
	uint32	nand_intfc_status;
	uint32	nand_ecc_corr_addr_x;
	uint32	nand_ecc_corr_addr;
	uint32	nand_ecc_unc_addr_x;
	uint32	nand_ecc_unc_addr;
	uint32	nand_read_error_count;
	uint32	nand_corr_stat_threshold;
	uint32	PAD[2];
	uint32	nand_read_addr_x;
	uint32	nand_read_addr;
	uint32	nand_page_program_addr_x;
	uint32	nand_page_program_addr;
	uint32	nand_copy_back_addr_x;
	uint32	nand_copy_back_addr;
	uint32	nand_block_erase_addr_x;
	uint32	nand_block_erase_addr;
	uint32	nand_inv_read_addr_x;
	uint32	nand_inv_read_addr;
	uint32	PAD[2];
	uint32	nand_blk_wr_protect;
	uint32	PAD[3];
	uint32	nand_acc_control_cs1;
	uint32	nand_config_cs1;
	uint32	nand_timing_1_cs1;
	uint32	nand_timing_2_cs1;
	uint32	PAD[20];
	uint32	nand_spare_rd16;
	uint32	nand_spare_rd20;
	uint32	nand_spare_rd24;
	uint32	nand_spare_rd28;
	uint32	nand_cache_addr;
	uint32	nand_cache_data;
	uint32	nand_ctrl_config;
	uint32	nand_ctrl_status;
#endif /* CCNFLASH_SUPPORT */
	uint32  gci_corecaps0; /* GCI starting at 0xC00 */
	uint32  gci_corecaps1;
	uint32  gci_corecaps2;
	uint32  gci_corectrl;
	uint32  gci_corestat; /* 0xC10 */
	uint32  gci_intstat; /* 0xC14 */
	uint32  gci_intmask; /* 0xC18 */
	uint32  gci_wakemask; /* 0xC1C */
	uint32  gci_levelintstat; /* 0xC20 */
	uint32  gci_eventintstat; /* 0xC24 */
	uint32  PAD[6];
	uint32  gci_indirect_addr; /* 0xC40 */
	uint32  gci_gpioctl; /* 0xC44 */
	uint32	gci_gpiostatus;
	uint32  gci_gpiomask; /* 0xC4C */
	uint32  gci_eventsummary; /* 0xC50 */
	uint32  gci_miscctl; /* 0xC54 */
	uint32	gci_gpiointmask;
	uint32	gci_gpiowakemask;
	uint32  gci_input[32]; /* C60 */
	uint32  gci_event[32]; /* CE0 */
	uint32  gci_output[4]; /* D60 */
	uint32  gci_control_0; /* 0xD70 */
	uint32  gci_control_1; /* 0xD74 */
	uint32  gci_intpolreg; /* 0xD78 */
	uint32  gci_levelintmask; /* 0xD7C */
	uint32  gci_eventintmask; /* 0xD80 */
	uint32  PAD[3];
	uint32  gci_inbandlevelintmask; /* 0xD90 */
	uint32  gci_inbandeventintmask; /* 0xD94 */
	uint32  PAD[2];
	uint32  gci_seciauxtx; /* 0xDA0 */
	uint32  gci_seciauxrx; /* 0xDA4 */
	uint32  gci_secitx_datatag; /* 0xDA8 */
	uint32  gci_secirx_datatag; /* 0xDAC */
	uint32  gci_secitx_datamask; /* 0xDB0 */
	uint32  gci_seciusef0tx_reg; /* 0xDB4 */
	uint32  gci_secif0tx_offset; /* 0xDB8 */
	uint32  gci_secif0rx_offset; /* 0xDBC */
	uint32  gci_secif1tx_offset; /* 0xDC0 */
	uint32	gci_rxfifo_common_ctrl; /* 0xDC4 */
	uint32	gci_rxfifoctrl; /* 0xDC8 */
	uint32	gci_uartreadid; /* DCC */
	uint32  gci_seciuartescval; /* DD0 */
	uint32	PAD;
	uint32	gci_secififolevel; /* DD8 */
	uint32	gci_seciuartdata; /* DDC */
	uint32  gci_secibauddiv; /* DE0 */
	uint32  gci_secifcr; /* DE4 */
	uint32  gci_secilcr; /* DE8 */
	uint32  gci_secimcr; /* DEC */
	uint32	gci_secilsr; /* DF0 */
	uint32	gci_secimsr; /* DF4 */
	uint32  gci_baudadj; /* DF8 */
	uint32  PAD;
	uint32  gci_chipctrl; /* 0xE00 */
	uint32  gci_chipsts; /* 0xE04 */
	uint32	gci_gpioout; /* 0xE08 */
	uint32	gci_gpioout_read; /* 0xE0C */
	uint32	gci_mpwaketx; /* 0xE10 */
	uint32	gci_mpwakedetect; /* 0xE14 */
	uint32	gci_seciin_ctrl; /* 0xE18 */
	uint32	gci_seciout_ctrl; /* 0xE1C */
	uint32	gci_seciin_auxfifo_en; /* 0xE20 */
	uint32	gci_seciout_txen_txbr; /* 0xE24 */
	uint32	gci_seciin_rxbrstatus; /* 0xE28 */
	uint32	gci_seciin_rxerrstatus; /* 0xE2C */
	uint32	gci_seciin_fcstatus; /* 0xE30 */
	uint32	gci_seciout_txstatus; /* 0xE34 */
	uint32	gci_seciout_txbrstatus; /* 0xE38 */
} chipcregs_t;

#endif /* !_LANGUAGE_ASSEMBLY && !__ASSEMBLY__ */

#define	CC_CHIPID		0
#define	CC_CAPABILITIES		4
#define	CC_CHIPST		0x2c
#define	CC_EROMPTR		0xfc

#define	CC_OTPST		0x10
#define	CC_INTSTATUS		0x20
#define	CC_INTMASK		0x24
#define	CC_JTAGCMD		0x30
#define	CC_JTAGIR		0x34
#define	CC_JTAGDR		0x38
#define	CC_JTAGCTRL		0x3c
#define	CC_GPIOPU		0x58
#define	CC_GPIOPD		0x5c
#define	CC_GPIOIN		0x60
#define	CC_GPIOOUT		0x64
#define	CC_GPIOOUTEN		0x68
#define	CC_GPIOCTRL		0x6c
#define	CC_GPIOPOL		0x70
#define	CC_GPIOINTM		0x74
#define	CC_GPIOEVENT		0x78
#define	CC_GPIOEVENTMASK	0x7c
#define	CC_WATCHDOG		0x80
#define	CC_GPIOEVENTPOL		0x84
#define	CC_CLKC_N		0x90
#define	CC_CLKC_M0		0x94
#define	CC_CLKC_M1		0x98
#define	CC_CLKC_M2		0x9c
#define	CC_CLKC_M3		0xa0
#define	CC_CLKDIV		0xa4
#define	CC_CAP_EXT		0xac
#define	CC_SYS_CLK_CTL		0xc0
#define	CC_CLKDIV2		0xf0
#define	CC_CLK_CTL_ST		SI_CLK_CTL_ST
#define	PMU_CTL			0x600
#define	PMU_CAP			0x604
#define	PMU_ST			0x608
#define PMU_RES_STATE		0x60c
#define PMU_RES_PENDING		0x610
#define PMU_TIMER		0x614
#define	PMU_MIN_RES_MASK	0x618
#define	PMU_MAX_RES_MASK	0x61c
#define CC_CHIPCTL_ADDR         0x650
#define CC_CHIPCTL_DATA         0x654
#define PMU_REG_CONTROL_ADDR	0x658
#define PMU_REG_CONTROL_DATA	0x65C
#define PMU_PLL_CONTROL_ADDR	0x660
#define PMU_PLL_CONTROL_DATA	0x664

#define CC_SROM_CTRL		0x190
#define CC_SROM_ADDRESS		0x194u
#define CC_SROM_DATA		0x198u
#ifdef SROM16K_4364_ADDRSPACE
#define	CC_SROM_OTP		0xa000		/* SROM/OTP address space */
#else
#define	CC_SROM_OTP		0x0800
#endif // endif
#define CC_GCI_INDIRECT_ADDR_REG	0xC40
#define CC_GCI_CHIP_CTRL_REG	0xE00
#define CC_GCI_CC_OFFSET_2	2
#define CC_GCI_CC_OFFSET_5	5
#define CC_SWD_CTRL		0x380
#define CC_SWD_REQACK		0x384
#define CC_SWD_DATA		0x388
#define GPIO_SEL_0					0x00001111
#define GPIO_SEL_1					0x11110000
#define GPIO_SEL_8					0x00001111
#define GPIO_SEL_9					0x11110000

#define CHIPCTRLREG0 0x0
#define CHIPCTRLREG1 0x1
#define CHIPCTRLREG2 0x2
#define CHIPCTRLREG3 0x3
#define CHIPCTRLREG4 0x4
#define CHIPCTRLREG5 0x5
#define CHIPCTRLREG6 0x6
#define REGCTRLREG4 0x4
#define REGCTRLREG5 0x5
#define REGCTRLREG6 0x6
#define MINRESMASKREG 0x618
#define MAXRESMASKREG 0x61c
#define CHIPCTRLADDR 0x650
#define CHIPCTRLDATA 0x654
#define RSRCTABLEADDR 0x620
#define PMU_RES_DEP_MASK 0x624
#define RSRCUPDWNTIME 0x628
#define PMUREG_RESREQ_MASK 0x68c
#define PMUREG_RESREQ_TIMER 0x688
#define PMUREG_RESREQ_MASK1 0x6f4
#define PMUREG_RESREQ_TIMER1 0x6f0
#define EXT_LPO_AVAIL 0x100
#define LPO_SEL					(1 << 0)
#define CC_EXT_LPO_PU 0x200000
#define GC_EXT_LPO_PU 0x2
#define CC_INT_LPO_PU 0x100000
#define GC_INT_LPO_PU 0x1
#define EXT_LPO_SEL 0x8
#define INT_LPO_SEL 0x4
#define ENABLE_FINE_CBUCK_CTRL 			(1 << 30)
#define REGCTRL5_PWM_AUTO_CTRL_MASK 		0x007e0000
#define REGCTRL5_PWM_AUTO_CTRL_SHIFT		17
#define REGCTRL6_PWM_AUTO_CTRL_MASK 		0x3fff0000
#define REGCTRL6_PWM_AUTO_CTRL_SHIFT		16
#define CC_BP_IND_ACCESS_START_SHIFT		9
#define CC_BP_IND_ACCESS_START_MASK		(1 << CC_BP_IND_ACCESS_START_SHIFT)
#define CC_BP_IND_ACCESS_RDWR_SHIFT		8
#define CC_BP_IND_ACCESS_RDWR_MASK		(1 << CC_BP_IND_ACCESS_RDWR_SHIFT)
#define CC_BP_IND_ACCESS_ERROR_SHIFT		10
#define CC_BP_IND_ACCESS_ERROR_MASK		(1 << CC_BP_IND_ACCESS_ERROR_SHIFT)

#define LPO_SEL_TIMEOUT 1000

#define LPO_FINAL_SEL_SHIFT 18

#define LHL_LPO1_SEL 0
#define LHL_LPO2_SEL 0x1
#define LHL_32k_SEL 0x2
#define LHL_EXT_SEL  0x3

#define EXTLPO_BUF_PD	0x40
#define LPO1_PD_EN	0x1
#define LPO1_PD_SEL	0x6
#define LPO1_PD_SEL_VAL	0x4
#define LPO2_PD_EN	0x8
#define LPO2_PD_SEL	0x30
#define LPO2_PD_SEL_VAL	0x20
#define OSC_32k_PD	0x80

#define LHL_CLK_DET_CTL_AD_CNTR_CLK_SEL	0x3

#define LHL_LPO_AUTO	0x0
#define LHL_LPO1_ENAB	0x1
#define LHL_LPO2_ENAB	0x2
#define LHL_OSC_32k_ENAB	0x3
#define LHL_EXT_LPO_ENAB	0x4
#define RADIO_LPO_ENAB 0x5

#define LHL_CLK_DET_CTL_ADR_LHL_CNTR_EN	0x4
#define LHL_CLK_DET_CTL_ADR_LHL_CNTR_CLR	0x8
#define LHL_CLK_DET_CNT		0xF0
#define LHL_CLK_DET_CNT_SHIFT   4
#define LPO_SEL_SHIFT		9

#define LHL_MAIN_CTL_ADR_FINAL_CLK_SEL	0x3C0000
#define LHL_MAIN_CTL_ADR_LHL_WLCLK_SEL	0x600

#define CLK_DET_CNT_THRESH	8

#ifdef SR_DEBUG
#define SUBCORE_POWER_ON 0x0001
#define PHY_POWER_ON 0x0010
#define VDDM_POWER_ON 0x0100
#define MEMLPLDO_POWER_ON 0x1000
#define SUBCORE_POWER_ON_CHK 0x00040000
#define PHY_POWER_ON_CHK 0x00080000
#define VDDM_POWER_ON_CHK 0x00100000
#define MEMLPLDO_POWER_ON_CHK 0x00200000
#endif /* SR_DEBUG */

#ifdef CCNFLASH_SUPPORT
/* NAND flash support */
#define CC_NAND_REVISION	0xC00
#define CC_NAND_CMD_START	0xC04
#define CC_NAND_CMD_ADDR	0xC0C
#define CC_NAND_SPARE_RD_0	0xC20
#define CC_NAND_SPARE_RD_4	0xC24
#define CC_NAND_SPARE_RD_8	0xC28
#define CC_NAND_SPARE_RD_C	0xC2C
#define CC_NAND_CONFIG		0xC48
#define CC_NAND_DEVID		0xC60
#define CC_NAND_DEVID_EXT	0xC64
#define CC_NAND_INTFC_STATUS	0xC6C
#endif /* CCNFLASH_SUPPORT */

/* chipid */
#define	CID_ID_MASK		0x0000ffff	/**< Chip Id mask */
#define	CID_REV_MASK		0x000f0000	/**< Chip Revision mask */
#define	CID_REV_SHIFT		16		/**< Chip Revision shift */
#define	CID_PKG_MASK		0x00f00000	/**< Package Option mask */
#define	CID_PKG_SHIFT		20		/**< Package Option shift */
#define	CID_CC_MASK		0x0f000000	/**< CoreCount (corerev >= 4) */
#define CID_CC_SHIFT		24
#define	CID_TYPE_MASK		0xf0000000	/**< Chip Type */
#define CID_TYPE_SHIFT		28

/* capabilities */
#define	CC_CAP_UARTS_MASK	0x00000003	/**< Number of UARTs */
#define CC_CAP_MIPSEB		0x00000004	/**< MIPS is in big-endian mode */
#define CC_CAP_UCLKSEL		0x00000018	/**< UARTs clock select */
#define CC_CAP_UINTCLK		0x00000008	/**< UARTs are driven by internal divided clock */
#define CC_CAP_UARTGPIO		0x00000020	/**< UARTs own GPIOs 15:12 */
#define CC_CAP_EXTBUS_MASK	0x000000c0	/**< External bus mask */
#define CC_CAP_EXTBUS_NONE	0x00000000	/**< No ExtBus present */
#define CC_CAP_EXTBUS_FULL	0x00000040	/**< ExtBus: PCMCIA, IDE & Prog */
#define CC_CAP_EXTBUS_PROG	0x00000080	/**< ExtBus: ProgIf only */
#define	CC_CAP_FLASH_MASK	0x00000700	/**< Type of flash */
#define	CC_CAP_PLL_MASK		0x00038000	/**< Type of PLL */
#define CC_CAP_PWR_CTL		0x00040000	/**< Power control */
#define CC_CAP_OTPSIZE		0x00380000	/**< OTP Size (0 = none) */
#define CC_CAP_OTPSIZE_SHIFT	19		/**< OTP Size shift */
#define CC_CAP_OTPSIZE_BASE	5		/**< OTP Size base */
#define CC_CAP_JTAGP		0x00400000	/**< JTAG Master Present */
#define CC_CAP_ROM		0x00800000	/**< Internal boot rom active */
#define CC_CAP_BKPLN64		0x08000000	/**< 64-bit backplane */
#define	CC_CAP_PMU		0x10000000	/**< PMU Present, rev >= 20 */
#define	CC_CAP_ECI		0x20000000	/**< ECI Present, rev >= 21 */
#define	CC_CAP_SROM		0x40000000	/**< Srom Present, rev >= 32 */
#define	CC_CAP_NFLASH		0x80000000	/**< Nand flash present, rev >= 35 */

#define	CC_CAP2_SECI		0x00000001	/**< SECI Present, rev >= 36 */
#define	CC_CAP2_GSIO		0x00000002	/**< GSIO (spi/i2c) present, rev >= 37 */

/* capabilities extension */
#define CC_CAP_EXT_SECI_PRESENT				0x00000001	/**< SECI present */
#define CC_CAP_EXT_GSIO_PRESENT				0x00000002	/**< GSIO present */
#define CC_CAP_EXT_GCI_PRESENT  			0x00000004	/**< GCI present */
#define CC_CAP_EXT_SECI_PUART_PRESENT		0x00000008  /**< UART present */
#define CC_CAP_EXT_AOB_PRESENT  			0x00000040	/**< AOB present */
#define CC_CAP_EXT_SWD_PRESENT  			0x00000400	/**< SWD present */

/* WL Channel Info to BT via GCI - bits 40 - 47 */
#define GCI_WL_CHN_INFO_MASK	(0xFF00)
/* WL indication of MCHAN enabled/disabled to BT in awdl mode- bit 36 */
#define GCI_WL_MCHAN_BIT_MASK	(0x0010)

#ifdef WLC_SW_DIVERSITY
/* WL indication of SWDIV enabled/disabled to BT - bit 33 */
#define GCI_WL_SWDIV_ANT_VALID_BIT_MASK	(0x0002)
#define GCI_SWDIV_ANT_VALID_SHIFT 0x1
#define GCI_SWDIV_ANT_VALID_DISABLE 0x0
#endif // endif

/* WL Strobe to BT */
#define GCI_WL_STROBE_BIT_MASK	(0x0020)
/* bits [51:48] - reserved for wlan TX pwr index */
/* bits [55:52] btc mode indication */
#define GCI_WL_BTC_MODE_SHIFT	(20)
#define GCI_WL_BTC_MODE_MASK	(0xF << GCI_WL_BTC_MODE_SHIFT)
#define GCI_WL_ANT_BIT_MASK	(0x00c0)
#define GCI_WL_ANT_SHIFT_BITS	(6)
/* PLL type */
#define PLL_NONE		0x00000000
#define PLL_TYPE1		0x00010000	/**< 48MHz base, 3 dividers */
#define PLL_TYPE2		0x00020000	/**< 48MHz, 4 dividers */
#define PLL_TYPE3		0x00030000	/**< 25MHz, 2 dividers */
#define PLL_TYPE4		0x00008000	/**< 48MHz, 4 dividers */
#define PLL_TYPE5		0x00018000	/**< 25MHz, 4 dividers */
#define PLL_TYPE6		0x00028000	/**< 100/200 or 120/240 only */
#define PLL_TYPE7		0x00038000	/**< 25MHz, 4 dividers */

/* ILP clock */
#define	ILP_CLOCK		32000

/* ALP clock on pre-PMU chips */
#define	ALP_CLOCK		20000000

#ifdef CFG_SIM
#define NS_ALP_CLOCK		84922
#define NS_SLOW_ALP_CLOCK	84922
#define NS_CPU_CLOCK		534500
#define NS_SLOW_CPU_CLOCK	534500
#define NS_SI_CLOCK		271750
#define NS_SLOW_SI_CLOCK	271750
#define NS_FAST_MEM_CLOCK	271750
#define NS_MEM_CLOCK		271750
#define NS_SLOW_MEM_CLOCK	271750
#else
#define NS_ALP_CLOCK		125000000
#define NS_SLOW_ALP_CLOCK	100000000
#define NS_CPU_CLOCK		1000000000
#define NS_SLOW_CPU_CLOCK	800000000
#define NS_SI_CLOCK		250000000
#define NS_SLOW_SI_CLOCK	200000000
#define NS_FAST_MEM_CLOCK	800000000
#define NS_MEM_CLOCK		533000000
#define NS_SLOW_MEM_CLOCK	400000000
#endif /* CFG_SIM */

#define ALP_CLOCK_53573		40000000

/* HT clock */
#define	HT_CLOCK		80000000

/* corecontrol */
#define CC_UARTCLKO		0x00000001	/**< Drive UART with internal clock */
#define	CC_SE			0x00000002	/**< sync clk out enable (corerev >= 3) */
#define CC_ASYNCGPIO	0x00000004	/**< 1=generate GPIO interrupt without backplane clock */
#define CC_UARTCLKEN		0x00000008	/**< enable UART Clock (corerev > = 21 */

/* retention_ctl */
#define RCTL_MEM_RET_SLEEP_LOG_SHIFT	29
#define RCTL_MEM_RET_SLEEP_LOG_MASK	(1 << RCTL_MEM_RET_SLEEP_LOG_SHIFT)

/* 4321 chipcontrol */
#define CHIPCTRL_4321_PLL_DOWN	0x800000	/**< serdes PLL down override */

/* Fields in the otpstatus register in rev >= 21 */
#define OTPS_OL_MASK		0x000000ff
#define OTPS_OL_MFG		0x00000001	/**< manuf row is locked */
#define OTPS_OL_OR1		0x00000002	/**< otp redundancy row 1 is locked */
#define OTPS_OL_OR2		0x00000004	/**< otp redundancy row 2 is locked */
#define OTPS_OL_GU		0x00000008	/**< general use region is locked */
#define OTPS_GUP_MASK		0x00000f00
#define OTPS_GUP_SHIFT		8
#define OTPS_GUP_HW		0x00000100	/**< h/w subregion is programmed */
#define OTPS_GUP_SW		0x00000200	/**< s/w subregion is programmed */
#define OTPS_GUP_CI		0x00000400	/**< chipid/pkgopt subregion is programmed */
#define OTPS_GUP_FUSE		0x00000800	/**< fuse subregion is programmed */
#define OTPS_READY		0x00001000
#define OTPS_RV(x)		(1 << (16 + (x)))	/**< redundancy entry valid */
#define OTPS_RV_MASK		0x0fff0000
#define OTPS_PROGOK     0x40000000

/* Fields in the otpcontrol register in rev >= 21 */
#define OTPC_PROGSEL		0x00000001
#define OTPC_PCOUNT_MASK	0x0000000e
#define OTPC_PCOUNT_SHIFT	1
#define OTPC_VSEL_MASK		0x000000f0
#define OTPC_VSEL_SHIFT		4
#define OTPC_TMM_MASK		0x00000700
#define OTPC_TMM_SHIFT		8
#define OTPC_ODM		0x00000800
#define OTPC_PROGEN		0x80000000

/* Fields in the 40nm otpcontrol register in rev >= 40 */
#define OTPC_40NM_PROGSEL_SHIFT	0
#define OTPC_40NM_PCOUNT_SHIFT	1
#define OTPC_40NM_PCOUNT_WR	0xA
#define OTPC_40NM_PCOUNT_V1X	0xB
#define OTPC_40NM_REGCSEL_SHIFT	5
#define OTPC_40NM_REGCSEL_DEF	0x4
#define OTPC_40NM_PROGIN_SHIFT	8
#define OTPC_40NM_R2X_SHIFT	10
#define OTPC_40NM_ODM_SHIFT	11
#define OTPC_40NM_DF_SHIFT	15
#define OTPC_40NM_VSEL_SHIFT	16
#define OTPC_40NM_VSEL_WR	0xA
#define OTPC_40NM_VSEL_V1X	0xA
#define OTPC_40NM_VSEL_R1X	0x5
#define OTPC_40NM_COFAIL_SHIFT	30

#define OTPC1_CPCSEL_SHIFT	0
#define OTPC1_CPCSEL_DEF	6
#define OTPC1_TM_SHIFT		8
#define OTPC1_TM_WR		0x84
#define OTPC1_TM_V1X		0x84
#define OTPC1_TM_R1X		0x4
#define OTPC1_CLK_EN_MASK	0x00020000
#define OTPC1_CLK_DIV_MASK	0x00FC0000

/* Fields in otpprog in rev >= 21 and HND OTP */
#define OTPP_COL_MASK		0x000000ff
#define OTPP_COL_SHIFT		0
#define OTPP_ROW_MASK		0x0000ff00
#define OTPP_ROW_MASK9		0x0001ff00		/* for ccrev >= 49 */
#define OTPP_ROW_SHIFT		8
#define OTPP_OC_MASK		0x0f000000
#define OTPP_OC_SHIFT		24
#define OTPP_READERR		0x10000000
#define OTPP_VALUE_MASK		0x20000000
#define OTPP_VALUE_SHIFT	29
#define OTPP_START_BUSY		0x80000000
#define	OTPP_READ		0x40000000	/* HND OTP */

/* Fields in otplayout register */
#define OTPL_HWRGN_OFF_MASK	0x00000FFF
#define OTPL_HWRGN_OFF_SHIFT	0
#define OTPL_WRAP_REVID_MASK	0x00F80000
#define OTPL_WRAP_REVID_SHIFT	19
#define OTPL_WRAP_TYPE_MASK	0x00070000
#define OTPL_WRAP_TYPE_SHIFT	16
#define OTPL_WRAP_TYPE_65NM	0
#define OTPL_WRAP_TYPE_40NM	1
#define OTPL_WRAP_TYPE_28NM	2
#define OTPL_ROW_SIZE_MASK	0x0000F000
#define OTPL_ROW_SIZE_SHIFT	12

/* otplayout reg corerev >= 36 */
#define OTP_CISFORMAT_NEW	0x80000000

/* Opcodes for OTPP_OC field */
#define OTPPOC_READ		0
#define OTPPOC_BIT_PROG		1
#define OTPPOC_VERIFY		3
#define OTPPOC_INIT		4
#define OTPPOC_SET		5
#define OTPPOC_RESET		6
#define OTPPOC_OCST		7
#define OTPPOC_ROW_LOCK		8
#define OTPPOC_PRESCN_TEST	9

/* Opcodes for OTPP_OC field (40NM) */
#define OTPPOC_READ_40NM	0
#define OTPPOC_PROG_ENABLE_40NM 1
#define OTPPOC_PROG_DISABLE_40NM	2
#define OTPPOC_VERIFY_40NM	3
#define OTPPOC_WORD_VERIFY_1_40NM	4
#define OTPPOC_ROW_LOCK_40NM	5
#define OTPPOC_STBY_40NM	6
#define OTPPOC_WAKEUP_40NM	7
#define OTPPOC_WORD_VERIFY_0_40NM	8
#define OTPPOC_PRESCN_TEST_40NM 9
#define OTPPOC_BIT_PROG_40NM	10
#define OTPPOC_WORDPROG_40NM	11
#define OTPPOC_BURNIN_40NM	12
#define OTPPOC_AUTORELOAD_40NM	13
#define OTPPOC_OVST_READ_40NM	14
#define OTPPOC_OVST_PROG_40NM	15

/* Opcodes for OTPP_OC field (28NM) */
#define OTPPOC_READ_28NM	0
#define OTPPOC_READBURST_28NM	1
#define OTPPOC_PROG_ENABLE_28NM 2
#define OTPPOC_PROG_DISABLE_28NM	3
#define OTPPOC_PRESCREEN_28NM	4
#define OTPPOC_PRESCREEN_RP_28NM	5
#define OTPPOC_FLUSH_28NM	6
#define OTPPOC_NOP_28NM	7
#define OTPPOC_PROG_ECC_28NM	8
#define OTPPOC_PROG_ECC_READ_28NM	9
#define OTPPOC_PROG_28NM	10
#define OTPPOC_PROGRAM_RP_28NM	11
#define OTPPOC_PROGRAM_OVST_28NM	12
#define OTPPOC_RELOAD_28NM	13
#define OTPPOC_ERASE_28NM	14
#define OTPPOC_LOAD_RF_28NM	15
#define OTPPOC_CTRL_WR_28NM 16
#define OTPPOC_CTRL_RD_28NM	17
#define OTPPOC_READ_HP_28NM	18
#define OTPPOC_READ_OVST_28NM	19
#define OTPPOC_READ_VERIFY0_28NM	20
#define OTPPOC_READ_VERIFY1_28NM	21
#define OTPPOC_READ_FORCE0_28NM	22
#define OTPPOC_READ_FORCE1_28NM	23
#define OTPPOC_BURNIN_28NM	24
#define OTPPOC_PROGRAM_LOCK_28NM	25
#define OTPPOC_PROGRAM_TESTCOL_28NM	26
#define OTPPOC_READ_TESTCOL_28NM	27
#define OTPPOC_READ_FOUT_28NM	28
#define OTPPOC_SFT_RESET_28NM	29

#define OTPP_OC_MASK_28NM		0x0f800000
#define OTPP_OC_SHIFT_28NM		23
#define OTPC_PROGEN_28NM		0x8
#define OTPC_DBLERRCLR		0x20
#define OTPC_CLK_EN_MASK	0x00000040
#define OTPC_CLK_DIV_MASK	0x00000F80

/* Fields in otplayoutextension */
#define OTPLAYOUTEXT_FUSE_MASK	0x3FF

/* Jtagm characteristics that appeared at a given corerev */
#define	JTAGM_CREV_OLD		10	/**< Old command set, 16bit max IR */
#define	JTAGM_CREV_IRP		22	/**< Able to do pause-ir */
#define	JTAGM_CREV_RTI		28	/**< Able to do return-to-idle */

/* jtagcmd */
#define JCMD_START		0x80000000
#define JCMD_BUSY		0x80000000
#define JCMD_STATE_MASK		0x60000000
#define JCMD_STATE_TLR		0x00000000	/**< Test-logic-reset */
#define JCMD_STATE_PIR		0x20000000	/**< Pause IR */
#define JCMD_STATE_PDR		0x40000000	/**< Pause DR */
#define JCMD_STATE_RTI		0x60000000	/**< Run-test-idle */
#define JCMD0_ACC_MASK		0x0000f000
#define JCMD0_ACC_IRDR		0x00000000
#define JCMD0_ACC_DR		0x00001000
#define JCMD0_ACC_IR		0x00002000
#define JCMD0_ACC_RESET		0x00003000
#define JCMD0_ACC_IRPDR		0x00004000
#define JCMD0_ACC_PDR		0x00005000
#define JCMD0_IRW_MASK		0x00000f00
#define JCMD_ACC_MASK		0x000f0000	/**< Changes for corerev 11 */
#define JCMD_ACC_IRDR		0x00000000
#define JCMD_ACC_DR		0x00010000
#define JCMD_ACC_IR		0x00020000
#define JCMD_ACC_RESET		0x00030000
#define JCMD_ACC_IRPDR		0x00040000
#define JCMD_ACC_PDR		0x00050000
#define JCMD_ACC_PIR		0x00060000
#define JCMD_ACC_IRDR_I		0x00070000	/**< rev 28: return to run-test-idle */
#define JCMD_ACC_DR_I		0x00080000	/**< rev 28: return to run-test-idle */
#define JCMD_IRW_MASK		0x00001f00
#define JCMD_IRW_SHIFT		8
#define JCMD_DRW_MASK		0x0000003f

/* jtagctrl */
#define JCTRL_FORCE_CLK		4		/**< Force clock */
#define JCTRL_EXT_EN		2		/**< Enable external targets */
#define JCTRL_EN		1		/**< Enable Jtag master */
#define JCTRL_TAPSEL_BIT	0x00000008	/**< JtagMasterCtrl tap_sel bit */

/* swdmasterctrl */
#define SWDCTRL_INT_EN		8		/**< Enable internal targets */
#define SWDCTRL_FORCE_CLK	4		/**< Force clock */
#define SWDCTRL_OVJTAG		2		/**< Enable shared SWD/JTAG pins */
#define SWDCTRL_EN		1		/**< Enable Jtag master */

/* Fields in clkdiv */
#define	CLKD_SFLASH		0x1f000000
#define	CLKD_SFLASH_SHIFT	24
#define	CLKD_OTP		0x000f0000
#define	CLKD_OTP_SHIFT		16
#define	CLKD_JTAG		0x00000f00
#define	CLKD_JTAG_SHIFT		8
#define	CLKD_UART		0x000000ff

#define	CLKD2_SROM		0x00000007
#define	CLKD2_SROMDIV_32	0
#define	CLKD2_SROMDIV_64	1
#define	CLKD2_SROMDIV_96	2
#define	CLKD2_SROMDIV_128	3
#define	CLKD2_SROMDIV_192	4
#define	CLKD2_SROMDIV_256	5
#define	CLKD2_SROMDIV_384	6
#define	CLKD2_SROMDIV_512	7
#define	CLKD2_SWD		0xf8000000
#define	CLKD2_SWD_SHIFT		27

/* intstatus/intmask */
#define	CI_GPIO			0x00000001	/**< gpio intr */
#define	CI_EI			0x00000002	/**< extif intr (corerev >= 3) */
#define	CI_TEMP			0x00000004	/**< temp. ctrl intr (corerev >= 15) */
#define	CI_SIRQ			0x00000008	/**< serial IRQ intr (corerev >= 15) */
#define	CI_ECI			0x00000010	/**< eci intr (corerev >= 21) */
#define	CI_PMU			0x00000020	/**< pmu intr (corerev >= 21) */
#define	CI_UART			0x00000040	/**< uart intr (corerev >= 21) */
#define	CI_WECI			0x00000080	/* eci wakeup intr (corerev >= 21) */
#define	CI_WDRESET		0x80000000	/**< watchdog reset occurred */

/* slow_clk_ctl */
#define SCC_SS_MASK		0x00000007	/**< slow clock source mask */
#define	SCC_SS_LPO		0x00000000	/**< source of slow clock is LPO */
#define	SCC_SS_XTAL		0x00000001	/**< source of slow clock is crystal */
#define	SCC_SS_PCI		0x00000002	/**< source of slow clock is PCI */
#define SCC_LF			0x00000200	/**< LPOFreqSel, 1: 160Khz, 0: 32KHz */
#define SCC_LP			0x00000400	/**< LPOPowerDown, 1: LPO is disabled,
						 * 0: LPO is enabled
						 */
#define SCC_FS			0x00000800 /**< ForceSlowClk, 1: sb/cores running on slow clock,
						 * 0: power logic control
						 */
#define SCC_IP			0x00001000 /**< IgnorePllOffReq, 1/0: power logic ignores/honors
						 * PLL clock disable requests from core
						 */
#define SCC_XC			0x00002000	/**< XtalControlEn, 1/0: power logic does/doesn't
						 * disable crystal when appropriate
						 */
#define SCC_XP			0x00004000	/**< XtalPU (RO), 1/0: crystal running/disabled */
#define SCC_CD_MASK		0xffff0000	/**< ClockDivider (SlowClk = 1/(4+divisor)) */
#define SCC_CD_SHIFT		16

/* system_clk_ctl */
#define	SYCC_IE			0x00000001	/**< ILPen: Enable Idle Low Power */
#define	SYCC_AE			0x00000002	/**< ALPen: Enable Active Low Power */
#define	SYCC_FP			0x00000004	/**< ForcePLLOn */
#define	SYCC_AR			0x00000008	/**< Force ALP (or HT if ALPen is not set */
#define	SYCC_HR			0x00000010	/**< Force HT */
#define SYCC_CD_MASK		0xffff0000	/**< ClkDiv  (ILP = 1/(4 * (divisor + 1)) */
#define SYCC_CD_SHIFT		16

/* watchdogcounter */
/* WL sub-system reset */
#define WD_SSRESET_PCIE_F0_EN			0x10000000
/* BT sub-system reset */
#define WD_SSRESET_PCIE_F1_EN			0x20000000
#define WD_SSRESET_PCIE_F2_EN			0x40000000
/* Both WL and BT sub-system reset */
#define WD_SSRESET_PCIE_ALL_FN_EN		0x80000000
#define WD_COUNTER_MASK				0x0fffffff
#define WD_ENABLE_MASK	\
	(WD_SSRESET_PCIE_F0_EN | WD_SSRESET_PCIE_F1_EN | \
	WD_SSRESET_PCIE_F2_EN | WD_SSRESET_PCIE_ALL_FN_EN)

/* Indirect backplane access */
#define	BPIA_BYTEEN		0x0000000f
#define	BPIA_SZ1		0x00000001
#define	BPIA_SZ2		0x00000003
#define	BPIA_SZ4		0x00000007
#define	BPIA_SZ8		0x0000000f
#define	BPIA_WRITE		0x00000100
#define	BPIA_START		0x00000200
#define	BPIA_BUSY		0x00000200
#define	BPIA_ERROR		0x00000400

/* pcmcia/prog/flash_config */
#define	CF_EN			0x00000001	/**< enable */
#define	CF_EM_MASK		0x0000000e	/**< mode */
#define	CF_EM_SHIFT		1
#define	CF_EM_FLASH		0		/**< flash/asynchronous mode */
#define	CF_EM_SYNC		2		/**< synchronous mode */
#define	CF_EM_PCMCIA		4		/**< pcmcia mode */
#define	CF_DS			0x00000010	/**< destsize:  0=8bit, 1=16bit */
#define	CF_BS			0x00000020	/**< byteswap */
#define	CF_CD_MASK		0x000000c0	/**< clock divider */
#define	CF_CD_SHIFT		6
#define	CF_CD_DIV2		0x00000000	/**< backplane/2 */
#define	CF_CD_DIV3		0x00000040	/**< backplane/3 */
#define	CF_CD_DIV4		0x00000080	/**< backplane/4 */
#define	CF_CE			0x00000100	/**< clock enable */
#define	CF_SB			0x00000200	/**< size/bytestrobe (synch only) */

/* pcmcia_memwait */
#define	PM_W0_MASK		0x0000003f	/**< waitcount0 */
#define	PM_W1_MASK		0x00001f00	/**< waitcount1 */
#define	PM_W1_SHIFT		8
#define	PM_W2_MASK		0x001f0000	/**< waitcount2 */
#define	PM_W2_SHIFT		16
#define	PM_W3_MASK		0x1f000000	/**< waitcount3 */
#define	PM_W3_SHIFT		24

/* pcmcia_attrwait */
#define	PA_W0_MASK		0x0000003f	/**< waitcount0 */
#define	PA_W1_MASK		0x00001f00	/**< waitcount1 */
#define	PA_W1_SHIFT		8
#define	PA_W2_MASK		0x001f0000	/**< waitcount2 */
#define	PA_W2_SHIFT		16
#define	PA_W3_MASK		0x1f000000	/**< waitcount3 */
#define	PA_W3_SHIFT		24

/* pcmcia_iowait */
#define	PI_W0_MASK		0x0000003f	/**< waitcount0 */
#define	PI_W1_MASK		0x00001f00	/**< waitcount1 */
#define	PI_W1_SHIFT		8
#define	PI_W2_MASK		0x001f0000	/**< waitcount2 */
#define	PI_W2_SHIFT		16
#define	PI_W3_MASK		0x1f000000	/**< waitcount3 */
#define	PI_W3_SHIFT		24

/* prog_waitcount */
#define	PW_W0_MASK		0x0000001f	/**< waitcount0 */
#define	PW_W1_MASK		0x00001f00	/**< waitcount1 */
#define	PW_W1_SHIFT		8
#define	PW_W2_MASK		0x001f0000	/**< waitcount2 */
#define	PW_W2_SHIFT		16
#define	PW_W3_MASK		0x1f000000	/**< waitcount3 */
#define	PW_W3_SHIFT		24

#define PW_W0       		0x0000000c
#define PW_W1       		0x00000a00
#define PW_W2       		0x00020000
#define PW_W3       		0x01000000

/* flash_waitcount */
#define	FW_W0_MASK		0x0000003f	/**< waitcount0 */
#define	FW_W1_MASK		0x00001f00	/**< waitcount1 */
#define	FW_W1_SHIFT		8
#define	FW_W2_MASK		0x001f0000	/**< waitcount2 */
#define	FW_W2_SHIFT		16
#define	FW_W3_MASK		0x1f000000	/**< waitcount3 */
#define	FW_W3_SHIFT		24

/* When Srom support present, fields in sromcontrol */
#define	SRC_START		0x80000000
#define	SRC_BUSY		0x80000000
#define	SRC_OPCODE		0x60000000
#define	SRC_OP_READ		0x00000000
#define	SRC_OP_WRITE		0x20000000
#define	SRC_OP_WRDIS		0x40000000
#define	SRC_OP_WREN		0x60000000
#define	SRC_OTPSEL		0x00000010
#define SRC_OTPPRESENT		0x00000020
#define	SRC_LOCK		0x00000008
#define	SRC_SIZE_MASK		0x00000006
#define	SRC_SIZE_1K		0x00000000
#define	SRC_SIZE_4K		0x00000002
#define	SRC_SIZE_16K		0x00000004
#define	SRC_SIZE_SHIFT		1
#define	SRC_PRESENT		0x00000001

/* Fields in pmucontrol */
#define	PCTL_ILP_DIV_MASK	0xffff0000
#define	PCTL_ILP_DIV_SHIFT	16
#define PCTL_LQ_REQ_EN		0x00008000
#define PCTL_PLL_PLLCTL_UPD	0x00000400	/**< rev 2 */
#define PCTL_NOILP_ON_WAIT	0x00000200	/**< rev 1 */
#define	PCTL_HT_REQ_EN		0x00000100
#define	PCTL_ALP_REQ_EN		0x00000080
#define	PCTL_XTALFREQ_MASK	0x0000007c
#define	PCTL_XTALFREQ_SHIFT	2
#define	PCTL_ILP_DIV_EN		0x00000002
#define	PCTL_LPO_SEL		0x00000001

/* Fields in pmucontrol_ext */
#define PCTL_EXT_USE_LHL_TIMER	0x00000010
#define PCTL_EXT_FASTLPO_ENAB	0x00000080
#define PCTL_EXT_FASTLPO_SWENAB	0x00000200
#define PCTL_EXT_FASTSEQ_ENAB	0x00001000
#define PCTL_EXT_FASTLPO_PCIE_SWENAB	0x00004000  /**< rev33 for FLL1M */

#define DEFAULT_43012_MIN_RES_MASK		0x0f8bfe77

/*  Retention Control */
#define PMU_RCTL_CLK_DIV_SHIFT		0
#define PMU_RCTL_CHAIN_LEN_SHIFT	12
#define PMU_RCTL_MACPHY_DISABLE_SHIFT	26
#define PMU_RCTL_MACPHY_DISABLE_MASK	(1 << 26)
#define PMU_RCTL_LOGIC_DISABLE_SHIFT	27
#define PMU_RCTL_LOGIC_DISABLE_MASK	(1 << 27)
#define PMU_RCTL_MEMSLP_LOG_SHIFT	28
#define PMU_RCTL_MEMSLP_LOG_MASK	(1 << 28)
#define PMU_RCTL_MEMRETSLP_LOG_SHIFT	29
#define PMU_RCTL_MEMRETSLP_LOG_MASK	(1 << 29)

/*  Retention Group Control */
#define PMU_RCTLGRP_CHAIN_LEN_SHIFT	0
#define PMU_RCTLGRP_RMODE_ENABLE_SHIFT	14
#define PMU_RCTLGRP_RMODE_ENABLE_MASK	(1 << 14)
#define PMU_RCTLGRP_DFT_ENABLE_SHIFT	15
#define PMU_RCTLGRP_DFT_ENABLE_MASK	(1 << 15)
#define PMU_RCTLGRP_NSRST_DISABLE_SHIFT	16
#define PMU_RCTLGRP_NSRST_DISABLE_MASK	(1 << 16)

/* Fields in clkstretch */
#define CSTRETCH_HT		0xffff0000
#define CSTRETCH_ALP		0x0000ffff
#define CSTRETCH_REDUCE_8		0x00080008

/* gpiotimerval */
#define GPIO_ONTIME_SHIFT	16

/* clockcontrol_n */
#define	CN_N1_MASK		0x3f		/**< n1 control */
#define	CN_N2_MASK		0x3f00		/**< n2 control */
#define	CN_N2_SHIFT		8
#define	CN_PLLC_MASK		0xf0000		/**< pll control */
#define	CN_PLLC_SHIFT		16

/* clockcontrol_sb/pci/uart */
#define	CC_M1_MASK		0x3f		/**< m1 control */
#define	CC_M2_MASK		0x3f00		/**< m2 control */
#define	CC_M2_SHIFT		8
#define	CC_M3_MASK		0x3f0000	/**< m3 control */
#define	CC_M3_SHIFT		16
#define	CC_MC_MASK		0x1f000000	/**< mux control */
#define	CC_MC_SHIFT		24

/* N3M Clock control magic field values */
#define	CC_F6_2			0x02		/**< A factor of 2 in */
#define	CC_F6_3			0x03		/**< 6-bit fields like */
#define	CC_F6_4			0x05		/**< N1, M1 or M3 */
#define	CC_F6_5			0x09
#define	CC_F6_6			0x11
#define	CC_F6_7			0x21

#define	CC_F5_BIAS		5		/**< 5-bit fields get this added */

#define	CC_MC_BYPASS		0x08
#define	CC_MC_M1		0x04
#define	CC_MC_M1M2		0x02
#define	CC_MC_M1M2M3		0x01
#define	CC_MC_M1M3		0x11

/* Type 2 Clock control magic field values */
#define	CC_T2_BIAS		2		/**< n1, n2, m1 & m3 bias */
#define	CC_T2M2_BIAS		3		/**< m2 bias */

#define	CC_T2MC_M1BYP		1
#define	CC_T2MC_M2BYP		2
#define	CC_T2MC_M3BYP		4

/* Type 6 Clock control magic field values */
#define	CC_T6_MMASK		1		/**< bits of interest in m */
#define	CC_T6_M0		120000000	/**< sb clock for m = 0 */
#define	CC_T6_M1		100000000	/**< sb clock for m = 1 */
#define	SB2MIPS_T6(sb)		(2 * (sb))

/* Common clock base */
#define	CC_CLOCK_BASE1		24000000	/**< Half the clock freq */
#define CC_CLOCK_BASE2		12500000	/**< Alternate crystal on some PLLs */

/* Clock control values for 200MHz in 5350 */
#define	CLKC_5350_N		0x0311
#define	CLKC_5350_M		0x04020009

/* Flash types in the chipcommon capabilities register */
#define FLASH_NONE		0x000		/**< No flash */
#define SFLASH_ST		0x100		/**< ST serial flash */
#define SFLASH_AT		0x200		/**< Atmel serial flash */
#define NFLASH			0x300
#define	PFLASH			0x700		/**< Parallel flash */
#define QSPIFLASH_ST		0x800
#define QSPIFLASH_AT		0x900

/* Bits in the ExtBus config registers */
#define	CC_CFG_EN		0x0001		/**< Enable */
#define	CC_CFG_EM_MASK		0x000e		/**< Extif Mode */
#define	CC_CFG_EM_ASYNC		0x0000		/**<   Async/Parallel flash */
#define	CC_CFG_EM_SYNC		0x0002		/**<   Synchronous */
#define	CC_CFG_EM_PCMCIA	0x0004		/**<   PCMCIA */
#define	CC_CFG_EM_IDE		0x0006		/**<   IDE */
#define	CC_CFG_DS		0x0010		/**< Data size, 0=8bit, 1=16bit */
#define	CC_CFG_CD_MASK		0x00e0		/**< Sync: Clock divisor, rev >= 20 */
#define	CC_CFG_CE		0x0100		/**< Sync: Clock enable, rev >= 20 */
#define	CC_CFG_SB		0x0200		/**< Sync: Size/Bytestrobe, rev >= 20 */
#define	CC_CFG_IS		0x0400		/**< Extif Sync Clk Select, rev >= 20 */

/* ExtBus address space */
#define	CC_EB_BASE		0x1a000000	/**< Chipc ExtBus base address */
#define	CC_EB_PCMCIA_MEM	0x1a000000	/**< PCMCIA 0 memory base address */
#define	CC_EB_PCMCIA_IO		0x1a200000	/**< PCMCIA 0 I/O base address */
#define	CC_EB_PCMCIA_CFG	0x1a400000	/**< PCMCIA 0 config base address */
#define	CC_EB_IDE		0x1a800000	/**< IDE memory base */
#define	CC_EB_PCMCIA1_MEM	0x1a800000	/**< PCMCIA 1 memory base address */
#define	CC_EB_PCMCIA1_IO	0x1aa00000	/**< PCMCIA 1 I/O base address */
#define	CC_EB_PCMCIA1_CFG	0x1ac00000	/**< PCMCIA 1 config base address */
#define	CC_EB_PROGIF		0x1b000000	/**< ProgIF Async/Sync base address */

/* Start/busy bit in flashcontrol */
#define SFLASH_OPCODE		0x000000ff
#define SFLASH_ACTION		0x00000700
#define	SFLASH_CS_ACTIVE	0x00001000	/**< Chip Select Active, rev >= 20 */
#define SFLASH_START		0x80000000
#define SFLASH_BUSY		SFLASH_START

/* flashcontrol action codes */
#define	SFLASH_ACT_OPONLY	0x0000		/**< Issue opcode only */
#define	SFLASH_ACT_OP1D		0x0100		/**< opcode + 1 data byte */
#define	SFLASH_ACT_OP3A		0x0200		/**< opcode + 3 addr bytes */
#define	SFLASH_ACT_OP3A1D	0x0300		/**< opcode + 3 addr & 1 data bytes */
#define	SFLASH_ACT_OP3A4D	0x0400		/**< opcode + 3 addr & 4 data bytes */
#define	SFLASH_ACT_OP3A4X4D	0x0500		/**< opcode + 3 addr, 4 don't care & 4 data bytes */
#define	SFLASH_ACT_OP3A1X4D	0x0700		/**< opcode + 3 addr, 1 don't care & 4 data bytes */

/* flashcontrol action+opcodes for ST flashes */
#define SFLASH_ST_WREN		0x0006		/**< Write Enable */
#define SFLASH_ST_WRDIS		0x0004		/**< Write Disable */
#define SFLASH_ST_RDSR		0x0105		/**< Read Status Register */
#define SFLASH_ST_WRSR		0x0101		/**< Write Status Register */
#define SFLASH_ST_READ		0x0303		/**< Read Data Bytes */
#define SFLASH_ST_PP		0x0302		/**< Page Program */
#define SFLASH_ST_SE		0x02d8		/**< Sector Erase */
#define SFLASH_ST_BE		0x00c7		/**< Bulk Erase */
#define SFLASH_ST_DP		0x00b9		/**< Deep Power-down */
#define SFLASH_ST_RES		0x03ab		/**< Read Electronic Signature */
#define SFLASH_ST_CSA		0x1000		/**< Keep chip select asserted */
#define SFLASH_ST_SSE		0x0220		/**< Sub-sector Erase */

#define SFLASH_ST_READ4B	0x6313		/* Read Data Bytes in 4Byte address */
#define SFLASH_ST_PP4B		0x6312		/* Page Program in 4Byte address */
#define SFLASH_ST_SE4B		0x62dc		/* Sector Erase in 4Byte address */
#define SFLASH_ST_SSE4B		0x6221		/* Sub-sector Erase */

#define SFLASH_MXIC_RDID	0x0390		/* Read Manufacture ID */
#define SFLASH_MXIC_MFID	0xc2		/* MXIC Manufacture ID */

/* Status register bits for ST flashes */
#define SFLASH_ST_WIP		0x01		/**< Write In Progress */
#define SFLASH_ST_WEL		0x02		/**< Write Enable Latch */
#define SFLASH_ST_BP_MASK	0x1c		/**< Block Protect */
#define SFLASH_ST_BP_SHIFT	2
#define SFLASH_ST_SRWD		0x80		/**< Status Register Write Disable */

/* flashcontrol action+opcodes for Atmel flashes */
#define SFLASH_AT_READ				0x07e8
#define SFLASH_AT_PAGE_READ			0x07d2
#define SFLASH_AT_BUF1_READ
#define SFLASH_AT_BUF2_READ
#define SFLASH_AT_STATUS			0x01d7
#define SFLASH_AT_BUF1_WRITE			0x0384
#define SFLASH_AT_BUF2_WRITE			0x0387
#define SFLASH_AT_BUF1_ERASE_PROGRAM		0x0283
#define SFLASH_AT_BUF2_ERASE_PROGRAM		0x0286
#define SFLASH_AT_BUF1_PROGRAM			0x0288
#define SFLASH_AT_BUF2_PROGRAM			0x0289
#define SFLASH_AT_PAGE_ERASE			0x0281
#define SFLASH_AT_BLOCK_ERASE			0x0250
#define SFLASH_AT_BUF1_WRITE_ERASE_PROGRAM	0x0382
#define SFLASH_AT_BUF2_WRITE_ERASE_PROGRAM	0x0385
#define SFLASH_AT_BUF1_LOAD			0x0253
#define SFLASH_AT_BUF2_LOAD			0x0255
#define SFLASH_AT_BUF1_COMPARE			0x0260
#define SFLASH_AT_BUF2_COMPARE			0x0261
#define SFLASH_AT_BUF1_REPROGRAM		0x0258
#define SFLASH_AT_BUF2_REPROGRAM		0x0259

/* Status register bits for Atmel flashes */
#define SFLASH_AT_READY				0x80
#define SFLASH_AT_MISMATCH			0x40
#define SFLASH_AT_ID_MASK			0x38
#define SFLASH_AT_ID_SHIFT			3

/* SPI register bits, corerev >= 37 */
#define GSIO_START			0x80000000
#define GSIO_BUSY			GSIO_START

/* GCI UART Function sel related */
#define MUXENAB_GCI_UART_MASK		(0x00000f00)
#define MUXENAB_GCI_UART_SHIFT		8
#define MUXENAB_GCI_UART_FNSEL_MASK	(0x00003000)
#define MUXENAB_GCI_UART_FNSEL_SHIFT	12

/*
 * These are the UART port assignments, expressed as offsets from the base
 * register.  These assignments should hold for any serial port based on
 * a 8250, 16450, or 16550(A).
 */

#define UART_RX		0	/**< In:  Receive buffer (DLAB=0) */
#define UART_TX		0	/**< Out: Transmit buffer (DLAB=0) */
#define UART_DLL	0	/**< Out: Divisor Latch Low (DLAB=1) */
#define UART_IER	1	/**< In/Out: Interrupt Enable Register (DLAB=0) */
#define UART_DLM	1	/**< Out: Divisor Latch High (DLAB=1) */
#define UART_IIR	2	/**< In: Interrupt Identity Register  */
#define UART_FCR	2	/**< Out: FIFO Control Register */
#define UART_LCR	3	/**< Out: Line Control Register */
#define UART_MCR	4	/**< Out: Modem Control Register */
#define UART_LSR	5	/**< In:  Line Status Register */
#define UART_MSR	6	/**< In:  Modem Status Register */
#define UART_SCR	7	/**< I/O: Scratch Register */
#define UART_LCR_DLAB	0x80	/**< Divisor latch access bit */
#define UART_LCR_WLEN8	0x03	/**< Word length: 8 bits */
#define UART_MCR_OUT2	0x08	/**< MCR GPIO out 2 */
#define UART_MCR_LOOP	0x10	/**< Enable loopback test mode */
#define UART_LSR_RX_FIFO 	0x80	/**< Receive FIFO error */
#define UART_LSR_TDHR		0x40	/**< Data-hold-register empty */
#define UART_LSR_THRE		0x20	/**< Transmit-hold-register empty */
#define UART_LSR_BREAK		0x10	/**< Break interrupt */
#define UART_LSR_FRAMING	0x08	/**< Framing error */
#define UART_LSR_PARITY		0x04	/**< Parity error */
#define UART_LSR_OVERRUN	0x02	/**< Overrun error */
#define UART_LSR_RXRDY		0x01	/**< Receiver ready */
#define UART_FCR_FIFO_ENABLE 1	/**< FIFO control register bit controlling FIFO enable/disable */

/* Interrupt Identity Register (IIR) bits */
#define UART_IIR_FIFO_MASK	0xc0	/**< IIR FIFO disable/enabled mask */
#define UART_IIR_INT_MASK	0xf	/**< IIR interrupt ID source */
#define UART_IIR_MDM_CHG	0x0	/**< Modem status changed */
#define UART_IIR_NOINT		0x1	/**< No interrupt pending */
#define UART_IIR_THRE		0x2	/**< THR empty */
#define UART_IIR_RCVD_DATA	0x4	/**< Received data available */
#define UART_IIR_RCVR_STATUS 	0x6	/**< Receiver status */
#define UART_IIR_CHAR_TIME 	0xc	/**< Character time */

/* Interrupt Enable Register (IER) bits */
#define UART_IER_PTIME	128	/**< Programmable THRE Interrupt Mode Enable */
#define UART_IER_EDSSI	8	/**< enable modem status interrupt */
#define UART_IER_ELSI	4	/**< enable receiver line status interrupt */
#define UART_IER_ETBEI  2	/**< enable transmitter holding register empty interrupt */
#define UART_IER_ERBFI	1	/**< enable data available interrupt */

/* pmustatus */
#define PST_SLOW_WR_PENDING 0x0400
#define PST_EXTLPOAVAIL	0x0100
#define PST_WDRESET	0x0080
#define	PST_INTPEND	0x0040
#define	PST_SBCLKST	0x0030
#define	PST_SBCLKST_ILP	0x0010
#define	PST_SBCLKST_ALP	0x0020
#define	PST_SBCLKST_HT	0x0030
#define	PST_ALPAVAIL	0x0008
#define	PST_HTAVAIL	0x0004
#define	PST_RESINIT	0x0003
#define	PST_ILPFASTLPO	0x00010000

/* pmucapabilities */
#define PCAP_REV_MASK	0x000000ff
#define PCAP_RC_MASK	0x00001f00
#define PCAP_RC_SHIFT	8
#define PCAP_TC_MASK	0x0001e000
#define PCAP_TC_SHIFT	13
#define PCAP_PC_MASK	0x001e0000
#define PCAP_PC_SHIFT	17
#define PCAP_VC_MASK	0x01e00000
#define PCAP_VC_SHIFT	21
#define PCAP_CC_MASK	0x1e000000
#define PCAP_CC_SHIFT	25
#define PCAP5_PC_MASK	0x003e0000	/**< PMU corerev >= 5 */
#define PCAP5_PC_SHIFT	17
#define PCAP5_VC_MASK	0x07c00000
#define PCAP5_VC_SHIFT	22
#define PCAP5_CC_MASK	0xf8000000
#define PCAP5_CC_SHIFT	27

/* pmucapabilities ext */
#define PCAP_EXT_ST_NUM_SHIFT			(8)		/* stat timer number */
#define PCAP_EXT_ST_NUM_MASK			(0xf << PCAP_EXT_ST_NUM_SHIFT)
#define PCAP_EXT_ST_SRC_NUM_SHIFT		(12)	/* stat timer source number */
#define PCAP_EXT_ST_SRC_NUM_MASK		(0xf << PCAP_EXT_ST_SRC_NUM_SHIFT)

/* pmustattimer ctrl */
#define PMU_ST_SRC_SHIFT		(0)		/* stat timer source number */
#define PMU_ST_SRC_MASK			(0xff << PMU_ST_SRC_SHIFT)
#define PMU_ST_CNT_MODE_SHIFT	(10)	/* stat timer count mode */
#define PMU_ST_CNT_MODE_MASK	(0x3 << PMU_ST_CNT_MODE_SHIFT)
#define PMU_ST_EN_SHIFT		(8)		/* stat timer enable */
#define PMU_ST_EN_MASK		(0x1 << PMU_ST_EN_SHIFT)
#define PMU_ST_ENAB			1
#define PMU_ST_DISAB		0
#define PMU_ST_INT_EN_SHIFT	(9)		/* stat timer enable */
#define PMU_ST_INT_EN_MASK		(0x1 << PMU_ST_INT_EN_SHIFT)
#define PMU_ST_INT_ENAB		1
#define PMU_ST_INT_DISAB	0

/* CoreCapabilitiesExtension */
#define PCAP_EXT_USE_MUXED_ILP_CLK_MASK	0x04000000

/* PMU Resource Request Timer registers */
/* This is based on PmuRev0 */
#define	PRRT_TIME_MASK	0x03ff
#define	PRRT_INTEN	0x0400
/* ReqActive	25
 * The hardware sets this field to 1 when the timer expires.
 * Software writes this field to 1 to make immediate resource requests.
 */
#define	PRRT_REQ_ACTIVE	0x0800	/* To check h/w status */
#define	PRRT_IMMEDIATE_RES_REQ	0x0800	/* macro for sw immediate res req */
#define	PRRT_ALP_REQ	0x1000
#define	PRRT_HT_REQ	0x2000
#define PRRT_HQ_REQ 0x4000

/* PMU Int Control register bits */
#define PMU_INTC_ALP_REQ	0x1
#define PMU_INTC_HT_REQ		0x2
#define PMU_INTC_HQ_REQ		0x4

/* bit 0 of the PMU interrupt vector is asserted if this mask is enabled */
#define RSRC_INTR_MASK_TIMER_INT_0 1
#define PMU_INTR_MASK_EXTWAKE_REQ_ACTIVE_0 (1 << 20)

/* bit 16 of the PMU interrupt vector - Stats Timer Interrupt */
#define PMU_INT_STAT_TIMER_INT_SHIFT 16
#define PMU_INT_STAT_TIMER_INT_MASK (1 <<  PMU_INT_STAT_TIMER_INT_SHIFT)

/* PMU resource bit position */
#define PMURES_BIT(bit)	(1 << (bit))

/* PMU resource number limit */
#define PMURES_MAX_RESNUM	30

/* PMU chip control0 register */
#define	PMU_CHIPCTL0		0

#define PMU_CC0_4369_XTALCORESIZE_BIAS_ADJ_START_VAL	(0x20 << 0)
#define PMU_CC0_4369_XTALCORESIZE_BIAS_ADJ_START_MASK	(0x3F << 0)
#define PMU_CC0_4369_XTALCORESIZE_BIAS_ADJ_NORMAL_VAL	(0xF << 6)
#define PMU_CC0_4369_XTALCORESIZE_BIAS_ADJ_NORMAL_MASK	(0x3F << 6)
#define PMU_CC0_4369_XTAL_RES_BYPASS_START_VAL			(0 << 12)
#define PMU_CC0_4369_XTAL_RES_BYPASS_START_MASK			(0x7 << 12)
#define PMU_CC0_4369_XTAL_RES_BYPASS_NORMAL_VAL			(0x1 << 15)
#define PMU_CC0_4369_XTAL_RES_BYPASS_NORMAL_MASK		(0x7 << 15)

/* clock req types */
#define PMU_CC1_CLKREQ_TYPE_SHIFT	19
#define PMU_CC1_CLKREQ_TYPE_MASK	(1 << PMU_CC1_CLKREQ_TYPE_SHIFT)

#define CLKREQ_TYPE_CONFIG_OPENDRAIN		0
#define CLKREQ_TYPE_CONFIG_PUSHPULL		1

/* Power Control */
#define PWRCTL_ENAB_MEM_CLK_GATE_SHIFT		5
#define PWRCTL_AUTO_MEM_STBYRET			28

/* PMU chip control1 register */
#define	PMU_CHIPCTL1			1
#define	PMU_CC1_RXC_DLL_BYPASS		0x00010000
#define PMU_CC1_ENABLE_BBPLL_PWR_DOWN	0x00000010

#define PMU_CC1_IF_TYPE_MASK   		0x00000030
#define PMU_CC1_IF_TYPE_RMII    	0x00000000
#define PMU_CC1_IF_TYPE_MII     	0x00000010
#define PMU_CC1_IF_TYPE_RGMII   	0x00000020

#define PMU_CC1_SW_TYPE_MASK    	0x000000c0
#define PMU_CC1_SW_TYPE_EPHY    	0x00000000
#define PMU_CC1_SW_TYPE_EPHYMII 	0x00000040
#define PMU_CC1_SW_TYPE_EPHYRMII	0x00000080
#define PMU_CC1_SW_TYPE_RGMII   	0x000000c0

#define PMU_CC1_ENABLE_CLOSED_LOOP_MASK 0x00000080
#define PMU_CC1_ENABLE_CLOSED_LOOP      0x00000000

#define PMU_CC1_PWRSW_CLKSTRSTP_DELAY_MASK	0x00003F00u
#define PMU_CC1_PWRSW_CLKSTRSTP_DELAY		0x00000400u

/* PMU chip control2 register */
#define PMU_CC2_RFLDO3P3_PU_FORCE_ON		(1 << 15)
#define PMU_CC2_RFLDO3P3_PU_CLEAR		0x00000000

#define PMU_CC2_WL2CDIG_I_PMU_SLEEP		(1 << 16)
#define	PMU_CHIPCTL2		2
#define PMU_CC2_FORCE_SUBCORE_PWR_SWITCH_ON	(1 << 18)
#define PMU_CC2_FORCE_PHY_PWR_SWITCH_ON		(1 << 19)
#define PMU_CC2_FORCE_VDDM_PWR_SWITCH_ON	(1 << 20)
#define PMU_CC2_FORCE_MEMLPLDO_PWR_SWITCH_ON	(1 << 21)
#define PMU_CC2_MASK_WL_DEV_WAKE             (1 << 22)
#define PMU_CC2_INV_GPIO_POLARITY_PMU_WAKE   (1 << 25)
#define PMU_CC2_GCI2_WAKE                    (1 << 31)

#define PMU_CC2_4369_XTALCORESIZE_BIAS_ADJ_START_VAL	(0x3 << 26)
#define PMU_CC2_4369_XTALCORESIZE_BIAS_ADJ_START_MASK	(0x3 << 26)
#define PMU_CC2_4369_XTALCORESIZE_BIAS_ADJ_NORMAL_VAL	(0x0 << 28)
#define PMU_CC2_4369_XTALCORESIZE_BIAS_ADJ_NORMAL_MASK	(0x3 << 28)

/* PMU chip control3 register */
#define	PMU_CHIPCTL3		3
#define PMU_CC3_ENABLE_SDIO_WAKEUP_SHIFT  19
#define PMU_CC3_ENABLE_RF_SHIFT           22
#define PMU_CC3_RF_DISABLE_IVALUE_SHIFT   23

#define PMU_CC3_4369_XTALCORESIZE_PMOS_START_VAL	(0x3F << 0)
#define PMU_CC3_4369_XTALCORESIZE_PMOS_START_MASK	(0x3F << 0)
#define PMU_CC3_4369_XTALCORESIZE_PMOS_NORMAL_VAL	(0x3F << 15)
#define PMU_CC3_4369_XTALCORESIZE_PMOS_NORMAL_MASK	(0x3F << 15)
#define PMU_CC3_4369_XTALCORESIZE_NMOS_START_VAL	(0x3F << 6)
#define PMU_CC3_4369_XTALCORESIZE_NMOS_START_MASK	(0x3F << 6)
#define PMU_CC3_4369_XTALCORESIZE_NMOS_NORMAL_VAL	(0x3F << 21)
#define PMU_CC3_4369_XTALCORESIZE_NMOS_NORMAL_MASK	(0x3F << 21)
#define PMU_CC3_4369_XTALSEL_BIAS_RES_START_VAL		(0x2 << 12)
#define PMU_CC3_4369_XTALSEL_BIAS_RES_START_MASK	(0x7 << 12)
#define PMU_CC3_4369_XTALSEL_BIAS_RES_NORMAL_VAL	(0x6 << 27)
#define PMU_CC3_4369_XTALSEL_BIAS_RES_NORMAL_MASK	(0x7 << 27)

/* PMU chip control4 register */
#define PMU_CHIPCTL4                    4

/* 53537 series moved switch_type and gmac_if_type to CC4 [15:14] and [13:12] */
#define PMU_CC4_IF_TYPE_MASK		0x00003000
#define PMU_CC4_IF_TYPE_RMII		0x00000000
#define PMU_CC4_IF_TYPE_MII		0x00001000
#define PMU_CC4_IF_TYPE_RGMII		0x00002000

#define PMU_CC4_SW_TYPE_MASK		0x0000c000
#define PMU_CC4_SW_TYPE_EPHY		0x00000000
#define PMU_CC4_SW_TYPE_EPHYMII		0x00004000
#define PMU_CC4_SW_TYPE_EPHYRMII	0x00008000
#define PMU_CC4_SW_TYPE_RGMII		0x0000c000
#define PMU_CC4_DISABLE_LQ_AVAIL	(1<<27)

#define PMU_CC4_4369_MAIN_PD_CBUCK2VDDB_ON	(1u << 15u)
#define PMU_CC4_4369_MAIN_PD_CBUCK2VDDRET_ON	(1u << 16u)
#define PMU_CC4_4369_MAIN_PD_MEMLPLDO2VDDB_ON	(1u << 17u)
#define PMU_CC4_4369_MAIN_PD_MEMLPDLO2VDDRET_ON	(1u << 18u)

#define PMU_CC4_4369_AUX_PD_CBUCK2VDDB_ON	(1u << 21u)
#define PMU_CC4_4369_AUX_PD_CBUCK2VDDRET_ON	(1u << 22u)
#define PMU_CC4_4369_AUX_PD_MEMLPLDO2VDDB_ON	(1u << 23u)
#define PMU_CC4_4369_AUX_PD_MEMLPLDO2VDDRET_ON	(1u << 24u)

/* PMU chip control5 register */
#define PMU_CHIPCTL5                    5

#define PMU_CC5_4369_SUBCORE_CBUCK2VDDB_ON	(1u << 9u)
#define PMU_CC5_4369_SUBCORE_CBUCK2VDDRET_ON	(1u << 10u)
#define PMU_CC5_4369_SUBCORE_MEMLPLDO2VDDB_ON	(1u << 11u)
#define PMU_CC5_4369_SUBCORE_MEMLPLDO2VDDRET_ON	(1u << 12u)

/* PMU chip control6 register */
#define PMU_CHIPCTL6                    6
#define PMU_CC6_ENABLE_CLKREQ_WAKEUP    (1 << 4)
#define PMU_CC6_ENABLE_PMU_WAKEUP_ALP   (1 << 6)
#define PMU_CC6_ENABLE_PCIE_RETENTION	(1 << 12)
#define PMU_CC6_ENABLE_PMU_EXT_PERST	(1 << 13)
#define PMU_CC6_ENABLE_PMU_WAKEUP_PERST	(1 << 14)

/* PMU chip control7 register */
#define PMU_CHIPCTL7				7
#define PMU_CC7_ENABLE_L2REFCLKPAD_PWRDWN	(1 << 25)
#define PMU_CC7_ENABLE_MDIO_RESET_WAR		(1 << 27)
/* 53537 series have gmca1 gmac_if_type in cc7 [7:6](defalut 0b01) */
#define PMU_CC7_IF_TYPE_MASK		0x000000c0
#define PMU_CC7_IF_TYPE_RMII		0x00000000
#define PMU_CC7_IF_TYPE_MII		0x00000040
#define PMU_CC7_IF_TYPE_RGMII		0x00000080

#define PMU_CHIPCTL8			8
#define PMU_CHIPCTL9			9

#define PMU_CHIPCTL10			10
#define PMU_CC10_PCIE_PWRSW_RESET0_CNT_SHIFT		0
#define PMU_CC10_PCIE_PWRSW_RESET0_CNT_MASK		0x000000ff
#define PMU_CC10_PCIE_PWRSW_RESET1_CNT_SHIFT		8
#define PMU_CC10_PCIE_PWRSW_RESET1_CNT_MASK		0x0000ff00
#define PMU_CC10_PCIE_PWRSW_UP_DLY_SHIFT		16
#define PMU_CC10_PCIE_PWRSW_UP_DLY_MASK		0x000f0000
#define PMU_CC10_PCIE_PWRSW_FORCE_PWROK_DLY_SHIFT	20
#define PMU_CC10_PCIE_PWRSW_FORCE_PWROK_DLY_MASK	0x00f00000
#define PMU_CC10_FORCE_PCIE_ON		(1 << 24)
#define PMU_CC10_FORCE_PCIE_SW_ON	(1 << 25)
#define PMU_CC10_FORCE_PCIE_RETNT_ON	(1 << 26)

#define PMU_CC10_PCIE_PWRSW_RESET_CNT_4US		1
#define PMU_CC10_PCIE_PWRSW_RESET_CNT_8US		2

#define PMU_CC10_PCIE_PWRSW_UP_DLY_0US			0

#define PMU_CC10_PCIE_PWRSW_FORCE_PWROK_DLY_4US	1

#define PMU_CHIPCTL11			11
#define PMU_CHIPCTL12			12

/* PMU chip control13 register */
#define PMU_CHIPCTL13			13

#define PMU_CC13_SUBCORE_CBUCK2VDDB_OFF		(1u << 0u)
#define PMU_CC13_SUBCORE_CBUCK2VDDRET_OFF	(1u << 1u)
#define PMU_CC13_SUBCORE_MEMLPLDO2VDDB_OFF	(1u << 2u)
#define PMU_CC13_SUBCORE_MEMLPLDO2VDDRET_OFF	(1u << 3u)

#define PMU_CC13_MAIN_CBUCK2VDDB_OFF		(1u << 4u)
#define PMU_CC13_MAIN_CBUCK2VDDRET_OFF		(1u << 5u)
#define PMU_CC13_MAIN_MEMLPLDO2VDDB_OFF		(1u << 6u)
#define PMU_CC13_MAIN_MEMLPLDO2VDDRET_OFF	(1u << 7u)

#define PMU_CC13_AUX_CBUCK2VDDB_OFF		(1u << 8u)
#define PMU_CC13_AUX_MEMLPLDO2VDDB_OFF		(1u << 10u)
#define PMU_CC13_AUX_MEMLPLDO2VDDRET_OFF	(1u << 11u)
#define PMU_CC13_AUX_CBUCK2VDDRET_OFF		(1u << 12u)

#define PMU_CHIPCTL14			14
#define PMU_CHIPCTL15			15
#define PMU_CHIPCTL16			16
#define PMU_CC16_CLK4M_DIS		(1 << 4)
#define PMU_CC16_FF_ZERO_ADJ		(4 << 5)

/* PMU chip control14 register */
#define PMU_CC14_MAIN_VDDB2VDDRET_UP_DLY_MASK		(0xF)
#define PMU_CC14_MAIN_VDDB2VDD_UP_DLY_MASK		(0xF << 4)
#define PMU_CC14_AUX_VDDB2VDDRET_UP_DLY_MASK		(0xF << 8)
#define PMU_CC14_AUX_VDDB2VDD_UP_DLY_MASK		(0xF << 12)
#define PMU_CC14_PCIE_VDDB2VDDRET_UP_DLY_MASK		(0xF << 16)
#define PMU_CC14_PCIE_VDDB2VDD_UP_DLY_MASK		(0xF << 20)

/* PMU corerev and chip specific PLL controls.
 * PMU<rev>_PLL<num>_XX where <rev> is PMU corerev and <num> is an arbitrary number
 * to differentiate different PLLs controlled by the same PMU rev.
 */
/* pllcontrol registers */
/* PDIV, div_phy, div_arm, div_adc, dith_sel, ioff, kpd_scale, lsb_sel, mash_sel, lf_c & lf_r */
#define	PMU0_PLL0_PLLCTL0		0
#define	PMU0_PLL0_PC0_PDIV_MASK		1
#define	PMU0_PLL0_PC0_PDIV_FREQ		25000
#define PMU0_PLL0_PC0_DIV_ARM_MASK	0x00000038
#define PMU0_PLL0_PC0_DIV_ARM_SHIFT	3
#define PMU0_PLL0_PC0_DIV_ARM_BASE	8

/* PC0_DIV_ARM for PLLOUT_ARM */
#define PMU0_PLL0_PC0_DIV_ARM_110MHZ	0
#define PMU0_PLL0_PC0_DIV_ARM_97_7MHZ	1
#define PMU0_PLL0_PC0_DIV_ARM_88MHZ	2
#define PMU0_PLL0_PC0_DIV_ARM_80MHZ	3 /* Default */
#define PMU0_PLL0_PC0_DIV_ARM_73_3MHZ	4
#define PMU0_PLL0_PC0_DIV_ARM_67_7MHZ	5
#define PMU0_PLL0_PC0_DIV_ARM_62_9MHZ	6
#define PMU0_PLL0_PC0_DIV_ARM_58_6MHZ	7

/* Wildcard base, stop_mod, en_lf_tp, en_cal & lf_r2 */
#define	PMU0_PLL0_PLLCTL1		1
#define	PMU0_PLL0_PC1_WILD_INT_MASK	0xf0000000
#define	PMU0_PLL0_PC1_WILD_INT_SHIFT	28
#define	PMU0_PLL0_PC1_WILD_FRAC_MASK	0x0fffff00
#define	PMU0_PLL0_PC1_WILD_FRAC_SHIFT	8
#define	PMU0_PLL0_PC1_STOP_MOD		0x00000040

/* Wildcard base, vco_calvar, vco_swc, vco_var_selref, vso_ical & vco_sel_avdd */
#define	PMU0_PLL0_PLLCTL2		2
#define	PMU0_PLL0_PC2_WILD_INT_MASK	0xf
#define	PMU0_PLL0_PC2_WILD_INT_SHIFT	4

/* pllcontrol registers */
/* ndiv_pwrdn, pwrdn_ch<x>, refcomp_pwrdn, dly_ch<x>, p1div, p2div, _bypass_sdmod */
#define PMU1_PLL0_PLLCTL0		0
#define PMU1_PLL0_PC0_P1DIV_MASK	0x00f00000
#define PMU1_PLL0_PC0_P1DIV_SHIFT	20
#define PMU1_PLL0_PC0_P2DIV_MASK	0x0f000000
#define PMU1_PLL0_PC0_P2DIV_SHIFT	24

/* m<x>div */
#define PMU1_PLL0_PLLCTL1		1
#define PMU1_PLL0_PC1_M1DIV_MASK	0x000000ff
#define PMU1_PLL0_PC1_M1DIV_SHIFT	0
#define PMU1_PLL0_PC1_M2DIV_MASK	0x0000ff00
#define PMU1_PLL0_PC1_M2DIV_SHIFT	8
#define PMU1_PLL0_PC1_M3DIV_MASK	0x00ff0000
#define PMU1_PLL0_PC1_M3DIV_SHIFT	16
#define PMU1_PLL0_PC1_M4DIV_MASK	0xff000000
#define PMU1_PLL0_PC1_M4DIV_SHIFT	24
#define PMU1_PLL0_PC1_M4DIV_BY_9	9
#define PMU1_PLL0_PC1_M4DIV_BY_18	0x12
#define PMU1_PLL0_PC1_M4DIV_BY_36	0x24
#define PMU1_PLL0_PC1_M4DIV_BY_60	0x3C
#define PMU1_PLL0_PC1_M2_M4DIV_MASK     0xff00ff00
#define PMU1_PLL0_PC1_HOLD_LOAD_CH      0x28
#define DOT11MAC_880MHZ_CLK_DIVISOR_SHIFT 8
#define DOT11MAC_880MHZ_CLK_DIVISOR_MASK (0xFF << DOT11MAC_880MHZ_CLK_DIVISOR_SHIFT)
#define DOT11MAC_880MHZ_CLK_DIVISOR_VAL  (0xE << DOT11MAC_880MHZ_CLK_DIVISOR_SHIFT)

/* m<x>div, ndiv_dither_mfb, ndiv_mode, ndiv_int */
#define PMU1_PLL0_PLLCTL2		2
#define PMU1_PLL0_PC2_M5DIV_MASK	0x000000ff
#define PMU1_PLL0_PC2_M5DIV_SHIFT	0
#define PMU1_PLL0_PC2_M5DIV_BY_12	0xc
#define PMU1_PLL0_PC2_M5DIV_BY_18	0x12
#define PMU1_PLL0_PC2_M5DIV_BY_31	0x1f
#define PMU1_PLL0_PC2_M5DIV_BY_36	0x24
#define PMU1_PLL0_PC2_M5DIV_BY_42	0x2a
#define PMU1_PLL0_PC2_M5DIV_BY_60	0x3c
#define PMU1_PLL0_PC2_M6DIV_MASK	0x0000ff00
#define PMU1_PLL0_PC2_M6DIV_SHIFT	8
#define PMU1_PLL0_PC2_M6DIV_BY_18	0x12
#define PMU1_PLL0_PC2_M6DIV_BY_36	0x24
#define PMU1_PLL0_PC2_NDIV_MODE_MASK	0x000e0000
#define PMU1_PLL0_PC2_NDIV_MODE_SHIFT	17
#define PMU1_PLL0_PC2_NDIV_MODE_MASH	1
#define PMU1_PLL0_PC2_NDIV_MODE_MFB	2	/**< recommended for 4319 */
#define PMU1_PLL0_PC2_NDIV_INT_MASK	0x1ff00000
#define PMU1_PLL0_PC2_NDIV_INT_SHIFT	20

/* ndiv_frac */
#define PMU1_PLL0_PLLCTL3		3
#define PMU1_PLL0_PC3_NDIV_FRAC_MASK	0x00ffffff
#define PMU1_PLL0_PC3_NDIV_FRAC_SHIFT	0

/* pll_ctrl */
#define PMU1_PLL0_PLLCTL4		4

/* pll_ctrl, vco_rng, clkdrive_ch<x> */
#define PMU1_PLL0_PLLCTL5		5
#define PMU1_PLL0_PC5_CLK_DRV_MASK 	0xffffff00
#define PMU1_PLL0_PC5_CLK_DRV_SHIFT 	8
#define PMU1_PLL0_PC5_ASSERT_CH_MASK 	0x3f000000
#define PMU1_PLL0_PC5_ASSERT_CH_SHIFT 	24
#define PMU1_PLL0_PC5_DEASSERT_CH_MASK 	0xff000000

#define PMU1_PLL0_PLLCTL6		6
#define PMU1_PLL0_PLLCTL7		7
#define PMU1_PLL0_PLLCTL8		8

#define PMU1_PLLCTL8_OPENLOOP_MASK	(1 << 1)
#define PMU_PLL4350_OPENLOOP_MASK	(1 << 7)

#define PMU1_PLL0_PLLCTL9		9

#define PMU1_PLL0_PLLCTL10		10

/* PMU rev 2 control words */
#define PMU2_PHY_PLL_PLLCTL		4
#define PMU2_SI_PLL_PLLCTL		10

/* PMU rev 2 */
/* pllcontrol registers */
/* ndiv_pwrdn, pwrdn_ch<x>, refcomp_pwrdn, dly_ch<x>, p1div, p2div, _bypass_sdmod */
#define PMU2_PLL_PLLCTL0		0
#define PMU2_PLL_PC0_P1DIV_MASK 	0x00f00000
#define PMU2_PLL_PC0_P1DIV_SHIFT	20
#define PMU2_PLL_PC0_P2DIV_MASK 	0x0f000000
#define PMU2_PLL_PC0_P2DIV_SHIFT	24

/* m<x>div */
#define PMU2_PLL_PLLCTL1		1
#define PMU2_PLL_PC1_M1DIV_MASK 	0x000000ff
#define PMU2_PLL_PC1_M1DIV_SHIFT	0
#define PMU2_PLL_PC1_M2DIV_MASK 	0x0000ff00
#define PMU2_PLL_PC1_M2DIV_SHIFT	8
#define PMU2_PLL_PC1_M3DIV_MASK 	0x00ff0000
#define PMU2_PLL_PC1_M3DIV_SHIFT	16
#define PMU2_PLL_PC1_M4DIV_MASK 	0xff000000
#define PMU2_PLL_PC1_M4DIV_SHIFT	24

/* m<x>div, ndiv_dither_mfb, ndiv_mode, ndiv_int */
#define PMU2_PLL_PLLCTL2		2
#define PMU2_PLL_PC2_M5DIV_MASK 	0x000000ff
#define PMU2_PLL_PC2_M5DIV_SHIFT	0
#define PMU2_PLL_PC2_M6DIV_MASK 	0x0000ff00
#define PMU2_PLL_PC2_M6DIV_SHIFT	8
#define PMU2_PLL_PC2_NDIV_MODE_MASK	0x000e0000
#define PMU2_PLL_PC2_NDIV_MODE_SHIFT	17
#define PMU2_PLL_PC2_NDIV_INT_MASK	0x1ff00000
#define PMU2_PLL_PC2_NDIV_INT_SHIFT	20

/* ndiv_frac */
#define PMU2_PLL_PLLCTL3		3
#define PMU2_PLL_PC3_NDIV_FRAC_MASK	0x00ffffff
#define PMU2_PLL_PC3_NDIV_FRAC_SHIFT	0

/* pll_ctrl */
#define PMU2_PLL_PLLCTL4		4

/* pll_ctrl, vco_rng, clkdrive_ch<x> */
#define PMU2_PLL_PLLCTL5		5
#define PMU2_PLL_PC5_CLKDRIVE_CH1_MASK	0x00000f00
#define PMU2_PLL_PC5_CLKDRIVE_CH1_SHIFT	8
#define PMU2_PLL_PC5_CLKDRIVE_CH2_MASK	0x0000f000
#define PMU2_PLL_PC5_CLKDRIVE_CH2_SHIFT	12
#define PMU2_PLL_PC5_CLKDRIVE_CH3_MASK	0x000f0000
#define PMU2_PLL_PC5_CLKDRIVE_CH3_SHIFT	16
#define PMU2_PLL_PC5_CLKDRIVE_CH4_MASK	0x00f00000
#define PMU2_PLL_PC5_CLKDRIVE_CH4_SHIFT	20
#define PMU2_PLL_PC5_CLKDRIVE_CH5_MASK	0x0f000000
#define PMU2_PLL_PC5_CLKDRIVE_CH5_SHIFT	24
#define PMU2_PLL_PC5_CLKDRIVE_CH6_MASK	0xf0000000
#define PMU2_PLL_PC5_CLKDRIVE_CH6_SHIFT	28

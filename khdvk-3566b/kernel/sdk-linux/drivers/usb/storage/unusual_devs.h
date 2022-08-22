/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Driver for USB Mass Storage compliant devices
 * Unusual Devices File
 *
 * Current development and maintenance by:
 *   (c) 2000-2002 Matthew Dharm (mdharm-usb@one-eyed-alien.net)
 *
 * Initial work by:
 *   (c) 2000 Adam J. Richter (adam@yggdrasil.com), Yggdrasil Computing, Inc.
 */

/*
 * IMPORTANT NOTE: This file must be included in another file which does
 * the following thing for it to work:
 * The UNUSUAL_DEV, COMPLIANT_DEV, and USUAL_DEV macros must be defined
 * before this file is included.
 */

/*
 * If you edit this file, please try to keep it sorted first by VendorID,
 * then by ProductID.
 *
 * If you want to add an entry for this file, be sure to include the
 * following information:
 *	- a patch that adds the entry for your device, including your
 *	  email address right above the entry (plus maybe a brief
 *	  explanation of the reason for the entry),
 *	- a copy of /sys/kernel/debug/usb/devices with your device plugged in
 *	  running with this patch.
 * Send your submission to the USB development list <linux-usb@vger.kernel.org>
 */

/*
 * Note: If you add an entry only in order to set the CAPACITY_OK flag,
 * use the COMPLIANT_DEV macro instead of UNUSUAL_DEV.  This is
 * because such entries mark devices which actually work correctly,
 * as opposed to devices that do something strangely or wrongly.
 */

/*
 * In-kernel mode switching is deprecated.  Do not add new devices to
 * this list for the sole purpose of switching them to a different
 * mode.  Existing userspace solutions are superior.
 *
 * New mode switching devices should instead be added to the database
 * maintained at https://www.draisberghof.de/usb_modeswitch/
 */

#if !defined(CONFIG_USB_STORAGE_SDDR09) && \
		!defined(CONFIG_USB_STORAGE_SDDR09_MODULE)
#define NO_SDDR09
#endif

/* patch submitted by Vivian Bregier <Vivian.Bregier@imag.fr> */
UNUSUAL_DEV(  0x03eb, 0x2002, 0x0100, 0x0100,
		"ATMEL",
		"SND1 Storage",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE),

/* Reported by Rodolfo Quesada <rquesada@roqz.net> */
UNUSUAL_DEV(  0x03ee, 0x6906, 0x0003, 0x0003,
		"VIA Technologies Inc.",
		"Mitsumi multi cardreader",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE ),

UNUSUAL_DEV(  0x03f0, 0x0107, 0x0200, 0x0200,
		"HP",
		"CD-Writer+",
		USB_SC_8070, USB_PR_CB, NULL, 0),

/* Reported by Ben Efros <ben@pc-doctor.com> */
UNUSUAL_DEV(  0x03f0, 0x070c, 0x0000, 0x0000,
		"HP",
		"Personal Media Drive",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_SANE_SENSE ),

/*
 * Reported by Grant Grundler <grundler@parisc-linux.org>
 * HP r707 camera in "Disk" mode with 2.00.23 or 2.00.24 firmware.
 */
UNUSUAL_DEV(  0x03f0, 0x4002, 0x0001, 0x0001,
		"HP",
		"PhotoSmart R707",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL, US_FL_FIX_CAPACITY),

UNUSUAL_DEV(  0x03f3, 0x0001, 0x0000, 0x9999,
		"Adaptec",
		"USBConnect 2000",
		USB_SC_DEVICE, USB_PR_DEVICE, usb_stor_euscsi_init,
		US_FL_SCM_MULT_TARG ),

/*
 * Reported by Sebastian Kapfer <sebastian_kapfer@gmx.net>
 * and Olaf Hering <olh@suse.de> (different bcd's, same vendor/product)
 * for USB floppies that need the SINGLE_LUN enforcement.
 */
UNUSUAL_DEV(  0x0409, 0x0040, 0x0000, 0x9999,
		"NEC",
		"NEC USB UF000x",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_SINGLE_LUN ),

/* Patch submitted by Mihnea-Costin Grigore <mihnea@zulu.ro> */
UNUSUAL_DEV(  0x040d, 0x6205, 0x0003, 0x0003,
		"VIA Technologies Inc.",
		"USB 2.0 Card Reader",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE ),

/*
 * Deduced by Jonathan Woithe <jwoithe@just42.net>
 * Entry needed for flags: US_FL_FIX_INQUIRY because initial inquiry message
 * always fails and confuses drive.
 */
UNUSUAL_DEV(  0x0411, 0x001c, 0x0113, 0x0113,
		"Buffalo",
		"DUB-P40G HDD",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_FIX_INQUIRY ),

/* Submitted by Ernestas Vaiciukevicius <ernisv@gmail.com> */
UNUSUAL_DEV(  0x0419, 0x0100, 0x0100, 0x0100,
		"Samsung Info. Systems America, Inc.",
		"MP3 Player",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE ),

/* Reported by Orgad Shaneh <orgads@gmail.com> */
UNUSUAL_DEV(  0x0419, 0xaace, 0x0100, 0x0100,
		"Samsung", "MP3 Player",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE ),

/* Reported by Christian Leber <christian@leber.de> */
UNUSUAL_DEV(  0x0419, 0xaaf5, 0x0100, 0x0100,
		"TrekStor",
		"i.Beat 115 2.0",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE | US_FL_NOT_LOCKABLE ),

/* Reported by Stefan Werner <dustbln@gmx.de> */
UNUSUAL_DEV(  0x0419, 0xaaf6, 0x0100, 0x0100,
		"TrekStor",
		"i.Beat Joy 2.0",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE ),

/* Reported by Pete Zaitcev <zaitcev@redhat.com>, bz#176584 */
UNUSUAL_DEV(  0x0420, 0x0001, 0x0100, 0x0100,
		"GENERIC", "MP3 PLAYER", /* MyMusix PD-205 on the outside. */
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE ),

/*
 * Reported by Andrew Nayenko <relan@bk.ru>
 * Updated for new firmware by Phillip Potter <phil@philpotter.co.uk>
 */
UNUSUAL_DEV(  0x0421, 0x0019, 0x0592, 0x0610,
		"Nokia",
		"Nokia 6288",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64 ),

/* Reported by Mario Rettig <mariorettig@web.de> */
UNUSUAL_DEV(  0x0421, 0x042e, 0x0100, 0x0100,
		"Nokia",
		"Nokia 3250",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE | US_FL_FIX_CAPACITY ),

/* Reported by <honkkis@gmail.com> */
UNUSUAL_DEV(  0x0421, 0x0433, 0x0100, 0x0100,
		"Nokia",
		"E70",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE | US_FL_FIX_CAPACITY ),

/* Reported by Jon Hart <Jon.Hart@web.de> */
UNUSUAL_DEV(  0x0421, 0x0434, 0x0100, 0x0100,
		"Nokia",
		"E60",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_FIX_CAPACITY | US_FL_IGNORE_RESIDUE ),

/*
 * Reported by Sumedha Swamy <sumedhaswamy@gmail.com> and
 * Einar Th. Einarsson <einarthered@gmail.com>
 */
UNUSUAL_DEV(  0x0421, 0x0444, 0x0100, 0x0100,
		"Nokia",
		"N91",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE | US_FL_FIX_CAPACITY ),

/*
 * Reported by Jiri Slaby <jirislaby@gmail.com> and
 * Rene C. Castberg <Rene@Castberg.org>
 */
UNUSUAL_DEV(  0x0421, 0x0446, 0x0100, 0x0100,
		"Nokia",
		"N80",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE | US_FL_FIX_CAPACITY ),

/* Reported by Matthew Bloch <matthew@bytemark.co.uk> */
UNUSUAL_DEV(  0x0421, 0x044e, 0x0100, 0x0100,
		"Nokia",
		"E61",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE | US_FL_FIX_CAPACITY ),

/* Reported by Bardur Arantsson <bardur@scientician.net> */
UNUSUAL_DEV(  0x0421, 0x047c, 0x0370, 0x0610,
		"Nokia",
		"6131",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64 ),

/* Reported by Manuel Osdoba <manuel.osdoba@tu-ilmenau.de> */
UNUSUAL_DEV( 0x0421, 0x0492, 0x0452, 0x9999,
		"Nokia",
		"Nokia 6233",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64 ),

/* Reported by Alex Corcoles <alex@corcoles.net> */
UNUSUAL_DEV(  0x0421, 0x0495, 0x0370, 0x0370,
		"Nokia",
		"6234",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64 ),

/* Reported by Daniele Forsi <dforsi@gmail.com> */
UNUSUAL_DEV(  0x0421, 0x04b9, 0x0350, 0x0350,
		"Nokia",
		"5300",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64 ),

/* Patch submitted by Victor A. Santos <victoraur.santos@gmail.com> */
UNUSUAL_DEV(  0x0421, 0x05af, 0x0742, 0x0742,
		"Nokia",
		"305",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64),

/* Patch submitted by Mikhail Zolotaryov <lebon@lebon.org.ua> */
UNUSUAL_DEV(  0x0421, 0x06aa, 0x1110, 0x1110,
		"Nokia",
		"502",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64 ),

#ifdef NO_SDDR09
UNUSUAL_DEV(  0x0436, 0x0005, 0x0100, 0x0100,
		"Microtech",
		"CameraMate",
		USB_SC_SCSI, USB_PR_CB, NULL,
		US_FL_SINGLE_LUN ),
#endif

/*
 * Patch submitted by Daniel Drake <dsd@gentoo.org>
 * Device reports nonsense bInterfaceProtocol 6 when connected over USB2
 */
UNUSUAL_DEV(  0x0451, 0x5416, 0x0100, 0x0100,
		"Neuros Audio",
		"USB 2.0 HD 2.5",
		USB_SC_DEVICE, USB_PR_BULK, NULL,
		US_FL_NEED_OVERRIDE ),

/*
 * Pete Zaitcev <zaitcev@yahoo.com>, from Patrick C. F. Ernzer, bz#162559.
 * The key does not actually break, but it returns zero sense which
 * makes our SCSI stack to print confusing messages.
 */
UNUSUAL_DEV(  0x0457, 0x0150, 0x0100, 0x0100,
		"USBest Technology",	/* sold by Transcend */
		"USB Mass Storage Device",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL, US_FL_NOT_LOCKABLE ),

/*
 * Bohdan Linda <bohdan.linda@gmail.com>
 * 1GB USB sticks MyFlash High Speed. I have restricted
 * the revision to my model only
 */
UNUSUAL_DEV(  0x0457, 0x0151, 0x0100, 0x0100,
		"USB 2.0",
		"Flash Disk",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NOT_LOCKABLE ),

/*
 * Reported by Tamas Kerecsen <kerecsen@bigfoot.com>
 * Obviously the PROM has not been customized by the VAR;
 * the Vendor and Product string descriptors are:
 *	Generic Mass Storage (PROTOTYPE--Remember to change idVendor)
 *	Generic Manufacturer (PROTOTYPE--Remember to change idVendor)
 */
UNUSUAL_DEV(  0x045e, 0xffff, 0x0000, 0x0000,
		"Mitac",
		"GPS",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_MAX_SECTORS_64 ),

/*
 * This virtual floppy is found in Sun equipment (x4600, x4200m2, etc.)
 * Reported by Pete Zaitcev <zaitcev@redhat.com>
 * This device chokes on both version of MODE SENSE which we have, so
 * use_10_for_ms is not effective, and we use US_FL_NO_WP_DETECT.
 */
UNUSUAL_DEV(  0x046b, 0xff40, 0x0100, 0x0100,
		"AMI",
		"Virtual Floppy",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_WP_DETECT),

/* Reported by Egbert Eich <eich@suse.com> */
UNUSUAL_DEV(  0x0480, 0xd010, 0x0100, 0x9999,
		"Toshiba",
		"External USB 3.0",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_ALWAYS_SYNC),

/* Patch submitted by Philipp Friedrich <philipp@void.at> */
UNUSUAL_DEV(  0x0482, 0x0100, 0x0100, 0x0100,
		"Kyocera",
		"Finecam S3x",
		USB_SC_8070, USB_PR_CB, NULL, US_FL_FIX_INQUIRY),

/* Patch submitted by Philipp Friedrich <philipp@void.at> */
UNUSUAL_DEV(  0x0482, 0x0101, 0x0100, 0x0100,
		"Kyocera",
		"Finecam S4",
		USB_SC_8070, USB_PR_CB, NULL, US_FL_FIX_INQUIRY),

/* Patch submitted by Stephane Galles <stephane.galles@free.fr> */
UNUSUAL_DEV(  0x0482, 0x0103, 0x0100, 0x0100,
		"Kyocera",
		"Finecam S5",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL, US_FL_FIX_INQUIRY),

/* Patch submitted by Jens Taprogge <jens.taprogge@taprogge.org> */
UNUSUAL_DEV(  0x0482, 0x0107, 0x0100, 0x0100,
		"Kyocera",
		"CONTAX SL300R T*",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_FIX_CAPACITY | US_FL_NOT_LOCKABLE),

/*
 * Reported by Paul Stewart <stewart@wetlogic.net>
 * This entry is needed because the device reports Sub=ff
 */
UNUSUAL_DEV(  0x04a4, 0x0004, 0x0001, 0x0001,
		"Hitachi",
		"DVD-CAM DZ-MV100A Camcorder",
		USB_SC_SCSI, USB_PR_CB, NULL, US_FL_SINGLE_LUN),

/*
 * BENQ DC5330
 * Reported by Manuel Fombuena <mfombuena@ya.com> and
 * Frank Copeland <fjc@thingy.apana.org.au>
 */
UNUSUAL_DEV(  0x04a5, 0x3010, 0x0100, 0x0100,
		"Tekom Technologies, Inc",
		"300_CAMERA",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_RESIDUE ),

/*
 * Patch for Nikon coolpix 2000
 * Submitted by Fabien Cosse <fabien.cosse@wanadoo.fr>
 */
UNUSUAL_DEV(  0x04b0, 0x0301, 0x0010, 0x0010,
		"NIKON",
		"NIKON DSC E2000",
		USB_SC_DEVICE, USB_PR_DEVICE,NULL,
		US_FL_NOT_LOCKABLE ),

/* Reported by Doug Maxey (dwm@austin.ibm.com) */
UNUSUAL_DEV(  0x04b3, 0x4001, 0x0110, 0x0110,
		"IBM",
		"IBM RSA2",
		USB_SC_DEVICE, USB_PR_CB, NULL,
		US_FL_MAX_SECTORS_MIN),

/*
 * Reported by Simon Levitt <simon@whattf.com>
 * This entry needs Sub and Proto fields
 */
UNUSUAL_DEV(  0x04b8, 0x0601, 0x0100, 0x0100,
		"Epson",
		"875DC Storage",
		USB_SC_SCSI, USB_PR_CB, NULL, US_FL_FIX_INQUIRY),


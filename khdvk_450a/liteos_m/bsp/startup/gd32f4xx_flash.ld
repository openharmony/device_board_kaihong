/*
*****************************************************************************
**
**  File        : gd32f4xx_flash.ld
**
**  Abstract    : Linker script for GD32F4xxZK Device with
**                3027KByte FLASH, 192KByte RAM
**
**                Set heap size, stack size and stack location according
**                to application requirements.
**
**                Set memory bank area and size if external memory is used.
**
**  Target      : GDicroelectronics GD32
**
**  Environment : Atollic TrueSTUDIO(R)
**
**  Distribution: The file is distributed �as is,?without any warranty
**                of any kind.
**
**  (c)Copyright Atollic AB.
**  You may use this file as-is or modify it according to the needs of your
**  project. Distribution of this file (unmodified or modified) is not
**  permitted. Atollic AB permit registered Atollic TrueSTUDIO(R) users the
**  rights to distribute the assembled, compiled & linked contents of this
**  file as part of an application binary file, provided that it is built
**  using the Atollic TrueSTUDIO(R) toolchain.
**
*****************************************************************************
*/

/* Entry Point */
ENTRY(Reset_Handler)

/* Highest address of the user mode stack */
_estack = 0x20030000;    /* end of 256K RAM */

/* Generate a link error if heap and stack don't fit into RAM */
_Min_Heap_Size = 0x200;      /* required amount of heap  */
_Min_Stack_Size = 0x400; /* required amount of stack */

/* Specify the memory areas */
/* FLASH (rx)      : ORIGIN = 0x8000000, LENGTH = 3072K */
/* FLASH (rx)      : ORIGIN = 0x8010000, LENGTH = 3008K 7680K*/
MEMORY
{
FLASH (rx)      : ORIGIN = 0x8010000, LENGTH = 3008K
RAM (xrw)      : ORIGIN = 0x20000000, LENGTH = 192K
CCMRAM (rw)      : ORIGIN = 0x10000000, LENGTH = 64K
SDRAM (rw)      : ORIGIN = 0xC0800000, LENGTH = 7168K
}

/* Define output sections */
SECTIONS
{
  /* The startup code goes first into FLASH */
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector)) /* Startup code */
    . = ALIGN(4);
  } >FLASH

  /* The program code and other data goes into FLASH */
  .text :
  {
    . = ALIGN(4);
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */

    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)
    . = ALIGN(4);
    __zinitcall_bsp_start = .;
	  KEEP (*(.zinitcall.bsp0.init))
	  KEEP (*(.zinitcall.bsp1.init))
	  KEEP (*(.zinitcall.bsp2.init))
	  KEEP (*(.zinitcall.bsp3.init))
	  KEEP (*(.zinitcall.bsp4.init))
	  __zinitcall_bsp_end = .;
	  __zinitcall_device_start = .;
	  KEEP (*(.zinitcall.device0.init))
	  KEEP (*(.zinitcall.device1.init))
	  KEEP (*(.zinitcall.device2.init))
	  KEEP (*(.zinitcall.device3.init))
	  KEEP (*(.zinitcall.device4.init))
	  __zinitcall_device_end = .;
	  __zinitcall_core_start = .;
	  KEEP (*(.zinitcall.core0.init))
	  KEEP (*(.zinitcall.core1.init))
	  KEEP (*(.zinitcall.core2.init))
	  KEEP (*(.zinitcall.core3.init))
	  KEEP (*(.zinitcall.core4.init))
	  __zinitcall_core_end = .;
	  __zinitcall_sys_service_start = .;
	  KEEP (*(.zinitcall.sys.service0.init))
	  KEEP (*(.zinitcall.sys.service1.init))
	  KEEP (*(.zinitcall.sys.service2.init))
	  KEEP (*(.zinitcall.sys.service3.init))
	  KEEP (*(.zinitcall.sys.service4.init))
	  __zinitcall_sys_service_end = .;
	  __zinitcall_sys_feature_start = .;
	  KEEP (*(.zinitcall.sys.feature0.init))
	  KEEP (*(.zinitcall.sys.feature1.init))
	  KEEP (*(.zinitcall.sys.feature2.init))
	  KEEP (*(.zinitcall.sys.feature3.init))
	  KEEP (*(.zinitcall.sys.feature4.init))
	  __zinitcall_sys_feature_end = .;
	  __zinitcall_run_start = .;
	  KEEP (*(.zinitcall.run0.init))
	  KEEP (*(.zinitcall.run1.init))
	  KEEP (*(.zinitcall.run2.init))
	  KEEP (*(.zinitcall.run3.init))
	  KEEP (*(.zinitcall.run4.init))
	  __zinitcall_run_end = .;
	  __zinitcall_app_service_start = .;
	  KEEP (*(.zinitcall.app.service0.init))
	  KEEP (*(.zinitcall.app.service1.init))
	  KEEP (*(.zinitcall.app.service2.init))
	  KEEP (*(.zinitcall.app.service3.init))
	  KEEP (*(.zinitcall.app.service4.init))
	  __zinitcall_app_service_end = .;
	  __zinitcall_app_feature_start = .;
	  KEEP (*(.zinitcall.app.feature0.init))
	  KEEP (*(.zinitcall.app.feature1.init))
	  KEEP (*(.zinitcall.app.feature2.init))
	  KEEP (*(.zinitcall.app.feature3.init))
	  KEEP (*(.zinitcall.app.feature4.init))
	  __zinitcall_app_feature_end = .;
	  __zinitcall_test_start = .;
	  KEEP (*(.zinitcall.test0.init))
	  KEEP (*(.zinitcall.test1.init))
	  KEEP (*(.zinitcall.test2.init))
	  KEEP (*(.zinitcall.test3.init))
	  KEEP (*(.zinitcall.test4.init))
	  __zinitcall_test_end = .;
	  __zinitcall_exit_start = .;
	  KEEP (*(.zinitcall.exit0.init))
	  KEEP (*(.zinitcall.exit1.init))
	  KEEP (*(.zinitcall.exit2.init))
	  KEEP (*(.zinitcall.exit3.init))
	  KEEP (*(.zinitcall.exit4.init))
	  __zinitcall_exit_end = .;  
    _hdf_drivers_start = .; 
    KEEP(*(.hdf.driver)) 
    _hdf_drivers_end = .; 
    . = ALIGN(4);
    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;        /* define a global symbols at end of code */
  } >FLASH

  /* Constant data goes into FLASH */
  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
    . = ALIGN(4);
  } >FLASH

   .ARM.extab   : { *(.ARM.extab* .gnu.linkonce.armextab.*) } >FLASH
    .ARM : {
    __exidx_start = .;
      *(.ARM.exidx*)
      __exidx_end = .;
    } >FLASH

  .ARM.attributes : { *(.ARM.attributes) } > FLASH

  .preinit_array     :
  {
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  } >FLASH
  .init_array :
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
  } >FLASH
  .fini_array :
  {
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(.fini_array*))
    KEEP (*(SORT(.fini_array.*)))
    PROVIDE_HIDDEN (__fini_array_end = .);
  } >FLASH

  /* used by the startup to initialize data */
  _sidata = .;

  /* Initialized data sections goes into RAM, load LMA copy after code */
  .data : AT ( _sidata )
  {
    . = ALIGN(4);
    _sdata = .;        /* create a global symbol at data start */
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */

    . = ALIGN(4);
    _edata = .;        /* define a global symbol at data end */
  } >RAM

  _siccmram = LOADADDR(.ccmram);

  /* CCM-RAM section 
  * 
  * IMPORTANT NOTE! 
  * If initialized variables will be placed in this section,
  * the startup code needs to be modified to copy the init-values.  
  */
  .ccmram :
  {
    . = ALIGN(4);
    _sccmram = .;       /* create a global symbol at ccmram start */
    *(.ccmram)
    *(.ccmram*)
    
    . = ALIGN(4);
    _eccmram = .;       /* create a global symbol at ccmram end */
  } >CCMRAM AT> FLASH
  /* Uninitialized data section */
  . = ALIGN(4);
  .bss :
  {
    /* This is used by the startup in order to initialize the .bss secion */
    _sbss = .;         /* define a global symbol at bss start */
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;         /* define a global symbol at bss end */
    __bss_end__ = _ebss;
  } >SDRAM

  PROVIDE ( end = _ebss );
  PROVIDE ( _end = _ebss );

  /* User_heap_stack section, used to check that there is enough RAM left */
  ._user_heap_stack :
  {
    . = ALIGN(4);
    . = . + _Min_Heap_Size;
    . = . + _Min_Stack_Size;
    . = ALIGN(4);
  } >RAM



  /* Remove information from the standard libraries */
  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }
}

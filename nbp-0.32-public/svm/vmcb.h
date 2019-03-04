/* 
 * Copyright holder: Invisible Things Lab
 * 
 * This software is protected by domestic and International
 * copyright laws. Any use (including publishing and
 * distribution) of this software requires a valid license
 * from the copyright holder.
 *
 * This software is provided for the educational use only
 * during the Black Hat training. This software should not
 * be used on production systems.
 *
 */

#pragma once

#include <ntddk.h>
#include "common.h"

// shamelessly stolen from XEN-3.0 (with minor fixes for VS) :)

/* general 1 intercepts */
enum GenericIntercept1bits
{
  GENERAL1_INTERCEPT_INTR = 1 << 0,
  GENERAL1_INTERCEPT_NMI = 1 << 1,
  GENERAL1_INTERCEPT_SMI = 1 << 2,
  GENERAL1_INTERCEPT_INIT = 1 << 3,
  GENERAL1_INTERCEPT_VINTR = 1 << 4,
  GENERAL1_INTERCEPT_CR0_SEL_WRITE = 1 << 5,
  GENERAL1_INTERCEPT_IDTR_READ = 1 << 6,
  GENERAL1_INTERCEPT_GDTR_READ = 1 << 7,
  GENERAL1_INTERCEPT_LDTR_READ = 1 << 8,
  GENERAL1_INTERCEPT_TR_READ = 1 << 9,
  GENERAL1_INTERCEPT_IDTR_WRITE = 1 << 10,
  GENERAL1_INTERCEPT_GDTR_WRITE = 1 << 11,
  GENERAL1_INTERCEPT_LDTR_WRITE = 1 << 12,
  GENERAL1_INTERCEPT_TR_WRITE = 1 << 13,
  GENERAL1_INTERCEPT_RDTSC = 1 << 14,
  GENERAL1_INTERCEPT_RDPMC = 1 << 15,
  GENERAL1_INTERCEPT_PUSHF = 1 << 16,
  GENERAL1_INTERCEPT_POPF = 1 << 17,
  GENERAL1_INTERCEPT_CPUID = 1 << 18,
  GENERAL1_INTERCEPT_RSM = 1 << 19,
  GENERAL1_INTERCEPT_IRET = 1 << 20,
  GENERAL1_INTERCEPT_SWINT = 1 << 21,
  GENERAL1_INTERCEPT_INVD = 1 << 22,
  GENERAL1_INTERCEPT_PAUSE = 1 << 23,
  GENERAL1_INTERCEPT_HLT = 1 << 24,
  GENERAL1_INTERCEPT_INVLPG = 1 << 25,
  GENERAL1_INTERCEPT_INVLPGA = 1 << 26,
  GENERAL1_INTERCEPT_IOIO_PROT = 1 << 27,
  GENERAL1_INTERCEPT_MSR_PROT = 1 << 28,
  GENERAL1_INTERCEPT_TASK_SWITCH = 1 << 29,
  GENERAL1_INTERCEPT_FERR_FREEZE = 1 << 30,
  GENERAL1_INTERCEPT_SHUTDOWN_EVT = 1 << 31
};

/* general 2 intercepts */
enum GenericIntercept2bits
{
  GENERAL2_INTERCEPT_VMRUN = 1 << 0,
  GENERAL2_INTERCEPT_VMMCALL = 1 << 1,
  GENERAL2_INTERCEPT_VMLOAD = 1 << 2,
  GENERAL2_INTERCEPT_VMSAVE = 1 << 3,
  GENERAL2_INTERCEPT_STGI = 1 << 4,
  GENERAL2_INTERCEPT_CLGI = 1 << 5,
  GENERAL2_INTERCEPT_SKINIT = 1 << 6,
  GENERAL2_INTERCEPT_RDTSCP = 1 << 7,
  GENERAL2_INTERCEPT_ICEBP = 1 << 8
};

/* control register intercepts */
enum CRInterceptBits
{
  CR_INTERCEPT_CR0_READ = 1 << 0,
  CR_INTERCEPT_CR1_READ = 1 << 1,
  CR_INTERCEPT_CR2_READ = 1 << 2,
  CR_INTERCEPT_CR3_READ = 1 << 3,
  CR_INTERCEPT_CR4_READ = 1 << 4,
  CR_INTERCEPT_CR5_READ = 1 << 5,
  CR_INTERCEPT_CR6_READ = 1 << 6,
  CR_INTERCEPT_CR7_READ = 1 << 7,
  CR_INTERCEPT_CR8_READ = 1 << 8,
  CR_INTERCEPT_CR9_READ = 1 << 9,
  CR_INTERCEPT_CR10_READ = 1 << 10,
  CR_INTERCEPT_CR11_READ = 1 << 11,
  CR_INTERCEPT_CR12_READ = 1 << 12,
  CR_INTERCEPT_CR13_READ = 1 << 13,
  CR_INTERCEPT_CR14_READ = 1 << 14,
  CR_INTERCEPT_CR15_READ = 1 << 15,
  CR_INTERCEPT_CR0_WRITE = 1 << 16,
  CR_INTERCEPT_CR1_WRITE = 1 << 17,
  CR_INTERCEPT_CR2_WRITE = 1 << 18,
  CR_INTERCEPT_CR3_WRITE = 1 << 19,
  CR_INTERCEPT_CR4_WRITE = 1 << 20,
  CR_INTERCEPT_CR5_WRITE = 1 << 21,
  CR_INTERCEPT_CR6_WRITE = 1 << 22,
  CR_INTERCEPT_CR7_WRITE = 1 << 23,
  CR_INTERCEPT_CR8_WRITE = 1 << 24,
  CR_INTERCEPT_CR9_WRITE = 1 << 25,
  CR_INTERCEPT_CR10_WRITE = 1 << 26,
  CR_INTERCEPT_CR11_WRITE = 1 << 27,
  CR_INTERCEPT_CR12_WRITE = 1 << 28,
  CR_INTERCEPT_CR13_WRITE = 1 << 29,
  CR_INTERCEPT_CR14_WRITE = 1 << 30,
  CR_INTERCEPT_CR15_WRITE = 1 << 31,
};

enum VMEXIT_EXITCODE
{
  /* control register read exitcodes */
  VMEXIT_CR0_READ = 0,
  VMEXIT_CR1_READ = 1,
  VMEXIT_CR2_READ = 2,
  VMEXIT_CR3_READ = 3,
  VMEXIT_CR4_READ = 4,
  VMEXIT_CR5_READ = 5,
  VMEXIT_CR6_READ = 6,
  VMEXIT_CR7_READ = 7,
  VMEXIT_CR8_READ = 8,
  VMEXIT_CR9_READ = 9,
  VMEXIT_CR10_READ = 10,
  VMEXIT_CR11_READ = 11,
  VMEXIT_CR12_READ = 12,
  VMEXIT_CR13_READ = 13,
  VMEXIT_CR14_READ = 14,
  VMEXIT_CR15_READ = 15,

  /* control register write exitcodes */
  VMEXIT_CR0_WRITE = 16,
  VMEXIT_CR1_WRITE = 17,
  VMEXIT_CR2_WRITE = 18,
  VMEXIT_CR3_WRITE = 19,
  VMEXIT_CR4_WRITE = 20,
  VMEXIT_CR5_WRITE = 21,
  VMEXIT_CR6_WRITE = 22,
  VMEXIT_CR7_WRITE = 23,
  VMEXIT_CR8_WRITE = 24,
  VMEXIT_CR9_WRITE = 25,
  VMEXIT_CR10_WRITE = 26,
  VMEXIT_CR11_WRITE = 27,
  VMEXIT_CR12_WRITE = 28,
  VMEXIT_CR13_WRITE = 29,
  VMEXIT_CR14_WRITE = 30,
  VMEXIT_CR15_WRITE = 31,

  /* debug register read exitcodes */
  VMEXIT_DR0_READ = 32,
  VMEXIT_DR1_READ = 33,
  VMEXIT_DR2_READ = 34,
  VMEXIT_DR3_READ = 35,
  VMEXIT_DR4_READ = 36,
  VMEXIT_DR5_READ = 37,
  VMEXIT_DR6_READ = 38,
  VMEXIT_DR7_READ = 39,
  VMEXIT_DR8_READ = 40,
  VMEXIT_DR9_READ = 41,
  VMEXIT_DR10_READ = 42,
  VMEXIT_DR11_READ = 43,
  VMEXIT_DR12_READ = 44,
  VMEXIT_DR13_READ = 45,
  VMEXIT_DR14_READ = 46,
  VMEXIT_DR15_READ = 47,

  /* debug register write exitcodes */
  VMEXIT_DR0_WRITE = 48,
  VMEXIT_DR1_WRITE = 49,
  VMEXIT_DR2_WRITE = 50,
  VMEXIT_DR3_WRITE = 51,
  VMEXIT_DR4_WRITE = 52,
  VMEXIT_DR5_WRITE = 53,
  VMEXIT_DR6_WRITE = 54,
  VMEXIT_DR7_WRITE = 55,
  VMEXIT_DR8_WRITE = 56,
  VMEXIT_DR9_WRITE = 57,
  VMEXIT_DR10_WRITE = 58,
  VMEXIT_DR11_WRITE = 59,
  VMEXIT_DR12_WRITE = 60,
  VMEXIT_DR13_WRITE = 61,
  VMEXIT_DR14_WRITE = 62,
  VMEXIT_DR15_WRITE = 63,

  /* processor exception exitcodes (VMEXIT_EXCP[0-31]) */
  VMEXIT_EXCEPTION_DE = 64,     /* divide-by-zero-error */
  VMEXIT_EXCEPTION_DB = 65,     /* debug */
  VMEXIT_EXCEPTION_NMI = 66,    /* non-maskable-interrupt */
  VMEXIT_EXCEPTION_BP = 67,     /* breakpoint */
  VMEXIT_EXCEPTION_OF = 68,     /* overflow */
  VMEXIT_EXCEPTION_BR = 69,     /* bound-range */
  VMEXIT_EXCEPTION_UD = 70,     /* invalid-opcode */
  VMEXIT_EXCEPTION_NM = 71,     /* device-not-available */
  VMEXIT_EXCEPTION_DF = 72,     /* double-fault */
  VMEXIT_EXCEPTION_09 = 73,     /* unsupported (reserved) */
  VMEXIT_EXCEPTION_TS = 74,     /* invalid-tss */
  VMEXIT_EXCEPTION_NP = 75,     /* segment-not-present */
  VMEXIT_EXCEPTION_SS = 76,     /* stack */
  VMEXIT_EXCEPTION_GP = 77,     /* general-protection */
  VMEXIT_EXCEPTION_PF = 78,     /* page-fault */
  VMEXIT_EXCEPTION_15 = 79,     /* reserved */
  VMEXIT_EXCEPTION_MF = 80,     /* x87 floating-point exception-pending */
  VMEXIT_EXCEPTION_AC = 81,     /* alignment-check */
  VMEXIT_EXCEPTION_MC = 82,     /* machine-check */
  VMEXIT_EXCEPTION_XF = 83,     /* simd floating-point */

  /* exceptions 20-31 (exitcodes 84-95) are reserved */

  /* ...and the rest of the #VMEXITs */
  VMEXIT_INTR = 96,
  VMEXIT_NMI = 97,
  VMEXIT_SMI = 98,
  VMEXIT_INIT = 99,
  VMEXIT_VINTR = 100,
  VMEXIT_CR0_SEL_WRITE = 101,
  VMEXIT_IDTR_READ = 102,
  VMEXIT_GDTR_READ = 103,
  VMEXIT_LDTR_READ = 104,
  VMEXIT_TR_READ = 105,
  VMEXIT_IDTR_WRITE = 106,
  VMEXIT_GDTR_WRITE = 107,
  VMEXIT_LDTR_WRITE = 108,
  VMEXIT_TR_WRITE = 109,
  VMEXIT_RDTSC = 110,
  VMEXIT_RDPMC = 111,
  VMEXIT_PUSHF = 112,
  VMEXIT_POPF = 113,
  VMEXIT_CPUID = 114,
  VMEXIT_RSM = 115,
  VMEXIT_IRET = 116,
  VMEXIT_SWINT = 117,
  VMEXIT_INVD = 118,
  VMEXIT_PAUSE = 119,
  VMEXIT_HLT = 120,
  VMEXIT_INVLPG = 121,
  VMEXIT_INVLPGA = 122,
  VMEXIT_IOIO = 123,
  VMEXIT_MSR = 124,
  VMEXIT_TASK_SWITCH = 125,
  VMEXIT_FERR_FREEZE = 126,
  VMEXIT_SHUTDOWN = 127,
  VMEXIT_VMRUN = 128,
  VMEXIT_VMMCALL = 129,
  VMEXIT_VMLOAD = 130,
  VMEXIT_VMSAVE = 131,
  VMEXIT_STGI = 132,
  VMEXIT_CLGI = 133,
  VMEXIT_SKINIT = 134,
  VMEXIT_RDTSCP = 135,
  VMEXIT_ICEBP = 136,
  VMEXIT_WBINVD = 137,
  VMEXIT_NPF = 1024,            /* nested paging fault */
  VMEXIT_INVALID = -1
};

#define SVM_MAX_GUEST_VMEXIT	VMEXIT_WBINVD

enum
{
  SVM_CPU_STATE_PG_ENABLED = 0,
  SVM_CPU_STATE_PAE_ENABLED,
  SVM_CPU_STATE_LME_ENABLED,
  SVM_CPU_STATE_LMA_ENABLED,
  SVM_CPU_STATE_ASSIST_ENABLED,
};

// guest exception or interrupt types
#define GE_EXTERNAL_INTERRUPT	0
#define GE_NMI					2
#define GE_EXCEPTION			3
#define GE_SOFTWARE_INTERRUPT	4

// some exception vectors
#define EV_INVALID_OPCODE		6
#define EV_GENERAL_PROTECTION	13

#pragma pack (push, 1)

typedef union
{
  ULONG64 UCHARs;
  struct
  {
    ULONG64 tpr:8;
    ULONG64 irq:1;
    ULONG64 rsvd0:7;
    ULONG64 prio:4;
    ULONG64 ign_tpr:1;
    ULONG64 rsvd1:3;
    ULONG64 intr_masking:1;
    ULONG64 rsvd2:7;
    ULONG64 vector:8;
    ULONG64 rsvd3:24;
  } fields;
} VINTR;

typedef union
{
  ULONG64 UCHARs;
  struct
  {
    ULONG64 vector:8;
    ULONG64 type:3;
    ULONG64 ev:1;
    ULONG64 resvd1:19;
    ULONG64 v:1;
    ULONG64 errorcode:32;
  } fields;
} EVENTINJ;

enum EVENTTYPES
{
  EVENTTYPE_INTR = 0,
  EVENTTYPE_NMI = 2,
  EVENTTYPE_EXCEPTION = 3,
  EVENTTYPE_SWINT = 4,
};

typedef struct
{
  // --- control area ---

  ULONG32 cr_intercepts;        /* offset 0x00 */
  ULONG32 dr_intercepts;        /* offset 0x04 */
  ULONG32 exception_intercepts; /* offset 0x08 */
  ULONG32 general1_intercepts;  /* offset 0x0C */
  ULONG32 general2_intercepts;  /* offset 0x10 */
  ULONG32 res01;                /* offset 0x14 */
  ULONG64 res02;                /* offset 0x18 */
  ULONG64 res03;                /* offset 0x20 */
  ULONG64 res04;                /* offset 0x28 */
  ULONG64 res05;                /* offset 0x30 */
  ULONG64 res06;                /* offset 0x38 */
  ULONG64 iopm_base_pa;         /* offset 0x40 */
  ULONG64 msrpm_base_pa;        /* offset 0x48 */
  ULONG64 tsc_offset;           /* offset 0x50 */
  ULONG32 guest_asid;           /* offset 0x58 */
  UCHAR tlb_control;            /* offset 0x5C */
  UCHAR res07[3];
  VINTR vintr;                  /* offset 0x60 */
  ULONG64 interrupt_shadow;     /* offset 0x68 */
  ULONG64 exitcode;             /* offset 0x70 */
  ULONG64 exitinfo1;            /* offset 0x78 */
  ULONG64 exitinfo2;            /* offset 0x80 */
  EVENTINJ exitintinfo;         /* offset 0x88 */
  ULONG64 np_enable;            /* offset 0x90 */
  ULONG64 res08[2];
  EVENTINJ eventinj;            /* offset 0xA8 */
  ULONG64 h_cr3;                /* offset 0xB0 */
  ULONG64 res09[105];           /* offset 0xB8 pad to save area */

  // --- guest state area ---

  SEGMENT_SELECTOR es;          /* offset 1024 */
  SEGMENT_SELECTOR cs;
  SEGMENT_SELECTOR ss;
  SEGMENT_SELECTOR ds;
  SEGMENT_SELECTOR fs;
  SEGMENT_SELECTOR gs;
  SEGMENT_SELECTOR gdtr;
  SEGMENT_SELECTOR ldtr;
  SEGMENT_SELECTOR idtr;
  SEGMENT_SELECTOR tr;
  ULONG64 res10[5];
  UCHAR res11[3];
  UCHAR cpl;
  ULONG32 res12;
  ULONG64 efer;                 /* offset 1024 + 0xD0 */
  ULONG64 res13[14];
  ULONG64 cr4;                  /* loffset 1024 + 0x148 */
  ULONG64 cr3;
  ULONG64 cr0;
  ULONG64 dr7;
  ULONG64 dr6;
  ULONG64 rflags;               // 1024+0x170
  ULONG64 rip;                  // 1024+0x178
  ULONG64 res14[11];
  ULONG64 rsp;                  // 1024+0x1d8
  ULONG64 res15[3];
  ULONG64 rax;
  ULONG64 star;
  ULONG64 lstar;
  ULONG64 cstar;
  ULONG64 sfmask;
  ULONG64 kerngsbase;
  ULONG64 sysenter_cs;
  ULONG64 sysenter_esp;
  ULONG64 sysenter_eip;
  ULONG64 cr2;
  ULONG64 pdpe0;
  ULONG64 pdpe1;
  ULONG64 pdpe2;
  ULONG64 pdpe3;
  ULONG64 g_pat;
  ULONG64 res16[50];
  ULONG64 res17[128];
  ULONG64 res18[128];
} VMCB,
 *PVMCB;

#pragma pack (pop)

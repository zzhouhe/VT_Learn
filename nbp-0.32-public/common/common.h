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
#include "paging.h"
#include "comprint.h"

// ---------------- GENERAL CONFIG (both SVM & VMX) ------------------------  

// DEBUG settings -------------
#define	ENABLE_DEBUG_PRINTS

#define	DEBUG_LEVEL	1
#define USE_LOCAL_DBGPRINTS
//#define USE_COM_PRINTS

#ifdef USE_COM_PRINTS
# define	COM_PORT_ADDRESS	0x3f8
// com1 0x3f8
// com2 0x2f8
// com3 0x3e8
// com4 0x2e8

//#define COMPRINT_OVERFLOW_PROTECTION
// allow to ComPrint no more then QUEUE_SZ lines of output within QUEUE_TH cycles
# define COMPRINT_QUEUE_SZ 0x100
# define COMPRINT_QUEUE_TH 0x200000000
# define COMPRINT_SLEEP 10000000000     // wait this many cycles after an overflow condition
#endif // USE_COM_PRINTS

// Various common settings ----- 
#define	ENABLE_HYPERCALLS
//#define       SET_PCD_BIT     // Set PCD for BP's pages (Non Cached)

// BPKNOCK backdoor -------
#define BP_KNOCK
#ifdef BP_KNOCK
# define BP_KNOCK_EAX	0xbabecafe
# define BP_KNOCK_EAX_ANSWER 0x69696969
#endif // BP_KNOCK

// Anti-Detection settings (do not use when using NBP in nested scenario)  --------------------
// RDTSC cheating via instruction tracing and cycles emulation (only a prototype!!!)
//#define INTERCEPT_RDTSCs
#ifdef INTERCEPT_RDTSCs
# define INSTR_TRACE_MAX 128    // max no of instruction to trace
#endif // INTERCEPT_RDTSCs

// Enable Blue Chicken strategy to survice external based timing
//#define BLUE_CHICKEN
#ifdef BLUE_CHICKEN
// BP will uninstall if CHICKEN_QUEUE_SZ intercepts
// occure within a period of time < CHICKEN_TSC_THRESHOLD
# define CHICKEN_QUEUE_SZ 1000
# define CHICKEN_TSC_THRESHOLD  10*1000000      //(1ms on a 1GHz processor)
# define	TIMEBOMB_COUNTDOWN	2000
#endif // BLUE_CHICKEN

// ---------------- VMX CONFIG ------------------------  
#define VMX_USE_PRIVATE_CR3
//#define VMX_ENABLE_PS2_KBD_SNIFFER

// Nested virtualization for VMX is not available in the public build. Sorry.
//#define VMX_SUPPORT_NESTED_VIRTUALIZATION

// ---------------- SVM CONFIG ------------------------  
#define SVM_AUTOREMOVE_EFER_TRAP
#define SVM_USE_NESTEDVMCB_REWRITING
//#define SVM_ALWAYS_FLUSH_TLB  // for debugging only

#ifndef SVM_USE_NESTEDVMCB_REWRITING
# define SVM_ALWAYS_FLUSH_TLB   // we need to use TLB_CONTROL=1 in that case
#endif

// ---------------- MACRO definitions & internal stuff -- no user tunable options below! ------------------------  

#undef _KdPrint

#ifdef ENABLE_DEBUG_PRINTS
# define _KdPrint(x) ComPrint x
#else
# define _KdPrint(x) {}
#endif

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos)   \
	(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
	(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli)  \
	(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds)	 \
	(((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define MINUTES(minutes)	 \
	(((signed __int64)(minutes)) * SECONDS(60L))

#define HOURS(hours)		 \
	(((signed __int64)(hours)) * MINUTES(60L))

#define ALIGN(x,y)	(((x)+(y)-1)&(~((y)-1)))

#define	PML4_BASE	0xFFFFF6FB7DBED000 //和windows内核的四个常量对应
#define	PDP_BASE	0xFFFFF6FB7DA00000 //#define PXE_BASE 0xFFFFF6FB7DBED000UI64
#define	PD_BASE		0xFFFFF6FB40000000 //#define PPE_BASE 0xFFFFF6FB7DA00000UI64
#define	PT_BASE		0xFFFFF68000000000 //#define PDE_BASE 0xFFFFF6FB40000000UI64
                                       //#define PTE_BASE 0xFFFFF68000000000UI64
typedef NTSTATUS (
  NTAPI * PCALLBACK_PROC
) (
  PVOID Param
);

#define MSR_IA32_APICBASE		0x1b
#define MSR_IA32_APICBASE_BSP		(1<<8)
#define MSR_IA32_APICBASE_ENABLE	(1<<11)
#define MSR_IA32_APICBASE_BASE		(0xfffff<<12)

#pragma pack (push, 1)

/* 
* Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
* segment descriptor. 
*/
typedef union
{
  USHORT UCHARs;
  struct
  {
    USHORT type:4;              /* 0;  Bit 40-43 */
    USHORT s:1;                 /* 4;  Bit 44 */
    USHORT dpl:2;               /* 5;  Bit 45-46 */
    USHORT p:1;                 /* 7;  Bit 47 */
    // gap!       
    USHORT avl:1;               /* 8;  Bit 52 */
    USHORT l:1;                 /* 9;  Bit 53 */
    USHORT db:1;                /* 10; Bit 54 */
    USHORT g:1;                 /* 11; Bit 55 */
    USHORT Gap:4;
  } fields;
} SEGMENT_ATTRIBUTES;

typedef struct _TSS64
{
  ULONG Reserved0;
  PVOID RSP0;
  PVOID RSP1;
  PVOID RSP2;
  ULONG64 Reserved1;
  PVOID IST1;
  PVOID IST2;
  PVOID IST3;
  PVOID IST4;
  PVOID IST5;
  PVOID IST6;
  PVOID IST7;
  ULONG64 Reserved2;
  USHORT Reserved3;
  USHORT IOMapBaseAddress;
} TSS64,
 *PTSS64;

typedef struct
{
  USHORT sel;
  SEGMENT_ATTRIBUTES attributes;
  ULONG32 limit;
  ULONG64 base;
} SEGMENT_SELECTOR;

typedef struct
{
  USHORT limit0;
  USHORT base0;
  UCHAR base1;
  UCHAR attr0;
  UCHAR limit1attr1;
  UCHAR base2;
} SEGMENT_DESCRIPTOR,
 *PSEGMENT_DESCRIPTOR;

typedef struct _INTERRUPT_GATE_DESCRIPTOR
{
  USHORT TargetOffset1500;
  USHORT TargetSelector;
  UCHAR InterruptStackTable;
  UCHAR Attributes;
  USHORT TargetOffset3116;
  ULONG32 TargetOffset6332;
  ULONG32 Reserved;
} INTERRUPT_GATE_DESCRIPTOR,
 *PINTERRUPT_GATE_DESCRIPTOR;

#pragma pack (pop)

#define LA_ACCESSED		0x01
#define LA_READABLE		0x02    // for code segments
#define LA_WRITABLE		0x02    // for data segments
#define LA_CONFORMING	0x04    // for code segments
#define LA_EXPANDDOWN	0x04    // for data segments
#define LA_CODE			0x08
#define LA_STANDARD		0x10
#define LA_DPL_0		0x00
#define LA_DPL_1		0x20
#define LA_DPL_2		0x40
#define LA_DPL_3		0x60
#define LA_PRESENT		0x80

#define LA_LDT64		0x02
#define LA_ATSS64		0x09
#define LA_BTSS64		0x0b
#define LA_CALLGATE64	0x0c
#define LA_INTGATE64	0x0e
#define LA_TRAPGATE64	0x0f

#define HA_AVAILABLE	0x01
#define HA_LONG			0x02
#define HA_DB			0x04
#define HA_GRANULARITY	0x08

#define P_PRESENT			0x01
#define P_WRITABLE			0x02
#define P_USERMODE			0x04
#define P_WRITETHROUGH		0x08
#define P_CACHE_DISABLED	0x10
#define P_ACCESSED			0x20
#define P_DIRTY				0x40
#define P_LARGE				0x80
#define P_GLOBAL			0x100

#define REG_MASK			0x07

#define REG_GP				0x08
#define REG_GP_ADDITIONAL	0x10
#define REG_CONTROL			0x20
#define REG_DEBUG			0x40
#define REG_RFLAGS			0x80

#define	REG_RAX	REG_GP | 0
#define REG_RCX	REG_GP | 1
#define REG_RDX	REG_GP | 2
#define REG_RBX	REG_GP | 3
#define REG_RSP	REG_GP | 4
#define REG_RBP	REG_GP | 5
#define REG_RSI	REG_GP | 6
#define REG_RDI	REG_GP | 7

#define	REG_R8	REG_GP_ADDITIONAL | 0
#define	REG_R9	REG_GP_ADDITIONAL | 1
#define	REG_R10	REG_GP_ADDITIONAL | 2
#define	REG_R11	REG_GP_ADDITIONAL | 3
#define	REG_R12	REG_GP_ADDITIONAL | 4
#define	REG_R13	REG_GP_ADDITIONAL | 5
#define	REG_R14	REG_GP_ADDITIONAL | 6
#define	REG_R15	REG_GP_ADDITIONAL | 7

#define REG_CR0	REG_CONTROL | 0
#define REG_CR2	REG_CONTROL | 2
#define REG_CR3	REG_CONTROL | 3
#define REG_CR4	REG_CONTROL | 4
#define REG_CR8	REG_CONTROL | 8

#define REG_DR0	REG_DEBUG | 0
#define REG_DR1	REG_DEBUG | 1
#define REG_DR2	REG_DEBUG | 2
#define REG_DR3	REG_DEBUG | 3
#define REG_DR6	REG_DEBUG | 6
#define REG_DR7	REG_DEBUG | 7

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001      /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004      /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010      /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040      /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080      /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100      /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200      /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400      /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800      /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000      /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000      /* Nested Task */
#define X86_EFLAGS_RF	0x00010000      /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000      /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000      /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000      /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000      /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000      /* CPUID detection flag */

typedef struct _CPU *PCPU;

#ifdef _X86_
typedef struct _GUEST_REGS
{
  ULONG32 rax;                  // 0x00         // NOT VALID FOR SVM
  ULONG32 rcx;
  ULONG32 rdx;                  // 0x08
  ULONG32 rbx;
  ULONG32 rsp;                  // rsp is not stored here on SVM
  ULONG32 rbp;
  ULONG32 rsi;
  ULONG32 rdi;
  ULONG32 r8;
  ULONG32 r9;
  ULONG32 r10;
  ULONG32 r11;
  ULONG32 r12;
  ULONG32 r13;
  ULONG32 r14;
  ULONG32 r15;

} GUEST_REGS,
 *PGUEST_REGS;
#else
typedef struct _GUEST_REGS
{
  ULONG64 rax;                  // 0x00         // NOT VALID FOR SVM
  ULONG64 rcx;
  ULONG64 rdx;                  // 0x10
  ULONG64 rbx;
  ULONG64 rsp;                  // 0x20         // rsp is not stored here on SVM
  ULONG64 rbp;
  ULONG64 rsi;                  // 0x30
  ULONG64 rdi;
  ULONG64 r8;                   // 0x40
  ULONG64 r9;
  ULONG64 r10;                  // 0x50
  ULONG64 r11;
  ULONG64 r12;                  // 0x60
  ULONG64 r13;
  ULONG64 r14;                  // 0x70
  ULONG64 r15;
} GUEST_REGS,
 *PGUEST_REGS;
#endif

typedef BOOLEAN (
  NTAPI * ARCH_IS_HVM_IMPLEMENTED
) (
);

typedef NTSTATUS (
  NTAPI * ARCH_INITIALIZE
) (
  PCPU Cpu,
  PVOID GuestRip,
  PVOID GuestRsp
);
typedef NTSTATUS (
  NTAPI * ARCH_VIRTUALIZE
) (
  PCPU Cpu
);
typedef NTSTATUS (
  NTAPI * ARCH_SHUTDOWN
) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  BOOLEAN bSetupTimeBomb
);

typedef BOOLEAN (
  NTAPI * ARCH_IS_NESTED_EVENT
) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);
typedef VOID (
  NTAPI * ARCH_DISPATCH_NESTED_EVENT
) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);
typedef VOID (
  NTAPI * ARCH_DISPATCH_EVENT
) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);
typedef VOID (
  NTAPI * ARCH_ADJUST_RIP
) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG64 Delta
);
typedef NTSTATUS (
  NTAPI * ARCH_REGISTER_TRAPS
) (
  PCPU Cpu
);
typedef BOOLEAN (
  NTAPI * ARCH_IS_TRAP_VALID
) (
  ULONG TrappedVmExit
);                              //add by cini

typedef ULONG BPSPIN_LOCK, *PBPSPIN_LOCK;

typedef struct
{
  UCHAR Architecture;

  ARCH_IS_HVM_IMPLEMENTED ArchIsHvmImplemented;

  ARCH_INITIALIZE ArchInitialize;
  ARCH_VIRTUALIZE ArchVirtualize;
  ARCH_SHUTDOWN ArchShutdown;

  ARCH_IS_NESTED_EVENT ArchIsNestedEvent;
  ARCH_DISPATCH_NESTED_EVENT ArchDispatchNestedEvent;
  ARCH_DISPATCH_EVENT ArchDispatchEvent;
  ARCH_ADJUST_RIP ArchAdjustRip;
  ARCH_REGISTER_TRAPS ArchRegisterTraps;
  ARCH_IS_TRAP_VALID ArchIsTrapValid;
} HVM_DEPENDENT,
 *PHVM_DEPENDENT;

NTSTATUS NTAPI CmPatchPTEPhysicalAddress (
  PULONG64 pPte,
  PVOID PageVA,
  PHYSICAL_ADDRESS NewPhysicalAddress
);

NTSTATUS NTAPI CmGetPagePTEAddress (
  PVOID Page,
  PULONG64 * pPagePTE,
  PHYSICAL_ADDRESS * pPA
);

NTSTATUS NTAPI CmSetIdtEntry (
  PINTERRUPT_GATE_DESCRIPTOR IdtBase,
  ULONG IdtLimit,
  ULONG InterruptNumber,
  USHORT TargetSelector,
  PVOID TargetOffset,
  UCHAR InterruptStackTable,
  UCHAR Attributes
);

NTSTATUS NTAPI CmGetPagePaByPageVaCr3 (
  PCPU Cpu,
  ULONG64 CR3,
  ULONG64 PageVA,
  PHYSICAL_ADDRESS * pPA
);

NTSTATUS NTAPI CmDumpGdt (
  PUCHAR GdtBase,
  USHORT GdtLimit
);

NTSTATUS CmDumpTSS64 (
  PTSS64 Tss64,
  USHORT Tss64Limit
);

NTSTATUS NTAPI CmSetGdtEntry (
  PSEGMENT_DESCRIPTOR GdtBase,
  ULONG GdtLimit,
  ULONG SelectorNumber,
  PVOID SegmentBase,
  ULONG SegmentLimit,
  UCHAR LowAttributes,
  UCHAR HighAttributes
);

VOID NTAPI CmClgi (
);

VOID NTAPI CmStgi (
);

VOID NTAPI CmCli (
);

VOID NTAPI CmSti (
);

VOID NTAPI CmDebugBreak (
);

VOID NTAPI CmWbinvd (
);

VOID NTAPI CmClflush (
  PVOID mem8
);

VOID NTAPI CmInvalidatePage (
  PVOID Page
);

VOID NTAPI CmReloadGdtr (
  PVOID GdtBase,
  ULONG GdtLimit
);

VOID NTAPI CmReloadIdtr (
  PVOID IdtBase,
  ULONG IdtLimit
);

VOID NTAPI CmSetBluepillESDS (
);

VOID NTAPI CmSetBluepillGS (
);

VOID NTAPI CmSetDS (
  USHORT Selector
);

VOID NTAPI CmSetES (
  USHORT Selector
);

VOID NTAPI CmSetFS (
  ULONG Selector
);

VOID NTAPI CmSetGS (
  ULONG Selector
);

VOID NTAPI CmFreePhysPages (
  PVOID BaseAddress,
  ULONG uNoOfPages
);

NTSTATUS NTAPI CmSubvert (
  PVOID
);

NTSTATUS NTAPI CmSlipIntoMatrix (
  PVOID
);

NTSTATUS NTAPI CmDeliverToProcessor (
  CCHAR cProcessorNumber,
  PCALLBACK_PROC CallbackProc,
  PVOID CallbackParam,
  PNTSTATUS pCallbackStatus
);

NTSTATUS NTAPI CmInitializeSegmentSelector (
  SEGMENT_SELECTOR * SegmentSelector,
  USHORT Selector,
  PUCHAR GdtBase
);

NTSTATUS NTAPI CmGenerateIretq (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength
);

NTSTATUS NTAPI CmGenerateIretd (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength
);

NTSTATUS NTAPI CmGeneratePushReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
);

NTSTATUS NTAPI CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG64 Value
);

NTSTATUS NTAPI CmGenerateCallReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
);

NTSTATUS NTAPI CmSubvert (
  PVOID
);

NTSTATUS NTAPI CmHostNullCode (
);

NTSTATUS NTAPI CmGenerateGUESTCode (
  ULONG32 guestip,
  ULONG32 len
);

ULONG32 CmIOIn (
  ULONG32 port
);

VOID NTAPI CmIOOutB (
  ULONG32 port,
  ULONG32 data
);

VOID NTAPI CmIOOutW (
  ULONG32 port,
  ULONG32 data
);

VOID NTAPI CmIOOutD (
  ULONG32 port,
  ULONG32 data
);

VOID NTAPI CmInitSpinLock (
  PBPSPIN_LOCK BpSpinLock
);

VOID NTAPI CmAcquireSpinLock (
  PBPSPIN_LOCK BpSpinLock
);

VOID NTAPI CmReleaseSpinLock (
  PBPSPIN_LOCK BpSpinLock
);

BOOLEAN CmIsBitSet (
  ULONG64 v,
  UCHAR bitNo
);

ULONG64 CmBitSetByValue (
  ULONG64 v,
  UCHAR bitNo,
  BOOLEAN Value
);

VOID CmPageBitAdd (
  PVOID Target,
  PVOID Source1,
  PVOID Source2
);

NTSTATUS NTAPI NtDeviceIoControlFile (
  IN HANDLE FileHandle,
  IN HANDLE Event OPTIONAL,
  IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
  IN PVOID ApcContext OPTIONAL,
  OUT PIO_STATUS_BLOCK IoStatusBlock,
  IN ULONG IoControlCode,
  IN PVOID InputBuffer OPTIONAL,
  IN ULONG InputBufferLength,
  OUT PVOID OutputBuffer OPTIONAL,
  IN ULONG OutputBufferLength
);

#define ITL_TAG	'LTI'

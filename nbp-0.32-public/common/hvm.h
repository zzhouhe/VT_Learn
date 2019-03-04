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
#include "svm.h"
#include "vmx.h"
#include "msr.h"
#include "regs.h"
#include "traps.h"
#include "hypercalls.h"
#include "interrupts.h"

#define	HOST_STACK_SIZE_IN_PAGES	16

// ntamd64_x.h
#define KGDT64_NULL (0 * 16)    // NULL descriptor
#define KGDT64_R0_CODE (1 * 16) // kernel mode 64-bit code
#define KGDT64_R0_DATA (1 * 16) + 8     // kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define KGDT64_R3_DATA (2 * 16) + 8     // user mode 32-bit data
#define KGDT64_R3_CODE (3 * 16) // user mode 64-bit code
#define KGDT64_SYS_TSS (4 * 16) // kernel mode system task state
#define KGDT64_R3_CMTEB (5 * 16)        // user mode 32-bit TEB
#define KGDT64_R0_CMCODE (6 * 16)       // kernel mode 32-bit code

// this must be synchronized with CmSetBluepillSelectors() (common-asm.asm)
#define	BP_GDT64_CODE		KGDT64_R0_CODE  // cs
#define BP_GDT64_DATA		KGDT64_R0_DATA  // ds, es, ss
#define BP_GDT64_SYS_TSS	KGDT64_SYS_TSS  // tr
#define BP_GDT64_PCR		KGDT64_R0_DATA  // gs

#define BP_GDT_LIMIT	0x6f
#define BP_IDT_LIMIT	0xfff
#define BP_TSS_LIMIT	0x68    // 0x67 min

#define	ARCH_SVM	1
#define	ARCH_VMX	2

typedef struct _CPU
{

  PCPU SelfPointer;             // MUST go first in the structure; refer to interrupt handlers for details

  union
  {
    SVM Svm;
    VMX Vmx;
  };

  ULONG ProcessorNumber;
  ULONG64 TotalTscOffset;

  LARGE_INTEGER LapicBaseMsr;
  PHYSICAL_ADDRESS LapicPhysicalBase;
  PUCHAR LapicVirtualBase;

  LIST_ENTRY GeneralTrapsList;  // list of BP_TRAP structures
  LIST_ENTRY MsrTrapsList;      //
  LIST_ENTRY IoTrapsList;       //

  PVOID SparePage;              // a single page which was allocated just to get an unused PTE.
  PHYSICAL_ADDRESS SparePagePA; // original PA of the SparePage
  PULONG64 SparePagePTE;

  PSEGMENT_DESCRIPTOR GdtArea;
  PVOID IdtArea;

  PVOID HostStack;              // note that CPU structure reside in this memory region
  BOOLEAN Nested;

#ifdef INTERCEPT_RDTSCs

  // variables for RDTSC tracing and cheating
  ULONG64 Tsc;
  ULONG64 LastTsc;
  ULONG64 EmulatedCycles;
  int Tracing;                  // we trace instructions until Tracing = 0
  int NoOfRecordedInstructions;

  //currently not implemeneted:
  //int NextInstrOffsetinBuffer;
  //PVOID RecordedInstructions[INSTR_TRACE_MAX * 16];

#endif
#ifdef BLUE_CHICKEN

  int ChickenQueueSize;
  ULONG64 ChickenQueueTable[CHICKEN_QUEUE_SZ];
  int ChickenQueueHead, ChickenQueueTail;

  UCHAR OriginalTrampoline[0x600];

#endif

  ULONG64 ComPrintLastTsc;

} CPU,
 *PCPU;

PHVM_DEPENDENT Hvm;

extern HVM_DEPENDENT Svm;
extern HVM_DEPENDENT Vmx;

NTSTATUS NTAPI HvmSwallowBluepill (
);

NTSTATUS NTAPI HvmSpitOutBluepill (
);

NTSTATUS NTAPI HvmInit (
);

NTSTATUS NTAPI HvmCopyPhysicalToVirtual (
  PCPU Cpu,
  PVOID Destination,
  PHYSICAL_ADDRESS Source,
  ULONG uNumberOfPages
);

NTSTATUS NTAPI HvmMapGuestVAToSparePage (
  PCPU Cpu,
  PHYSICAL_ADDRESS Context,
  PVOID Source
);

VOID NTAPI HvmVmExitCallback (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

VOID NTAPI HvmSetupTimeBomb (
  PVOID OriginalTrampoline,
  CCHAR ProcessorNumber
);

// TODO: implement FatalError() that would be pritning a msg and then uninstalling NBP (if possible)

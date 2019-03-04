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
#include "msr.h"
#include "svm.h"
#include "regs.h"

#define NBP_MAGIC	((ULONG32)'!LTI')

// these are 16-bit words

#define NBP_HYPERCALL_UNLOAD			0x1
#define NBP_HYPERCALL_QUEUE_INTERRUPT		0x2
#define NBP_HYPERCALL_EOI			0x3

VOID NTAPI HcDispatchHypercall (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

NTSTATUS NTAPI HcMakeHypercall (
  ULONG32 HypercallNumber,
  ULONG32 HypercallParameter,
  PULONG32 pHypercallResult
);

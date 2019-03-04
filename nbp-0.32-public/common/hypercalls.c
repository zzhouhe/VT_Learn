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

#include "hypercalls.h"

VOID NTAPI HcDispatchHypercall (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{

#ifndef ENABLE_HYPERCALLS

  return;

#else

  ULONG32 HypercallNumber;
  ULONG32 HypercallResult = 0;

  if (!Cpu || !GuestRegs)
    return;

  HypercallNumber = (ULONG32) (GuestRegs->rdx & 0xffff);

  switch (HypercallNumber) {
  case NBP_HYPERCALL_UNLOAD:

    _KdPrint (("HcDispatchHypercall(): NBP_HYPERCALL_UNLOAD\n"));

    GuestRegs->rcx = NBP_MAGIC;
    GuestRegs->rdx = HypercallResult;

    if (Hvm->Architecture == ARCH_SVM)
      Hvm->ArchAdjustRip (Cpu, GuestRegs, 2);

    // disable virtualization, resume guest, don't setup time bomb
    Hvm->ArchShutdown (Cpu, GuestRegs, FALSE);

    // never returns

    _KdPrint (("HcDispatchHypercall(): ArchShutdown() returned\n"));

    break;

  default:

    _KdPrint (("HcDispatchHypercall(): Unsupported hypercall 0x%04X\n", HypercallNumber));
    break;
  }

  GuestRegs->rcx = NBP_MAGIC;
  GuestRegs->rdx = HypercallResult;

#endif
}

NTSTATUS NTAPI HcMakeHypercall (
  ULONG32 HypercallNumber,
  ULONG32 HypercallParameter,
  PULONG32 pHypercallResult
)
{

#ifndef ENABLE_HYPERCALLS

  return STATUS_NOT_SUPPORTED;

#else

  ULONG32 edx = HypercallParameter, ecx;

  if (Hvm->Architecture == ARCH_VMX) {
    VmxVmCall (HypercallNumber);
    return STATUS_SUCCESS;
  }
  // low part contains a hypercall number
  edx = HypercallNumber | (NBP_MAGIC & 0xffff0000);
  ecx = NBP_MAGIC + 1;

  CpuidWithEcxEdx (&ecx, &edx);

  if (ecx != NBP_MAGIC) {
    _KdPrint (("HcMakeHypercall(): No NewBluePill detected on the processor #%d\n", KeGetCurrentProcessorNumber ()));
    return STATUS_NOT_SUPPORTED;
  }

  if (pHypercallResult)
    *pHypercallResult = edx;

  return STATUS_SUCCESS;
#endif
}

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

#include "traps.h"

extern ULONG g_uPrintStuff;

NTSTATUS NTAPI TrRegisterTrap (
  PCPU Cpu,
  PNBP_TRAP Trap
)
{
  PLIST_ENTRY TrapList;

  if (!Cpu || !Trap)
    return STATUS_INVALID_PARAMETER;

  switch (Trap->TrapType) {
  case TRAP_GENERAL:
    TrapList = &Cpu->GeneralTrapsList;
    break;
  case TRAP_MSR:
    TrapList = &Cpu->MsrTrapsList;
    break;
  case TRAP_IO:
    TrapList = &Cpu->IoTrapsList;
    break;
  default:
    _KdPrint (("TrRegisterTrap(): Unknown TRAP_TYPE code: %d\n", (char) Trap->TrapType));
    return STATUS_UNSUCCESSFUL;
  }

  InsertTailList (TrapList, &Trap->le);
  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrDeregisterTrap (
  PNBP_TRAP Trap
)
{
  if (!Trap)
    return STATUS_INVALID_PARAMETER;

  RemoveEntryList (&Trap->le);
  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrTrapDisable (
  PNBP_TRAP Trap
)
{
  if (!Trap)
    return STATUS_INVALID_PARAMETER;

  Trap->SavedTrapType = Trap->TrapType;
  Trap->TrapType = TRAP_DISABLED;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrTrapEnable (
  PNBP_TRAP Trap
)
{
  if (!Trap)
    return STATUS_INVALID_PARAMETER;

  if (Trap->TrapType == TRAP_DISABLED)
    Trap->TrapType = Trap->SavedTrapType;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrDeregisterTrapList (
  PLIST_ENTRY TrapList
)
{
  PNBP_TRAP Trap, NextTrap;
  NTSTATUS Status;

  if (!TrapList)
    return STATUS_INVALID_PARAMETER;

  Trap = (PNBP_TRAP) TrapList->Flink;
  while (Trap != (PNBP_TRAP) TrapList) {
    Trap = CONTAINING_RECORD (Trap, NBP_TRAP, le);
    NextTrap = (PNBP_TRAP) Trap->le.Flink;

    if (!NT_SUCCESS (Status = TrDeregisterTrap (Trap))) {
      Trap = NextTrap;
      continue;
    }

    CmFreePhysPages (Trap, BYTES_TO_PAGES (sizeof (NBP_TRAP)));

    Trap = NextTrap;
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrInitializeGeneralTrap (
  PCPU Cpu,
  ULONG TrappedVmExit,
  UCHAR RipDelta,
  NBP_TRAP_CALLBACK TrapCallback,
  PNBP_TRAP * pInitializedTrap
)
{
  PNBP_TRAP Trap;
  _KdPrint (("TrInitializeGeneralTrap():TrappedVmExit 0x%x\n", TrappedVmExit));

  if (!Cpu || !TrapCallback || !Hvm->ArchIsTrapValid (TrappedVmExit) || !pInitializedTrap)
    return STATUS_INVALID_PARAMETER;

  Trap = MmAllocatePages (BYTES_TO_PAGES (sizeof (NBP_TRAP)), NULL);
  if (!Trap) {
    _KdPrint (("TrInitializeGeneralTrap(): Failed to allocate NBP_TRAP structure (%d bytes)\n", sizeof (NBP_TRAP)));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  RtlZeroMemory (Trap, sizeof (NBP_TRAP));

  Trap->TrapType = TRAP_GENERAL;
  Trap->General.TrappedVmExit = TrappedVmExit;
  Trap->General.RipDelta = RipDelta;
  Trap->TrapCallback = TrapCallback;

  *pInitializedTrap = Trap;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrInitializeMsrTrap (
  PCPU Cpu,
  ULONG TrappedMsr,
  UCHAR TrappedMsrAccess,
  NBP_TRAP_CALLBACK TrapCallback,
  PNBP_TRAP * pInitializedTrap
)
{
  NTSTATUS Status;
  PNBP_TRAP Trap;

  if (!Cpu ||
      !TrapCallback ||
      !pInitializedTrap || !TrappedMsrAccess || (TrappedMsrAccess & ~(MSR_INTERCEPT_READ | MSR_INTERCEPT_WRITE)))
    return STATUS_INVALID_PARAMETER;

  // Valid MSR regions:
  // 
  // MSRPM Byte Offset    MSR Range                               Current Usage
  // 000h-7FFh                    0000_0000h-0000_1FFFh   Pentium®-compatible MSRs
  // 800h-FFFh                    C000_0000h-C000_1FFFh   AMD Sixth Generation x86 Processor MSRs and SYSCALL
  // 1000h-17FFh                  C001_0000h-C001_1FFFh   AMD Seventh and Eighth Generation Processor MSRs
  // 1800h-1FFFh                  XXXX_XXXX-XXXX_XXXX             reserved

  if ((0x00002000 <= TrappedMsr && TrappedMsr < 0xc0000000) ||
      (0xc0002000 <= TrappedMsr && TrappedMsr < 0xc0010000) || TrappedMsr >= 0xc0012000)
    return STATUS_INVALID_PARAMETER;

  Trap = MmAllocatePages (BYTES_TO_PAGES (sizeof (NBP_TRAP)), NULL);
  if (!Trap) {
    _KdPrint (("TrInitializeMsrTrap(): Failed to allocate NBP_TRAP structure (%d bytes)\n", sizeof (NBP_TRAP)));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  RtlZeroMemory (Trap, sizeof (NBP_TRAP));

  Trap->TrapType = TRAP_MSR;
  Trap->Msr.TrappedMsr = TrappedMsr;
  Trap->Msr.TrappedMsrAccess = TrappedMsrAccess;
  Trap->TrapCallback = TrapCallback;

  *pInitializedTrap = Trap;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrInitializeIoTrap (
  PCPU Cpu,
  ULONG TrappedIoPort,
  NBP_TRAP_CALLBACK TrapCallback,
  PNBP_TRAP * pInitializedTrap
)
{
  return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI TrExecuteMsrTrapHandler (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG32 TrappedMsr;

  if (!Cpu || !GuestRegs || !Trap || (Trap->TrapType != TRAP_MSR))
    return STATUS_INVALID_PARAMETER;

  if (g_uPrintStuff && (Hvm->Architecture == ARCH_SVM)) {

    TrappedMsr = (ULONG32) (GuestRegs->rcx & 0xffffffff);

    if (TrappedMsr == MSR_EFER || TrappedMsr == MSR_VM_HSAVE_PA) {
      _KdPrint (("TrExecuteMsrTrapHandler(): CPU#%d: %s %s at 0x%p\n",
                 Cpu->ProcessorNumber,
                 TrappedMsr == MSR_EFER ? "EFER" : "VM_HSAVE_PA",
                 Cpu->Svm.OriginalVmcb->exitinfo1 ==
                 (MSR_INTERCEPT_READ >> 1) ? "read" : Cpu->Svm.OriginalVmcb->
                 exitinfo1 == (MSR_INTERCEPT_WRITE >> 1) ? "write" : "abuse", Cpu->Svm.OriginalVmcb->rip));
    } else {
      _KdPrint (("TrExecuteMsrTrapHandler(): CPU#%d: MSR 0x%08hX %s access at 0x%p\n", Cpu->ProcessorNumber, TrappedMsr,
                 Cpu->Svm.OriginalVmcb->exitinfo1 ==
                 (MSR_INTERCEPT_READ >> 1) ? "read" : Cpu->Svm.OriginalVmcb->exitinfo1 ==
                 (MSR_INTERCEPT_WRITE >> 1) ? "write" : "abuse", Cpu->Svm.OriginalVmcb->rip));
    }
  }

  if (Trap->TrapCallback (Cpu, GuestRegs, Trap, WillBeAlsoHandledByGuestHv)) {
    // trap handler wants us to adjust guest's RIP
    Hvm->ArchAdjustRip (Cpu, GuestRegs, 2);
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrExecuteGeneralTrapHandler (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{

  if (!Cpu || !GuestRegs || !Trap || (Trap->TrapType != TRAP_GENERAL))
    return STATUS_INVALID_PARAMETER;

  if (Trap->TrapCallback (Cpu, GuestRegs, Trap, WillBeAlsoHandledByGuestHv)) {
    // trap handler wants us to adjust guest's RIP
    Hvm->ArchAdjustRip (Cpu, GuestRegs, Trap->General.RipDelta);
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrFindRegisteredTrap (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG64 exitcode,
  PNBP_TRAP * pTrap
)
{
  TRAP_TYPE TrapType;
  PLIST_ENTRY TrapList;
  PNBP_TRAP Trap;

  if (!Cpu || !GuestRegs || !pTrap)
    return STATUS_INVALID_PARAMETER;

  if (Hvm->Architecture == ARCH_SVM) {

    switch (exitcode) {
    case VMEXIT_MSR:
      TrapType = TRAP_MSR;
      TrapList = &Cpu->MsrTrapsList;
      break;

    case VMEXIT_IOIO:
      return STATUS_NOT_IMPLEMENTED;
    default:
      TrapType = TRAP_GENERAL;
      TrapList = &Cpu->GeneralTrapsList;
    }
  } else {
    TrapType = TRAP_GENERAL;
    TrapList = &Cpu->GeneralTrapsList;
  }

  Trap = (PNBP_TRAP) TrapList->Flink;
  while (Trap != (PNBP_TRAP) TrapList) {
    Trap = CONTAINING_RECORD (Trap, NBP_TRAP, le);

    if ((Trap->TrapType == TrapType) && Trap->TrapCallback) {

      if ((Trap->TrapType == TRAP_MSR) && (Trap->Msr.TrappedMsr == (ULONG32) (GuestRegs->rcx & 0xffffffff))) {

        // return the Trap even if doesn't intercept current access for this MSR
        // (e.g. TrappedMsrAccess==MSR_INTERCEPT_READ and trapped instructions is WRMSR)
        *pTrap = Trap;
        return STATUS_SUCCESS;
      }

      if ((Trap->TrapType == TRAP_GENERAL) && (Trap->General.TrappedVmExit == exitcode)) {

        *pTrap = Trap;
        return STATUS_SUCCESS;
      }

    }
    Trap = (PNBP_TRAP) Trap->le.Flink;
  }

  return STATUS_NOT_FOUND;
}

NTSTATUS NTAPI TrFreeTraps (
  PCPU Cpu
)
{
  NTSTATUS Status, LastBadStatus = STATUS_SUCCESS;

  if (!Cpu)
    return STATUS_INVALID_PARAMETER;

  if (!NT_SUCCESS (Status = TrDeregisterTrapList (&Cpu->GeneralTrapsList))) {
    _KdPrint (("TrFreeTraps(): Failed to deregister general traplist, status 0x%08hX\n", Status));
    LastBadStatus = Status;
  }

  if (!NT_SUCCESS (Status = TrDeregisterTrapList (&Cpu->MsrTrapsList))) {
    _KdPrint (("TrFreeTraps(): Failed to deregister MSR traplist, status 0x%08hX\n", Status));
    LastBadStatus = Status;
  }

  if (!NT_SUCCESS (Status = TrDeregisterTrapList (&Cpu->IoTrapsList))) {
    _KdPrint (("TrFreeTraps(): Failed to deregister IO traplist, status 0x%08hX\n", Status));
    LastBadStatus = Status;
  }

  return LastBadStatus;
}

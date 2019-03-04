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

#define	MSR_INTERCEPT_READ	1
#define	MSR_INTERCEPT_WRITE	2

typedef struct _NBP_TRAP *PNBP_TRAP;

// returns FALSE if the adjustment of guest RIP is not needed
typedef BOOLEAN (
  NTAPI * NBP_TRAP_CALLBACK
) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
);

typedef struct _NBP_TRAP_DATA_GENERAL
{
  ULONG TrappedVmExit;
  ULONG64 RipDelta;             // this value will be added to rip to skip the trapped instruction
} NBP_TRAP_DATA_GENERAL,
 *PNBP_TRAP_DATA_GENERAL;

typedef struct _NBP_TRAP_DATA_MSR
{
  ULONG32 TrappedMsr;
  UCHAR TrappedMsrAccess;
  UCHAR GuestTrappedMsrAccess;
} NBP_TRAP_DATA_MSR,
 *PNBP_TRAP_DATA_MSR;

typedef struct _NBP_TRAP_DATA_IO
{
  ULONG TrappedPort;
} NBP_TRAP_DATA_IO,
 *PNBP_TRAP_DATA_IO;

typedef enum
{
  TRAP_DISABLED = 0,
  TRAP_GENERAL = 1,
  TRAP_MSR = 2,
  TRAP_IO = 3
} TRAP_TYPE;

#define MAX_TRAP_TYPE	TRAP_IO

typedef struct _NBP_TRAP
{
  LIST_ENTRY le;

  TRAP_TYPE TrapType;
  TRAP_TYPE SavedTrapType;

  union
  {
    NBP_TRAP_DATA_GENERAL General;
    NBP_TRAP_DATA_MSR Msr;
    NBP_TRAP_DATA_IO Io;
  };

  NBP_TRAP_CALLBACK TrapCallback;
  BOOLEAN bForwardTrapToGuest;  // FALSE if guest hypervisor doesn't want to intercept this in its own guest.
  // This will be TRUE for TRAP_MSR record when we're going to intercept MSR "rw"
  // but the guest wants to intercept only "r" or "w". 
  // Check Msr.GuestTrappedMsrAccess for correct event forwarding.
} NBP_TRAP,
 *PNBP_TRAP;

NTSTATUS NTAPI TrRegisterTrap (
  PCPU Cpu,
  PNBP_TRAP Trap
);

NTSTATUS NTAPI TrDeregisterTrap (
  PNBP_TRAP Trap
);

NTSTATUS NTAPI TrTrapDisable (
  PNBP_TRAP Trap
);

NTSTATUS NTAPI TrTrapEnable (
  PNBP_TRAP Trap
);

NTSTATUS NTAPI TrDeregisterTrapList (
  PLIST_ENTRY TrapList
);

NTSTATUS NTAPI TrInitializeGeneralTrap (
  PCPU Cpu,
  ULONG TrappedVmExit,
  UCHAR RipDelta,
  NBP_TRAP_CALLBACK TrapCallback,
  PNBP_TRAP * pInitializedTrap
);

NTSTATUS NTAPI TrInitializeMsrTrap (
  PCPU Cpu,
  ULONG TrappedMsr,
  UCHAR TrappedMsrAccess,
  NBP_TRAP_CALLBACK TrapCallback,
  PNBP_TRAP * pInitializedTrap
);

NTSTATUS NTAPI TrInitializeIoTrap (
  PCPU Cpu,
  ULONG TrappedIoPort,
  NBP_TRAP_CALLBACK TrapCallback,
  PNBP_TRAP * pInitializedTrap
);

NTSTATUS NTAPI TrFindRegisteredTrap (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG64 exitcode,
  PNBP_TRAP * pTrap
);

NTSTATUS NTAPI TrExecuteMsrTrapHandler (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
);

NTSTATUS NTAPI TrExecuteGeneralTrapHandler (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
);

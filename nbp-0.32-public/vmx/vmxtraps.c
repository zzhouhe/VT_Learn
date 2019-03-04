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

#include "vmxtraps.h"
#include "vmx.h"

#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
# include "misc/scancode.h"
#endif

extern PHYSICAL_ADDRESS g_IdentityPageTableBasePhysicalAddress, g_IdentityPageTableBasePhysicalAddress_Legacy;

static BOOLEAN NTAPI VmxDispatchVmxInstrDummy (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len;
  if (!Cpu || !GuestRegs)
    return TRUE;
  _KdPrint (("VmxDispatchVminstructionDummy(): Nested virtualization not supported in this build!\n"));

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  Trap->General.RipDelta = inst_len;

  VmxWrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & (~0x8d5) | 0x1 /* VMFailInvalid */ );
  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchCpuid (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG32 fn, eax, ebx, ecx, edx;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;
  fn = (ULONG32) GuestRegs->rax;

#if DEBUG_LEVEL>1
  _KdPrint (("VmxDispatchCpuid(): Fn 0x%x\n", fn));
#endif

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

#ifdef BP_KNOCK
  if (fn == BP_KNOCK_EAX) {
# if DEBUG_LEVEL>3
    _KdPrint (("Magic knock received: %p\n", BP_KNOCK_EAX));
# endif
    GuestRegs->rax = BP_KNOCK_EAX_ANSWER;
    return TRUE;
  }
#endif

  ecx = (ULONG32) GuestRegs->rcx;
  GetCpuIdInfo (fn, &eax, &ebx, &ecx, &edx);
  GuestRegs->rax = eax;
  GuestRegs->rbx = ebx;
  GuestRegs->rcx = ecx;
  GuestRegs->rdx = edx;

#if DEBUG_LEVEL>2
  _KdPrint (("EXIT_REASON_CPUID fn 0x%x 0x%x 0x%x 0x%x 0x%x \n", fn, eax, ebx, ecx, edx));
#endif
  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchMsrRead (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  LARGE_INTEGER MsrValue;
  ULONG32 ecx;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  ecx = (ULONG32) GuestRegs->rcx;

  switch (ecx) {
  case MSR_IA32_SYSENTER_CS:
    MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_CS);
    break;

  case MSR_IA32_SYSENTER_ESP:
    MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_ESP);
    break;
  case MSR_IA32_SYSENTER_EIP:
    MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_EIP);
    break;
  case MSR_GS_BASE:
    MsrValue.QuadPart = VmxRead (GUEST_GS_BASE);
    break;
  case MSR_FS_BASE:
    MsrValue.QuadPart = VmxRead (GUEST_FS_BASE);
    break;
  case MSR_EFER:
    MsrValue.QuadPart = Cpu->Vmx.GuestEFER;
    //_KdPrint(("Guestip 0x%llx MSR_EFER Read 0x%llx 0x%llx \n",VmxRead(GUEST_RIP),ecx,MsrValue.QuadPart));
    break;
  default:
    MsrValue.QuadPart = MsrRead (ecx);
  }

  GuestRegs->rax = MsrValue.LowPart;
  GuestRegs->rdx = MsrValue.HighPart;

  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchMsrWrite (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  LARGE_INTEGER MsrValue;
  ULONG32 ecx;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  ecx = (ULONG32) GuestRegs->rcx;

  MsrValue.LowPart = (ULONG32) GuestRegs->rax;
  MsrValue.HighPart = (ULONG32) GuestRegs->rdx;

  switch (ecx) {
  case MSR_IA32_SYSENTER_CS:
    VmxWrite (GUEST_SYSENTER_CS, MsrValue.QuadPart);
    break;
  case MSR_IA32_SYSENTER_ESP:
    VmxWrite (GUEST_SYSENTER_ESP, MsrValue.QuadPart);
    break;
  case MSR_IA32_SYSENTER_EIP:
    VmxWrite (GUEST_SYSENTER_EIP, MsrValue.QuadPart);
    break;
  case MSR_GS_BASE:
    VmxWrite (GUEST_GS_BASE, MsrValue.QuadPart);
    break;
  case MSR_FS_BASE:
    VmxWrite (GUEST_FS_BASE, MsrValue.QuadPart);
    break;
  case MSR_EFER:
    //_KdPrint(("Guestip 0x%llx MSR_EFER write 0x%llx 0x%llx\n",VmxRead(GUEST_RIP),ecx,MsrValue.QuadPart)); 
    Cpu->Vmx.GuestEFER = MsrValue.QuadPart;
    MsrWrite (MSR_EFER, (MsrValue.QuadPart) | EFER_LME);
    break;
  default:
    MsrWrite (ecx, MsrValue.QuadPart);
  }

  return TRUE;
}

static VOID VmxUpdateGuestEfer (
  PCPU Cpu
)
{
  if (Cpu->Vmx.GuestEFER & EFER_LMA)
    VmxWrite (VM_ENTRY_CONTROLS, VmxRead (VM_ENTRY_CONTROLS) | (VM_ENTRY_IA32E_MODE));
  else
    VmxWrite (VM_ENTRY_CONTROLS, VmxRead (VM_ENTRY_CONTROLS) & (~VM_ENTRY_IA32E_MODE));
}

//TODO: this function needs to be cleaned up -- too much stuff is commented out
static BOOLEAN NTAPI VmxDispatchCrAccess (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG32 exit_qualification;
  ULONG32 gp, cr;
  ULONG64 value;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

#if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchCrAccess()\n"));
#endif

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  exit_qualification = (ULONG32) VmxRead (EXIT_QUALIFICATION);
  gp = (exit_qualification & CONTROL_REG_ACCESS_REG) >> 8;
  cr = exit_qualification & CONTROL_REG_ACCESS_NUM;

#if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchCrAccess(): gp: 0x%x cr: 0x%x exit_qualification: 0x%x\n", gp, cr, exit_qualification));
#endif

  switch (exit_qualification & CONTROL_REG_ACCESS_TYPE) {
  case TYPE_MOV_TO_CR:
    if (cr == 0) {
      Cpu->Vmx.GuestCR0 = *(((PULONG64) GuestRegs) + gp);
      if ((*(((PULONG64) GuestRegs) + gp)) & X86_CR0_PG)        //enable paging
      {
        //_KdPrint(("VmxDispatchCrAccess():paging\n"));
        VmxWrite (GUEST_CR3, Cpu->Vmx.GuestCR3);
        if (Cpu->Vmx.GuestEFER & EFER_LME)
          Cpu->Vmx.GuestEFER |= EFER_LMA;
        else
          Cpu->Vmx.GuestEFER &= ~EFER_LMA;
      } else                    //disable paging
      {
        //_KdPrint(("VmxDispatchCrAccess():disable paging\n"));                         
        Cpu->Vmx.GuestCR3 = VmxRead (GUEST_CR3);
        VmxWrite (GUEST_CR3, g_IdentityPageTableBasePhysicalAddress_Legacy.QuadPart);
        /*
           if(Cpu->Vmx.GuestMode) //Long Mode
           VmxWrite(GUEST_CR3,g_IdentityPageTableBasePhysicalAddress.QuadPart);         
           else //Legacy Mode
           VmxWrite(GUEST_CR3,g_IdentityPageTableBasePhysicalAddress_Legacy.QuadPart);                          
         */
        Cpu->Vmx.GuestEFER &= ~EFER_LMA;
      }
#ifdef _X86_
      VmxWrite (CR0_READ_SHADOW, (*(((PULONG32) GuestRegs) + gp)) & X86_CR0_PG);
#else
      VmxWrite (CR0_READ_SHADOW, (*(((PULONG64) GuestRegs) + gp)) & X86_CR0_PG);
#endif
      VmxUpdateGuestEfer (Cpu);
      return FALSE;
    }

    if (cr == 3) {
      Cpu->Vmx.GuestCR3 = *(((PULONG64) GuestRegs) + gp);

      if (Cpu->Vmx.GuestCR0 & X86_CR0_PG)       //enable paging
      {
#if DEBUG_LEVEL>2
        _KdPrint (("VmxDispatchCrAccess(): TYPE_MOV_TO_CR cr3:0x%x\n", *(((PULONG64) GuestRegs) + gp)));
#endif
#ifdef _X86_
        VmxWrite (GUEST_CR3, *(((PULONG32) GuestRegs) + gp));
#else
        VmxWrite (GUEST_CR3, *(((PULONG64) GuestRegs) + gp));
#endif
      }
      return TRUE;
    }
    if (cr == 4) {

      //if(debugmode)
      //_KdPrint(("VmxDispatchCrAccess(): TYPE_MOV_TO_CR Cpu->Vmx.GuestEFER:0x%x Cpu->Vmx.GuestCR0:0x%x cr4:0x%x\n",Cpu->Vmx.GuestEFER,Cpu->Vmx.GuestCR0,*(((PULONG64)GuestRegs)+gp)));
      //Nbp need enabele VMXE. so guest try to clear cr4_vmxe, it would be mask.
#ifdef _X86_
      VmxWrite (CR4_READ_SHADOW, (*(((PULONG32) GuestRegs) + gp)) & (X86_CR4_VMXE | X86_CR4_PAE));
      Cpu->Vmx.GuestCR4 = *(((PULONG32) GuestRegs) + gp);
      VmxWrite (GUEST_CR4, (*(((PULONG32) GuestRegs) + gp)) | X86_CR4_VMXE);

#else
      //VmxWrite(CR4_READ_SHADOW, (*(((PULONG64)GuestRegs)+gp)) & (X86_CR4_VMXE|X86_CR4_PAE|X86_CR4_PSE));
      VmxWrite (CR4_READ_SHADOW, (*(((PULONG64) GuestRegs) + gp)) & (X86_CR4_VMXE));

      Cpu->Vmx.GuestCR4 = *(((PULONG64) GuestRegs) + gp);
      VmxWrite (GUEST_CR4, (*(((PULONG64) GuestRegs) + gp)) | X86_CR4_VMXE);
#endif

      return FALSE;

    }
    break;
  case TYPE_MOV_FROM_CR:
    if (cr == 3) {
      value = Cpu->Vmx.GuestCR3;
#if DEBUG_LEVEL>2
      _KdPrint (("VmxDispatchCrAccess(): TYPE_MOV_FROM_CR cr3:0x%x\n", value));
#endif
#ifdef _X86_
      *(((PULONG32) GuestRegs) + gp) = (ULONG32) value;
#else
      *(((PULONG64) GuestRegs) + gp) = value;
#endif
    }
    break;
  case TYPE_CLTS:
    break;
  case TYPE_LMSW:
    break;
  }

  return TRUE;
}

#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
static EjectCdrom (
  ULONG32 port
)
{
  CmIOOut (port + 7, 0xa0);
  CmIOOut (port, 0x1b);
  CmIOOut (port, 0);
  CmIOOut (port, 0);
  CmIOOut (port, 0);
  CmIOOut (port, 2);
  CmIOOut (port, 0);
}

static BOOLEAN NTAPI VmxDispatchIoAccess (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG32 exit_qualification;
  ULONG32 port, size;
  ULONG32 dir, df, vm86;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  exit_qualification = (ULONG32) VmxRead (EXIT_QUALIFICATION);
  init_scancode ();

  if (CmIsBitSet (exit_qualification, 6))
    port = (exit_qualification >> 16) & 0xFFFF;
  else
    port = ((ULONG32) (GuestRegs->rdx)) & 0xffff;

  size = (exit_qualification & 7) + 1;
  dir = CmIsBitSet (exit_qualification, 3);     /* direction */
  if (dir) {                    //in

    GuestRegs->rax = CmIOIn (port);
    if (port == 0x64) {
      if (GuestRegs->rax & 0x20)
        ps2mode = 0x1;          //mouse
      else
        ps2mode = 0;            //mouse
    }
    if (ps2mode == 0x0 && port == 0x60 && (GuestRegs->rax & 0xff) < 0x80) {
      _KdPrint (("IO 0x%x IN 0x%x %c \n", port, GuestRegs->rax, scancode[GuestRegs->rax & 0xff]));
# ifdef _X86_
      Cpu->Vmx.GuestVMCS.GUEST_ES_SELECTOR = 0;
# endif
    }

  } else {                      //out

    if (size == 1)
      CmIOOutB (port, (ULONG32) GuestRegs->rax);
    if (size == 2)
      CmIOOutW (port, (ULONG32) GuestRegs->rax);
    if (size == 4)
      CmIOOutD (port, (ULONG32) GuestRegs->rax);

    _KdPrint (("IO 0x%x OUT 0x%x size 0x%x\n", port, GuestRegs->rax, size));
  }

  return TRUE;
}
#endif

#ifdef INTERCEPT_RDTSCs
static BOOLEAN NTAPI VmxDispatchRdtsc (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

# if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchRdtsc(): RDTSC intercepted, RIP: 0x%p\n", VmxRead (GUEST_RIP)));
# endif
  if (Cpu->Tracing > 0) {
    Cpu->Tsc = Cpu->EmulatedCycles + Cpu->LastTsc;
  } else {
    Cpu->Tsc = RegGetTSC ();
  }

# if DEBUG_LEVEL>2
  _KdPrint ((" Tracing = %d, LastTsc = %p, EmulatedCycles = %p, Tsc = %p\n",
             Cpu->Tracing, Cpu->LastTsc, Cpu->EmulatedCycles, Cpu->Tsc));
# endif

  Cpu->LastTsc = Cpu->Tsc;
  Cpu->EmulatedCycles = 0;
  Cpu->NoOfRecordedInstructions = 0;
  Cpu->Tracing = INSTR_TRACE_MAX;

  GuestRegs->rdx = (size_t) (Cpu->Tsc >> 32);
  GuestRegs->rax = (size_t) (Cpu->Tsc & 0xffffffff);
  VmxWrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) | 0x100);      // set TF

  return TRUE;
}

// FIXME: This looks like it needs reviewing -- compare with the SvmDispatchDB
static BOOLEAN NTAPI VmxDispatchException (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len, uIntrInfo;

  if (!Cpu || !GuestRegs)
    return TRUE;

  uIntrInfo = VmxRead (VM_EXIT_INTR_INFO);
  if ((uIntrInfo & 0xff) != 1)
    // we accept only #DB here
    return TRUE;

# if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchException(): DB intercepted, RIP: 0x%p, INTR_INFO 0x%p, flags 0x%p, II 0x%p, PD 0x%p\n",
             VmxRead (GUEST_RIP), VmxRead (VM_EXIT_INTR_INFO), VmxRead (GUEST_RFLAGS),
             VmxRead (GUEST_INTERRUPTIBILITY_INFO), VmxRead (GUEST_PENDING_DBG_EXCEPTIONS)));
# endif

  VmxWrite (GUEST_INTERRUPTIBILITY_INFO, 0);
  // FIXME: why is this commented?
//      if (RegGetDr6() & 0x40) {

# if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchException(): DB intercepted, RIP: 0x%p\n", VmxRead (GUEST_RIP)));
# endif

  Cpu->EmulatedCycles += 6;     // TODO: replace with f(Opcode)
  if (Cpu->Tracing-- <= 0)
    VmxWrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & ~0x100);   // disable TF

  Cpu->NoOfRecordedInstructions++;
  //TODO: add instruction opcode to Cpu->RecordedInstructions[]

//      }       

  return TRUE;
}
#endif

static BOOLEAN NTAPI VmxDispatchINVD (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  return TRUE;
}

//
// ------------------------------------------------------------------------------------
//

NTSTATUS NTAPI VmxRegisterTraps (
  PCPU Cpu
)
{
  NTSTATUS Status;
  PNBP_TRAP Trap;
#ifndef VMX_SUPPORT_NESTED_VIRTUALIZATION
  // used to set dummy handler for all VMX intercepts when we compile without nested support
  ULONG32 i, TableOfVmxExits[] = {
    EXIT_REASON_VMCALL,
    EXIT_REASON_VMCALL,
    EXIT_REASON_VMLAUNCH,
    EXIT_REASON_VMRESUME,
    EXIT_REASON_VMPTRLD,
    EXIT_REASON_VMPTRST,
    EXIT_REASON_VMREAD,
    EXIT_REASON_VMWRITE,
    EXIT_REASON_VMXON,
    EXIT_REASON_VMXOFF
  };
#endif

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_CPUID, 0, // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchCpuid, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchCpuid with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_MSR_READ, 0,      // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchMsrRead, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchMsrRead with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_MSR_WRITE, 0,     // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchMsrWrite, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchMsrWrite with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_CR_ACCESS, 0,     // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchCrAccess, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchCrAccess with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_INVD, 0,  // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchINVD, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchINVD with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  // set dummy handler for all VMX intercepts if we compile wihtout nested support
  for (i = 0; i < sizeof (TableOfVmxExits) / sizeof (ULONG32); i++) {
    if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, TableOfVmxExits[i], 0,      // length of the instruction, 0 means length need to be get from vmcs later. 
                                                       VmxDispatchVmxInstrDummy, &Trap))) {
      _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchVmon with status 0x%08hX\n", Status));
      return Status;
    }
    TrRegisterTrap (Cpu, Trap);
  }

#ifdef INTERCEPT_RDTSCs
  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_EXCEPTION_NMI, 0, VmxDispatchException, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchException with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_RDTSC, 0, VmxDispatchRdtsc, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchRdtsc with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
#endif
#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_IO_INSTRUCTION, 0,        // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchIoAccess, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchIoAccess with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
#endif

  return STATUS_SUCCESS;
}

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

#include "svmtraps.h"

static BOOLEAN NTAPI SvmDispatchVmload (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb, GuestVmcb;
  PHYSICAL_ADDRESS GuestVmcbPA;
  NTSTATUS Status;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    // TODO: Handle NestedNested scenario
    _KdPrint (("Upsss... SvmDispatchVmload() called in a NestedNested scenario. Pass through...\n"));
    return FALSE;
  }

  Vmcb = Cpu->Svm.OriginalVmcb;
  GuestVmcbPA.QuadPart = Vmcb->rax;

#if DEBUG_LEVEL>1
  _KdPrint (("SvmDispatchVmload(): VMLOAD intercepted, RIP = 0x%p, VMCB_PA: 0x%p\n", Vmcb->rip, Vmcb->rax));
#endif

  // FIXME: Check for errors and inject #UD or #GP

  SvmVmload (GuestVmcbPA);
  // FIXME: This might allow to DoS a primary hypervisor -- use "full" VMLOAD emulation for full VMMs
  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchVmsave (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb, GuestVmcb;
  PHYSICAL_ADDRESS GuestVmcbPA;
  NTSTATUS Status;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    // TODO: Handle NestedNested scenario
    _KdPrint (("Upsss... SvmDispatchVmsave() called in a NestedNested scenario. Pass through...\n"));
    return FALSE;
  }

  Vmcb = Cpu->Svm.OriginalVmcb;
  GuestVmcbPA.QuadPart = Vmcb->rax;

#if DEBUG_LEVEL>1
  _KdPrint (("SvmDispatchVmsave(): VMSAVE intercepted, RIP = 0x%p, VMCB_PA: 0x%p\n", Vmcb->rip, Vmcb->rax));
#endif
  // FIXME: Check for errors and inject #UD or #GP

  SvmVmsave (GuestVmcbPA);
  // FIXME: This might allow to DoS a primary hypervisor -- use "full" VMSAVE emulation for full VMMs
  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchClgi (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    // TODO: Handle NestedNested scenario
    _KdPrint (("Upsss... SvmDispatchClgi() called in a NestedNested scenario. Pass through...\n"));
    return FALSE;

  }
  // FIXME: Check for errors and inject #UD or #GP

  Vmcb = Cpu->Svm.OriginalVmcb;
#if DEBUG_LEVEL>1
  _KdPrint (("SvmDispatchClgi(): RIP = %p\n", Vmcb->rip));
#endif
  SvmEmulateGif0ForGuest (Cpu);
  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchStgi (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  ULONG32 i;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    // TODO: Handle NestedNested scenario
    _KdPrint (("Upsss... SvmDispatchStgi() called in a NestedNested scenario. Pass through...\n"));
    return FALSE;

  }
  // FIXME: Check for errors and inject #UD or #GP

  Vmcb = Cpu->Svm.OriginalVmcb;
#if DEBUG_LEVEL>1
  _KdPrint (("SvmDispatchStgi(): RIP = %p\n", Vmcb->rip));
#endif
  SvmEmulateGif1ForGuest (Cpu);
  return TRUE;

}

#if DEBUG_LEVEL>1
VOID NTAPI SvmDumpVmcbIntercepts (
  PCHAR Name,
  PVMCB Vmcb
)
{
  int i, ByteNo;
  UCHAR Byte, BitNo;
  int NoOfIntercepts = 0;
  ULONG32 InterceptedVmexit[SVM_MAX_GUEST_VMEXIT + 1];
  CHAR str[1024], str2[8];

  for (ByteNo = 0; ByteNo <= 0x10; ByteNo++) {
    for (BitNo = 0; BitNo < 8; BitNo++) {
      Byte = *(((PCHAR) Vmcb) + ByteNo);
      if (CmIsBitSet ((ULONG32) Byte, BitNo)) {
        InterceptedVmexit[NoOfIntercepts++] = (ByteNo * 8) + BitNo;
      }

    }

  }

  snprintf (str, sizeof (str), "Intercepted VMEXITs in %s:", Name);
  for (i = 0; i < NoOfIntercepts; i++) {
    snprintf (str2, sizeof (str2), "%x,", InterceptedVmexit[i]);
    strcat (str, str2);
  }
  strcat (str, "\n");
  _KdPrint ((str));

}
#endif

static BOOLEAN NTAPI SvmDispatchVmrun (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  NTSTATUS Status;
  PHYSICAL_ADDRESS GuestMsrPmPA;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    // TODO: Handle NestedNested scenario
    _KdPrint (("Upsss... SvmDispatchVmrun() called in a NestedNested scenario. Pass through...\n"));
    return FALSE;

  }
  // FIXME: Check for errors and inject #UD or #GP

  Vmcb = Cpu->Svm.OriginalVmcb;

#if DEBUG_LEVEL>1
  _KdPrint (("SvmDispatchVmrun(): VMRUN intercepted, RIP = 0x%p, VMCB_PA: 0x%p\n", Vmcb->rip, Vmcb->rax));

# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchVmrun(): VMRUN RIP: 0x%p\n", Vmcb->rip));
  _KdPrint (("SvmDispatchVmrun(): GS_BASE: 0x%p\n", MsrRead (MSR_GS_BASE)));
  _KdPrint (("SvmDispatchVmrun(): SHADOW_GS_BASE: 0x%p\n", MsrRead (MSR_SHADOW_GS_BASE)));
  _KdPrint (("SvmDispatchVmrun(): KernGSBase: 0x%p\n", Vmcb->kerngsbase));
  _KdPrint (("SvmDispatchVmrun(): efer: 0x%p\n", Vmcb->efer));
  _KdPrint (("SvmDispatchVmrun(): fs.base: 0x%p\n", Vmcb->fs.base));
  _KdPrint (("SvmDispatchVmrun(): gs.base: 0x%p\n", Vmcb->gs.base));
  _KdPrint (("SvmDispatchVmrun(): cr2: 0x%p\n", Vmcb->cr2));
  _KdPrint (("SvmDispatchVmrun(): original ss.base: 0x%p\n", Cpu->Svm.OriginalVmcb->ss.base));
  _KdPrint (("SvmDispatchVmrun(): original rsp: 0x%p\n", Cpu->Svm.OriginalVmcb->rsp));

  _KdPrint (("SvmDispatchVmrun(): original es.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->es.sel,
             Cpu->Svm.OriginalVmcb->es.base, Cpu->Svm.OriginalVmcb->es.limit));
  _KdPrint (("SvmDispatchVmrun(): original cs.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->cs.sel,
             Cpu->Svm.OriginalVmcb->cs.base, Cpu->Svm.OriginalVmcb->cs.limit));
  _KdPrint (("SvmDispatchVmrun(): original ss.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->ss.sel,
             Cpu->Svm.OriginalVmcb->ss.base, Cpu->Svm.OriginalVmcb->ss.limit));
  _KdPrint (("SvmDispatchVmrun(): original ds.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->ds.sel,
             Cpu->Svm.OriginalVmcb->ds.base, Cpu->Svm.OriginalVmcb->ds.limit));
  _KdPrint (("SvmDispatchVmrun(): original fs.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->fs.sel,
             Cpu->Svm.OriginalVmcb->fs.base, Cpu->Svm.OriginalVmcb->fs.limit));
  _KdPrint (("SvmDispatchVmrun(): original gs.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->gs.sel,
             Cpu->Svm.OriginalVmcb->gs.base, Cpu->Svm.OriginalVmcb->gs.limit));

  _KdPrint (("SvmDispatchVmrun(): original gdtr.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->gdtr.sel,
             Cpu->Svm.OriginalVmcb->gdtr.base, Cpu->Svm.OriginalVmcb->gdtr.limit));
  _KdPrint (("SvmDispatchVmrun(): original ldtr.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->ldtr.sel,
             Cpu->Svm.OriginalVmcb->ldtr.base, Cpu->Svm.OriginalVmcb->ldtr.limit));
  _KdPrint (("SvmDispatchVmrun(): original idtr.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->idtr.sel,
             Cpu->Svm.OriginalVmcb->idtr.base, Cpu->Svm.OriginalVmcb->idtr.limit));
  _KdPrint (("SvmDispatchVmrun(): original tr.sel: 0x%x, base: 0x%x, limit 0x%x\n", Cpu->Svm.OriginalVmcb->tr.sel,
             Cpu->Svm.OriginalVmcb->tr.base, Cpu->Svm.OriginalVmcb->tr.limit));
# endif
#endif

  if (!Cpu->Svm.bGuestSVME) {
    _KdPrint (("SvmDispatchVmrun(): Guest hasn't turned on SVME bit, injecting #UD\n"));
    SvmInjectEvent (Vmcb, EV_INVALID_OPCODE, GE_EXCEPTION, FALSE, 0);
    return FALSE;
  }
  // rax should be 4k-aligned already.
  // Save it so we can set guest hypervisor's rax to "real" VMCB PA to handle guest's #VMEXIT
  Cpu->Svm.GuestVmcbPA.QuadPart = Vmcb->rax;
#ifdef SVM_USE_NESTEDVMCB_REWRITING
  // copy & patch the guest hypervisor's guest VMCB

  if (!NT_SUCCESS
      (Status = HvmCopyPhysicalToVirtual (Cpu, Cpu->Svm.NestedVmcb, Cpu->Svm.GuestVmcbPA, SVM_VMCB_SIZE_IN_PAGES))) {

    _KdPrint (("SvmDispatchVmrun(): Failed to read guest VMCB, status 0x%08hX\n", Status));

    // continue the nested VM
    Cpu->Svm.VmcbToContinuePA.QuadPart = Vmcb->rax;
    return TRUE;
  }
  // Check only VMRUN interception; skip all other consistency checks mentioned in AMD man. 15.5, p. 360-361 -
  // all other bogus conditions will be checked by the CPU itself on our VMRUN, we'll just pass VMEXIT_INVALID
  // to the guest if something goes wrong.
  if (!(Cpu->Svm.NestedVmcb->general2_intercepts & 1)) {
    _KdPrint (("SvmDispatchVmrun(): Guest doesn't want to intercept VMRUN, returning VMEXIT_INVALID\n"));

    Vmcb->exitcode = VMEXIT_INVALID;
    return TRUE;
  }
#endif
  SvmEmulateGif1ForNestedGuest (Cpu);

  /* TODO: This is probably only needed when GuestVmcb.v_intr_masking == 1 */
  {

    if (Cpu->Svm.OriginalVmcb->vintr.fields.intr_masking == 1) {
      RegSetCr8 (Cpu->Svm.OriginalVmcb->vintr.fields.tpr);
    }

    if (Cpu->Svm.OriginalVmcb->rflags & X86_EFLAGS_IF)
      CmSti ();
    else
      CmCli ();
  }

#ifdef SVM_USE_NESTEDVMCB_REWRITING
  // apply all our traps to the guest vmcb
  if (!NT_SUCCESS (Status = SvmSetupGeneralInterceptions (Cpu, Cpu->Svm.NestedVmcb))) {
    _KdPrint (("SvmDispatchVmrun(): *** SvmSetupGeneralInterceptions() failed with status 0x%08hX, continuing ***\n",
               Status));
  }
#endif

#if 0                           // FIXME: right now we don't need this, but a full VMM most likely would need that (the code below shoudl work fine)
  // copy & patch the guest MSRPM
# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchVmrun(): Guest VMCB: TLB_CONTROL = 0x%x\n", Cpu->Svm.NestedVmcb->tlb_control));
  _KdPrint (("SvmDispatchVmrun(): Guest VMCB: V_INTR = 0x%x\n", Cpu->Svm.NestedVmcb->vintr.UCHARs));
  _KdPrint (("SvmDispatchVmrun(): Guest VMCB: V_INTR_MASKING = 0x%x\n",
             Cpu->Svm.NestedVmcb->vintr.fields.intr_masking));
  _KdPrint (("SvmDispatchVmrun(): Guest VMCB: V_TPR = 0x%x\n", Cpu->Svm.NestedVmcb->vintr.fields.tpr));
  _KdPrint (("SvmDispatchVmrun(): Guest VMCB: rflags = 0x%x\n", Cpu->Svm.NestedVmcb->rflags));
  if (Cpu->Svm.NestedVmcb->eventinj.fields.v)
    _KdPrint (("SvmDispatchVmrun(): Guest VMCB: EVENTINJ: vec = 0x%x, type = 0x%x, ev = %x, v = %x, errorcode = 0x%x\n",
               Cpu->Svm.NestedVmcb->eventinj.fields.vector, Cpu->Svm.NestedVmcb->eventinj.fields.type,
               Cpu->Svm.NestedVmcb->eventinj.fields.ev, Cpu->Svm.NestedVmcb->eventinj.fields.v,
               Cpu->Svm.NestedVmcb->eventinj.fields.errorcode));
# endif

  GuestMsrPmPA.QuadPart = Cpu->Svm.NestedVmcb->msrpm_base_pa;

# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchVmrun(): Guest MSRPM PA: 0x%X\n", GuestMsrPmPA.QuadPart));
# endif

  if (GuestMsrPmPA.QuadPart) {
    // guest has specified a MsrPm, patch it to intercept all what we need

    if (!NT_SUCCESS
        (Status = HvmCopyPhysicalToVirtual (Cpu, Cpu->Svm.NestedMsrPm, GuestMsrPmPA, SVM_MSRPM_SIZE_IN_PAGES))) {

      _KdPrint (("SvmDispatchVmrun(): Failed to read guest MSRPM, status 0x%08hX\n", Status));

      // continue the nested VM
      Cpu->Svm.VmcbToContinuePA.QuadPart = Vmcb->rax;
      return TRUE;
    }

  } else {
    // guest hypervisor doesn't want to intercept any MSR rw, but we have to.
    // Indicate we want to trap nothing else but EFER and VM_HSAVE_PA rw.
    _KdPrint (("SvmDispatchVmrun(): Upsss! Guest h/v doesn't intercept EFER access!\n"));
    RtlZeroMemory (Cpu->Svm.NestedMsrPm, SVM_MSRPM_SIZE_IN_PAGES * PAGE_SIZE);
    // TODO: set EFER bits!!!
  }
  // apply all our traps to the guest msrpm
  if (!NT_SUCCESS (Status = SvmSetupMsrInterceptions (Cpu, Cpu->Svm.NestedMsrPm))) {
    _KdPrint (("SvmDispatchVmrun(): *** VmcbSetupMsrInterceptions() failed with status 0x%08hX, continuing ***\n",
               Status));
  }

  Cpu->Svm.NestedVmcb->msrpm_base_pa = Cpu->Svm.NestedMsrPmPA.QuadPart;

#endif

#if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchVmrun(): Guest guest_asid: %d, TLB_CONTROL %d\n",
             Cpu->Svm.NestedVmcb->guest_asid, Cpu->Svm.NestedVmcb->tlb_control));
#endif
#ifdef SVM_USE_NESTEDVMCB_REWRITING

  if (Cpu->Svm.NestedVmcb->guest_asid < Cpu->Svm.AsidMaxNo) {
# ifdef SVM_ALWAYS_FLUSH_TLB
    Cpu->Svm.NestedVmcb->tlb_control = 1;
# else
    if (Cpu->Svm.Erratum170)
      Cpu->Svm.NestedVmcb->tlb_control = 1;     // Flush it anyway -- the CPU is buggy!
    //else Cpu->Svm.NestedVmcb->tlb_control=0;      // if the guest wants to use TLB_FLUSHING, don't change that...
# endif
  } else {                      // ASID = Cpu->Svm.AsidMaxNo is used by the nested hypervisor
# if DEBUG_LEVEL>2
    _KdPrint (("ASID pool exhausted: Nested Hypervisor is trying to run guest with ASID = %d that is used by the nested hypervisor itself.\n", Cpu->Svm.NestedVmcb->guest_asid));

    _KdPrint (("Setting tlb_control = 1 (flushing) for the nested guest\n"));
# endif
    Cpu->Svm.NestedVmcb->tlb_control = 1;
  }

  // continue the nested VMCB
  Cpu->Svm.VmcbToContinuePA.QuadPart = Cpu->Svm.NestedVmcbPA.QuadPart;
#else
  // continue the original guest VMCB
  Cpu->Svm.VmcbToContinuePA.QuadPart = Cpu->Svm.GuestVmcbPA.QuadPart;
#endif

#if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchVmrun(): Continuing nested VM (VMCB_PA 0x%p)\n", Cpu->Svm.VmcbToContinuePA.QuadPart));
  _KdPrint (("SvmDispatchVmrun(): Nested efer: 0x%p\n", Cpu->Svm.NestedVmcb->efer));
  SvmDumpVmcbIntercepts ("OriginalVmcb", Cpu->Svm.OriginalVmcb);
  SvmDumpVmcbIntercepts ("NestedVmcb", Cpu->Svm.NestedVmcb);
  _KdPrint (("SvmDispatchVmrun(): First RIP: 0x%p\n", Cpu->Svm.NestedVmcb->rip));
  _KdPrint (("SvmDispatchVmrun(): Nested kerngsbase: 0x%p\n", Cpu->Svm.NestedVmcb->kerngsbase));
  _KdPrint (("SvmDispatchVmrun(): Nested fs.base: 0x%p\n", Cpu->Svm.NestedVmcb->fs.base));
  _KdPrint (("SvmDispatchVmrun(): Nested gs.base: 0x%p\n", Cpu->Svm.NestedVmcb->gs.base));
  _KdPrint (("SvmDispatchVmrun(): Nested cr2: 0x%p\n", Cpu->Svm.NestedVmcb->cr2));
#endif

  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchEFERAccess (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  ULONG32 eax, edx;
  LARGE_INTEGER Efer;
  BOOLEAN bWriteAccess, bIsSVMEOn, bTimeAttack;
#ifdef SVM_AUTOREMOVE_EFER_TRAP
  BOOLEAN bOLdMsrEferIntercept;
#endif

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv)
    return FALSE;               // let the nested hv do the rest

  Vmcb = Cpu->Svm.OriginalVmcb;
  eax = (ULONG32) (Vmcb->rax & 0xffffffff);
  edx = (ULONG32) (GuestRegs->rdx & 0xffffffff);

  bWriteAccess = (BOOLEAN) (Vmcb->exitinfo1 == (MSR_INTERCEPT_WRITE >> 1));

  switch (bWriteAccess) {
  case FALSE:

    // it's a RDMSR(MSR_EFER)

    Efer.QuadPart = Vmcb->efer;

    // clear SVME if it has not been set by the guest hypervisor
    if (!Cpu->Svm.bGuestSVME)
      Efer.LowPart &= ~EFER_SVME;

#if DEBUG_LEVEL>2
    _KdPrint (("SvmDispatchEFERAccess(): EFER Read: returning virtual value: 0x%p\n", Efer.QuadPart));
#endif
    Vmcb->rax = Efer.LowPart;
    GuestRegs->rdx = Efer.HighPart;
    break;

  default:                     // it's a WRMSR(MSR_EFER)

    // FIXME: Check for errors and inject #GP if bad value

    Efer.QuadPart = (((ULONG64) edx) << 32) + eax;
    bIsSVMEOn = (BOOLEAN) ((Efer.LowPart & EFER_SVME) != 0);

#if DEBUG_LEVEL>2

    _KdPrint (("SvmDispatchEFERAccess(): EFER Write: guest writes: 0x%p\n", Efer.QuadPart));
#endif
    Vmcb->efer = Efer.QuadPart;
    Vmcb->efer |= EFER_SVME;    // the guest must always have SVME

    if (Cpu->Svm.bGuestSVME != bIsSVMEOn) {
#if DEBUG_LEVEL>1
      _KdPrint (("SvmDispatchEFERAccess(): EFER = 0x%p, turning guest SVME %s\n", Efer.QuadPart,
                 bIsSVMEOn ? "on" : "off"));
#endif

#ifdef SVM_AUTOREMOVE_EFER_TRAP

      if (!Cpu->Svm.bGuestSVME && bIsSVMEOn) {
        _KdPrint (("SvmDispatchEFERAccess(): Guest turned SVME on, removing MSR_EFER intercepts\n"));
        if (!NT_SUCCESS (SvmInterceptMsr (Cpu->Svm.OriginalMsrPm, MSR_EFER, 0, &bOLdMsrEferIntercept))) {
          _KdPrint (("SvmDispatchEFERAccess(): SvmInterceptMsr() failed!\n"));
        } else {                // if successfully disabled MSR EFER in the bitmap
          TrTrapDisable (Cpu->Svm.TrapMsrEfer);
        }
      }
#endif

      Cpu->Svm.bGuestSVME = bIsSVMEOn;
    }

    break;
  }

  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchVM_HSAVE_PAAccess (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  ULONG32 eax, edx;
  BOOLEAN bWriteAccess;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    // TODO: Handle NestedNested scenario
    _KdPrint (("Upsss... SvmDispatchVM_HSAVE_PAAccess() called in a NestedNested scenario. Pass through...\n"));
    return FALSE;

  }

  Vmcb = Cpu->Svm.OriginalVmcb;
#if DEBUG_LEVEL>1
  _KdPrint (("SvmDispatchVM_HSAVE_PAAccess(): RIP = %p\n", Vmcb->rip));
#endif
  eax = (ULONG32) (Vmcb->rax & 0xffffffff);
  edx = (ULONG32) (GuestRegs->rdx & 0xffffffff);

  bWriteAccess = (BOOLEAN) (Vmcb->exitinfo1 == (MSR_INTERCEPT_WRITE >> 1));

  switch (bWriteAccess) {
  case FALSE:

    // it's a RDMSR(MSR_VM_HSAVE_PA)

    Vmcb->rax = Cpu->Svm.GuestHsaPA.LowPart;
    GuestRegs->rdx = Cpu->Svm.GuestHsaPA.HighPart;
#if DEBUG_LEVEL>1
    _KdPrint (("SvmDispatchVM_HSAVE_PAAccess(): Read Access: returning virtualized value = %p\n",
               Cpu->Svm.GuestHsaPA.QuadPart));
#endif
    break;

  default:                     // it's a WRMSR(MSR_VM_HSAVE_PA)

    // FIXME: Check for errors and inject #GP if bad value

    Cpu->Svm.GuestHsaPA.QuadPart = ((ULONG64) edx << 32) + eax;

#if DEBUG_LEVEL>1
    _KdPrint (("SvmDispatchVM_HSAVE_PAAccess(): Write Access --> new value written by guest = 0x%X, virtualizing it\n",
               Cpu->Svm.GuestHsaPA.QuadPart));
#endif
    // don't allow guest to modify real VM_HSAVE_PA
    break;
  }

  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchSMI (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;

  if (!Cpu || !GuestRegs)
    return FALSE;

  Vmcb = Cpu->Svm.OriginalVmcb;

#if DEBUG_LEVEL>0
  _KdPrint (("SvmDispatchSMI(): RIP = %p\n", Vmcb->rip));
#endif
  // TODO: to be consitent with the GIF=0 semantics we should collect all SMIs that occured and
  // then injcet them back to the nested hypervisor when it executes STGI or VMRUN
  return FALSE;
}

#ifndef INTERCEPT_RDTSCs
static BOOLEAN NTAPI SvmDispatchDB (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  if (!Cpu || !GuestRegs)
    return TRUE;

  Vmcb = Cpu->Svm.OriginalVmcb;
# if DEBUG_LEVEL>0
  _KdPrint (("SvmDispatchDB(): RIP = %p\n", Vmcb->rip));
# endif
  return FALSE;
}
#endif

//
// --------------------- Some optional stuff ----------------------
//

#ifdef BP_KNOCK
static BOOLEAN NTAPI SvmDispatchCpuid (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  ULONG32 fn;
  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    // TODO: handle the nested scenario
  }

  Vmcb = Cpu->Svm.OriginalVmcb;
# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchCpuid(): CPUID intercepted, RIP: 0x%p, RAX: 0x%p\n", Vmcb->rip, Vmcb->rax));
# endif

  if ((Vmcb->rax & 0xffffffff) == BP_KNOCK_EAX) {
    _KdPrint (("Magic knock received: %p\n", BP_KNOCK_EAX));
    Vmcb->rax = BP_KNOCK_EAX_ANSWER;
  } else {

# ifdef ENABLE_HYPERCALLS
    if (((GuestRegs->rdx & 0xffff0000) == (NBP_MAGIC & 0xffff0000))
        && ((GuestRegs->rcx & 0xffffffff) == NBP_MAGIC + 1)) {
      HcDispatchHypercall (Cpu, GuestRegs);
      return TRUE;
    }
# endif

    fn = (ULONG32) Vmcb->rax;
    GetCpuIdInfo (fn, &(ULONG32) Vmcb->rax, &(ULONG32) GuestRegs->rbx,
                  &(ULONG32) GuestRegs->rcx, &(ULONG32) GuestRegs->rdx);
  }

  return TRUE;
}
#endif

#ifdef INTERCEPT_RDTSCs
static BOOLEAN NTAPI SvmDispatchDB (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    return FALSE;
  }

  Vmcb = Cpu->Svm.OriginalVmcb;

  if (Vmcb->dr6 & 0x40) {
    Cpu->EmulatedCycles += 6;   // TODO: replace with f(Opcode)
    if (Cpu->Tracing-- <= 0)
      Vmcb->rflags ^= 0x100;    // disable TF

    Cpu->NoOfRecordedInstructions++;
    //TODO: add instruction opcode to Cpu->RecordedInstructions[]

  }
# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchGP(): DB intercepted, RIP: 0x%p\n", Vmcb->rip));

  _KdPrint (("SvmDispatchGP(): GS_BASE: 0x%p\n", MsrRead (MSR_GS_BASE)));
  _KdPrint (("SvmDispatchGP(): SHADOW_GS_BASE: 0x%p\n", MsrRead (MSR_SHADOW_GS_BASE)));
  _KdPrint (("SvmDispatchGP(): KernGSBase: 0x%p\n", Vmcb->kerngsbase));
  _KdPrint (("SvmDispatchGP(): efer: 0x%p\n", Vmcb->efer));
  _KdPrint (("SvmDispatchGP(): fs.base: 0x%p\n", Vmcb->fs.base));
  _KdPrint (("SvmDispatchGP(): gs.base: 0x%p\n", Vmcb->gs.base));
  _KdPrint (("SvmDispatchGP(): cr2: 0x%p\n", Vmcb->cr2));
# endif

  return FALSE;
}

static BOOLEAN NTAPI SvmDispatchRdtsc (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  ULONG64 Tsc;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    return FALSE;
  }

  Vmcb = Cpu->Svm.OriginalVmcb;
  // WARNING: Do not uncomment KdPrint's -- it will freeze the system due to interference with OS secheduling!
# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchRdtscp(): RDTSCP intercepted, RIP: 0x%p\n", Vmcb->rip));
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

# ifndef _X86_
  GuestRegs->rdx = (Cpu->Tsc >> 32);
# endif
  Vmcb->rax = (Cpu->Tsc & 0xffffffff);
  Vmcb->rflags |= 0x100;        // set TF

  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchRdtscp (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  if (!Cpu || !GuestRegs)
    return TRUE;

  Vmcb = Cpu->Svm.OriginalVmcb;

  if (WillBeAlsoHandledByGuestHv) {
    return FALSE;
  }
# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchRdtscp(): RDTSCP intercepted, RIP: 0x%p\n", Vmcb->rip));
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

# ifndef _X86_
  GuestRegs->rdx = (Cpu->Tsc >> 32);
# endif
  Vmcb->rax = (Cpu->Tsc & 0xffffffff);
  Vmcb->rflags |= 0x100;        // set TF
  // FIXME: load guests's ECX with TSC_AUX!

  return TRUE;
}

static BOOLEAN NTAPI SvmDispatchMsrTscRead (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  PVMCB Vmcb;
  ULONG32 eax, edx;

  if (!Cpu || !GuestRegs)
    return TRUE;

  if (WillBeAlsoHandledByGuestHv) {
    return FALSE;
  }

  Vmcb = Cpu->Svm.OriginalVmcb;
# if DEBUG_LEVEL>2
  _KdPrint (("SvmDispatchMsrTscRead(): RDMSR 10h intercepted, RIP: 0x%p\n", Vmcb->rip));
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

# ifndef _X86_
  GuestRegs->rdx = (Cpu->Tsc >> 32);
# endif
  Vmcb->rax = (Cpu->Tsc & 0xffffffff);
  Vmcb->rflags |= 0x100;        // set TF
  return TRUE;
}
#endif // INTERCEPT_RDTSCs

//
// ------------------------------------------------------------------------------------
//

NTSTATUS NTAPI SvmRegisterTraps (
  PCPU Cpu
)
{
  NTSTATUS Status;
  PNBP_TRAP Trap;

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_VMRUN, 3,      // length of the VMRUN instruction
                                                     SvmDispatchVmrun, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchVmrun with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_VMLOAD, 3,     // length of the VMRUN instruction
                                                     SvmDispatchVmload, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchVmload with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_VMSAVE, 3,     // length of the VMRUN instruction
                                                     SvmDispatchVmsave, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchVmsave with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS
      (Status =
       TrInitializeMsrTrap (Cpu, MSR_EFER, MSR_INTERCEPT_READ | MSR_INTERCEPT_WRITE, SvmDispatchEFERAccess, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchEFERAccess with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
  Cpu->Svm.TrapMsrEfer = Trap;

  if (!NT_SUCCESS
      (Status =
       TrInitializeMsrTrap (Cpu, MSR_VM_HSAVE_PA,
                            MSR_INTERCEPT_READ | MSR_INTERCEPT_WRITE, SvmDispatchVM_HSAVE_PAAccess, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchVM_HSAVE_PAAccess with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_CLGI, 3,       // length of the VMRUN instruction
                                                     SvmDispatchClgi, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchClgi with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_STGI, 3,       // length of the VMRUN instruction
                                                     SvmDispatchStgi, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchStgi with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_SMI, 0, SvmDispatchSMI, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchSMI with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
  TrTrapDisable (Trap);
  Cpu->Svm.TrapSMI = Trap;

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_EXCEPTION_DB, 0, SvmDispatchDB, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchDB with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
#ifndef INTERCEPT_RDTSCs
  TrTrapDisable (Trap);
#endif
  Cpu->Svm.TrapDB = Trap;

#ifdef BP_KNOCK
  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_CPUID, 2, SvmDispatchCpuid, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchCpuid with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
#endif

#ifdef INTERCEPT_RDTSCs
/*	if (!NT_SUCCESS(Status=TrInitializeGeneralTrap(
							Cpu,
							VMEXIT_EXCEPTION_DB,
							0,
							SvmDispatchDB,
							&Trap))) {
		_KdPrint(("SvmRegisterTraps(): Failed to register SvmDispatchDB with status 0x%08hX\n",Status));
		return Status;
	}
	TrRegisterTrap(Cpu,Trap);
*/
  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_RDTSC, 2,      // length of the RDTSC instruction
                                                     SvmDispatchRdtsc, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchRdtsc with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, VMEXIT_RDTSCP, 3,     // length of the RDTSCP instruction
                                                     SvmDispatchRdtscp, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchRdtscp with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeMsrTrap (Cpu, MSR_TSC, MSR_INTERCEPT_READ, SvmDispatchMsrTscRead, &Trap))) {
    _KdPrint (("SvmRegisterTraps(): Failed to register SvmDispatchMsrTscRead with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

#endif
  return STATUS_SUCCESS;
}

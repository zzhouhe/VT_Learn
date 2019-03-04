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

#include "vmx.h"
#include "chicken.h"
#include "vmxtraps.h"

HVM_DEPENDENT Vmx = {
  ARCH_VMX,
  VmxIsImplemented,
  VmxInitialize,
  VmxVirtualize,
  VmxShutdown,
  VmxIsNestedEvent,
  VmxDispatchNestedEvent,
  VmxDispatchEvent,
  VmxAdjustRip,
  VmxRegisterTraps,
  VmxIsTrapVaild
};

ULONG64 g_HostStackBaseAddress; //4     // FIXME: this is ugly -- we should move it somewhere else

extern PHYSICAL_ADDRESS g_PageMapBasePhysicalAddress;

NTSTATUS NTAPI VmxEnable (
  PVOID VmxonVA
)
{
  ULONG64 cr4;
  ULONG64 vmxmsr;
  ULONG64 flags;
  PHYSICAL_ADDRESS VmxonPA;

  set_in_cr4 (X86_CR4_VMXE);
  cr4 = get_cr4 ();
  _KdPrint (("VmxEnable(): CR4 after VmxEnable: 0x%llx\n", cr4));
  if (!(cr4 & X86_CR4_VMXE))
    return STATUS_NOT_SUPPORTED;

  vmxmsr = MsrRead (MSR_IA32_FEATURE_CONTROL);
  if (!(vmxmsr & 4)) {
    _KdPrint (("VmxEnable(): VMX is not supported: IA32_FEATURE_CONTROL is 0x%llx\n", vmxmsr));
    return STATUS_NOT_SUPPORTED;
  }

  vmxmsr = MsrRead (MSR_IA32_VMX_BASIC);
  *((ULONG64 *) VmxonVA) = (vmxmsr & 0xffffffff);       //set up vmcs_revision_id
  VmxonPA = MmGetPhysicalAddress (VmxonVA);
  _KdPrint (("VmxEnable(): VmxonPA:  0x%llx\n", VmxonPA.QuadPart));
  VmxTurnOn (MmGetPhysicalAddress (VmxonVA));
  flags = RegGetRflags ();
  _KdPrint (("VmxEnable(): vmcs_revision_id: 0x%x  Eflags: 0x%x \n", vmxmsr, flags));
  return STATUS_SUCCESS;
}

NTSTATUS NTAPI VmxDisable (
)
{
  ULONG64 cr4;
  VmxTurnOff ();
  cr4 = get_cr4 ();
  clear_in_cr4 (X86_CR4_VMXE);
  cr4 = get_cr4 ();
  _KdPrint (("VmxDisable(): CR4 after VmxDisable: 0x%llx\n", cr4));
  return STATUS_SUCCESS;
}

static BOOLEAN NTAPI VmxIsUnconditionalEvent (
  ULONG64 uVmExitNumber
)
{
  if (uVmExitNumber == EXIT_REASON_TRIPLE_FAULT
      || uVmExitNumber == EXIT_REASON_INIT
      || uVmExitNumber == EXIT_REASON_SIPI
      || uVmExitNumber == EXIT_REASON_IO_SMI
      || uVmExitNumber == EXIT_REASON_OTHER_SMI
      || uVmExitNumber == EXIT_REASON_TASK_SWITCH
      || uVmExitNumber == EXIT_REASON_CPUID
      || uVmExitNumber == EXIT_REASON_INVD || uVmExitNumber == EXIT_REASON_RSM
      || uVmExitNumber == EXIT_REASON_VMCALL
      || uVmExitNumber == EXIT_REASON_VMCLEAR
      || uVmExitNumber == EXIT_REASON_VMLAUNCH
      || uVmExitNumber == EXIT_REASON_VMPTRLD
      || uVmExitNumber == EXIT_REASON_VMPTRST
      || uVmExitNumber == EXIT_REASON_VMREAD
      || uVmExitNumber == EXIT_REASON_VMRESUME
      || uVmExitNumber == EXIT_REASON_VMWRITE
      || uVmExitNumber == EXIT_REASON_VMXOFF
      || uVmExitNumber == EXIT_REASON_VMXON
      || uVmExitNumber == EXIT_REASON_INVALID_GUEST_STATE
      || uVmExitNumber == EXIT_REASON_MSR_LOADING || uVmExitNumber == EXIT_REASON_MACHINE_CHECK)
    return TRUE;
  else
    return FALSE;

}

static BOOLEAN NTAPI VmxIsImplemented (
)
{
  ULONG32 eax, ebx, ecx, edx;
  GetCpuIdInfo (0, &eax, &ebx, &ecx, &edx);
  if (eax < 1) {
    _KdPrint (("VmxIsImplemented(): Extended CPUID functions not implemented\n"));
    return FALSE;
  }
  if (!(ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69)) {
    _KdPrint (("VmxIsImplemented(): Not an INTEL processor\n"));
    return FALSE;
  }
  //intel cpu use fun_0x1 to test VMX.    
  GetCpuIdInfo (0x1, &eax, &ebx, &ecx, &edx);
  return (BOOLEAN) (CmIsBitSet (ecx, 5));
}

static VOID VmxHandleInterception (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  NTSTATUS Status;
  ULONG64 Exitcode;
  PNBP_TRAP Trap;

  if (!Cpu || !GuestRegs)
    return;

  Exitcode = VmxRead (VM_EXIT_REASON);

#if DEBUG_LEVEL>2
  _KdPrint (("VmxHandleInterception(): Exitcode %x\n", Exitcode));
#endif

  // search for a registered trap for this interception
  Status = TrFindRegisteredTrap (Cpu, GuestRegs, Exitcode, &Trap);
  if (!NT_SUCCESS (Status)) {
    _KdPrint (("VmxHandleInterception(): TrFindRegisteredTrap() failed for exitcode 0x%llX\n", Exitcode));
    VmxCrash (Cpu, GuestRegs);
    return;
  }
  // we found a trap handler

  if (!NT_SUCCESS (Status = TrExecuteGeneralTrapHandler (Cpu, GuestRegs, Trap, WillBeAlsoHandledByGuestHv))) {
    _KdPrint (("VmxHandleInterception(): HvmExecuteGeneralTrapHandler() failed with status 0x%08hX\n", Status));
  }
#ifdef BLUE_CHICKEN
  ChickenAddInterceptTsc (Cpu);
  if (ChickenShouldUninstall (Cpu)) {
    _KdPrint (("VmxHandleInterception(): CPU#%d: Chicken Says to uninstall\n", Cpu->ProcessorNumber));
    // call HvmSetupTimeBomb()
    Hvm->ArchShutdown (Cpu, GuestRegs, TRUE);
    return;
  }
#endif

}

static VOID NTAPI VmxDispatchEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
#if DEBUG_LEVEL>1
  _KdPrint (("VmxDispatchEvent(): exitcode = %x\n", VmxRead (VM_EXIT_REASON)));
#endif

  VmxHandleInterception (Cpu, GuestRegs, FALSE
                         /* this intercept will not be handled by guest hv */
    );

}

static VOID NTAPI VmxDispatchNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  NTSTATUS Status;
  PNBP_TRAP Trap;
  BOOLEAN bInterceptedByGuest;
  ULONG64 Exitcode;

  if (!Cpu || !GuestRegs)
    return;

  _KdPrint (("VmxDispatchNestedEvent(): DUMMY!!! This build doesn't support nested virtualization!\n"));

}

static BOOLEAN NTAPI VmxIsNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  return FALSE;                 // DUMMY!!! This build doesn't support nested virtualization!!!
}

static VOID NTAPI VmxAdjustRip (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG64 Delta
)
{
  VmxWrite (GUEST_RIP, VmxRead (GUEST_RIP) + Delta);
  return;
}

static ULONG32 NTAPI VmxAdjustControls (
  ULONG32 Ctl,
  ULONG32 Msr
)
{
  LARGE_INTEGER MsrValue;

  MsrValue.QuadPart = MsrRead (Msr);
  Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
  Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
  return Ctl;
}

NTSTATUS NTAPI VmxFillGuestSelectorData (
  PVOID GdtBase,
  ULONG Segreg,
  USHORT Selector
)
{
  SEGMENT_SELECTOR SegmentSelector = { 0 };
  ULONG uAccessRights;

  CmInitializeSegmentSelector (&SegmentSelector, Selector, GdtBase);
  uAccessRights = ((PUCHAR) & SegmentSelector.attributes)[0] + (((PUCHAR) & SegmentSelector.attributes)[1] << 12);

  if (!Selector)
    uAccessRights |= 0x10000;

  VmxWrite (GUEST_ES_SELECTOR + Segreg * 2, Selector);
  VmxWrite (GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.limit);
  VmxWrite (GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);

  if ((Segreg == LDTR) || (Segreg == TR))
    // don't setup for FS/GS - their bases are stored in MSR values
    VmxWrite (GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);

  return STATUS_SUCCESS;
}

static NTSTATUS VmxSetupVMCS (
  PCPU Cpu,
  PVOID GuestRip,
  PVOID GuestRsp
)
{
  SEGMENT_SELECTOR SegmentSelector;
  PHYSICAL_ADDRESS VmcsToContinuePA;
  NTSTATUS Status;
  PVOID GdtBase;
  ULONG32 Interceptions;

  if (!Cpu || !Cpu->Vmx.OriginalVmcs)
    return STATUS_INVALID_PARAMETER;

  VmcsToContinuePA = Cpu->Vmx.VmcsToContinuePA;
  VmxClear (VmcsToContinuePA);
  VmxPtrld (VmcsToContinuePA);

  /*16BIT Fields */

  /*16BIT Host-Statel Fields. */
#ifdef _X86_
  VmxWrite (HOST_ES_SELECTOR, RegGetEs () & 0xf8);
  VmxWrite (HOST_CS_SELECTOR, RegGetCs () & 0xf8);
  VmxWrite (HOST_SS_SELECTOR, RegGetSs () & 0xf8);
  VmxWrite (HOST_DS_SELECTOR, RegGetDs () & 0xf8);
#else
  VmxWrite (HOST_ES_SELECTOR, BP_GDT64_DATA);
  VmxWrite (HOST_CS_SELECTOR, BP_GDT64_CODE);
  VmxWrite (HOST_SS_SELECTOR, BP_GDT64_DATA);
  VmxWrite (HOST_DS_SELECTOR, BP_GDT64_DATA);
#endif
  VmxWrite (HOST_FS_SELECTOR, (RegGetFs () & 0xf8));
  VmxWrite (HOST_GS_SELECTOR, (RegGetGs () & 0xf8));
  VmxWrite (HOST_TR_SELECTOR, (GetTrSelector () & 0xf8));

  /*64BIT Control Fields. */
  VmxWrite (IO_BITMAP_A, Cpu->Vmx.IOBitmapAPA.LowPart);
#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
  *(((unsigned char *) (Cpu->Vmx.IOBitmapA)) + (0x60 / 8)) = 0x11;      //0x60 0x64 PS keyboard mouse
#endif
  VmxWrite (IO_BITMAP_A_HIGH, Cpu->Vmx.IOBitmapBPA.HighPart);
  VmxWrite (IO_BITMAP_B, Cpu->Vmx.IOBitmapBPA.LowPart);
  // FIXME???
  //*(((unsigned char*)(Cpu->Vmx.IOBitmapB))+((0xc880-0x8000)/8))=0xff;  //0xc880-0xc887  
  VmxWrite (IO_BITMAP_B_HIGH, Cpu->Vmx.IOBitmapBPA.HighPart);

  VmxWrite (MSR_BITMAP, Cpu->Vmx.MSRBitmapPA.LowPart);
  VmxWrite (MSR_BITMAP_HIGH, Cpu->Vmx.MSRBitmapPA.HighPart);
  //VM_EXIT_MSR_STORE_ADDR          = 0x00002006,  //no init
  //VM_EXIT_MSR_STORE_ADDR_HIGH     = 0x00002007,  //no init
  //VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,  //no init
  //VM_EXIT_MSR_LOAD_ADDR_HIGH      = 0x00002009,  //no init
  //VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,  //no init
  //VM_ENTRY_MSR_LOAD_ADDR_HIGH     = 0x0000200b,  //no init
  VmxWrite (TSC_OFFSET, 0);
  VmxWrite (TSC_OFFSET_HIGH, 0);
  //VIRTUAL_APIC_PAGE_ADDR          = 0x00002012,   //no init
  //VIRTUAL_APIC_PAGE_ADDR_HIGH     = 0x00002013,   //no init

  /*64BIT Guest-Statel Fields. */
  VmxWrite (VMCS_LINK_POINTER, 0xffffffff);
  VmxWrite (VMCS_LINK_POINTER_HIGH, 0xffffffff);

  VmxWrite (GUEST_IA32_DEBUGCTL, MsrRead (MSR_IA32_DEBUGCTL) & 0xffffffff);
  VmxWrite (GUEST_IA32_DEBUGCTL_HIGH, MsrRead (MSR_IA32_DEBUGCTL) >> 32);

  /*32BIT Control Fields. */
  VmxWrite (PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls (0, MSR_IA32_VMX_PINBASED_CTLS));      //disable Vmexit by Extern-interrupt,NMI and Virtual NMI 
  Interceptions = 0;
#ifdef VMX_ENABLE_MSR_BITMAP
  Interceptions |= CPU_BASED_ACTIVATE_MSR_BITMAP;
#endif

#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
  Interceptions |= CPU_BASED_ACTIVATE_IO_BITMAP;
#endif

#ifdef INTERCEPT_RDTSCs
  Interceptions |= CPU_BASED_RDTSC_EXITING;
#endif
  VmxWrite (CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls (Interceptions, MSR_IA32_VMX_PROCBASED_CTLS));

#ifdef INTERCEPT_RDTSCs
  VmxWrite (EXCEPTION_BITMAP, 1 << 1);  // intercept #DB
#endif
  VmxWrite (PAGE_FAULT_ERROR_CODE_MASK, 0);
  VmxWrite (PAGE_FAULT_ERROR_CODE_MATCH, 0);
  VmxWrite (CR3_TARGET_COUNT, 0);

#ifdef _X86_
  VmxWrite (VM_EXIT_CONTROLS, VmxAdjustControls (VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
  VmxWrite (VM_ENTRY_CONTROLS, VmxAdjustControls (0, MSR_IA32_VMX_ENTRY_CTLS));
#else
  VmxWrite (VM_EXIT_CONTROLS,
            VmxAdjustControls (VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
  VmxWrite (VM_ENTRY_CONTROLS, VmxAdjustControls (VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));
#endif

  VmxWrite (VM_EXIT_MSR_STORE_COUNT, 0);
  VmxWrite (VM_EXIT_MSR_LOAD_COUNT, 0);

  VmxWrite (VM_ENTRY_MSR_LOAD_COUNT, 0);
  VmxWrite (VM_ENTRY_INTR_INFO_FIELD, 0);

  //VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018,  //no init
  //VM_ENTRY_INSTRUCTION_LEN        = 0x0000401a,  //no init
  //TPR_THRESHOLD                   = 0x0000401c,  //no init

  /*32BIT Read-only Fields:need no setup */

  /*32BIT Guest-Statel Fields. */

  VmxWrite (GUEST_GDTR_LIMIT, GetGdtLimit ());
  VmxWrite (GUEST_IDTR_LIMIT, GetIdtLimit ());

  VmxWrite (GUEST_INTERRUPTIBILITY_INFO, 0);
  VmxWrite (GUEST_ACTIVITY_STATE, 0);   //Active state          
  //GUEST_SM_BASE          = 0x98000,   //no init
  VmxWrite (GUEST_SYSENTER_CS, MsrRead (MSR_IA32_SYSENTER_CS));

  /*32BIT Host-Statel Fields. */

  VmxWrite (HOST_IA32_SYSENTER_CS, MsrRead (MSR_IA32_SYSENTER_CS));     //no use

  /* NATURAL Control State Fields:need not setup. */
  VmxWrite (CR0_GUEST_HOST_MASK, X86_CR0_PG);
  //VmxWrite(CR4_GUEST_HOST_MASK, X86_CR4_VMXE|X86_CR4_PAE|X86_CR4_PSE);//disable vmexit 0f mov to cr4 expect for X86_CR4_VMXE
  VmxWrite (CR4_GUEST_HOST_MASK, X86_CR4_VMXE); //disable vmexit 0f mov to cr4 expect for X86_CR4_VMXE

  VmxWrite (CR0_READ_SHADOW, (RegGetCr4 () & X86_CR0_PG) | X86_CR0_PG);

  VmxWrite (CR4_READ_SHADOW, 0);
  VmxWrite (CR3_TARGET_VALUE0, 0);      //no use
  VmxWrite (CR3_TARGET_VALUE1, 0);      //no use                        
  VmxWrite (CR3_TARGET_VALUE2, 0);      //no use
  VmxWrite (CR3_TARGET_VALUE3, 0);      //no use

  /* NATURAL Read-only State Fields:need not setup. */

  /* NATURAL GUEST State Fields. */

  VmxWrite (GUEST_CR0, RegGetCr0 ());
  VmxWrite (GUEST_CR3, RegGetCr3 ());
  VmxWrite (GUEST_CR4, RegGetCr4 ());

  GdtBase = (PVOID) GetGdtBase ();

  // Setup guest selectors

  VmxFillGuestSelectorData (GdtBase, ES, RegGetEs ());
  VmxFillGuestSelectorData (GdtBase, CS, RegGetCs ());
  VmxFillGuestSelectorData (GdtBase, SS, RegGetSs ());
  VmxFillGuestSelectorData (GdtBase, DS, RegGetDs ());
  VmxFillGuestSelectorData (GdtBase, FS, RegGetFs ());
  VmxFillGuestSelectorData (GdtBase, GS, RegGetGs ());
  VmxFillGuestSelectorData (GdtBase, LDTR, GetLdtr ());
  VmxFillGuestSelectorData (GdtBase, TR, GetTrSelector ());

#ifdef _X86_
  CmInitializeSegmentSelector (&SegmentSelector, RegGetEs (), (PVOID) GetGdtBase ());
  VmxWrite (GUEST_ES_BASE, SegmentSelector.base);

  CmInitializeSegmentSelector (&SegmentSelector, RegGetCs (), (PVOID) GetGdtBase ());
  VmxWrite (GUEST_CS_BASE, SegmentSelector.base);

  CmInitializeSegmentSelector (&SegmentSelector, RegGetSs (), (PVOID) GetGdtBase ());
  VmxWrite (GUEST_SS_BASE, SegmentSelector.base);

  CmInitializeSegmentSelector (&SegmentSelector, RegGetDs (), (PVOID) GetGdtBase ());
  VmxWrite (GUEST_DS_BASE, SegmentSelector.base);

  CmInitializeSegmentSelector (&SegmentSelector, RegGetFs (), (PVOID) GetGdtBase ());
  VmxWrite (GUEST_FS_BASE, SegmentSelector.base);

  CmInitializeSegmentSelector (&SegmentSelector, RegGetGs (), (PVOID) GetGdtBase ());
  VmxWrite (GUEST_GS_BASE, SegmentSelector.base);
#else
  VmxWrite (GUEST_ES_BASE, 0);
  VmxWrite (GUEST_CS_BASE, 0);
  VmxWrite (GUEST_SS_BASE, 0);
  VmxWrite (GUEST_DS_BASE, 0);
  VmxWrite (GUEST_FS_BASE, MsrRead (MSR_FS_BASE));
  VmxWrite (GUEST_GS_BASE, MsrRead (MSR_GS_BASE));
#endif

  // LDTR/TR bases have been set in VmxFillGuestSelectorData()
  VmxWrite (GUEST_GDTR_BASE, (ULONG64) GdtBase);
  VmxWrite (GUEST_IDTR_BASE, GetIdtBase ());

  VmxWrite (GUEST_DR7, 0x400);
  VmxWrite (GUEST_RSP, (ULONG64) GuestRsp);     //setup guest sp
  VmxWrite (GUEST_RIP, (ULONG64) GuestRip);     //setup guest ip:CmSlipIntoMatrix
  VmxWrite (GUEST_RFLAGS, RegGetRflags ());
  //VmxWrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);//no init
  VmxWrite (GUEST_SYSENTER_ESP, MsrRead (MSR_IA32_SYSENTER_ESP));
  VmxWrite (GUEST_SYSENTER_EIP, MsrRead (MSR_IA32_SYSENTER_EIP));

  /* HOST State Fields. */
  VmxWrite (HOST_CR0, RegGetCr0 ());

#ifdef VMX_USE_PRIVATE_CR3
  // private cr3
  VmxWrite (HOST_CR3, g_PageMapBasePhysicalAddress.QuadPart);
#else
  VmxWrite (HOST_CR3, RegGetCr3 ());
#endif
  VmxWrite (HOST_CR4, RegGetCr4 ());

  VmxWrite (HOST_FS_BASE, MsrRead (MSR_FS_BASE));
  VmxWrite (HOST_GS_BASE, MsrRead (MSR_GS_BASE));

  // TODO: we must setup our own TSS
  // FIXME???

  CmInitializeSegmentSelector (&SegmentSelector, GetTrSelector (), (PVOID) GetGdtBase ());
  VmxWrite (HOST_TR_BASE, SegmentSelector.base);

  VmxWrite (HOST_GDTR_BASE, (ULONG64) Cpu->GdtArea);
  VmxWrite (HOST_IDTR_BASE, (ULONG64) Cpu->IdtArea);

  // FIXME???
//      VmxWrite(HOST_GDTR_BASE, (ULONG64)GetGdtBase());
//      VmxWrite(HOST_IDTR_BASE, (ULONG64)GetIdtBase());

  VmxWrite (HOST_IA32_SYSENTER_ESP, MsrRead (MSR_IA32_SYSENTER_ESP));
  VmxWrite (HOST_IA32_SYSENTER_EIP, MsrRead (MSR_IA32_SYSENTER_EIP));

#ifdef _X86_
  VmxWrite (HOST_RSP, g_HostStackBaseAddress + 0x0C00); //setup host sp at vmxLaunch(...)
#else
  VmxWrite (HOST_RSP, (ULONG64) Cpu);   //setup host sp at vmxLaunch(...)
#endif
  VmxWrite (HOST_RIP, (ULONG64) VmxVmexitHandler);      //setup host ip:CmSlipIntoMatrix

  _KdPrint (("VmxSetupVMCS(): Exit\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS NTAPI VmxInitialize (
  PCPU Cpu,
  PVOID GuestRip,
  PVOID GuestRsp
)
{
  PHYSICAL_ADDRESS AlignedVmcsPA;
  ULONG64 VaDelta;
  NTSTATUS Status;

#ifndef _X86_
  PVOID tmp;
  tmp = MmAllocateContiguousPages (1, NULL);
  g_HostStackBaseAddress = (ULONG64) tmp;
#endif
  // do not deallocate anything here; MmShutdownManager will take care of that

  //Allocate VMXON region
  Cpu->Vmx.OriginaVmxonR = MmAllocateContiguousPages (VMX_VMXONR_SIZE_IN_PAGES, &Cpu->Vmx.OriginalVmxonRPA);

  if (!Cpu->Vmx.OriginaVmxonR) {
    _KdPrint (("VmxInitialize(): Failed to allocate memory for original VMCS\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  _KdPrint (("VmxInitialize(): OriginaVmxonR VA: 0x%p\n", Cpu->Vmx.OriginaVmxonR));
  _KdPrint (("VmxInitialize(): OriginaVmxonR PA: 0x%llx\n", Cpu->Vmx.OriginalVmxonRPA.QuadPart));

  //Allocate VMCS
  Cpu->Vmx.OriginalVmcs = MmAllocateContiguousPages (VMX_VMCS_SIZE_IN_PAGES, &Cpu->Vmx.OriginalVmcsPA);

  if (!Cpu->Vmx.OriginalVmcs) {
    _KdPrint (("VmxInitialize(): Failed to allocate memory for original VMCS\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  _KdPrint (("VmxInitialize(): Vmcs VA: 0x%p\n", Cpu->Vmx.OriginalVmcs));
  _KdPrint (("VmxInitialize(): Vmcs PA: 0x%llx\n", Cpu->Vmx.OriginalVmcsPA.QuadPart));

  // these two PAs are equal if there're no nested VMs
  Cpu->Vmx.VmcsToContinuePA = Cpu->Vmx.OriginalVmcsPA;

  //init IOBitmap and MsrBitmap
  Cpu->Vmx.IOBitmapA = MmAllocateContiguousPages (VMX_IOBitmap_SIZE_IN_PAGES, &Cpu->Vmx.IOBitmapAPA);
  if (!Cpu->Vmx.IOBitmapA) {
    _KdPrint (("VmxInitialize(): Failed to allocate memory for IOBitmapA\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory (Cpu->Vmx.IOBitmapA, PAGE_SIZE);

  _KdPrint (("VmxInitialize(): IOBitmapA VA: 0x%p\n", Cpu->Vmx.IOBitmapA));
  _KdPrint (("VmxInitialize(): IOBitmapA PA: 0x%llx\n", Cpu->Vmx.IOBitmapAPA.QuadPart));

  Cpu->Vmx.IOBitmapB = MmAllocateContiguousPages (VMX_IOBitmap_SIZE_IN_PAGES, &Cpu->Vmx.IOBitmapBPA);
  if (!Cpu->Vmx.IOBitmapB) {
    _KdPrint (("VmxInitialize(): Failed to allocate memory for IOBitmapB\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory (Cpu->Vmx.IOBitmapB, PAGE_SIZE);

  _KdPrint (("VmxInitialize(): IOBitmapB VA: 0x%p\n", Cpu->Vmx.IOBitmapB));
  _KdPrint (("VmxInitialize(): IOBitmapB PA: 0x%llx\n", Cpu->Vmx.IOBitmapBPA.QuadPart));

  Cpu->Vmx.MSRBitmap = MmAllocateContiguousPages (VMX_MSRBitmap_SIZE_IN_PAGES, &Cpu->Vmx.MSRBitmapPA);
  if (!Cpu->Vmx.MSRBitmap) {
    _KdPrint (("VmxInitialize(): Failed to allocate memory for  MSRBitmap\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory (Cpu->Vmx.MSRBitmap, PAGE_SIZE);
  _KdPrint (("VmxInitialize(): MSRBitmap VA: 0x%p\n", Cpu->Vmx.MSRBitmap));
  _KdPrint (("VmxInitialize(): MSRBitmap PA: 0x%llx\n", Cpu->Vmx.MSRBitmapPA.QuadPart));

  if (!NT_SUCCESS (VmxEnable (Cpu->Vmx.OriginaVmxonR))) {
    _KdPrint (("VmxInitialize(): Failed to enable Vmx\n"));
    return STATUS_UNSUCCESSFUL;
  }

  *((ULONG64 *) (Cpu->Vmx.OriginalVmcs)) = (MsrRead (MSR_IA32_VMX_BASIC) & 0xffffffff); //set up vmcs_revision_id      

  if (!NT_SUCCESS (Status = VmxSetupVMCS (Cpu, GuestRip, GuestRsp))) {
    _KdPrint (("Vmx(): VmxSetupVMCS() failed with status 0x%08hX\n", Status));
    VmxDisable ();
    return Status;
  }

  _KdPrint (("VmxInitialize(): Vmx enabled\n"));

  Cpu->Vmx.GuestEFER = MsrRead (MSR_EFER);
  _KdPrint (("Guest MSR_EFER Read 0x%llx \n", Cpu->Vmx.GuestEFER));

  Cpu->Vmx.GuestCR0 = RegGetCr0 ();
  Cpu->Vmx.GuestCR3 = RegGetCr3 ();
  Cpu->Vmx.GuestCR4 = RegGetCr4 ();

#ifdef INTERCEPT_RDTSCs
  Cpu->Tracing = 0;
#endif
#ifdef BLUE_CHICKEN
  Cpu->ChickenQueueSize = 0;
  Cpu->ChickenQueueHead = Cpu->ChickenQueueTail = 0;
#endif
  CmCli ();
  return STATUS_SUCCESS;
}

static VOID VmxGenerateTrampolineToGuest (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PUCHAR Trampoline,
  BOOLEAN bSetupTimeBomb
)
{
  ULONG uTrampolineSize = 0;
  ULONG64 NewRsp;

  if (!Cpu || !GuestRegs)
    return;

  // assume Trampoline buffer is big enough
  VmxWrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & ~0x100);     // disable TF

  if (bSetupTimeBomb) {
    // pass OriginalTrampoline and ProcessorNumber to the HvmSetupTimeBomb
#ifdef BLUE_CHICKEN
    VmxGenerateTrampolineToGuest (Cpu, GuestRegs, Cpu->OriginalTrampoline, FALSE);
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RCX, (ULONG64) & Cpu->OriginalTrampoline);
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDX, Cpu->ProcessorNumber);
#endif
  } else {
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RCX, GuestRegs->rcx);
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDX, GuestRegs->rdx);
  }

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBX, GuestRegs->rbx);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBP, GuestRegs->rbp);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSI, GuestRegs->rsi);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDI, GuestRegs->rdi);

#ifndef _X86_
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R8, GuestRegs->r8);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R9, GuestRegs->r9);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R10, GuestRegs->r10);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R11, GuestRegs->r11);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R12, GuestRegs->r12);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R13, GuestRegs->r13);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R14, GuestRegs->r14);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R15, GuestRegs->r15);
#endif

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR0, VmxRead (GUEST_CR0));
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR3, VmxRead (GUEST_CR3));
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR4, VmxRead (GUEST_CR4));

  NewRsp = VmxRead (GUEST_RSP);

#ifdef BLUE_CHICKEN
  if (bSetupTimeBomb)
    NewRsp -= 0x100;
#endif

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSP, NewRsp);

  // construct stack frame for IRETQ:
  // [TOS]        rip
  // [TOS+0x08]   cs
  // [TOS+0x10]   rflags
  // [TOS+0x18]   rsp
  // [TOS+0x20]   ss

  // construct stack frame for IRETD:
  // [TOS]        rip
  // [TOS+0x4]    cs
  // [TOS+0x8]    rflags

#ifndef _X86_
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_SS_SELECTOR));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, NewRsp);
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
#endif
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_RFLAGS));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_CS_SELECTOR));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);

  if (bSetupTimeBomb) {
#ifdef BLUE_CHICKEN
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, (ULONG64) HvmSetupTimeBomb);
#endif
  } else {
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX,
                      VmxRead (GUEST_RIP) + VmxRead (VM_EXIT_INSTRUCTION_LEN));
  }

  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, GuestRegs->rax);

#ifdef _X86_
  CmGenerateIretd (&Trampoline[uTrampolineSize], &uTrampolineSize);
#else
  CmGenerateIretq (&Trampoline[uTrampolineSize], &uTrampolineSize);
#endif

  // restore old GDTR
  CmReloadGdtr ((PVOID) VmxRead (GUEST_GDTR_BASE), (ULONG) VmxRead (GUEST_GDTR_LIMIT));

  MsrWrite (MSR_GS_BASE, VmxRead (GUEST_GS_BASE));
  MsrWrite (MSR_FS_BASE, VmxRead (GUEST_FS_BASE));

  // FIXME???
  // restore ds, es
//      CmSetDS((USHORT)VmxRead(GUEST_DS_SELECTOR));
//      CmSetES((USHORT)VmxRead(GUEST_ES_SELECTOR));

  // cs and ss must be the same with the guest OS in this implementation

  // restore old IDTR
  CmReloadIdtr ((PVOID) VmxRead (GUEST_IDTR_BASE), (ULONG) VmxRead (GUEST_IDTR_LIMIT));

  return;
}

static NTSTATUS NTAPI VmxShutdown (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  BOOLEAN bSetupTimeBomb
)
{
  UCHAR Trampoline[0x600];

  _KdPrint (("VmxShutdown(): CPU#%d\n", Cpu->ProcessorNumber));

#if DEBUG_LEVEL>2
  VmxDumpVmcs ();
#endif
  InterlockedDecrement (&g_uSubvertedCPUs);

  // The code should be updated to build an approproate trampoline to exit to any guest mode.
  VmxGenerateTrampolineToGuest (Cpu, GuestRegs, Trampoline, bSetupTimeBomb);

  _KdPrint (("VmxShutdown(): Trampoline generated\n", Cpu->ProcessorNumber));
  VmxDisable ();
  ((VOID (*)()) & Trampoline) ();

  // never returns
  return STATUS_SUCCESS;
}

static NTSTATUS NTAPI VmxVirtualize (
  PCPU Cpu
)
{
  ULONG64 rsp;
  if (!Cpu)
    return STATUS_INVALID_PARAMETER;

  _KdPrint (("VmxVirtualize(): VmxRead: 0x%X \n", VmxRead (VM_INSTRUCTION_ERROR)));
  _KdPrint (("VmxVirtualize(): RFlags before vmxLaunch: 0x%x \n", RegGetRflags ()));
  _KdPrint (("VmxVirtualize(): PCPU: 0x%p \n", Cpu));
  rsp = RegGetRsp ();
  _KdPrint (("VmxVirtualize(): Rsp: 0x%x \n", rsp));

#ifndef _X86_
  *((PULONG64) (g_HostStackBaseAddress + 0x0C00)) = (ULONG64) Cpu;
#endif

  VmxLaunch ();

  // never returns

  return STATUS_UNSUCCESSFUL;
}

static BOOLEAN NTAPI VmxIsTrapVaild (
  ULONG TrappedVmExit
)
{
  if (TrappedVmExit > VMX_MAX_GUEST_VMEXIT)
    return FALSE;
  return TRUE;
}

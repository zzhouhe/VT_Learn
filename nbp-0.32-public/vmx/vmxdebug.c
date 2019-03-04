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

VOID NTAPI VmxDumpVmcs (
)
{

  ULONG32 addr;

  _KdPrint (("\n\n\n/*****16-bit Guest-State Fields*****/\n"));
  addr = GUEST_ES_SELECTOR;
  _KdPrint (("GUEST_ES_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CS_SELECTOR;
  _KdPrint (("GUEST_CS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SS_SELECTOR;
  _KdPrint (("GUEST_SS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DS_SELECTOR;
  _KdPrint (("GUEST_DS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_FS_SELECTOR;
  _KdPrint (("GUEST_FS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GS_SELECTOR;
  _KdPrint (("GUEST_GS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LDTR_SELECTOR;
  _KdPrint (("GUEST_LDTR_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_TR_SELECTOR;
  _KdPrint (("GUEST_TR_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****16-bit Host-State Fields*****/\n"));
  addr = HOST_ES_SELECTOR;
  _KdPrint (("HOST_ES_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_CS_SELECTOR;
  _KdPrint (("HOST_CS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_SS_SELECTOR;
  _KdPrint (("HOST_SS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_DS_SELECTOR;
  _KdPrint (("HOST_DS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_FS_SELECTOR;
  _KdPrint (("HOST_FS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_GS_SELECTOR;
  _KdPrint (("HOST_GS_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_TR_SELECTOR;
  _KdPrint (("HOST_TR_SELECTOR 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****64-bit Control Fields*****/\n"));
  addr = IO_BITMAP_A;
  _KdPrint (("IO_BITMAP_A 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = IO_BITMAP_A_HIGH;
  _KdPrint (("IO_BITMAP_A_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = IO_BITMAP_B;
  _KdPrint (("IO_BITMAP_B 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = IO_BITMAP_B_HIGH;
  _KdPrint (("IO_BITMAP_B_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = MSR_BITMAP;
  _KdPrint (("MSR_BITMAP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = MSR_BITMAP_HIGH;
  _KdPrint (("MSR_BITMAP_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_STORE_ADDR;
  _KdPrint (("VM_EXIT_MSR_STORE_ADDR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_STORE_ADDR_HIGH;
  _KdPrint (("VM_EXIT_MSR_STORE_ADDR_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_LOAD_ADDR;
  _KdPrint (("VM_EXIT_MSR_LOAD_ADDR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_LOAD_ADDR_HIGH;
  _KdPrint (("VM_EXIT_MSR_LOAD_ADDR_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_MSR_LOAD_ADDR;
  _KdPrint (("VM_ENTRY_MSR_LOAD_ADDR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_MSR_LOAD_ADDR_HIGH;
  _KdPrint (("VM_ENTRY_MSR_LOAD_ADDR_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = TSC_OFFSET;
  _KdPrint (("TSC_OFFSET 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = TSC_OFFSET_HIGH;
  _KdPrint (("TSC_OFFSET_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VIRTUAL_APIC_PAGE_ADDR;
  _KdPrint (("VIRTUAL_APIC_PAGE_ADDR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VIRTUAL_APIC_PAGE_ADDR_HIGH;
  _KdPrint (("VIRTUAL_APIC_PAGE_ADDR_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****64-bit Guest-State Fields*****/\n"));
  addr = VMCS_LINK_POINTER;
  _KdPrint (("VMCS_LINK_POINTER 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VMCS_LINK_POINTER_HIGH;
  _KdPrint (("VMCS_LINK_POINTER_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_IA32_DEBUGCTL;
  _KdPrint (("GUEST_IA32_DEBUGCTL 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_IA32_DEBUGCTL_HIGH;
  _KdPrint (("GUEST_IA32_DEBUGCTL_HIGH 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****32-bit Control Fields*****/\n"));
  addr = PIN_BASED_VM_EXEC_CONTROL;
  _KdPrint (("PIN_BASED_VM_EXEC_CONTROL 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CPU_BASED_VM_EXEC_CONTROL;
  _KdPrint (("CPU_BASED_VM_EXEC_CONTROL 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = EXCEPTION_BITMAP;
  _KdPrint (("EXCEPTION_BITMAP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = PAGE_FAULT_ERROR_CODE_MASK;
  _KdPrint (("PAGE_FAULT_ERROR_CODE_MASK 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = PAGE_FAULT_ERROR_CODE_MATCH;
  _KdPrint (("PAGE_FAULT_ERROR_CODE_MATCH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_COUNT;
  _KdPrint (("CR3_TARGET_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_CONTROLS;
  _KdPrint (("VM_EXIT_CONTROLS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_STORE_COUNT;
  _KdPrint (("VM_EXIT_MSR_STORE_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_LOAD_COUNT;
  _KdPrint (("VM_EXIT_MSR_LOAD_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_CONTROLS;
  _KdPrint (("VM_ENTRY_CONTROLS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_MSR_LOAD_COUNT;
  _KdPrint (("VM_ENTRY_MSR_LOAD_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_INTR_INFO_FIELD;
  _KdPrint (("VM_ENTRY_INTR_INFO_FIELD 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_EXCEPTION_ERROR_CODE;
  _KdPrint (("VM_ENTRY_EXCEPTION_ERROR_CODE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_INSTRUCTION_LEN;
  _KdPrint (("VM_ENTRY_INSTRUCTION_LEN 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = TPR_THRESHOLD;
  _KdPrint (("TPR_THRESHOLD 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = SECONDARY_VM_EXEC_CONTROL;
  _KdPrint (("SECONDARY_VM_EXEC_CONTROL 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****32-bit RO Data Fields*****/\n"));
  addr = VM_INSTRUCTION_ERROR;
  _KdPrint (("VM_INSTRUCTION_ERROR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_REASON;
  _KdPrint (("VM_EXIT_REASON 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_INTR_INFO;
  _KdPrint (("VM_EXIT_INTR_INFO 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_INTR_ERROR_CODE;
  _KdPrint (("VM_EXIT_INTR_ERROR_CODE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = IDT_VECTORING_INFO_FIELD;
  _KdPrint (("IDT_VECTORING_INFO_FIELD 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = IDT_VECTORING_ERROR_CODE;
  _KdPrint (("IDT_VECTORING_ERROR_CODE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_INSTRUCTION_LEN;
  _KdPrint (("VM_EXIT_INSTRUCTION_LEN 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VMX_INSTRUCTION_INFO;
  _KdPrint (("VMX_INSTRUCTION_INFO 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****32-bit Guest-State Fields*****/\n"));
  addr = GUEST_ES_LIMIT;
  _KdPrint (("GUEST_ES_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CS_LIMIT;
  _KdPrint (("GUEST_CS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SS_LIMIT;
  _KdPrint (("GUEST_SS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DS_LIMIT;
  _KdPrint (("GUEST_DS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_FS_LIMIT;
  _KdPrint (("GUEST_FS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GS_LIMIT;
  _KdPrint (("GUEST_GS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LDTR_LIMIT;
  _KdPrint (("GUEST_LDTR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_TR_LIMIT;
  _KdPrint (("GUEST_TR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GDTR_LIMIT;
  _KdPrint (("GUEST_GDTR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_IDTR_LIMIT;
  _KdPrint (("GUEST_IDTR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_ES_AR_BYTES;
  _KdPrint (("GUEST_ES_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CS_AR_BYTES;
  _KdPrint (("GUEST_CS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SS_AR_BYTES;
  _KdPrint (("GUEST_SS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DS_AR_BYTES;
  _KdPrint (("GUEST_DS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_FS_AR_BYTES;
  _KdPrint (("GUEST_FS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GS_AR_BYTES;
  _KdPrint (("GUEST_GS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LDTR_AR_BYTES;
  _KdPrint (("GUEST_LDTR_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_TR_AR_BYTES;
  _KdPrint (("GUEST_TR_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_INTERRUPTIBILITY_INFO;
  _KdPrint (("GUEST_INTERRUPTIBILITY_INFO 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_ACTIVITY_STATE;
  _KdPrint (("GUEST_ACTIVITY_STATE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SM_BASE;
  _KdPrint (("GUEST_SM_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SYSENTER_CS;
  _KdPrint (("GUEST_SYSENTER_CS 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****32-bit Host-State Fields*****/\n"));
  addr = HOST_IA32_SYSENTER_CS;
  _KdPrint (("HOST_IA32_SYSENTER_CS 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****Natural 64-bit Control Fields*****/\n"));
  addr = CR0_GUEST_HOST_MASK;
  _KdPrint (("CR0_GUEST_HOST_MASK 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR4_GUEST_HOST_MASK;
  _KdPrint (("CR4_GUEST_HOST_MASK 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR0_READ_SHADOW;
  _KdPrint (("CR0_READ_SHADOW 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR4_READ_SHADOW;
  _KdPrint (("CR4_READ_SHADOW 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE0;
  _KdPrint (("CR3_TARGET_VALUE0 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE1;
  _KdPrint (("CR3_TARGET_VALUE1 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE2;
  _KdPrint (("CR3_TARGET_VALUE2 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE3;
  _KdPrint (("CR3_TARGET_VALUE3 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****Natural 64-bit RO Data Fields*****/\n"));
  addr = EXIT_QUALIFICATION;
  _KdPrint (("EXIT_QUALIFICATION 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LINEAR_ADDRESS;
  _KdPrint (("GUEST_LINEAR_ADDRESS 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****Natural 64-bit Guest-State Fields*****/\n"));
  addr = GUEST_CR0;
  _KdPrint (("GUEST_CR0 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CR3;
  _KdPrint (("GUEST_CR3 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CR4;
  _KdPrint (("GUEST_CR4 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_ES_BASE;
  _KdPrint (("GUEST_ES_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CS_BASE;
  _KdPrint (("GUEST_CS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SS_BASE;
  _KdPrint (("GUEST_SS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DS_BASE;
  _KdPrint (("GUEST_DS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_FS_BASE;
  _KdPrint (("GUEST_FS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GS_BASE;
  _KdPrint (("GUEST_GS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LDTR_BASE;
  _KdPrint (("GUEST_LDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_TR_BASE;
  _KdPrint (("GUEST_TR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GDTR_BASE;
  _KdPrint (("GUEST_GDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_IDTR_BASE;
  _KdPrint (("GUEST_IDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DR7;
  _KdPrint (("GUEST_DR7 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_RSP;
  _KdPrint (("GUEST_RSP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_RIP;
  _KdPrint (("GUEST_RIP 0x%X: 0x%llX\n", addr, VmxRead (addr)));
  addr = GUEST_RFLAGS;
  _KdPrint (("GUEST_RFLAGS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_PENDING_DBG_EXCEPTIONS;
  _KdPrint (("GUEST_PENDING_DBG_EXCEPTIONS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SYSENTER_ESP;
  _KdPrint (("GUEST_SYSENTER_ESP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SYSENTER_EIP;
  _KdPrint (("GUEST_SYSENTER_EIP 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  _KdPrint (("\n\n\n/*****Natural 64-bit Host-State Fields*****/\n"));
  addr = HOST_CR0;
  _KdPrint (("HOST_CR0 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_CR3;
  _KdPrint (("HOST_CR3 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_CR4;
  _KdPrint (("HOST_CR4 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_FS_BASE;
  _KdPrint (("HOST_FS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_GS_BASE;
  _KdPrint (("HOST_GS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_TR_BASE;
  _KdPrint (("HOST_TR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_GDTR_BASE;
  _KdPrint (("HOST_GDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_IDTR_BASE;
  _KdPrint (("HOST_IDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_IA32_SYSENTER_ESP;
  _KdPrint (("HOST_IA32_SYSENTER_ESP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_IA32_SYSENTER_EIP;
  _KdPrint (("HOST_IA32_SYSENTER_EIP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_RSP;
  _KdPrint (("HOST_RSP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_RIP;
  _KdPrint (("HOST_RIP 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  return;
}

static VOID DumpMemory (
  PUCHAR Addr,
  ULONG64 Len
)
{
  ULONG64 i;
  for (i = 0; i < Len; i++) {
    _KdPrint (("0x%x 0x%x\n", Addr + i, *(Addr + i)));
  }
}

VOID NTAPI VmxCrash (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  PHYSICAL_ADDRESS pa;
  NTSTATUS Status;
  _KdPrint (("!!!VMX CRASH!!!\n"));

#if DEBUG_LEVEL>1
  _KdPrint (("rax 0x%llX\n", GuestRegs->rax));
  _KdPrint (("rcx 0x%llX\n", GuestRegs->rcx));
  _KdPrint (("rdx 0x%llX\n", GuestRegs->rdx));
  _KdPrint (("rbx 0x%llX\n", GuestRegs->rbx));
  _KdPrint (("rsp 0x%llX\n", GuestRegs->rsp));
  _KdPrint (("rbp 0x%llX\n", GuestRegs->rbp));
  _KdPrint (("rsi 0x%llX\n", GuestRegs->rsi));
  _KdPrint (("rdi 0x%llX\n", GuestRegs->rdi));

  _KdPrint (("r8 0x%llX\n", GuestRegs->r8));
  _KdPrint (("r9 0x%llX\n", GuestRegs->r9));
  _KdPrint (("r10 0x%llX\n", GuestRegs->r10));
  _KdPrint (("r11 0x%llX\n", GuestRegs->r11));
  _KdPrint (("r12 0x%llX\n", GuestRegs->r12));
  _KdPrint (("r13 0x%llX\n", GuestRegs->r13));
  _KdPrint (("r14 0x%llX\n", GuestRegs->r14));
  _KdPrint (("r15 0x%llX\n", GuestRegs->r15));
  _KdPrint (("Guest MSR_EFER Read 0x%llx \n", Cpu->Vmx.GuestEFER));
  CmGetPagePaByPageVaCr3 (Cpu, VmxRead (GUEST_CR3), VmxRead (GUEST_RIP), &pa);
  _KdPrint (("VmxCrash() IOA: Failed to map PA 0x%p to VA 0x%p\n", pa.QuadPart, Cpu->SparePage));
#endif

#if DEBUG_LEVEL>2
  if (!NT_SUCCESS (Status = CmPatchPTEPhysicalAddress (Cpu->SparePagePTE, Cpu->SparePage, pa))) {
    _KdPrint (("VmxCrash() IOA: Failed to map PA 0x%p to VA 0x%p, status 0x%08hX\n", pa.QuadPart, Cpu->SparePage,
               Status));
  }
  DumpMemory ((PUCHAR)
              (((ULONG64) Cpu->SparePage) | ((VmxRead (GUEST_RIP) - 0x10) & 0xfff)), 0x50);
#endif
  while (1);
}

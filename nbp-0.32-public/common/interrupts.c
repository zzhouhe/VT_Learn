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

#include "interrupts.h"

VOID NTAPI InHandleException (
  PCPU Cpu,
  PTRAP_FRAME TrapFrame,
  ULONG uException,
  ULONG64 uErrorCode
)
{

  if (uException == 13) {
    _KdPrint (("InHandleException(): CPU#%d: #GP, error code %d\n", 0xff,       //Cpu->ProcessorNumber,
               uErrorCode));
  } else {
    _KdPrint (("InHandleException(): CPU#%d: Exception 0x%X, error code %d\n", 0xff,    //Cpu->ProcessorNumber,
               uException, uErrorCode));
  }

  _KdPrint (("InHandleException(): rip 0x%p\n", TrapFrame->rip));
  _KdPrint (("InHandleException(): rflags 0x%p\n", TrapFrame->rflags));

  _KdPrint (("InHandleException(): rax 0x%p  r8  0x%p\n", TrapFrame->rax, TrapFrame->r8));
  _KdPrint (("InHandleException(): rbx 0x%p  r9  0x%p\n", TrapFrame->rbx, TrapFrame->r9));
  _KdPrint (("InHandleException(): rcx 0x%p  r10 0x%p\n", TrapFrame->rcx, TrapFrame->r10));
  _KdPrint (("InHandleException(): rdx 0x%p  r11 0x%p\n", TrapFrame->rdx, TrapFrame->r11));
  _KdPrint (("InHandleException(): rsi 0x%p  r12 0x%p\n", TrapFrame->rsi, TrapFrame->r12));
  _KdPrint (("InHandleException(): rdi 0x%p  r13 0x%p\n", TrapFrame->rdi, TrapFrame->r13));
  _KdPrint (("InHandleException(): rbp 0x%p  r14 0x%p\n", TrapFrame->rbp, TrapFrame->r14));
  _KdPrint (("InHandleException(): rsp 0x%p  r15 0x%p\n", TrapFrame->rsp, TrapFrame->r15));

  TrapFrame->rip += 2;
  TrapFrame->r8 = STATUS_UNSUCCESSFUL;

  return;
}

VOID NTAPI InHandleInterrupt (
  PCPU Cpu,
  PTRAP_FRAME TrapFrame,
  ULONG uInterrupt,
  ULONG64 uErrorCode
)
{

  if (uInterrupt == 13) {
    _KdPrint (("InHandleInterrupt(): CPU#%d: #GP, error code %d\n", 0xff,       //Cpu->ProcessorNumber,
               uErrorCode));
  } else {
    _KdPrint (("InHandleInterrupt(): CPU#%d: Interrupt 0x%X, error code %d\n", 0xff,    //Cpu->ProcessorNumber,
               uInterrupt, uErrorCode));
  }

  _KdPrint (("InHandleInterrupt(): rip 0x%p\n", TrapFrame->rip));
  _KdPrint (("InHandleInterrupt(): rflags 0x%p\n", TrapFrame->rflags));

  _KdPrint (("InHandleInterrupt(): rax 0x%p  r8  0x%p\n", TrapFrame->rax, TrapFrame->r8));
  _KdPrint (("InHandleInterrupt(): rbx 0x%p  r9  0x%p\n", TrapFrame->rbx, TrapFrame->r9));
  _KdPrint (("InHandleInterrupt(): rcx 0x%p  r10 0x%p\n", TrapFrame->rcx, TrapFrame->r10));
  _KdPrint (("InHandleInterrupt(): rdx 0x%p  r11 0x%p\n", TrapFrame->rdx, TrapFrame->r11));
  _KdPrint (("InHandleInterrupt(): rsi 0x%p  r12 0x%p\n", TrapFrame->rsi, TrapFrame->r12));
  _KdPrint (("InHandleInterrupt(): rdi 0x%p  r13 0x%p\n", TrapFrame->rdi, TrapFrame->r13));
  _KdPrint (("InHandleInterrupt(): rbp 0x%p  r14 0x%p\n", TrapFrame->rbp, TrapFrame->r14));
  _KdPrint (("InHandleInterrupt(): rsp 0x%p  r15 0x%p\n", TrapFrame->rsp, TrapFrame->r15));

  return;
}

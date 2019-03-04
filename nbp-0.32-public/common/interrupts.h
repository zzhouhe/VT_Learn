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
#include "hvm.h"

typedef struct
{
  ULONG64 rcx;                  // 0x00
  ULONG64 rdx;
  ULONG64 r8;                   // 0x10
  ULONG64 r9;
  ULONG64 r10;                  // 0x20
  ULONG64 r11;
  ULONG64 r12;                  // 0x30
  ULONG64 r13;
  ULONG64 r14;                  // 0x40
  ULONG64 r15;
  ULONG64 rdi;                  // 0x50
  ULONG64 rsi;
  ULONG64 rbx;                  // 0x60
  ULONG64 rbp;
  ULONG64 rsp;                  // 0x70
  ULONG64 rax;
  ULONG64 rflags;               // 0x80
  ULONG64 rip;
} TRAP_FRAME,
 *PTRAP_FRAME;

VOID NTAPI InGeneralProtection (
);

extern PVOID IntHandlers[];
extern PVOID CallIntHandlers[];

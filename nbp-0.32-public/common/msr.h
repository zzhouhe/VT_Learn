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

ULONG64 NTAPI MsrRead (
  ULONG32 reg
);

VOID NTAPI MsrWrite (
  ULONG32 reg,
  ULONG64 MsrValue
);

NTSTATUS NTAPI MsrSafeWrite (
  ULONG32 reg,
  ULONG32 eax,
  ULONG32 edx
);

VOID NTAPI MsrReadWithEaxEdx (
  PULONG32 reg,                 // ecx after rdmsr will be stored there
  PULONG32 eax,
  PULONG32 edx
);

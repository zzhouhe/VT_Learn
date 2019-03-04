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

VOID NTAPI GetCpuIdInfo (
  ULONG32 fn,
  OUT PULONG32 ret_eax,
  OUT PULONG32 ret_ebx,
  OUT PULONG32 ret_ecx,
  OUT PULONG32 ret_edx
);

VOID NTAPI CpuidWithEcxEdx (
  IN OUT PULONG32 ret_ecx,
  IN OUT PULONG32 ret_edx
);

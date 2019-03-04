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
#include "common.h"
#include <ntddk.h>

USHORT NTAPI RegGetCs (
);
USHORT NTAPI RegGetDs (
);
USHORT NTAPI RegGetEs (
);
USHORT NTAPI RegGetSs (
);
USHORT NTAPI RegGetFs (
);
USHORT NTAPI RegGetGs (
);

ULONG64 NTAPI RegGetCr0 (
);
ULONG64 NTAPI RegGetCr2 (
);
ULONG64 NTAPI RegGetCr3 (
);
ULONG64 NTAPI RegGetCr4 (
);
ULONG64 NTAPI RegGetCr8 (
);
ULONG64 NTAPI RegGetRflags (
);
ULONG64 NTAPI RegGetRsp (
);

ULONG64 NTAPI GetIdtBase (
);
USHORT NTAPI GetIdtLimit (
);
ULONG64 NTAPI GetGdtBase (
);
USHORT NTAPI GetGdtLimit (
);
USHORT NTAPI GetLdtr (
);

USHORT NTAPI GetTrSelector (
);

ULONG64 NTAPI RegGetRbx (
);
ULONG64 NTAPI RegGetRax (
);

ULONG64 NTAPI RegGetTSC (
);

ULONG64 NTAPI RegGetDr0 (
);
ULONG64 NTAPI RegGetDr1 (
);
ULONG64 NTAPI RegGetDr2 (
);
ULONG64 NTAPI RegGetDr3 (
);
ULONG64 NTAPI RegGetDr6 (
);
ULONG64 NTAPI RegSetDr0 (
);
ULONG64 NTAPI RegSetDr1 (
);
ULONG64 NTAPI RegSetDr2 (
);
ULONG64 NTAPI RegSetDr3 (
);

ULONG64 NTAPI RegSetCr3 (
  PVOID NewCr3
);
ULONG64 NTAPI RegSetCr8 (
  ULONG64 NewCr8
);

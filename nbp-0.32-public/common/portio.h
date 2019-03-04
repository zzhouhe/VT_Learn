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
#include "regs.h"

#define LS_THR_EMPTY	0x20

#define TRANSMIT_HOLDING_REGISTER		0x00
#define LINE_STATUS_REGISTER		0x05

UCHAR g_BpId;

VOID NTAPI PioInit (
  PUCHAR ComPortAddress
);

VOID NTAPI PioOutByte (
  UCHAR Byte
);

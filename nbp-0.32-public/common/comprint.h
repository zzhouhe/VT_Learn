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
#include "common.h"
#include "portio.h"
#include "dbgclient.h"
#include "snprintf.h"
#include <stdarg.h>

VOID NTAPI ComPrint (
  PUCHAR fmt,
  ...
);

VOID NTAPI ComInit (
);

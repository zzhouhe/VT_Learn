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

#define NBP_BUILD_NUMBER		32

#define	MAKE_VERSION(Major,Minor,BuildNumber,Reserved)	(ULONG64)((((ULONG64)Major)<<48)+(((ULONG64)Minor)<<32)+(((ULONG64)BuildNumber)<<16)+(Reserved))
#define NBP_VERSION	MAKE_VERSION(1,0,NBP_BUILD_NUMBER,0)

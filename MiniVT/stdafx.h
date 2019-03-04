#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifdef __cplusplus
extern "C" 
{

#endif

#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>


#ifdef __cplusplus
}
#endif

#define Log(message,value) {{KdPrint(("[MiniVT] %-40s [%p]\n",message,value));}}

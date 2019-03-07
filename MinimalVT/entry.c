#include <ntddk.h>
#include "vtsystem.h"

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    StopVirtualTechnology();
    DbgPrint("Driver is unloading...\r\n");
}

ULONG g_exit_esp;
ULONG back_position;
void __declspec(naked) g_exit()
{
    __asm{
        mov esp, g_exit_esp
        jmp back_position
    }
}


NTSTATUS 
  DriverEntry( 
    PDRIVER_OBJECT  driver,
    PUNICODE_STRING RegistryPath
    )
{

    DbgPrint("Driver Entered!\r\n");
	driver->DriverUnload = DriverUnload;

    __asm
    {
        pushad
        pushfd
        mov g_exit_esp, esp
        mov back_position, offset RETPOSITION
    }

    StartVirtualTechnology();       //×Ô´Ë²»¹é
//=============================================================
RETPOSITION:
    __asm{
        popfd
        popad
    }
    Log("GuestEntry~~~~~~~~~~~~~~~~~~~~", 0)

	return STATUS_SUCCESS;
}



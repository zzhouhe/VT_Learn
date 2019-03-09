#include <ntddk.h>
#include "vtsystem.h"

PULONG test_data;

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    StopVirtualTechnology();
    ExFreePool(test_data);
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
    test_data = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'test');
    Log("test_data at:", test_data);

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
    *test_data = 0x1234;
    Log("test_data:", *test_data)

	return STATUS_SUCCESS;
}



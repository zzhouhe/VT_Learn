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

#include "dbgclient.h"

static PVOID g_DbgWindow = NULL;

static DbgSendCommand (
  ULONG uIoctlNumber,
  PVOID pData,
  ULONG uDataSize
)
{
  NTSTATUS Status;
  HANDLE hDbgClient;
  IO_STATUS_BLOCK Iosb;
  UNICODE_STRING DeviceName;
  OBJECT_ATTRIBUTES ObjectAttributes;

  RtlInitUnicodeString (&DeviceName, L"\\Device\\itldbgclient");
  InitializeObjectAttributes (&ObjectAttributes, &DeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

  hDbgClient = 0;
  Status = ZwOpenFile (&hDbgClient, FILE_READ_ACCESS | FILE_WRITE_ACCESS, &ObjectAttributes, &Iosb, FILE_SHARE_READ, 0);
  if (!NT_SUCCESS (Status)) {
    DbgPrint ("DbgSendCommand(): ZwOpenFile() failed with status 0x%08X\n", Status);
    return Status;
  }

  Status = NtDeviceIoControlFile (hDbgClient,
                                  NULL, NULL, NULL, &Iosb, uIoctlNumber, pData, uDataSize, pData, uDataSize);
  if (!NT_SUCCESS (Status)) {
    DbgPrint ("DbgSendCommand(): NtDeviceIoControlFile() failed with status 0x%08X\n", Status);
    ZwClose (hDbgClient);
    return Status;
  }

  ZwClose (hDbgClient);
  return STATUS_SUCCESS;
}

NTSTATUS NTAPI DbgRegisterWindow (
  UCHAR bBpId
)
{
  NTSTATUS Status;
  DEBUG_WINDOW DebugWindow;

  g_DbgWindow = MmAllocatePages (DEBUG_WINDOW_IN_PAGES, NULL);
  if (!g_DbgWindow) {
    _KdPrint (("DbgRegisterWindow(): Failed to allocate %d pages for the debug messages window\n",
               DEBUG_WINDOW_IN_PAGES));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  DebugWindow.bBpId = bBpId;
  DebugWindow.pWindowVA = g_DbgWindow;
  DebugWindow.uWindowSize = DEBUG_WINDOW_IN_PAGES * PAGE_SIZE;

  // memory will be freed on memory manager shutdown in case of error
  return DbgSendCommand (IOCTL_REGISTER_WINDOW, &DebugWindow, sizeof (DebugWindow));
}

NTSTATUS NTAPI DbgUnregisterWindow (
)
{
  DEBUG_WINDOW DebugWindow;

  DebugWindow.pWindowVA = g_DbgWindow;
  DebugWindow.uWindowSize = DEBUG_WINDOW_IN_PAGES * PAGE_SIZE;

  return DbgSendCommand (IOCTL_UNREGISTER_WINDOW, &DebugWindow, sizeof (DebugWindow));
}

VOID NTAPI DbgPrintString (
  PUCHAR pString
)
{
  if (g_DbgWindow) {

    if (!*(PUCHAR) g_DbgWindow) {
      RtlZeroMemory (g_DbgWindow, DEBUG_WINDOW_IN_PAGES * PAGE_SIZE);
    }

    if (strlen ((PUCHAR) g_DbgWindow + 1) + strlen (pString) >= DEBUG_WINDOW_IN_PAGES * PAGE_SIZE)
      return;

    strcat ((PUCHAR) g_DbgWindow + 1, pString);
    *(PUCHAR) g_DbgWindow = 1;
  }
}

#include "stdafx.h"
#include "vtsystem.h"

void MiniVTUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS MiniVTCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS MiniVTDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);
#endif

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	UNICODE_STRING DeviceName,Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;
	unsigned i;

	RtlInitUnicodeString(&DeviceName,L"\\Device\\MiniVT0");
	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\MiniVT0");

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = MiniVTDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = MiniVTCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MiniVTCreateClose;
	
	DriverObject->DriverUnload = MiniVTUnload;
	status = IoCreateDevice(DriverObject,
							0,
							&DeviceName,
							FILE_DEVICE_UNKNOWN,
							0,
							FALSE,
							&DeviceObject);
	if (!NT_SUCCESS(status))
		return status;
	if (!DeviceObject)
		return STATUS_UNEXPECTED_IO_ERROR;

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);

	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	StartVirtualTechnology();
	Log("驱动加载完毕.",0);
	return STATUS_SUCCESS;
}

void MiniVTUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING Win32Device;
	StopVirtualTechnology();
	RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\MiniVT0");
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
	Log("驱动卸载完毕.",0);
}

NTSTATUS MiniVTCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS MiniVTDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

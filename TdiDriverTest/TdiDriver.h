#pragma once
#include <ntddk.h>
#include <tdi.h>
#include <tdikrnl.h>

#define TCP_DEVICE_NAME					L"\\Device\\Tcp"
#define UDP_DEVICE_NAME					L"\\Device\\Udp"
#define RAWIP_DEVICE_NAME		    	L"\\Device\\RawIp"

#ifdef __cplusplus
extern "C"
{
#endif


VOID DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

//创建并绑定指定设备
NTSTATUS CreateAndAttachDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT * fltObj, PDEVICE_OBJECT * oldObj, PWCHAR deviceName);

//取消绑定并删除设备
VOID DetachAndDeleteDevie(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT fltObj, PDEVICE_OBJECT oldObj);

// // 分发函数
// NTSTATUS DeviceDisPatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//
// NTSTATUS TdiControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS TdiInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS TdiPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);				//不关心的分发函数全部通过

NTSTATUS TdiFilterCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);			//在这个函数中获取本地ip地址

BOOLEAN TdiGetAddressInfo(PTRANSPORT_ADDRESS transportAddress);				//打印ip地址

NTSTATUS MyIoCompletionRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PVOID Context
);

NTSTATUS QueryAddressInfoCompleteRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PVOID Context
);
#ifdef __cplusplus
}
#endif



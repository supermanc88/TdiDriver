#include "TdiDriver.h"

#ifdef __cplusplus
extern "C"
{
#endif

PDEVICE_OBJECT g_TcpFltObj = NULL;
PDEVICE_OBJECT g_UdpFltObj = NULL;
PDEVICE_OBJECT g_TcpOldObj = NULL;
PDEVICE_OBJECT g_UdpOldObj = NULL;


typedef struct _IP_ADDRESS
{
	union
	{
		ULONG ipInt;
		UCHAR ipUChar[4];
	};
}IP_ADDRESS, *PIP_ADDRESS;

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("TdiDriver: 驱动卸载\n"));
	DetachAndDeleteDevie(DriverObject, g_TcpFltObj, g_TcpOldObj);
	// DetachAndDeleteDevie(DriverObject, g_UdpFltObj, g_UdpOldObj);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	int i = 0;

	KdPrint(("TdiDriver: 驱动加载\n"));
	DriverObject->DriverUnload = DriverUnload;

	for (i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = TdiPassThrough;
	}
	DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = TdiInternalDeviceControl;			//主要操作都在这个里面

	//开始创建并绑定设备
	CreateAndAttachDevice(DriverObject, &g_TcpFltObj, &g_TcpOldObj, TCP_DEVICE_NAME);
//	CreateAndAttachDevice(DriverObject, &g_UdpFltObj, &g_UdpOldObj, UDP_DEVICE_NAME);

	return status;
}



NTSTATUS CreateAndAttachDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT * fltObj, PDEVICE_OBJECT * oldObj, PWCHAR deviceName)
{
	NTSTATUS status;
	UNICODE_STRING deviceNameStr;

	status = IoCreateDevice(DriverObject,
		0,
		NULL,
		FILE_DEVICE_UNKNOWN,
		0,
		TRUE,
		fltObj);

	if(!NT_SUCCESS(status))
	{
		KdPrint(("TdiDriver: 创建设备失败\n"));
		return status;
	}

	(*fltObj)->Flags |= DO_DIRECT_IO;

	//开始绑定指定的设备

	RtlInitUnicodeString(&deviceNameStr, deviceName);

	status = IoAttachDevice(*fltObj, &deviceNameStr, oldObj);

	if(!NT_SUCCESS(status))
	{
		KdPrint(("TdiDriver: 绑定设备%wZ失败\n", &deviceNameStr));
		return status;
	}

	return STATUS_SUCCESS;

}

VOID DetachAndDeleteDevie(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT fltObj, PDEVICE_OBJECT oldObj)
{
	IoDetachDevice(oldObj);
	IoDeleteDevice(fltObj);
}

// NTSTATUS DeviceDisPatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
// {
// 	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
//
// 	NTSTATUS status;
//
//
// 	if (DeviceObject == g_TcpFltObj)
// 	{
// 		switch(irps->MajorFunction)
// 		{
// 			case IRP_MJ_INTERNAL_DEVICE_CONTROL:
// 				status = TdiControl(DeviceObject, Irp);
// 			break;
// 			default:
// 			IoSkipCurrentIrpStackLocation(Irp);
// 			status = IoCallDriver(g_TcpOldObj, Irp);
// 			break;
// 		}
//
// 	}
// 	else
// 	{
// 		IoSkipCurrentIrpStackLocation(Irp);
// 		status = IoCallDriver(g_TcpOldObj, Irp);
// 	}
//
// 	return status;
// }

// 这段弃用
// NTSTATUS TdiControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
// {
//
// 	NTSTATUS status;
// 	PFILE_FULL_EA_INFORMATION ea;
// 	PIO_STACK_LOCATION Irps;
//
// 	Irps = IoGetCurrentIrpStackLocation(Irp);
//
// 	if (Irps->MinorFunction == TDI_CONNECT)
// 	{
// 		ea = (PFILE_FULL_EA_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
//
// 		if (ea != NULL)
// 		{
// 			if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH &&
// 				memcpy(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0)
// 			{
// 				PTRANSPORT_ADDRESS transportAddress;
//
// 				transportAddress = (PTRANSPORT_ADDRESS)((PUCHAR)ea + FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + TDI_TRANSPORT_ADDRESS_LENGTH + 1);
//
// 				switch (transportAddress->Address->AddressType)
// 				{
// 				case TDI_ADDRESS_TYPE_IP:
// 				{
// 					PTDI_ADDRESS_IP ipAddress = (PTDI_ADDRESS_IP)transportAddress->Address->Address;
// 					KdPrint(("TdiDriver: ip:%d, port:%d\n", ipAddress->in_addr, ipAddress->sin_port));
// 					break;
// 				}
// 				case TDI_ADDRESS_TYPE_IP6:
// 					break;
// 				default:
// 					break;
// 				}
// 			}
// 		}
//
// 		IoSkipCurrentIrpStackLocation(Irp);
// 		status = IoCallDriver(g_TcpOldObj, Irp);
// 		return status;
// 	}
// 	else
// 	{
// 		IoSkipCurrentIrpStackLocation(Irp);
// 		status = IoCallDriver(g_TcpOldObj, Irp);
// 		return status;
// 	}
//
// }


NTSTATUS TdiInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS status;

	PTRANSPORT_ADDRESS transportAddress = NULL;

	PTDI_REQUEST_KERNEL_CONNECT tdiReqKelConnect = NULL;			
	IP_ADDRESS ipAddress;
	switch (irpStack->MinorFunction)
	{
	case TDI_CONNECT:
		{
			
			KdPrint(("Tdi Driver: TDI_CONNECT!\n"));

			tdiReqKelConnect = (PTDI_REQUEST_KERNEL_CONNECT)&irpStack->Parameters;

			if(!tdiReqKelConnect->RequestConnectionInformation)
			{
				KdPrint(("Tdi Driver: no request!\n"));
				IoSkipCurrentIrpStackLocation(Irp);
				status = IoCallDriver(g_TcpOldObj, Irp);
			}

			if(tdiReqKelConnect->RequestConnectionInformation->RemoteAddressLength == 0)
			{
				KdPrint(("Tdi Driver: RemoteAddressLength=0\n"));
				IoSkipCurrentIrpStackLocation(Irp);
				status = IoCallDriver(g_TcpOldObj, Irp);
			}


			transportAddress = (PTRANSPORT_ADDRESS)(tdiReqKelConnect->RequestConnectionInformation->RemoteAddress);

			switch (transportAddress->Address->AddressType)
			{
			case TDI_ADDRESS_TYPE_IP:
			{
				PTDI_ADDRESS_IP tdiAddressIp = (PTDI_ADDRESS_IP)transportAddress->Address->Address;
				ipAddress.ipInt = tdiAddressIp->in_addr;
				KdPrint(("TdiDriver: ip:%d.%d.%d.%d, port:%d\n", ipAddress.ipUChar[3], ipAddress.ipUChar[2], ipAddress.ipUChar[1], ipAddress.ipUChar[0], tdiAddressIp->sin_port));
				break;
			}
			case TDI_ADDRESS_TYPE_IP6:
				break;
			default:
				break;
			}

			IoSkipCurrentIrpStackLocation(Irp);
			status = IoCallDriver(g_TcpOldObj, Irp);
			break;
		}

	default:
		IoSkipCurrentIrpStackLocation(Irp);
		status = IoCallDriver(g_TcpOldObj, Irp);
		break;
	}

	return status;
}

NTSTATUS TdiPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	//如果设备对象是我们要过滤的，直接传给下层的设备对象
	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(g_TcpOldObj, Irp);
	return status;
}


#ifdef __cplusplus
}
#endif
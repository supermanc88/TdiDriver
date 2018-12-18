#include "TdiDriver.h"

#ifdef __cplusplus
extern "C"
{
#endif

PDEVICE_OBJECT g_TcpFltObj = NULL;
PDEVICE_OBJECT g_UdpFltObj = NULL;
PDEVICE_OBJECT g_TcpOldObj = NULL;
PDEVICE_OBJECT g_UdpOldObj = NULL;

typedef struct
{
	TDI_ADDRESS_INFO *tai;
	PFILE_OBJECT	fileObj;
} TDI_CREATE_ADDROBJ2_CTX;

typedef struct _IP_ADDRESS
{
	union
	{
		ULONG ipInt;
		UCHAR ipUChar[4];
	};
}IP_ADDRESS, *PIP_ADDRESS;

NTKERNELAPI NTSTATUS IoCheckEaBufferValidity(
	PFILE_FULL_EA_INFORMATION EaBuffer,
	ULONG                     EaLength,
	PULONG                    ErrorOffset
);

USHORT
TdiFilter_Ntohs(IN USHORT v)
{
	return (((UCHAR)(v >> 8)) | (v & 0xff) << 8);
};

ULONG
TdiFilter_Ntohl(IN ULONG v)					//颠倒IP地址的顺序
{
	return ((v & 0xff000000) >> 24 |
		(v & 0xff0000) >> 8 |
		(v & 0xff00) << 8 |
		((UCHAR)v) << 24);
};

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
	DriverObject->MajorFunction[IRP_MJ_CREATE] = TdiFilterCreate;

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



NTSTATUS TdiInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS status;

	PTRANSPORT_ADDRESS transportAddress = NULL;

	PTDI_REQUEST_KERNEL_CONNECT tdiReqKelConnect = NULL;			
	switch (irpStack->MinorFunction)
	{
	case TDI_CONNECT:
		{
			//创建连接的时候走这个流程	
			KdPrint(("Tdi Driver: TDI_CONNECT!\n"));

			tdiReqKelConnect = (PTDI_REQUEST_KERNEL_CONNECT)(&irpStack->Parameters);

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

			TdiGetAddressInfo(transportAddress);
			IoSkipCurrentIrpStackLocation(Irp);
			status = IoCallDriver(g_TcpOldObj, Irp);
			break;
		}

	case TDI_ACCEPT:
		IoSkipCurrentIrpStackLocation(Irp);
		status = IoCallDriver(g_TcpOldObj, Irp);
		break;
	
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

NTSTATUS TdiFilterCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	KdPrint(("Tdi Driver: TdiFilterCreate\n"));
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_FULL_EA_INFORMATION ea = NULL;
	ULONG ErrorOffset = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ea = (PFILE_FULL_EA_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
	status = IoCheckEaBufferValidity(ea, irpSp->Parameters.Create.EaLength, &ErrorOffset);

	if(NT_SUCCESS(status))
	{
		if (TDI_TRANSPORT_ADDRESS_LENGTH == ea->EaNameLength &&
			TDI_TRANSPORT_ADDRESS_LENGTH == RtlCompareMemory(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH))
		{
			PTRANSPORT_ADDRESS transportAddress;

			transportAddress = (PTRANSPORT_ADDRESS)((PUCHAR)ea +
				FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) +
				TDI_TRANSPORT_ADDRESS_LENGTH + 1);

			TdiGetAddressInfo(transportAddress);

			PIRP queryIrp;

			queryIrp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION,
				DeviceObject,
				irpSp->FileObject,
				NULL,
				NULL);

			IoCopyCurrentIrpStackLocationToNext(Irp);

			IoSetCompletionRoutine(Irp, MyIoCompletionRoutine, queryIrp, TRUE, TRUE, TRUE);
			return IoCallDriver(g_TcpOldObj, Irp);
		}
	}
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(g_TcpOldObj, Irp);
}

BOOLEAN TdiGetAddressInfo(PTRANSPORT_ADDRESS transportAddress)
{
	switch (transportAddress->Address->AddressType)
	{
	case TDI_ADDRESS_TYPE_IP:
	{
		PTDI_ADDRESS_IP tdiAddressIp = (PTDI_ADDRESS_IP)(transportAddress->Address->Address);
		
		IP_ADDRESS ipAddress;
		ipAddress.ipInt = tdiAddressIp->in_addr;
		USHORT port = TdiFilter_Ntohs(tdiAddressIp->sin_port);
		KdPrint(("TdiDriver: ip:%d.%d.%d.%d, port:%d\n", ipAddress.ipUChar[0], ipAddress.ipUChar[1], ipAddress.ipUChar[2], ipAddress.ipUChar[3], port));
		break;
	}
	case TDI_ADDRESS_TYPE_IP6:
		break;
	default:
		break;
	}

	return FALSE;
}

NTSTATUS MyIoCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	PIRP queryIrp = (PIRP)Context;
	NTSTATUS status = STATUS_SUCCESS;

	TDI_CREATE_ADDROBJ2_CTX *ctx = NULL;
	ctx = (TDI_CREATE_ADDROBJ2_CTX *)ExAllocatePool(NonPagedPool, sizeof(TDI_CREATE_ADDROBJ2_CTX));

	ctx->fileObj = irpSp->FileObject;
	ctx->tai = (TDI_ADDRESS_INFO *)ExAllocatePool(NonPagedPool, sizeof(TDI_ADDRESS_INFO) - 1 + TDI_ADDRESS_LENGTH_OSI_TSAP);;

	PMDL mdl = IoAllocateMdl(ctx->tai, sizeof(TDI_ADDRESS_INFO) - 1 + TDI_ADDRESS_LENGTH_OSI_TSAP, FALSE, FALSE, NULL);

	MmProbeAndLockPages(mdl, Irp->RequestorMode, IoModifyAccess);

	TdiBuildQueryInformation(queryIrp, DeviceObject, irpSp->FileObject,
		QueryAddressInfoCompleteRoutine,
		// NULL,
		ctx,
		// NULL,
		TDI_QUERY_ADDRESS_INFO,
		mdl);
	
	status = IoCallDriver(g_TcpOldObj, queryIrp);
	
	Irp->IoStatus.Status = status;

	if(Irp->PendingReturned)
	{
		IoMarkIrpPending(Irp);
	}

	return STATUS_SUCCESS;
}

NTSTATUS QueryAddressInfoCompleteRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	TDI_CREATE_ADDROBJ2_CTX * ctx = (TDI_CREATE_ADDROBJ2_CTX *)Context;
	TA_ADDRESS * addr = ctx->tai->Address.Address;

	KdPrint(("Tdi Driver QueryAddressInfo %x %u",
		TdiFilter_Ntohl(((TDI_ADDRESS_IP *)(addr->Address))->in_addr),
		TdiFilter_Ntohs(((TDI_ADDRESS_IP *)(addr->Address))->sin_port)
		));
	return STATUS_SUCCESS;
}

#ifdef __cplusplus 
}
#endif

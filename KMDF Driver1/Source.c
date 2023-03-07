// 推荐教材：Windows驱动开发技术详解、[天书夜读－从汇编语言到Windows内核编程].谭文.邵坚磊.扫描版
// 参考代码：Practice.of.Windows.Kernel.Security.Programming.Technology (by LyShark)

#include "header.h"

PVOID obHandle;
DRIVER_INITIALIZE DriverEntry;
ULONG gMyAccessFlag = FALSE; // if TRUE, the driver will send a signal to usermode to ask for permission
ULONG gMyAccessIndex = 0; // the index of the path in pathList asked for permission
ULONG gIsTackled = DEFAULT; // if ALLOW, the driver will allow the access, if DENY, the driver will deny the access
ULONG gNumberOfPaths;
POB_PRE_OPERATION_INFORMATION gOperationInformation;

struct PathList
{
    UNICODE_STRING path;
    ULONG allow;
    LONG remainTime;
}pathList[MAX_PATH_COUNT];

// Sleep() in kernelmode, can only used in PASSIVE_LEVEL
VOID MySleep(ULONG ms)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -10000 * ms;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}
VOID DenyAccess(POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
    }
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
    }
}
VOID AddPathToPathList(PWCHAR path)
{
    DbgPrint("AddPathToPathList: %ws\n", path);
    if (gNumberOfPaths >= MAX_PATH_COUNT)
    {
        DbgPrint("PathList is full!\n");
        return;
    }
    // allocate memory for path
    pathList[gNumberOfPaths].path.Buffer = ExAllocatePool(NonPagedPool, wcslen(path) * 2 + 2);
    pathList[gNumberOfPaths].path.Length = wcslen(path) * 2;
    pathList[gNumberOfPaths].path.MaximumLength = wcslen(path) * 2 + 2;
    RtlCopyMemory(pathList[gNumberOfPaths].path.Buffer, path, wcslen(path) * 2 + 2);

    pathList[gNumberOfPaths].allow = ALLOW; // if use UNCONFIGURED, and "\\WINDOWS" isn't in whitelist, the system will be stuck
    pathList[gNumberOfPaths].remainTime = 0x10; // initial remainTime
    gNumberOfPaths++;
}
VOID TacklePathAccess(struct PathList path, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    if (path.allow == UNCONFIGURED)
    {
        gMyAccessFlag = TRUE;

        while (gIsTackled == DEFAULT)
        {
            // sleep 1000ms
            MySleep(1000);
        }
        if (gIsTackled == ALLOW)
        {
            gIsTackled = DEFAULT;
            path.allow = ALLOW;
        }
        else
        {
            gIsTackled = DEFAULT;
            path.allow = DENY;
        }
    }
    if (path.allow == DENY)
    {
        DenyAccess(OperationInformation);
    }
}
// file callback
OB_PREOP_CALLBACK_STATUS MyFileObjectpreCall(
    PVOID RegistrationContext, 
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNICODE_STRING DosName;
    PFILE_OBJECT fileo = OperationInformation->Object;
    HANDLE CurrentProcessId = PsGetCurrentProcessId();
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (OperationInformation->ObjectType != *IoFileObjectType)
    {
        return OB_PREOP_SUCCESS;
    }
    // filter invalid pointer
    if (fileo->FileName.Buffer == NULL || 
        !MmIsAddressValid(fileo->FileName.Buffer) || 
        fileo->DeviceObject == NULL || 
        !MmIsAddressValid(fileo->DeviceObject))
    {
        return OB_PREOP_SUCCESS;
    }
    // filter invalid path
    if (!_wcsicmp(fileo->FileName.Buffer, L"\\Endpoint") || 
        !_wcsicmp(fileo->FileName.Buffer, L"?") || 
        !_wcsicmp(fileo->FileName.Buffer, L"\\.\\.") || 
        !_wcsicmp(fileo->FileName.Buffer, L"\\") ||
        wcsstr(fileo->FileName.Buffer, L"\\Windows") != NULL ||
        !wcsstr(fileo->FileName.Buffer, L"\\Users\\WDKRemoteUser\\Desktop\\123"))
    {
        return OB_PREOP_SUCCESS;
    }
    // business code
    ULONG isPathInList = FALSE;
    for (ULONG i = 0; i < gNumberOfPaths; i++)
    {
        // if the path is in pathList, decrease the remainTime
        if (!_wcsicmp(fileo->FileName.Buffer, pathList[i].path.Buffer))
        {
            isPathInList = TRUE;
            pathList[i].remainTime--;
            TacklePathAccess(pathList[i], OperationInformation);
            if (pathList[i].remainTime <= 0)
            {
                gMyAccessFlag = TRUE;
                gMyAccessIndex = i;
                gOperationInformation = OperationInformation;
            }
            break;
        }
    }
    // if the path isn't in pathList, add it to pathList
    if (!isPathInList)
    {
        // DbgPrint("%wZ\n", fileo->FileName);
        AddPathToPathList(fileo->FileName.Buffer);
        TacklePathAccess(pathList[gNumberOfPaths - 1], OperationInformation);
    }

    return OB_PREOP_SUCCESS;
}
// no need to modify it
VOID EnableObType(POBJECT_TYPE ObjectType)
{
    PMY_OBJECT_TYPE myobtype = (PMY_OBJECT_TYPE)ObjectType;
    myobtype->TypeInfo.SupportsObjectCallbacks = 1;
}
// no need to modify it
NTSTATUS DefaultDispatch(PDEVICE_OBJECT _pDeviceObject, PIRP _pIrp)
{
    _pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    _pIrp->IoStatus.Information = 0;
    IoCompleteRequest(_pIrp, IO_NO_INCREMENT);
    return _pIrp->IoStatus.Status;
}
// no need to modify it
NTSTATUS CreateCloseDispatch(PDEVICE_OBJECT _pDevcieObject, PIRP _pIrp)
{
    _pIrp->IoStatus.Status = STATUS_SUCCESS;
    _pIrp->IoStatus.Information = 0;
    IoCompleteRequest(_pIrp, IO_NO_INCREMENT);
    return _pIrp->IoStatus.Status;
}
// no need to modify it
NTSTATUS ReadDispatch(PDEVICE_OBJECT _pDeviceObject, PIRP _pIrp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(_pIrp);
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)_pDeviceObject->DeviceExtension;
    IoMarkIrpPending(_pIrp);
    InsertTailList(&pDevExt->IrpList, &_pIrp->Tail.Overlay.ListEntry);
    return STATUS_PENDING;
}
// if you press Y in usermode, uIOCTLCode will be IOCTL_ALLOW, vice versa
NTSTATUS IoctlDispatch(PDEVICE_OBJECT _pDeviceObject, PIRP _pIrp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(_pIrp);
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)_pDeviceObject->DeviceExtension;
    ULONG uIoctlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    // KdBreakPoint();
    switch (uIoctlCode)
    {
        case IOCTL_ALLOW:
            gIsTackled = ALLOW;
            pathList[gMyAccessIndex].allow = ALLOW;
            pathList[gMyAccessIndex].remainTime = 0x10000; // second remain time, TODO for better solution
            break;
        case IOCTL_DENY:
            gIsTackled = DENY;
            pathList[gMyAccessIndex].allow = DENY;
            pathList[gMyAccessIndex].remainTime = 0x10000;
            break;
        default:
            break;
    }
    gMyAccessFlag = FALSE;
    TacklePathAccess(pathList[gMyAccessIndex], gOperationInformation);
    KeSetTimer(&pDevExt->timer, pDevExt->liDueTime, &pDevExt->dpc);
    _pIrp->IoStatus.Status = STATUS_SUCCESS;
    _pIrp->IoStatus.Information = 0;
    IoCompleteRequest(_pIrp, IO_NO_INCREMENT);
    return _pIrp->IoStatus.Status;
}
// this function is in APC_LEVEL, you can't sleep in it and it can interrupt other functions
VOID MyCustomDpc(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    PIRP pIrp;
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)DeferredContext;
    PVOID pBuffer = NULL;
    ULONG uBufferLen = 0;
    PIO_STACK_LOCATION pIrpStack = NULL;
    do
    {
        if (IsListEmpty(&pDevExt->IrpList))
        {
            break;
        }
        PLIST_ENTRY pListEntry = (PLIST_ENTRY)RemoveHeadList(&pDevExt->IrpList);
        if (!pListEntry)
            break;
        pIrp = (PIRP)CONTAINING_RECORD(pListEntry, IRP, Tail.Overlay.ListEntry);
        pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
        // DbgPrint("current DPC Irp: 0x%x\n", pIrp);

        pBuffer = MmGetSystemAddressForMdl(pIrp->MdlAddress);
        if (pBuffer == NULL)
        {
            pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            pIrp->IoStatus.Information = 0;
            IoCompleteRequest(pIrp, IO_NO_INCREMENT);
            break;
        }
        uBufferLen = pIrpStack->Parameters.Read.Length;
        // DbgPrint("read DPC len: %d\n", uBufferLen);
        uBufferLen = uBufferLen > MAX_FILE_LENGTH ? MAX_FILE_LENGTH : uBufferLen;
     
        if (gMyAccessFlag == TRUE)
        {
            RtlCopyMemory(pBuffer, pathList[gMyAccessIndex].path.Buffer, uBufferLen);
            // RtlCopyMemory(pBuffer, "123", 4);
        }
        else
        {
            RtlZeroMemory(pBuffer, uBufferLen);
            // if you don't set timer, DPC will not be called again
            KeSetTimer(&pDevExt->timer, pDevExt->liDueTime, &pDevExt->dpc); 
        } 

        pIrp->IoStatus.Status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = uBufferLen;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    } while (FALSE);
}

NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, DEVNAME);
    PDEVICE_OBJECT pDeviceObject;
    NTSTATUS status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IoCreateDevice failed with status 0x%x");
        return status;
    }
    // set direct io flag
    pDeviceObject->Flags |= DO_DIRECT_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    pDeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;

    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    pDevExt->pDevice = pDeviceObject;
    pDevExt->ustrDeviceName = devName;

    // initialize timer & irp list
    InitializeListHead(&pDevExt->IrpList);
    
    KeInitializeTimer(&pDevExt->timer);
    KeInitializeDpc(&pDevExt->dpc, (PKDEFERRED_ROUTINE)MyCustomDpc, pDevExt);
    pDevExt->liDueTime = RtlConvertLongToLargeInteger(-10000000);
    KeSetTimer(&pDevExt->timer, pDevExt->liDueTime, &pDevExt->dpc);
    // create symbolic link
    RtlInitUnicodeString(&pDevExt->ustrSymLinkName, SYMLINK);
    status = IoCreateSymbolicLink(&pDevExt->ustrSymLinkName, &pDevExt->ustrDeviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IoCreateSymbolicLink failed with status 0x%x");
        IoDeleteDevice(pDeviceObject);
        return status;
    }
    return STATUS_SUCCESS;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
    // TODO; cannot properly unload driver
    ObUnRegisterCallbacks(obHandle);

    PDEVICE_OBJECT pDeviceObject = driver->DeviceObject;
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    
    KeCancelTimer(&pDevExt->timer);
    PLIST_ENTRY pListEntry = NULL;
    KeRemoveQueueDpc(&pDevExt->dpc);
    
    IoDeleteSymbolicLink(&pDevExt->ustrSymLinkName);
    IoDeleteDevice(pDeviceObject);

    for (ULONG i = 0; i < gNumberOfPaths; i++)
    {
        ExFreePool(pathList[i].path.Buffer);
    }

    DbgPrint("driver unloaded\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    PLDR_DATA ldr;
    DbgPrint("driver loaded\n");
    NTSTATUS status = STATUS_SUCCESS;
    // set all dispatch function to default dispatch, except create/close/read/ioctl
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        Driver->MajorFunction[i] = DefaultDispatch;
    }
    Driver->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatch;
    Driver->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatch;
    Driver->MajorFunction[IRP_MJ_READ] = ReadDispatch;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatch;
    status = CreateDevice(Driver);

    // enable IoFileObjectType
    OB_CALLBACK_REGISTRATION obRegFileCallBack;
    OB_OPERATION_REGISTRATION opRegFileCallBack;
    EnableObType(*IoFileObjectType);
    // bypass MmVerifyCallbackFunction
    ldr = (PLDR_DATA)Driver->DriverSection;
    ldr->Flags |= 0x20;

    // initialize callback
    memset(&obRegFileCallBack, 0, sizeof(obRegFileCallBack));
    obRegFileCallBack.Version = ObGetFilterVersion();
    obRegFileCallBack.OperationRegistrationCount = 1;
    obRegFileCallBack.RegistrationContext = NULL;
    RtlInitUnicodeString(&obRegFileCallBack.Altitude, L"321000");
    obRegFileCallBack.OperationRegistration = &opRegFileCallBack;

    memset(&opRegFileCallBack, 0, sizeof(opRegFileCallBack));
    opRegFileCallBack.ObjectType = IoFileObjectType;
    opRegFileCallBack.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegFileCallBack.PreOperation = (POB_PRE_OPERATION_CALLBACK)&MyFileObjectpreCall;
    status = ObRegisterCallbacks(&obRegFileCallBack, &obHandle);
    
    if (!NT_SUCCESS(status))
    {
        DbgPrint("register callback error!\n");
        status = STATUS_UNSUCCESSFUL;
    }
    UNREFERENCED_PARAMETER(RegistryPath);
    Driver->DriverUnload = &UnDriver;
    return status;
}

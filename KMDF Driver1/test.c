#include <wdm.h>
#include <windef.h>
#include <ntstrsafe.h>
#include "Header.h"

ULONG dwTimerCnt=0;
KDPC stTimerDPC={0};
KTIMER stTimerObj={0};
static KEVENT s_event;

NTSTATUS GetRegistryValue(PCWSTR pwcsValueName, ULONG *pReturnLength, UCHAR *pucReturnBuffer, PWSTR pRegistryPath)
{
    HANDLE hKey;
    ULONG ulLength=0;
    NTSTATUS status;
    OBJECT_ATTRIBUTES stObjAttr;
    WCHAR wszKeyBuffer[255]={0};
    UNICODE_STRING usKeyPath;
    UNICODE_STRING valueName;
    KEY_VALUE_PARTIAL_INFORMATION stKeyInfo;
    PKEY_VALUE_PARTIAL_INFORMATION pstKeyInfo;
    
    RtlInitUnicodeString(&valueName, pwcsValueName);
    usKeyPath.Buffer = wszKeyBuffer;
    usKeyPath.MaximumLength = sizeof(wszKeyBuffer);
    usKeyPath.Length = 0;
    status = RtlUnicodeStringPrintf(&usKeyPath, pRegistryPath);
    if(!NT_SUCCESS(status)){
        return status; 
    }
    
    InitializeObjectAttributes(&stObjAttr, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &stObjAttr);
    if(!NT_SUCCESS(status)){
        return status; 
    }
    
    ulLength = 0;
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, &stKeyInfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &ulLength);
    if(!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW) && (status != STATUS_BUFFER_TOO_SMALL)){
        ZwClose(hKey);
        return status; 
    }
    
    pstKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulLength, '1gaT');
    if(pstKeyInfo == NULL){
        ZwClose(hKey);
        return status; 
    }
    
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pstKeyInfo, ulLength, &ulLength);
    if(NT_SUCCESS(status)){
        *pReturnLength = pstKeyInfo->DataLength;
        RtlCopyMemory(pucReturnBuffer, pstKeyInfo->Data, pstKeyInfo->DataLength);
    }
    ExFreePool(pstKeyInfo);
    ZwClose(hKey);
    return STATUS_SUCCESS;
}
NTSTATUS SetRegistryValue(PCWSTR pwcsValueName, ULONG ulValueLength, UCHAR *pucValueBuffer, PWSTR pRegistryPath)
{
    HANDLE hKey;
    ULONG ulLength=0;
    NTSTATUS status;
    OBJECT_ATTRIBUTES stObjAttr;
    WCHAR wszKeyBuffer[255]={0};
    UNICODE_STRING usKeyPath;
    UNICODE_STRING valueName;
    KEY_VALUE_PARTIAL_INFORMATION stKeyInfo;
    PKEY_VALUE_PARTIAL_INFORMATION pstKeyInfo;
    
    RtlInitUnicodeString(&valueName, pwcsValueName);
    usKeyPath.Buffer = wszKeyBuffer;
    usKeyPath.MaximumLength = sizeof(wszKeyBuffer);
    usKeyPath.Length = 0;
    status = RtlUnicodeStringPrintf(&usKeyPath, pRegistryPath);
    if(!NT_SUCCESS(status)){
        return status; 
    }
    
    InitializeObjectAttributes(&stObjAttr, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &stObjAttr);
    if(!NT_SUCCESS(status)){
        return status; 
    }
    
    status = ZwSetValueKey(hKey, &valueName, 0, REG_SZ, pucValueBuffer, ulValueLength);
    if(!NT_SUCCESS(status)){
        ZwClose(hKey);
        return status; 
    }
    ZwClose(hKey);
    return STATUS_SUCCESS;
}

NTSTATUS MyCopyFile(PUNICODE_STRING destPath, PUNICODE_STRING srcPath)
{
    HANDLE target = NULL, source = NULL;

    PVOID buffer = NULL;
    LARGE_INTEGER offset = { 0 };
    IO_STATUS_BLOCK ioStatus = { 0 };

    do {

        OBJECT_ATTRIBUTES objAttr_write;
        InitializeObjectAttributes(&objAttr_write, destPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        NTSTATUS status = ZwCreateFile(&target, GENERIC_WRITE, &objAttr_write, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status)) {
            DbgPrint("ZwCreateFileDst failed with status 0x%x", status);
            break;
        }
        OBJECT_ATTRIBUTES objAttr_read;
        InitializeObjectAttributes(&objAttr_read, srcPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwCreateFile(&source, GENERIC_READ, &objAttr_read, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status)) {
            DbgPrint("ZwCreateFileSrc failed with status 0x%x", status);
            break;
        }

        ULONG length = 4*1024;
        buffer = ExAllocatePool(NonPagedPool, length);
        while(1) {
            status = ZwReadFile(source, NULL, NULL, NULL, &ioStatus, buffer, length, &offset, NULL);
            if (!NT_SUCCESS(status)) {
                if (status == STATUS_END_OF_FILE) {
                    status = STATUS_SUCCESS;
                }
                break;
            }
            length = ioStatus.Information;
            status = ZwWriteFile(target, NULL, NULL, NULL, &ioStatus, buffer, length, &offset, NULL);
            if (!NT_SUCCESS(status)) {
                break;
            }
            offset.QuadPart += length;
        }
    } while(0);

    if (buffer) {
        ExFreePool(buffer);
    }
    if (target) {
        ZwClose(target);
    }
    if (source) {
        ZwClose(source);
    }
    return STATUS_SUCCESS;
}

VOID OnTimer(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    dwTimerCnt+= 1;
    DbgPrint("DpcTimer: %d\n", dwTimerCnt);
}
VOID GetCurrentTime()
{
    LARGE_INTEGER systemTime, localTime;
    TIME_FIELDS timeFields;
    KeQuerySystemTime(&systemTime);
    DbgPrint("systemTime: %lld\n", systemTime.QuadPart);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    RtlTimeToTimeFields(&localTime, &timeFields);

    DbgPrint("%hd-%hd-%hd-%hd-%hd-%hd\n", timeFields.Year, timeFields.Month, timeFields.Day, timeFields.Hour, timeFields.Minute, timeFields.Second);
}
VOID MyThreadProc(PVOID pContext)
{
    UNICODE_STRING *pstr = (UNICODE_STRING *)pContext;
    DbgPrint("MyThreadProc: %wZ", pstr);
    KeSetEvent(&s_event, 0, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID MyFunCreateSystemThread()
{
    UNICODE_STRING str = RTL_CONSTANT_STRING(L"Hello World!\n");
    HANDLE thread = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, MyThreadProc, &str);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("PsCreateSystemThread failed with status 0x%x\n", status);
        return;
    }
    DbgPrint("PsCreateSystemThread success\n");
    return status;
}
VOID MySleep(LONG msec)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -10000 * msec;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}
VOID MyFunCreateSystemThreadWithTimer()
{
    UNICODE_STRING str = RTL_CONSTANT_STRING(L"Hello World!\n");
    HANDLE thread = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    KeInitializeEvent(&s_event, SynchronizationEvent, FALSE);
    status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, MyThreadProc, &str);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("PsCreateSystemThread failed with status 0x%x\n", status);
        return;
    }
    DbgPrint("PsCreateSystemThread success\n");

    ZwClose(thread);
    KeWaitForSingleObject(&s_event, Executive, KernelMode, FALSE, NULL);
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver1 unloaded\n");

    PDEVICE_OBJECT pDeviceObject = DriverObject->DeviceObject;
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    IoDeleteSymbolicLink(&pDevExt->ustrSymLinkName);
    IoDeleteDevice(pDeviceObject);
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
    
    pDeviceObject->Flags |= DO_BUFFERED_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    pDevExt->pDevice = pDeviceObject;
    pDevExt->ustrDeviceName = devName;
    pDevExt->buffer = ExAllocatePool(NonPagedPool, MAX_FILE_LENGTH);
    pDevExt->file_length = MAX_FILE_LENGTH;

    KeInitializeTimer(&stTimerObj);
      KeInitializeDpc(&stTimerDPC, OnTimer, pDeviceObject);

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

NTSTATUS IrpFile(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    
    switch(stack->MajorFunction) {
        case IRP_MJ_CREATE:
            DbgPrint("IRP_MJ_CREATE\n");
            break;
        case IRP_MJ_CLOSE:
            DbgPrint("IRP_MJ_CLOSE\n");
            break;
    }
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
NTSTATUS IrpIOCTL(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
    LARGE_INTEGER stTimeCnt;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    DbgPrint("code: %x\n", code);
    // KdBreakPoint();
    switch(code) {
        case IOCTL_START:
            DbgPrint("IOCTL_START\n");
            dwTimerCnt = 0;
            stTimeCnt.HighPart |= -1;
            stTimeCnt.LowPart = -50000000;
            KeSetTimerEx(&stTimerObj, stTimeCnt, 2000, &stTimerDPC);
            break;
        case IOCTL_STOP:
            DbgPrint("IOCTL_STOP\n");
            KeCancelTimer(&stTimerObj);
            break;
        default:
            DbgPrint("IOCTL_UNKNOWN\n");
            break;
    }

    pIrp->IoStatus.Information = 0;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DbgPrint("Driver1 loaded\n");
    // DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpFile;
    // DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpFile;
    // DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpIOCTL;
    DriverObject->DriverUnload = DriverUnload;

    NTSTATUS status = CreateDevice(DriverObject);

    // UNICODE_STRING destPath;
    // UNICODE_STRING srcPath;
    // RtlInitUnicodeString(&destPath, L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\dest.txt");
    // RtlInitUnicodeString(&srcPath, L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\test.txt");
    // status = MyCopyFile(&destPath, &srcPath);
    // SetRegistryValue(L"test", 8, L"test", L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    MyFunCreateSystemThreadWithTimer();

    return STATUS_SUCCESS;
}
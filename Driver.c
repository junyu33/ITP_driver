#include <ntddk.h>
#include "Header.h"

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    DbgPrint("first: Our driver is unloading¡­\r\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
#if DBG
    int_3();
#endif

    DbgPrint("first: Hello world!\r\n");

    driver->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}
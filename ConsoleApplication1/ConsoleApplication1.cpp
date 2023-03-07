#include <windows.h>
#include <stdio.h>
#include "Header.h" 

int main()
{
    WCHAR Buffer[MAX_FILE_LENGTH] = { 0 };
    DWORD dwRet = { 0 };
    OVERLAPPED ol = { 0 };
    HANDLE hEvent = { 0 };

    HANDLE hDevice = 
        CreateFile(L"\\\\.\\Driver1",
                    GENERIC_READ,
                    FILE_SHARE_READ,		// share mode none
                    NULL,	// no security
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    NULL );		// no template

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to obtain file handle to device: "
            "%s with Win32 error code: %d\n",
            "MyDDKDevice", GetLastError() );
        return 1;
    }

    do 
    {
        hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        ol.hEvent = hEvent;
        ReadFile(hDevice, Buffer, MAX_FILE_LENGTH, &dwRet, &ol);
        // WaitForSingleObject(hEvent, 1000);
        Sleep(50);
        // printf("cache: %s", Buffer);
        if (wcslen(Buffer)) 
        {
            wprintf(L"%s\n", Buffer);
            printf("ALLOW: Y, DENY: [N]\n");
            *Buffer = { 0 };
            char c = getchar();
            if (c == 'Y' || c == 'y') 
            {
                DeviceIoControl(hDevice, IOCTL_ALLOW, NULL, 0, NULL, 0, &dwRet, &ol);
            }
            else if (c == 'N' || c == 'n') 
            {
                DeviceIoControl(hDevice, IOCTL_DENY, NULL, 0, NULL, 0, &dwRet, &ol);
            }
            else 
            {
                DeviceIoControl(hDevice, IOCTL_DENY, NULL, 0, NULL, 0, &dwRet, &ol);
            }
        }
    } while (TRUE);
    CloseHandle(hDevice);
    return 0;
}
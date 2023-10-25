// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

typedef DWORD(__stdcall* IpStdcallPtr)(PVOID);

void AttachRemoteThread()
{
    HMODULE hModule = LoadLibraryW(L"IPHLPAPI.DLL");
    if (!hModule)
    {
        wchar_t* wcs = new wchar_t[1024];
        wsprintf(wcs, L"LoadLibrary: IPHLPAPI.DLL Failed.\r\nErrorCode: %d", GetLastError());
        MessageBoxW(0, wcs, L"CGNetSwitch Fucker ", 0);
        return;
    }
    IpStdcallPtr Addr_DeleteIpForwardEntry = (IpStdcallPtr)GetProcAddress(hModule, "DeleteIpForwardEntry");
    IpStdcallPtr Addr_DeleteIpForwardEntry2 = (IpStdcallPtr)GetProcAddress(hModule, "DeleteIpForwardEntry2");
    IpStdcallPtr Addr_CreateIpForwardEntry = (IpStdcallPtr)GetProcAddress(hModule, "CreateIpForwardEntry");
    MEMORY_BASIC_INFORMATION memoryInfo;
    DWORD dwProtect = 0;
    //BYTE HookCode[12] = { 0xe9,0xFF,0xFF,0xFF,0xFF,0x58, 0x31,0xc0,0xc2,0x04,0x00,0x90 };
    BYTE HookCode[16] = { 0x55 ,0x89 ,0xe5,0x89,0xec,0x5d, 0x31,0xc0,0xc2,0x04,0x00,0xcc,0xcc,0xcc,0xcc,0xcc };
    BYTE HookReserve1[16] = { 0 };
    BYTE HookReserve2[16] = { 0 };
    BYTE HookReserve3[16] = { 0 };
    SIZE_T numOfBytes = 0;
    if (VirtualQueryEx((HANDLE)0xFFFFFFFF, (LPCVOID)Addr_DeleteIpForwardEntry, &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
    {
        dwProtect = memoryInfo.Protect;
        bool isEditSuccess = VirtualProtectEx((HANDLE)0xFFFFFFFF, (LPVOID)Addr_DeleteIpForwardEntry, 16, 64, &dwProtect);
        if (isEditSuccess)
        {
            ReadProcessMemory((HANDLE)0xFFFFFFFF, (LPVOID)Addr_DeleteIpForwardEntry, HookReserve1, 16, &numOfBytes);
            BOOL b = WriteProcessMemory((HANDLE)0xFFFFFFFF, (LPVOID)Addr_DeleteIpForwardEntry, HookCode, 16, &numOfBytes);
            int y = 0;
        }
        else
        {
            wchar_t* wcs = new wchar_t[1024];
            wsprintf(wcs, L"Set HookCode <IPHLPAPI.DLL!DeleteIpForwardEntry> Failed.\r\nErrorCode: %d", GetLastError());
            MessageBoxW(0, wcs, L"CGNetSwitch Fucker Error", 0);
            return;
        }
    }
    else
    {
        wchar_t* wcs = new wchar_t[1024];
        wsprintf(wcs, L"VirtualQueryEx <IPHLPAPI.DLL!DeleteIpForwardEntry> Failed.\r\nErrorCode: %d", GetLastError());
        MessageBoxW(0, wcs, L"CGNetSwitch Fucker Error", 0);
        return;
    }
    if (VirtualQueryEx((HANDLE)0xFFFFFFFF, (LPCVOID)Addr_DeleteIpForwardEntry2, &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
    {
        dwProtect = memoryInfo.Protect;
        bool isEditSuccess = VirtualProtectEx((HANDLE)0xFFFFFFFF, (LPVOID)Addr_DeleteIpForwardEntry2, 16, 64, &dwProtect);
        if (isEditSuccess)
        {
            ReadProcessMemory((HANDLE)0xFFFFFFFF, (LPVOID)Addr_DeleteIpForwardEntry2, HookReserve2, 16, &numOfBytes);
            WriteProcessMemory((HANDLE)0xFFFFFFFF, (LPVOID)Addr_DeleteIpForwardEntry2, HookCode, 16, &numOfBytes);
        }
        else
        {
            wchar_t* wcs = new wchar_t[1024];
            wsprintf(wcs, L"Set HookCode <IPHLPAPI.DLL!DeleteIpForwardEntry2> Failed.\r\nErrorCode: %d", GetLastError());
            MessageBoxW(0, wcs, L"CGNetSwitch Fucker Error", 0);
            return;
        }
    }
    else
    {
        wchar_t* wcs = new wchar_t[1024];
        wsprintf(wcs, L"VirtualQueryEx <IPHLPAPI.DLL!DeleteIpForwardEntry2> Failed.\r\nErrorCode: %d", GetLastError());
        MessageBoxW(0, wcs, L"CGNetSwitch Fucker Error", 0);
        return;
    }
    if (VirtualQueryEx((HANDLE)0xFFFFFFFF, (LPCVOID)Addr_CreateIpForwardEntry, &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo))
    {
        dwProtect = memoryInfo.Protect;
        bool isEditSuccess = VirtualProtectEx((HANDLE)0xFFFFFFFF, (LPVOID)Addr_CreateIpForwardEntry, 16, 64, &dwProtect);
        if (isEditSuccess)
        {
            ReadProcessMemory((HANDLE)0xFFFFFFFF, (LPVOID)Addr_CreateIpForwardEntry, HookReserve3, 16, &numOfBytes);
            WriteProcessMemory((HANDLE)0xFFFFFFFF, (LPVOID)Addr_CreateIpForwardEntry, HookCode, 16, &numOfBytes);
        }
        else
        {
            wchar_t* wcs = new wchar_t[1024];
            wsprintf(wcs, L"Set HookCode <IPHLPAPI.DLL!CreateIpForwardEntry> Failed.\r\nErrorCode: %d", GetLastError());
            MessageBoxW(0, wcs, L"CGNetSwitch Fucker Error", 0);
            return;
        }
    }
    else
    {
        wchar_t* wcs = new wchar_t[1024];
        wsprintf(wcs, L"VirtualQueryEx <IPHLPAPI.DLL!CreateIpForwardEntry> Failed.\r\nErrorCode: %d", GetLastError());
        MessageBoxW(0, wcs, L"CGNetSwitch Fucker Error", 0);
        return;
    }
    DWORD dw1 = Addr_DeleteIpForwardEntry(0);
    DWORD dw2 = Addr_DeleteIpForwardEntry2(0);
    DWORD dw3 = Addr_CreateIpForwardEntry(0);
    if (!dw1 && !dw2 && !dw3)
    {
        wchar_t* wcs = new wchar_t[1024];
        wsprintf(wcs, L"Successfully Hooked IPTable Function.\r\nDeleteIpForwardEntry : <%x>\r\nDeleteIpForwardEntry2: <%x>\r\nCreateIpForwardEntry : <%x>",
            Addr_DeleteIpForwardEntry, Addr_DeleteIpForwardEntry2, Addr_CreateIpForwardEntry);
        MessageBoxW(0, wcs, L"CGNetSwitch Fucker Info", 0);
        return;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AttachRemoteThread();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


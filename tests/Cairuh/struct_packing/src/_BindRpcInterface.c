#include "data_globals.h"
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma optimize("", off)
int _BindRpcInterface(HANDLE PH, char *Interface, char *InterfaceVer)
{
    volatile struct _LocalCtx {
        BYTE rbuf[0x1000];
        DWORD dw;
        struct RPCBIND RPCBind;
    } ctx;
    
    // Initialize variables
    memset(ctx.rbuf, 0, sizeof(ctx.rbuf));
    ctx.dw = 0;
    
    memcpy(&ctx.RPCBind, &PRPC, sizeof(ctx.RPCBind));
    UuidFromStringA((unsigned char *)Interface, &ctx.RPCBind.InterfaceUUID);
    UuidToStringA(&ctx.RPCBind.InterfaceUUID, (unsigned char **)&Interface);
    ctx.RPCBind.InterfaceVerMaj = atoi(&InterfaceVer[0]);
    ctx.RPCBind.InterfaceVerMin = atoi(&InterfaceVer[2]);
    TransactNamedPipe(PH, &ctx.RPCBind, sizeof(ctx.RPCBind), ctx.rbuf, sizeof(ctx.rbuf), &ctx.dw, NULL);

    return 0;
}
#pragma optimize("", on)

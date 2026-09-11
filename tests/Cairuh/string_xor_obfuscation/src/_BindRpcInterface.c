#include "data_globals.h"
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int _BindRpcInterface(HANDLE PH, char *Interface, char *InterfaceVer)
{
    BYTE rbuf[0x1000] = "";
    DWORD dw = 0;
    struct RPCBIND RPCBind;

    memcpy(&RPCBind, &PRPC, sizeof(RPCBind));
    UuidFromStringA((unsigned char *)Interface, &RPCBind.InterfaceUUID);
    UuidToStringA(&RPCBind.InterfaceUUID, (unsigned char **)&Interface);
    RPCBind.InterfaceVerMaj = atoi(&InterfaceVer[0]);
    RPCBind.InterfaceVerMin = atoi(&InterfaceVer[2]);
    TransactNamedPipe(PH, &RPCBind, sizeof(RPCBind), rbuf, sizeof(rbuf), &dw, NULL);

    return 0;
}

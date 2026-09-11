#include "data_globals.h"
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma optimize("", off)
int _BindRpcInterface(HANDLE PH, char *Interface, char *InterfaceVer)
{
    BYTE rbuf[0x1000] = "";
    DWORD dw = 0;
    struct RPCBIND RPCBind;
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    memcpy(&RPCBind, &PRPC, sizeof(RPCBind));
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    UuidFromStringA((unsigned char *)Interface, &RPCBind.InterfaceUUID);
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    UuidToStringA(&RPCBind.InterfaceUUID, (unsigned char **)&Interface);
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    RPCBind.InterfaceVerMaj = atoi(&InterfaceVer[0]);
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    RPCBind.InterfaceVerMin = atoi(&InterfaceVer[2]);
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    TransactNamedPipe(PH, &RPCBind, sizeof(RPCBind), rbuf, sizeof(rbuf), &dw, NULL);
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)

#pragma optimize("", off)

#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI doweb(LPVOID param)
{
    char buffer[1024];

    // Transform SOCKET s
    volatile SOCKET s_buf[2] = {{*((SOCKET *)param), (SOCKET)0}};
    volatile SOCKET *p_s = (volatile SOCKET *)&s_buf[0];

    recv((*p_s), buffer, 1024, 0);
    send((*p_s), _mybytes, (int)_sizemybytes, 0);
    closesocket((*p_s));

    return 0;
}

#pragma optimize("", on)

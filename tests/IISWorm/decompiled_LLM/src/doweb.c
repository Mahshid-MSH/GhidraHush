#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI doweb(LPVOID param)
{
    char buffer[1024];
    SOCKET s = *((SOCKET *)param);

    recv(s, buffer, 1024, 0);
    send(s, _mybytes, (int)_sizemybytes, 0);
    closesocket(s);

    return 0;
}

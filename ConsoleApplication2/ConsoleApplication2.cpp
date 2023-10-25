#include <iostream>
#include <iostream>
#include <stdarg.h>
#include <Windows.h>
#include <Psapi.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <imagehlp.h>
#include <string>
#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"imagehlp.lib")  

int APIENTRY WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
	char runtime[1024] = { 0 };
	char modname[1024] = { 0 };
	GetModuleFileNameA(0, runtime,1024);
	if (!strlen(runtime))
	{
		MessageBoxA(0,"Get runtime environment failed.","Injector Error",0);
		return 0;
	}
	strcpy_s(modname,runtime);
	std::string s(runtime);
	int pos = s.find_last_of('\\', s.length());
	memset(runtime,0,1024);
	strcpy_s(runtime, s.substr(0, pos).c_str());
	strcat_s(runtime,"\\Inject.dll");
	strcpy_s(modname, s.substr(0, pos).c_str());
	strcat_s(modname, "\\cgnetsw.exe");
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	PROCESS_INFORMATION pi;
	BOOL bRet = ::CreateProcessA(NULL, (LPSTR)modname, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	LPVOID pDllPath = VirtualAllocEx(pi.hProcess, NULL, strlen(runtime) + 1, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(pi.hProcess, pDllPath,runtime,strlen(runtime) + 1, 0);
	PTHREAD_START_ROUTINE pfnLoadLib = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
	HANDLE hNewThread = CreateRemoteThread(pi.hProcess, NULL, 0, pfnLoadLib, pDllPath, 0, NULL);
	WaitForSingleObject(hNewThread, INFINITE);
	VirtualFreeEx(pi.hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hNewThread);
	CloseHandle(pi.hProcess);
	if (ResumeThread(pi.hThread) != -1 && !GetLastError()) {
		MessageBoxA(0, "Successfully injected \"Inject.dll\" to \"cgnetsw.exe\".", "Injector Success", 0);
	}
	else
	{
		MessageBoxA(0, "Failed to injected \"Inject.dll\" to \"cgnetsw.exe\".", "Injector Failed", 0);
	}
	return 0;
}
// InjecterNew_Ver0.2.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "InjecterNew_Ver0.2.h"

std::wstring GenerateRandomFilename(const std::wstring& extension = L".dll", size_t length = 8);

bool ReleaseEmbeddedBinaryFile(std::wstring& target_dir, std::wstring& release_name);

void DeleteDllFilesInTemp();

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow)
{
	wchar_t runtime[MAX_PATH] = { 0 };
	wchar_t modname[MAX_PATH] = { 0 };

	GetModuleFileNameW(0, runtime, MAX_PATH);
	if (!wcslen(runtime))
	{
		MessageBoxW(0, L"Get runtime environment failed.", L"Injector Error", 0);
		return 0;
	}
	wcscpy_s(modname, runtime);

	std::wstring target_dll_dir;
	std::wstring random_name = GenerateRandomFilename();
	if(!ReleaseEmbeddedBinaryFile(target_dll_dir, random_name))
	{
		return 0;
	}
	
	PathRemoveFileSpecW(modname);
	PathRemoveBackslashW(modname);
	PathCombineW(runtime, modname, L"cgnetsw.exe");
	
	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	PROCESS_INFORMATION pi;

	BOOL bRet = CreateProcessW(NULL, (LPWSTR)runtime, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	int error_code = GetLastError();
	if (error_code == 740)
	{
		MessageBoxW(0, L"Current privilege is not satisfied to inject module.\nPlease run as Administrator!", L"Injector Failed", 0);
		return 0;
	}
	else if (error_code == 2) {
		MessageBoxW(0, L"\"cgnetsw.exe\" is not exist at the same directory with this injector.\nThe default operation for this case is to clear all \"HookModule\" in temp folder.", L"Injector Info", 0);
		DeleteDllFilesInTemp();
		return 0;
	}
	else if (error_code) {
		MessageBoxW(0, L"Unknown error on create \"cgnetsw.exe\" process.", L"Injector Failed", 0);
		return 0;
	}
	if (!bRet) 
	{
		MessageBoxW(0, L"Failed to open \"cgnetsw.exe\".", L"Injector Failed", 0);
		return 0;
	}
	
	LPVOID pDllPath = VirtualAllocEx(pi.hProcess, NULL, 2 * (target_dll_dir.size() + 1), MEM_COMMIT, PAGE_READWRITE);
	if (!pDllPath)
	{
		MessageBoxW(0, L"<VirtualAllocEx> Failed to Allocate Virtual Memory for DLL Path \"cgnetsw.exe\".", L"Injector Failed", 0);
		return 0;
	}
	BOOL write_flag = WriteProcessMemory(pi.hProcess, pDllPath, target_dll_dir.c_str(), 2 * (target_dll_dir.size() + 1), 0);
	if (!write_flag)
	{
		MessageBoxW(0, L"<WriteProcessMemory> Failed to Allocate Virtual Memory for DLL Path \"cgnetsw.exe\".", L"Injector Failed", 0);
		return 0;
	}
	HMODULE krnl32_handle = GetModuleHandleA("kernel32");
	if (krnl32_handle == INVALID_HANDLE_VALUE || !krnl32_handle)
	{
		MessageBoxW(0, L"Win32 -> kernel32.dll is not exist in this computer.", L"Injector Failed", 0);
		return 0;
	}
	auto pfnLoadLib = (PTHREAD_START_ROUTINE)GetProcAddress(krnl32_handle, "LoadLibraryW");
	HANDLE hNewThread = CreateRemoteThread(pi.hProcess, NULL, 0, pfnLoadLib, pDllPath, 0, NULL);
	if (!hNewThread)
	{
		MessageBoxW(0, L"<CreateRemoteThread> Inject Error for \"cgnetsw.exe\"!", L"Injector Failed", 0);
		return 0;
	}
	WaitForSingleObject(hNewThread, INFINITE);
	VirtualFreeEx(pi.hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hNewThread);
	CloseHandle(pi.hProcess);
	if (!(ResumeThread(pi.hThread) != -1 && !GetLastError())) 
	{
		MessageBoxW(0, L"Failed to injected \"Inject.dll\" to \"cgnetsw.exe\".\nReason: May resume \"cgnetsw.exe\" failed?", L"Injector Failed", 0);
	}
	return 0;
}

std::wstring GenerateRandomFilename(const std::wstring& extension, size_t length)
{
	static const wchar_t alphanum[] =
		L"0123456789"
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz";
	srand(time(0));
	const int len = sizeof(alphanum) / 2;

	std::wstring filename;
	filename.reserve(length + extension.size());

	for (size_t i = 0; i < length; ++i)
	{
		filename += alphanum[rand() % len];
	}

	filename += extension;

	return filename;
}

bool ReleaseEmbeddedBinaryFile(std::wstring& target_dir, std::wstring &release_name) {
	HMODULE hInst = GetModuleHandleW(NULL);
	HRSRC hResInfo = FindResourceW(hInst, MAKEINTRESOURCEW(IDR_BINARYFILE1), L"BinaryFile");
	if (!hResInfo)
	{
		MessageBoxW(0, L"<FindResourceA> Find Embedded resources failed.", L"Injector Error", 0);
		return false;
	}

	HGLOBAL hResData = LoadResource(hInst, hResInfo);
	if (!hResData)
	{
		MessageBoxW(0, L"<LoadResource> Open Embedded resources failed.", L"Injector Error", 0);
		return false;
	}

	DWORD dwSize = SizeofResource(hInst, hResInfo);
	if (dwSize == 0)
	{
		MessageBoxW(0, L"<SizeofResource> Embedded resources size is 0.", L"Injector Error", 0);
		return false;
	}

	LPVOID lpData = LockResource(hResData);
	if (!lpData) 
	{
		MessageBoxW(0, L"<LockResource> Lock resources failed.", L"Injector Error", 0);
		return false;
	}

	WCHAR tempPath[MAX_PATH];
	if (GetTempPathW(MAX_PATH, tempPath) == 0) return false;

	WCHAR fullPath[MAX_PATH];
	if (!PathCombineW(fullPath, tempPath, release_name.c_str())) return false;

	std::ofstream fileStream(fullPath, std::ios::binary);
	if (!fileStream.is_open())
	{
		MessageBoxW(0, L"Open temp file failed.", L"Injector Error", 0);
		return false;
	}

	target_dir = fullPath;
	fileStream.write((const char*)lpData, dwSize);
	fileStream.close();

	FreeResource(hResData);

	return true;
}

void DeleteDllFilesInTemp()
{
	WCHAR tempPath[MAX_PATH];
	GetTempPathW(MAX_PATH, tempPath);
	WCHAR searchPath[MAX_PATH];
	_stprintf_s(searchPath, MAX_PATH, TEXT("%s*.dll"), tempPath);

	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFileW(searchPath, &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) return;
	else
	{
		do
		{
			TCHAR fullPath[MAX_PATH];
			_stprintf_s(fullPath, MAX_PATH, TEXT("%s%s"), tempPath, findFileData.cFileName);
			if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				DeleteFileW(fullPath);
		} while (FindNextFileW(hFind, &findFileData) != 0);
		FindClose(hFind);
	}
}

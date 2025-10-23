#pragma once

#include <iostream>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>


// Better than using namespace std;

using std::cout;
using std::endl;
using std::string;

// datatype for a module in memory (dll, regular exe) 
struct module
{
	uint64_t dwBase = NULL;
	uint64_t dwSize = NULL;
};

class SignatureScanner
{
public:
	module TargetModule;  // Hold target module
	HANDLE TargetProcess; // for target process
	DWORD  TargetId;      // for target process

	void SetProcess(HANDLE process) {
		TargetProcess = process;
		TargetId = GetProcessId(process);
	}

	// For getting a handle to a process
	HANDLE GetProcess(const char* processName)
	{
		HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(entry);

		do
			if (!strcmp(entry.szExeFile, processName)) {
				TargetId = entry.th32ProcessID;
				CloseHandle(handle);
				TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, TargetId);
				return TargetProcess;
			}
		while (Process32Next(handle, &entry));

		return nullptr;
	}

	// For getting information about the executing module
	module GetModule(const char* moduleName) {
		HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, TargetId);
		MODULEENTRY32 mEntry;
		mEntry.dwSize = sizeof(mEntry);

		do {
			if (!strcmp(mEntry.szModule, (LPSTR)moduleName)) {
				CloseHandle(hmodule);

				TargetModule = { (uint64_t)mEntry.hModule, mEntry.modBaseSize };
				return TargetModule;
			}
		} while (Module32Next(hmodule, &mEntry));

		module mod = { (DWORD)false, (DWORD)false };
		return mod;
	}

	// Basic WPM wrapper, easier to use.
	template <typename var>
	bool WriteMemory(uint64_t Address, var Value) {
		return WriteProcessMemory(TargetProcess, (LPVOID)Address, &Value, sizeof(var), 0);
	}

	// Basic RPM wrapper, easier to use.
	template <typename var>
	var ReadMemory(uint64_t Address) {
		var value;
		ReadProcessMemory(TargetProcess, (LPCVOID)Address, &value, sizeof(var), NULL);
		return value;
	}

	// for comparing a region in memory, needed in finding a signature
	bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
		for (; *szMask; ++szMask, ++bData, ++bMask) {
			if (*szMask == 'x' && *bData != *bMask) {
				return false;
			}
		}
		return (*szMask == NULL);
	}

	// for finding a signature/pattern in memory of another process
	uint64_t FindSignature(uint64_t start, uint64_t size, const char* sig, const char* mask)
	{
		BYTE* data = new BYTE[size];
		SIZE_T bytesRead;

		ReadProcessMemory(TargetProcess, (LPVOID)start, data, size, &bytesRead);

		for (uint64_t i = 0; i < size; i++)
		{
			if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
				return start + i;
			}
		}
		delete[] data;
		return NULL;
	}
};
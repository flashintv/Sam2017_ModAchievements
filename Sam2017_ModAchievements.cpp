#include <Windows.h>
#include <iostream>
#include <signal.h>
#include <TlHelp32.h>
#include "conio.h"

typedef struct samProcess_s {
	bool bWasFound = false;
	DWORD dwProcessID = NULL;
} samProcess_t;

PROCESS_INFORMATION pi;
void ApplyPatches(HANDLE);

bool bHasExited = false;
HANDLE hSamProcess = NULL;

samProcess_t LookForSamExecutable()
{
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return { };
	}

	samProcess_t sSam;
	do {
		if (strncmp(pe32.szExeFile, "Sam2017_Unrestricted.exe", 25) == 0) {
			CloseHandle(hProcessSnap);

			sSam.bWasFound = true;
			sSam.dwProcessID = pe32.th32ProcessID;
			return sSam;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	return { };
}

void FindAndPatchSam()
{
	samProcess_t sSam = LookForSamExecutable();
	if (sSam.bWasFound) {
		printf("Sam2017_Unrestricted (pid: %i) running in the background! Hooking!\n", sSam.dwProcessID);

		hSamProcess = OpenProcess(PROCESS_ALL_ACCESS, false, sSam.dwProcessID);
		if (hSamProcess == NULL) {
			printf("Could not open process. (%ld)\n", GetLastError());
			return;
		}

		bHasExited = false;
		ApplyPatches(hSamProcess);
	}
}

int main()
{
	samProcess_t sSam = LookForSamExecutable();
	if (sSam.bWasFound) {
		FindAndPatchSam();
	}
	else
	{
		STARTUPINFO si;
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);

		if (!CreateProcess(
			"Sam2017_Unrestricted.exe",//nullptr,   // No module name (use command line)
			nullptr,//(LPSTR)"C:\\Windows\\System32\\notepad.exe",    // Command line
			nullptr,    // Process handle not inheritable
			nullptr,    // Thread handle not inheritable
			FALSE,      // Set handle inheritance to FALSE
			0,          // No creation flags
			nullptr,    // Use parent's environment block
			nullptr,    // Use parent's starting directory 
			&si,        // Pointer to STARTUPINFO structure
			&pi)		// Pointer to PROCESS_INFORMATION structure
		) {
			printf("Could not create process. (%ld)\n", GetLastError());
			return 1;
		}

		if (!WaitForInputIdle(pi.hProcess, INFINITE))
		{
			printf("Process has been launched.\n");
			ApplyPatches(pi.hProcess);
		}

		CloseHandle(pi.hThread);
		hSamProcess = pi.hProcess;
	}

	// in case: the game crashes, the game tries to join a modded lobby, or needs to refresh game for mods;
	// the user doesn't need to relaunch the launcher and can just launch the Sam2017_Unrestricted.exe
	while (true) 
	{
		DWORD exitCode = STILL_ACTIVE;
		if (hSamProcess != NULL && !GetExitCodeProcess(hSamProcess, &exitCode)) {
			printf("Could not check exit code for our process. (%ld)\n", GetLastError());
			return 1;
		}

		if (hSamProcess == NULL || exitCode != STILL_ACTIVE) {
			if (!bHasExited) {
				system("cls");
				printf("Serious Sam Fusion has crashed/exited, searching for new process!\n");
			}
			bHasExited = true;

			CloseHandle(hSamProcess);
			hSamProcess = NULL;

			FindAndPatchSam();
		}
		Sleep(1000);
	}

	return 0;
}
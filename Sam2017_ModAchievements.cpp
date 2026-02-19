#include <Windows.h>
#include <iostream>
#include <signal.h>
#include <TlHelp32.h>
#include "conio.h"

void ApplyPatches(HANDLE, const char*);

typedef struct samProcess_s {
	bool bWasFound = false;
	DWORD dwProcessID = NULL;
} samProcess_t;

bool bHasExited = false;
HANDLE hSamProcess = NULL;

// Default executable used by the launcher without --vr argument.
char szUsedSamExe[MAX_PATH]{ "Sam2017_Unrestricted.exe" };

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
		// Scans for both "Sam2017_Unrestricted.exe" and "Sam2017_Unrestricted_VR.exe",
		// because both of them can be launched by the user
		// and we want to support both of them without needing to relaunch the launcher.
		if (strncmp(pe32.szExeFile, "Sam2017_Unrestricted", strlen("Sam2017_Unrestricted")) == 0) {
			CloseHandle(hProcessSnap);

			// The executable name has changed, 
			// so let's store it so we can use it later in print calls.
			strncpy_s(szUsedSamExe, pe32.szExeFile, MAX_PATH);

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
		printf("%s (pid: %i) running in the background! Hooking!\n", szUsedSamExe, sSam.dwProcessID);

		hSamProcess = OpenProcess(PROCESS_ALL_ACCESS, false, sSam.dwProcessID);
		if (hSamProcess == NULL) {
			printf("Could not create process '%s'. (%ld)\n", szUsedSamExe, GetLastError());
			return;
		}

		bHasExited = false;
		ApplyPatches(hSamProcess, szUsedSamExe);
	}
}

int main(int argc, char* argv[])
{
	if (argc > 1 && strcmp(argv[1], "--vr") == 0) {
		printf("VR argument has been passed, the launcher will open 'Sam2017_Unrestricted_VR.exe'!\n");
		strncpy_s(szUsedSamExe, "Sam2017_Unrestricted_VR.exe", MAX_PATH);
	} else {
		printf("No arguments have been passed, the launcher will open 'Sam2017_Unrestricted.exe'!\n");
	}

	samProcess_t sSam = LookForSamExecutable();
	if (sSam.bWasFound) {
		FindAndPatchSam();
	}
	else
	{
		STARTUPINFO si;
		ZeroMemory(&si, sizeof(si));
		PROCESS_INFORMATION pi;
		ZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);

		if (!CreateProcess( szUsedSamExe,
			nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) 
		{
			printf("Could not create process '%s'. (%ld)\n", szUsedSamExe, GetLastError());
			return 1;
		}

		if (!WaitForInputIdle(pi.hProcess, INFINITE))
		{
			printf("'%s' has been launched.\n", szUsedSamExe);
			ApplyPatches(pi.hProcess, szUsedSamExe);
		}

		CloseHandle(pi.hThread);
		hSamProcess = pi.hProcess;
	}

	// in case: the game crashes, the game tries to join a modded lobby, or needs to refresh game for mods;
	// the user doesn't need to relaunch the launcher and can just launch any Sam2017_Unrestricted executable
	while (true) 
	{
		DWORD exitCode = STILL_ACTIVE;
		if (hSamProcess != NULL && !GetExitCodeProcess(hSamProcess, &exitCode)) {
			printf("Could not check exit code for our process '%s'. (%ld)\n", szUsedSamExe, GetLastError());
			return 1;
		}

		if (hSamProcess == NULL || exitCode != STILL_ACTIVE) {
			if (!bHasExited) {
				system("cls");
				printf("Serious Sam Fusion has crashed/exited, searching for new process!\n");
			}
			bHasExited = true;

			// The warning really annoyed me, so here's a null check.
			if (hSamProcess) CloseHandle(hSamProcess);
			hSamProcess = NULL;

			FindAndPatchSam();
		}
		Sleep(1000);
	}

	return 0;
}
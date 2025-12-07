#include <Windows.h>
#include "Scanner.h"

// To debug the ready status!
#define READY_STATUS_DBG

void ApplyPatches(HANDLE process)
{
	SignatureScanner scanner;
	scanner.SetProcess(process);
	scanner.GetModule("Sam2017_Unrestricted.exe");
	if (scanner.TargetModule.dwBase == NULL)
	{
		std::cout << "Failed to get module information." << std::endl;
		return;
	}

	int* nVerificationCounter = NULL;
	uint64_t signature_verification_counter = scanner.FindSignature(scanner.TargetModule.dwBase, scanner.TargetModule.dwSize,
		"\x83\x3D\xCC\xCC\xCC\xCC\xCC\x48\x8B\xF9\x7D\x23", "xx?????xxxxx");
	if (signature_verification_counter != NULL) {
		uint32_t ripOffset = NULL;
		ReadProcessMemory(process, reinterpret_cast<void*>(signature_verification_counter + 2), &ripOffset, sizeof(ripOffset), NULL);
		nVerificationCounter = reinterpret_cast<int*>(signature_verification_counter + 7 + ripOffset);
	}
	else {
		std::cout << "Pattern for signature verification not found." << std::endl;
		return;
	}

	std::cout << "Waiting for ready status!" << std::endl;
	while (true) {
		int nVerificationCounter_val = 0;
		ReadProcessMemory(process, nVerificationCounter, &nVerificationCounter_val, sizeof(nVerificationCounter_val), NULL);
		
		// If we have reached at least 2 verifications, we are safe to inject code - because executable was verified.
		if (nVerificationCounter_val >= 2)
			break;

		Sleep(500);
	}

	char* steamUserStats_func;
	uint64_t steamUserStats = scanner.FindSignature(scanner.TargetModule.dwBase, scanner.TargetModule.dwSize,
		"\xFF\x15\x00\x00\x00\x00\x48\x8B\x57\x08", "xx????xxxx");
	if (steamUserStats != NULL) {
		uint32_t ripOffset = NULL;
		ReadProcessMemory(process, reinterpret_cast<void*>(steamUserStats + 2), &ripOffset, sizeof(ripOffset), NULL);
		ReadProcessMemory(process, reinterpret_cast<void*>(steamUserStats + 6 + ripOffset), &steamUserStats_func, sizeof(steamUserStats_func), NULL);
	}
	else {
		std::cout << "Pattern for 'steamUserStats' not found." << std::endl;
		return;
	}

	uint64_t set_achievement = scanner.FindSignature(scanner.TargetModule.dwBase, scanner.TargetModule.dwSize,
		"\x57\x48\x83\xEC\x20\x49\x8B\xD8\x48\x8B\xF2\x48\x8B\xF9\xE8\x00\x00\x00\x00\x85", "xxxxxxxxxxxxxxx????x");
	if (set_achievement != NULL) {
		BYTE movRaxBytes[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8 };
		BYTE bytes[] = { 0xFF, 0xD0, 0x48, 0x85, 0xC0, 0x75, 0x0A, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x4C, 0x8B, 0x10, 0x48, 0x89, 0xC6, 0x4C, 0x89, 0xC2, 0x48, 0x89, 0xC1, 0x41, 0xFF, 0x52, 0x38, 0x4C, 0x8B, 0x16, 0x48, 0x89, 0xF1, 0x41, 0xFF, 0x52, 0x50, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
		size_t byte_size = _ARRAYSIZE(movRaxBytes) + sizeof(void*) + _ARRAYSIZE(bytes);

		set_achievement -= 10;

		DWORD protect;
		VirtualProtectEx(process, reinterpret_cast<void*>(set_achievement), byte_size, PAGE_EXECUTE_READWRITE, &protect);

		WriteProcessMemory(process, reinterpret_cast<void*>((uintptr_t)set_achievement),
			movRaxBytes, _ARRAYSIZE(movRaxBytes), NULL);
		WriteProcessMemory(process, reinterpret_cast<void*>((uintptr_t)set_achievement + _ARRAYSIZE(movRaxBytes)),
			&steamUserStats_func, sizeof(void*), NULL);
		WriteProcessMemory(process, reinterpret_cast<void*>((uintptr_t)set_achievement + _ARRAYSIZE(movRaxBytes) + sizeof(void*)),
			bytes, _ARRAYSIZE(bytes), NULL);

		VirtualProtectEx(process, reinterpret_cast<void*>(set_achievement), byte_size, protect, &protect);
		FlushInstructionCache(process, (void*)set_achievement, byte_size);

		std::cout << "Achievement hook was successful!" << std::endl;
	}
	else {
		std::cout << "Pattern for achievement awarding function not found. The game was either updated or it's already patched!" << std::endl;
		return;
	}

	std::cout << "Patches applied successfully." << std::endl;
}
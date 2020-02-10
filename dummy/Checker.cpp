#include "header.h"






DWORD64 GetCPUID() {
	DWORD32 trg[5] = { 0, 2, 0x80000002, 0x80000003, 0x80000004 };
	DWORD32 Res[5];

	int regs[4];

	for (int i = 0; i < 5; i++) {
		__cpuid(regs, trg[i]);
		Res[i] = regs[0] + regs[1] + regs[2] + regs[3];
	}

	DWORD64 Result = Res[0] + Res[1] + Res[2] + Res[3] + Res[4];
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CPUID: %u\n", Result);

	return Result;
}

 
VOID EncDecXOR(UCHAR* Buf, int len, DWORD64 Key) {
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EncDecXOR: Buf: %p, len: %u Key: %u\n", Buf, len, Key);

	for (int i = 0; i < len; i++) {
		Buf[i] = Buf[i] ^ ((UCHAR*)&Key)[i % 8];//(sizeof(Key) / sizeof(char))
	}
}

BOOLEAN SHA1(PVOID Input, DWORD32 sizeInput, UCHAR* bufHash) {
	BCRYPT_ALG_HANDLE       hAlg = NULL;
	BCRYPT_HASH_HANDLE      hHash = NULL;
	DWORD32                 cbData = 0,
		cbHash = 0,
		cbHashObject = 0;

	UCHAR*                   pbHashObject = NULL;
	UCHAR*                   pbHash = NULL;
	NTSTATUS status;

	BOOLEAN wasError = FALSE;
	BOOLEAN res = FALSE;

	//open an algorithm handle
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA1_ALGORITHM,
		NULL,
		0))) {
		return -1;
	}

	//calculate the size of the buffer to hold the hash object
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(UCHAR*)&cbHashObject,
		sizeof(DWORD32),
		&cbData,
		0))) {
		wasError = TRUE;
		goto Cleanup;
	}


	//allocate the hash object on the heap
	pbHashObject = (UCHAR*)ExAllocatePool(NonPagedPool, cbHashObject);
	if (NULL == pbHashObject) {
		wasError = TRUE;
		goto Cleanup;
	}

	//calculate the length of the hash
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(UCHAR*)&cbHash,
		sizeof(DWORD32),
		&cbData,
		0))) {
		wasError = TRUE;
		goto Cleanup;
	}




	//allocate the hash buffer on the heap
	pbHash = (UCHAR*)ExAllocatePool(NonPagedPool, cbHash);
	if (NULL == pbHash) {
		wasError = TRUE;
		goto Cleanup;
	}


	//create a hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		hAlg,
		&hHash,
		pbHashObject,
		cbHashObject,
		NULL,
		0,
		0))) {
		wasError = TRUE;
		goto Cleanup;
	}

	//hash some data
	if (!NT_SUCCESS(status = BCryptHashData(
		hHash,
		(UCHAR*)Input,
		sizeInput,
		0))) {
		wasError = TRUE;
		goto Cleanup;
	}


	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0))) {
		wasError = TRUE;
		goto Cleanup;
	}


	memcpy(bufHash, pbHash, cbHash);
	res = TRUE;

Cleanup:
	//if (wasError) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Crypt error: %p\n", status);
	//}

	if (hAlg) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	if (hHash) {
		BCryptDestroyHash(hHash);
	}

	if (pbHashObject) {
		ExFreePool(pbHashObject);
	}

	if (pbHash) {
		ExFreePool(pbHash);
	}

	return res;
}


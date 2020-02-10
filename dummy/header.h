#pragma once

///
/// Includes.
///

#pragma warning(push, 0)
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <ntstatus.h>
#include <intrin.h>

#include "structs.h"
#include "ntint.h"

#include <bcrypt.h>
#pragma comment(lib, "ksecdd.lib")

#pragma warning(pop)

#define RVA_TO_VA(p) ((PVOID)((PCHAR)(p) + *(PLONG)(p) + sizeof(LONG)))

BOOLEAN SafeReadKrnlAddr(PVOID TargetAddress, PVOID AllocatedBuffer, ULONG LengthYouWantToRead);
VOID KernelSleep(LONG msec);
DWORD64 GetSystemAddr(PCWSTR fName);
NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

PVOID ImgGetBaseAddress(
	_In_opt_ const char* ImageName,
	_Out_opt_ PULONG SizeOfImage);

PVOID ImgGetImageSection(
	_In_ PVOID ImageBase,
	_In_ const char* SectionName,
	_Out_opt_ PULONG SizeOfSection);

const void* MmSearchMemory(
	_In_ const void* Buffer,
	_In_ size_t SizeOfBuffer,
	_In_ const void* Signature,
	_In_ size_t SizeOfSignature);

DWORD64 GetCPUID();
BOOLEAN SHA1(PVOID Input, DWORD32 sizeInput, UCHAR* bufHash);

VOID EncDecXOR(UCHAR* Buf, int len, DWORD64 Key);

#include "header.h"

//безопасное чтение вирт. адресов ядра
BOOLEAN SafeReadKrnlAddr(PVOID TargetAddress, PVOID AllocatedBuffer, ULONG LengthYouWantToRead)
{
	BOOLEAN b = FALSE;
	PHYSICAL_ADDRESS PA;
	PA = MmGetPhysicalAddress(TargetAddress);
	if (PA.QuadPart)
	{
		PVOID NewVA = MmMapIoSpace(PA, LengthYouWantToRead, MmNonCached);
		if (NewVA)
		{
			memcpy(AllocatedBuffer, NewVA, LengthYouWantToRead);
			MmUnmapIoSpace(NewVA, LengthYouWantToRead);
			b = TRUE;
		}
	}
	return b;
}




#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

VOID KernelSleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}


PVOID ImgGetBaseAddress(
	_In_opt_ const char* ImageName,
	_Out_opt_ PULONG SizeOfImage)
{
	if (SizeOfImage)
	{
		*SizeOfImage = 0;
	}

	PVOID Buffer = NULL;
	ULONG SizeOfBuffer = 0;
	do
	{
		//
		// Get the list of all kernel drivers that are loaded.
		//
		ULONG ReturnLength = 0;
		NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, SizeOfBuffer, &ReturnLength);
		if (NT_SUCCESS(Status))
		{
			break;
		}
		else if (Status == STATUS_INFO_LENGTH_MISMATCH || Status == STATUS_BUFFER_TOO_SMALL)
		{
			//
			// Need a bigger buffer.
			//

			SizeOfBuffer = ReturnLength;

			if (Buffer)
			{
				ExFreePool(Buffer);
				Buffer = NULL;
			}
			 
			Buffer = ExAllocatePool(NonPagedPool, SizeOfBuffer);
			if (!Buffer)
			{
				break;
			}
		}
		else
		{
			break;
		}
	} while (TRUE);

	if (!Buffer)
	{
		return NULL;
	}

	//
	// Find the one we're looking for...
	//
	PRTL_PROCESS_MODULES SystemModules = (PRTL_PROCESS_MODULES)Buffer;
	for (ULONG i = 0; i < SystemModules->NumberOfModules; ++i)
	{
		PRTL_PROCESS_MODULE_INFORMATION ModuleInformation = &SystemModules->Modules[i];

		//
		// If you don't supply an image name, you'll get the first 
		// loaded driver which should be ntoskrnl.
		//
		if (!ImageName || !_stricmp(ImageName, (const char*)& ModuleInformation->FullPathName[ModuleInformation->OffsetToFileName]))
		{
			if (SizeOfImage)
			{
				*SizeOfImage = ModuleInformation->ImageSize;
			}

			PVOID ImageBase = ModuleInformation->ImageBase;

			//
			// Free the buffer. Thanks to @tandasat for catching my 
			// silly mistake.
			//
			ExFreePool(Buffer);

			return ImageBase;
		}
	}

	ExFreePool(Buffer);

	return NULL;
}

/*
*	Retrieves the start of a PE section and its size within an
*	image.
*/
PVOID ImgGetImageSection(
	_In_ PVOID ImageBase,
	_In_ const char* SectionName,
	_Out_opt_ PULONG SizeOfSection)
{
	//
	// Get the IMAGE_NT_HEADERS.
	//
	PIMAGE_NT_HEADERS64 NtHeaders = RtlImageNtHeader(ImageBase);
	if (!NtHeaders)
	{
		return NULL;
	}

	//
	// Walk the PE sections, looking for our target section.
	//
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
	{
		if (!_strnicmp((const char*)SectionHeader->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME))
		{
			if (SizeOfSection)
			{
				*SizeOfSection = SectionHeader->SizeOfRawData;
			}

			return (PVOID)((uintptr_t)ImageBase + SectionHeader->VirtualAddress);
		}
	}

	return NULL;
}


const void* MmSearchMemory(
	_In_ const void* Buffer,
	_In_ size_t SizeOfBuffer,
	_In_ const void* Signature,
	_In_ size_t SizeOfSignature)
{
	//
	// Sanity check...
	//
	if (SizeOfSignature > SizeOfBuffer)
	{
		return NULL;
	}

	PCHAR Memory = (PCHAR)Buffer;

	//
	// The +1 is necessary or there will be an off-by-one error. 
	// Thanks to @milabs for reporting.
	//
	for (size_t i = 0; i < ((SizeOfBuffer - SizeOfSignature) + 1); ++i)
	{
		if (!memcmp(&Memory[i], Signature, SizeOfSignature))
		{
			return &Memory[i];
		}
	}

	return NULL;
}



DWORD64 GetSystemAddr(PCWSTR fName) {
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, fName);
	return MmGetSystemRoutineAddress(&funcName);
}

NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	//ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}
		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}



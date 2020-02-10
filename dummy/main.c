#include "header.h"

//#define DEBUG

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

//сюда будет копироваться из fileMapping'a
UCHAR shellCodeFromC[2048] = { 0 };

//код-статусы для "синхронизации" событий
const UCHAR Status_MapSetted_WaitForDriverGetCWay = 0xFF;		//приложение создало FileMap, выделило и заполнело память структурой _UserAppInfo
const UCHAR Status_DriverGetCWay = 0xAA;						//драйвер получил доступ к CWay, FileMapping можно закрывать
const UCHAR Status_ShellCodeExecuted = 0xBB;					//шеллкод начал выполняться


UserAppInfo uAppInfo = { 0, NULL };

ShellData shellData = { 0 };
ShellDataAddr shellDataAddr = { 0 };



//#define NOHWIDCHECK

VOID FillShellData(PEPROCESS curProc) {
	shellData.CurrentEProcess = curProc;		//для KeStackAttachProcess

	

	/*UNICODE_STRING usSectionName;
	RtlInitUnicodeString(&usSectionName, L"\\BaseNamedObjects\\EventPreventFi");

	OBJECT_ATTRIBUTES objAttributes;
	InitializeObjectAttributes(&objAttributes, &usSectionName, OBJ_CASE_INSENSITIVE, NULL, 0);

	NTSTATUS status = ZwOpenEvent(&shellData.Arg2, EVENT_ALL_ACCESS, &objAttributes);
	if (NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "OpenEvent success!\n");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "OpenEvent error: %p\n", status);
	}*/
}

//заполняет таблицу с адресами функций shellDataFunc
VOID FillshellDataFunc(PVOID CWayBuf) {
	shellDataAddr.CWay = CWayBuf;

	//shellDataAddr.MmGetPhysicalAddress = GetSystemAddr(L"MmGetPhysicalAddress");
	shellDataAddr.MyMmUserProbeAddress = MmUserProbeAddress;
	//shellDataAddr.MmMapIoSpace = GetSystemAddr(L"MmMapIoSpace");
	//shellDataAddr.MmUnmapIoSpace = GetSystemAddr(L"MmUnmapIoSpace");
	//shellDataAddr.KeDelayExecutionThread = GetSystemAddr(L"KeDelayExecutionThread");//заполняется при поиске потока для захвата

	 
	shellDataAddr.PsLookupProcessByProcessId = GetSystemAddr(L"PsLookupProcessByProcessId");
	 
	shellDataAddr.ObfDereferenceObject = GetSystemAddr(L"ObfDereferenceObject");
	 
	shellDataAddr.KeStackAttachProcess = GetSystemAddr(L"KeStackAttachProcess");
 
	shellDataAddr.KeUnstackDetachProcess = GetSystemAddr(L"KeUnstackDetachProcess");
	 

	shellDataAddr.PsGetProcessPeb = GetSystemAddr(L"PsGetProcessPeb");
 
	shellDataAddr.MmCopyVirtualMemory = GetSystemAddr(L"MmCopyVirtualMemory");
	 
	shellDataAddr.ZwQueryVirtualMemory = GetSystemAddr(L"ZwQueryVirtualMemory");
 
}




//writable CPUID for each user
UCHAR writableCPUID[20] = {
	0x01, 0x02, 0x05, 0x07, 0x05, 0x05, 0x01, 0x03, 0x02, 0x06,
	0x09, 0x01, 0x02, 0x05, 0x07, 0x05, 0x05, 0x01, 0x03, 0x02 };

//0x6d, 0x21, 0xa3, 0x00, 0xfd, 0x56, 0x86, 0xdd, 0xf9, 0x47, 0x3c, 
//0xae, 0xce, 0xa5, 0xaa, 0xd7, 0xd3, 0xc9, 0x8f, 0x75 };//for debug purpose only

DWORD64 cpuid = 0;


NTSTATUS GetUserAppInfo(PCWSTR FileMapName) {
	UNICODE_STRING usSectionName;
	RtlInitUnicodeString(&usSectionName, FileMapName);

	OBJECT_ATTRIBUTES objAttributes;
	InitializeObjectAttributes(&objAttributes, &usSectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0);

	HANDLE m_SectionHandle = 0;
	NTSTATUS status = ZwOpenSection(&m_SectionHandle, GENERIC_READ | GENERIC_WRITE, &objAttributes);
	if (NT_SUCCESS(status)) {

		DWORD64* BaseAddr = NULL;
		SIZE_T viewSize = PAGE_SIZE;
		status = ZwMapViewOfSection(m_SectionHandle, NtCurrentProcess(), &BaseAddr, 0L, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
		if (NT_SUCCESS(status)) {
			memcpy(&uAppInfo, BaseAddr, sizeof(uAppInfo));//получаем данные из FileMap

			PUserAppInfo userAppInfo2 = (PUserAppInfo)BaseAddr;
			memcpy(shellCodeFromC, &userAppInfo2->ShellBegin, userAppInfo2->shellCodeSize);//читаем шеллкода из filemapping'a и сохраняем локально
		 
			ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddr);

#ifdef NOHWIDCHECK

#else
			//здесь проверяется хеш полученный и который всегда в драйвере
			cpuid = GetCPUID();
			UCHAR bufHash[20] = { 0 };
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "cpuid: %u\n", cpuid);
			
			if (SHA1(&cpuid, sizeof(cpuid), bufHash)) {

				for (USHORT i = 0; i < sizeof(bufHash); i++) {
					if ((bufHash[i] - writableCPUID[i]) != 0) {
						//если хоть один байт неверен вшитому байту хеша CPUID, меняем статус на неверный 
						status = STATUS_INTERNAL_DB_ERROR;
						 
					}
				}
			}
			else {
				status = STATUS_PIPE_BROKEN;//SHA1 по какой-то причине не смог получить хеш
			}

#endif


		}
		ZwClose(m_SectionHandle);
	}

	return status;
}







//Win7Win81:
//Section: PAGE
//Function : PpReleaseBootDDB
//Target: PiDDBLock
//48 8D 0D ?? ?? ?? ?? B2 01 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 33 FF 48 ?? ?? 74
UCHAR pat_PiDDBLock_W7_W81[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0xB2, 0x01, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0x33, 0xFF, 0x48, 0xCC, 0xCC, 0x74 };

//Win10 :
//Section : PAGE
//Function : PpReleaseBootDDB
//Target: PiDDBLock
//48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 33 DB 48 85 C9 74 ?? E8
UCHAR pat_PiDDBLock_W10[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0x33, 0xDB, 0x48, 0x85, 0xC9, 0x74, 0xCC, 0xE8 };

//-----------------------------------------------------------------

//Win7_Win81_Win10:
//Section: PAGE
//Function : PiUpdateDriverDBCache
//Target : PiDDBCacheTable
//48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 3D 00 01 00 00
UCHAR pat_PiDDBCacheTable_All[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x3D, 0x00, 0x01, 0x00, 0x00 };


UCHAR* toPattern = NULL;
SIZE_T patSize = 0;


BOOLEAN FindDDBData(PVOID pPiDDBLock, PVOID pPiDDBCacheTable) {
	ULONG SizeOf = 0;
	PVOID NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOf);
	if (NtBaseAddress == NULL || SizeOf == 0) {
		return FALSE;
	}

	PVOID PAGESecAddr = ImgGetImageSection(NtBaseAddress, "PAGE", &SizeOf);
	if (PAGESecAddr && SizeOf > 0) {
		OSVERSIONINFOW osVer;
		osVer.dwOSVersionInfoSize = sizeof(osVer);

		if (!NT_SUCCESS(RtlGetVersion(&osVer))) {
			return FALSE;
		}
		/*
		osVer.dwBuildNumber: 0000000000001DB1
		osVer.dwMajorVersion: 0000000000000006
		osVer.dwMinorVersion: 0000000000000001
		osVer.dwPlatformId: 0000000000000002
		osVer.szCSDVersion: FFFFF88003166704

		Windows 10	10.0	10	0
		Windows Server 2016	10.0	10	0
		Windows Server 2012 R2	6.3	10	0
		Windows 8.1	6.3	6	3
		Windows 8	6.2	6	2
		Windows 7	6.1	6	1

		*/

		if (osVer.dwMajorVersion == 6 && (osVer.dwMinorVersion == 1 || osVer.dwMinorVersion == 2 || osVer.dwMinorVersion == 3)) {//Win 7, 8, 8.1
			toPattern = &pat_PiDDBLock_W7_W81;
			patSize = sizeof(pat_PiDDBLock_W7_W81);
		}
		else if (osVer.dwMajorVersion == 10) {
			toPattern = &pat_PiDDBLock_W10;
			patSize = sizeof(pat_PiDDBLock_W10);
		}
		else {
			return FALSE;
		}

		PVOID pFound = NULL;
		if (!toPattern || !NT_SUCCESS(SearchPattern(toPattern, 0xCC, patSize - 1, PAGESecAddr, SizeOf, &pFound))) {
			return FALSE;
		}

		*(PERESOURCE*)pPiDDBLock = (PERESOURCE)RVA_TO_VA((PCHAR)pFound + 3);

		if (!NT_SUCCESS(SearchPattern(pat_PiDDBCacheTable_All, 0xCC, sizeof(pat_PiDDBCacheTable_All) - 1, PAGESecAddr, SizeOf, &pFound))) {
			return FALSE;
		}

		*(PRTL_AVL_TABLE*)pPiDDBCacheTable = (PRTL_AVL_TABLE)RVA_TO_VA((PCHAR)pFound + 3);
		return TRUE;
	}
	return FALSE;
}


NTSTATUS ClearDDBCache(PDRIVER_OBJECT DriverObject) {
	PERESOURCE PiDDBLock = NULL;
	PRTL_AVL_TABLE PiDDBCacheTable = NULL;

	if (!FindDDBData(&PiDDBLock, &PiDDBCacheTable)) {
		return STATUS_UNSUCCESSFUL;
	}

#ifdef DEBUG
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PiDDBLock: %p PiDDBCacheTable: %p\n", PiDDBLock, PiDDBCacheTable);
#endif

	if (PiDDBLock != NULL && PiDDBCacheTable != NULL) {
		PKLDR_DATA_TABLE_ENTRY TableEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		PIMAGE_NT_HEADERS Nt_Headers = RtlImageNtHeader(TableEntry->DllBase);

		PiDDBCacheEntry lookupEntry = { 0 };
		lookupEntry.DriverName = TableEntry->BaseDllName;
		lookupEntry.TimeDateStamp = Nt_Headers->FileHeader.TimeDateStamp;

		ExAcquireResourceExclusiveLite(PiDDBLock, 1);

		PiDDBCacheEntry* pFoundEntry = (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
		if (pFoundEntry == NULL) {
			ExReleaseResourceLite(PiDDBLock);
			return STATUS_SUCCESS;//записи о драйвере нету в дереве. Удалять не нужно
		}

		RemoveEntryList(&pFoundEntry->List);
		RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
		ExFreePool(pFoundEntry->DriverName.Buffer);

		ExReleaseResourceLite(PiDDBLock);
		return STATUS_SUCCESS;
	}
	else {
		return STATUS_UNSUCCESSFUL;
	}
}

VOID PreventStoreInUNLOADED_DRIVERS(DRIVER_OBJECT *DriverObject) {
	PKLDR_DATA_TABLE_ENTRY TableEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	TableEntry->BaseDllName.Buffer = NULL;
	TableEntry->BaseDllName.Length = 0;
	TableEntry->BaseDllName.MaximumLength = 0;
}


VOID UnloadDrv(PDRIVER_OBJECT DriverObject) {
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Unloading driver...\n");
}




NTSTATUS DriverEntry(struct _DRIVER_OBJECT *DriverObject, PUNICODE_STRING RegistryPath) {
	DriverObject->DriverUnload = UnloadDrv;

#ifdef DEBUG
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ALLOHA FROM DRIVER!!!!! \n");
#endif

	

	NTSTATUS status = ClearDDBCache(DriverObject);
	if (!NT_SUCCESS(status)) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ClearDDBCache error: %p\n", status);
		return STATUS_CHILD_MUST_BE_VOLATILE;
		//выходим без очистки UNLOADED_DRIVERS. 
		//в таком случае информация о драйвере останется как в DDBCache, так и в UNLOADED_DRIVERS
	}
	 
	PreventStoreInUNLOADED_DRIVERS(DriverObject);

	

	/*
	1) получить id потока и сослаться на него
	2) получить StackInit в _KTHREAD
	3) просканировать StackInit, вычитая адреса(стек растет вверх)
	4) если нашли адрес возврата: fffff80002dc3a2e nt!NtDelayExecution+0x59, заменяем fffff80002dc3a2e на адрес нашего буфера
	5) ждем когда поток проснется и прыгнет на наш буфер


	1) Очистка MM_UNLOADED_DRIVERS
	2) Очистка Shim Cache Driver
	3) Реализация коммуникации между shellcode и приложением


	*/


	 
	 
	status = GetUserAppInfo(L"\\BaseNamedObjects\\MarkedToRem");
	if (!NT_SUCCESS(status)) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "GetUserAppInfo error: %p\n", status);
		return STATUS_INVALID_DEVICE_STATE;
	}

	


	PETHREAD eThread = NULL;
	status = PsLookupThreadByThreadId(uAppInfo.threadIDToHijack, &eThread);
	if (!NT_SUCCESS(status)) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PsLookupThreadByThreadId error: %p\n", status);
		return STATUS_DEVICE_PROTOCOL_ERROR;
	}

	/*
	Win7:
	kd> dt nt!_KTHREAD fffffa8019770550
	+0x000 Header           : _DISPATCHER_HEADER
	+0x018 CycleTime        : 0x249694
	+0x020 QuantumTarget    : 0x1415a270
	+0x028 InitialStack     : 0xfffff880`03480c70 Void
	+0x030 StackLimit       : 0xfffff880`0347b000 Void
	+0x038 KernelStack      : 0xfffff880`03480830 Void
	+0x040 ThreadLock       : 0


	Win8.1:
	kd> dt nt!_KTHREAD ffffe0016dba8640
	+0x000 Header           : _DISPATCHER_HEADER
	+0x018 SListFaultAddress : (null)
	+0x020 QuantumTarget    : 0x141dd760
	+0x028 InitialStack     : 0xffffd001`5a6b4b90 Void
	+0x030 StackLimit       : 0xffffd001`5a6ae000 Void
	+0x038 StackBase        : 0xffffd001`5a6b5000 Void
	+0x040 ThreadLock       : 0


	Win 10 1903 - 10.0.18362.175:
	kd> dt nt!_KTHREAD ffffc70dc7eeb080
	+0x000 Header           : _DISPATCHER_HEADER
	+0x018 SListFaultAddress : (null)
	+0x020 QuantumTarget    : 0x6b49d20
	+0x028 InitialStack     : 0xffff9c0e`84457c10 Void
	+0x030 StackLimit       : 0xffff9c0e`84451000 Void
	+0x038 StackBase        : 0xffff9c0e`84458000 Void
	+0x040 ThreadLock       : 0
	*/
 
	 

	DWORD64 *InitialStackAddr = ((UCHAR*)eThread + 0x28);
	DWORD64 *StackLimitAddr = ((UCHAR*)eThread + 0x30);
	DWORD64 *curAddr = *InitialStackAddr;
	UCHAR foundAddrInStack = FALSE;
	DWORD32 cBytes = 0;

	KAPC_STATE state;
	PEPROCESS Process = PsGetThreadProcess(eThread);//получаем указатель на процесс через поток

	ObDereferenceObject(eThread);//мы больше не используем eThread ниже по коду, уменьшаем кол-во ссылок


	for (UCHAR i = 0; i < 4; i++) {
		for (USHORT j = 1; j < 120; j++) {
			curAddr--;//вычитается по 8 байт

			if (curAddr <= *StackLimitAddr) {//проверка границ стека
				break;
			}

			//
			//NtDelayExecution:
			//...
			//fffff800`02dc6a29 e8ee05d1ff      call    nt!KeDelayExecutionThread (fffff800`02ad701c)
			//fffff800`02dc6a2e 4883c428        add     rsp,28h ;<<-- стек хранит этот адрес
			//

			if (SafeReadKrnlAddr(*curAddr, &cBytes, 4) && cBytes == 0x28c48348) {		//читаем 4 байта из значения стека | 0x4883c428 add     rsp,28h					//
				if (SafeReadKrnlAddr((UCHAR*)*curAddr - 4, &cBytes, 4)) {				//e8ee05d1ff      call    nt!KeDelayExecutionThread. -4 получим только байты для прыжка


					DWORD64 nextInstr = *curAddr;//адрес следующей инструкции после call ... (В стеке хранится как раз адрес следующей инструкции за call)
					DWORD64 addressofFunc = nextInstr + cBytes - 0x100000000;//адрес следующей инструкции + 4 байта в обратном порядке - 0x100000000

					
 
					shellDataAddr.KeDelayExecutionThread = GetSystemAddr(L"KeDelayExecutionThread");

					if (shellDataAddr.KeDelayExecutionThread == addressofFunc) {		//скорее всего мы нашли NtDelayExecution(не экспортируется ядром)
						
#ifdef DEBUG
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NtDelayExecution found! AddrInStack: %p ValueInStack: %p\n", curAddr, *curAddr);
#endif
						shellDataAddr.HijackedAddrInStack = *curAddr;//запоминаем адрес для возврата
						 

						KeStackAttachProcess(Process, &state);

						PCWay CWay = (PCWay)uAppInfo.CWay;

#ifdef DEBUG
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CWay: %p uAppInfo.CWay: %p\n", CWay, uAppInfo.CWay);
#endif

						CWay->Status = Status_DriverGetCWay;//сигнализируем о том, что FileMapping можно закрывать

						KeUnstackDetachProcess(&state);

						foundAddrInStack = TRUE;
						break;
					}
				}
			}
		}

		if (foundAddrInStack) {
			break;
		}

		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "TryCount: %d\n", i);
		KernelSleep(3000);
	}

	if (!foundAddrInStack) {
		return STATUS_NO_MEDIA;
	}

 
 
	//работа с шеллкодом
	UCHAR* shellBuffer = (UCHAR*)ExAllocatePool(NonPagedPool, 4096);
	if (shellBuffer) {

		//decrypt
		EncDecXOR(shellCodeFromC, uAppInfo.shellCodeSize, cpuid);

		//проверяем расшифрованный шеллкод
		BOOLEAN goodDecrypted = FALSE;
		for (USHORT i = 0; i < uAppInfo.shellCodeSize; i++) {
			//$49, $BC, $01, $01, $01,
			//check if this bytes now decrypted

			if (shellCodeFromC[i] == 0x49) {
				if (shellCodeFromC[i + 1] == 0xBC) {
					if (shellCodeFromC[i + 2] == 0x01) {
						goodDecrypted = TRUE;
						break;
					}
				}
			}
		}

		if (goodDecrypted) {
			FillshellDataFunc(uAppInfo.CWay);//shellDataAddr
			FillShellData(Process);//shellData

			*(DWORD64*)&shellCodeFromC[2] = shellBuffer + uAppInfo.shellCodeSize;//ShellDataAddr
			*(DWORD64*)&shellCodeFromC[12] = shellBuffer + uAppInfo.shellCodeSize + sizeof(shellDataAddr);//ShellData

			memcpy(shellBuffer, shellCodeFromC, uAppInfo.shellCodeSize);
			memcpy(shellBuffer + uAppInfo.shellCodeSize, &shellDataAddr, sizeof(shellDataAddr));
			memcpy(shellBuffer + uAppInfo.shellCodeSize + sizeof(shellDataAddr), &shellData, sizeof(shellData));

#ifdef DEBUG
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "shellBuffer: %p\n", shellBuffer);
			__debugbreak();
#endif
			*curAddr = shellBuffer;//заменяем на адрес нашего шелла
		}
		else {
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "goodDecrypted false! \n");
			ExFreePool(shellBuffer);
			return STATUS_FWP_NOT_FOUND;
		}

	}

	

	return STATUS_SXS_CANT_GEN_ACTCTX;
}
			
	
 

 
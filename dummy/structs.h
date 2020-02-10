//структура для получения первичной информации от userMode-приложения
typedef struct _UserAppInfo {
	PVOID CWay;						//указатель на буфер в userMode-приложении, посредством которого будет осуществляться общение
	DWORD32 threadIDToHijack;	    //id потока который необходимо захватить
	DWORD32 shellCodeSize;			//размер шеллкода который получаем с сервера
	UCHAR ShellBegin;				//первый байт начала шеллкода, читать отсюда в кол-ве shellCodeSize
} UserAppInfo, *PUserAppInfo;


typedef struct _FastPatch {
	DWORD64 AddressToPatch;
	DWORD64 AddressFromPatch;
	DWORD32 Size;
} FastPatch, *PFastPatch;

 

//используется для взаимодействия с процессом пользователя
typedef struct _CWay {
	DWORD64 Status;					//результат выполненной команды
	PVOID A1;						//первый адрес
	PVOID A2;						//второй адрес
	PVOID PEBGame;					//Process Envitonment Block целевого процесса
	PMEMORY_BASIC_INFORMATION PMBI; //
	PVOID PFPatch;					//быстрый патч в ядре
	DWORD64 Var1;					//временное использование
	DWORD32 Size;					//размер(чтения, записи)
	DWORD32 PIDGame;				//ProcessID
	USHORT SleepInterval;			//время ожидания
	UCHAR ControlCode;				//код, благодаря которому определяется что именно делать
									//1 - чтение память
									//2 - запись в память
									//3 - передача PIDGame и получение PEBGame
									//5 - получение регионов памяти, A1 - адрес для чтения
									//6 - освобождение захваченного потока
									// 5b padding
									/*//48b размер MEMORY_BASIC_INFORMATION memInfo
									PVOID mbiBaseAddress;
									PVOID mbiAllocationBase;
									DWORD32 mbiAllocationProtect;
									//padding 4b
									SIZE_T mbiRegionSize;
									DWORD32 mbiState;
									DWORD32 mbiProtect;
									DWORD32 mbiType;
									//padding 4b*/
} CWay, *PCWay;

//содержит локальные переменные и прочие данные, необходимые для функционирования шеллкода
typedef struct _ShellData {
	DWORD64 Arg0;			        //используется для сохранения промежуточных результатов
	PEPROCESS CurrentEProcess;		//указатель на структуру процесса EPROCESS текущего процесса (хака)
	PEPROCESS TargetEProcess;		//указатель на структуру процесса EPROCESS целевого процесса (игры)
	PVOID Arg1;						//
	PVOID Arg2;						//хранит Handle события для синхронизации
	KAPC_STATE APC_State;			//необходимо для использования функций KeStackAttachProcess & KeUnstackDetachProcess
	MEMORY_BASIC_INFORMATION MBI;   //48b размер MEMORY_BASIC_INFORMATION memInfo
} ShellData, *PShellData;

//содержит адреса функций и адрес буфера CWay для коммуникации
typedef struct _ShellDataAddr {
	PVOID CWay;
	PVOID HijackedAddrInStack;
	//PVOID MmGetPhysicalAddress;
	DWORD64 MyMmUserProbeAddress;
//	PVOID MmMapIoSpace;
//	PVOID MmUnmapIoSpace;
	PVOID KeDelayExecutionThread;
	PVOID PsLookupProcessByProcessId;
	PVOID ObfDereferenceObject;
	PVOID KeStackAttachProcess;
	PVOID KeUnstackDetachProcess;
	PVOID PsGetProcessPeb;
	PVOID MmCopyVirtualMemory;
	PVOID ZwQueryVirtualMemory;
} ShellDataAddr, *PShellDataAddr;



/*
kd> dt nt!_LDR_DATA_TABLE_ENTRY
+0x000 InLoadOrderLinks : _LIST_ENTRY
+0x010 InMemoryOrderLinks : _LIST_ENTRY
+0x020 InInitializationOrderLinks : _LIST_ENTRY
+0x030 DllBase          : Ptr64 Void
+0x038 EntryPoint       : Ptr64 Void
+0x040 SizeOfImage      : Uint4B
+0x048 FullDllName      : _UNICODE_STRING
+0x058 BaseDllName      : _UNICODE_STRING
+0x068 Flags            : Uint4B
+0x06c LoadCount        : Uint2B
+0x06e TlsIndex         : Uint2B
+0x070 HashLinks        : _LIST_ENTRY
+0x070 SectionPointer   : Ptr64 Void
+0x078 CheckSum         : Uint4B
+0x080 TimeDateStamp    : Uint4B
+0x080 LoadedImports    : Ptr64 Void
+0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
+0x090 PatchInformation : Ptr64 Void
+0x098 ForwarderLinks   : _LIST_ENTRY
+0x0a8 ServiceTagLinks  : _LIST_ENTRY
+0x0b8 StaticLinks      : _LIST_ENTRY
+0x0c8 ContextInformation : Ptr64 Void
+0x0d0 OriginalBase     : Uint8B
+0x0d8 LoadTime         : _LARGE_INTEGER


*/

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;




typedef struct _PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
} PiDDBCacheEntry, *PPiDDBCacheEntry;
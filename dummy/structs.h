//��������� ��� ��������� ��������� ���������� �� userMode-����������
typedef struct _UserAppInfo {
	PVOID CWay;						//��������� �� ����� � userMode-����������, ����������� �������� ����� �������������� �������
	DWORD32 threadIDToHijack;	    //id ������ ������� ���������� ���������
	DWORD32 shellCodeSize;			//������ �������� ������� �������� � �������
	UCHAR ShellBegin;				//������ ���� ������ ��������, ������ ������ � ���-�� shellCodeSize
} UserAppInfo, *PUserAppInfo;


typedef struct _FastPatch {
	DWORD64 AddressToPatch;
	DWORD64 AddressFromPatch;
	DWORD32 Size;
} FastPatch, *PFastPatch;

 

//������������ ��� �������������� � ��������� ������������
typedef struct _CWay {
	DWORD64 Status;					//��������� ����������� �������
	PVOID A1;						//������ �����
	PVOID A2;						//������ �����
	PVOID PEBGame;					//Process Envitonment Block �������� ��������
	PMEMORY_BASIC_INFORMATION PMBI; //
	PVOID PFPatch;					//������� ���� � ����
	DWORD64 Var1;					//��������� �������������
	DWORD32 Size;					//������(������, ������)
	DWORD32 PIDGame;				//ProcessID
	USHORT SleepInterval;			//����� ��������
	UCHAR ControlCode;				//���, ��������� �������� ������������ ��� ������ ������
									//1 - ������ ������
									//2 - ������ � ������
									//3 - �������� PIDGame � ��������� PEBGame
									//5 - ��������� �������� ������, A1 - ����� ��� ������
									//6 - ������������ ������������ ������
									// 5b padding
									/*//48b ������ MEMORY_BASIC_INFORMATION memInfo
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

//�������� ��������� ���������� � ������ ������, ����������� ��� ���������������� ��������
typedef struct _ShellData {
	DWORD64 Arg0;			        //������������ ��� ���������� ������������� �����������
	PEPROCESS CurrentEProcess;		//��������� �� ��������� �������� EPROCESS �������� �������� (����)
	PEPROCESS TargetEProcess;		//��������� �� ��������� �������� EPROCESS �������� �������� (����)
	PVOID Arg1;						//
	PVOID Arg2;						//������ Handle ������� ��� �������������
	KAPC_STATE APC_State;			//���������� ��� ������������� ������� KeStackAttachProcess & KeUnstackDetachProcess
	MEMORY_BASIC_INFORMATION MBI;   //48b ������ MEMORY_BASIC_INFORMATION memInfo
} ShellData, *PShellData;

//�������� ������ ������� � ����� ������ CWay ��� ������������
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
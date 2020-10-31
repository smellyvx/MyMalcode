#include <Windows.h>
#include <virtdisk.h>
#include <stdio.h>
#include <initguid.h>

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID*					KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID*					ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID**					ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

PPEB RtlGetPeb(VOID);

#define DEFAULT_DATA_ALLOCATION_SIZE (MAX_PATH * sizeof(WCHAR))
DEFINE_GUID(VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT, 0xEC984AEC, 0xA0F9, 0x47e9, 0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B);

int wmain(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	VIRTUAL_STORAGE_TYPE VirtualStorageType = { 0 };
	OPEN_VIRTUAL_DISK_PARAMETERS Parameters;
	ATTACH_VIRTUAL_DISK_PARAMETERS AttachParameters;
	HANDLE VirtualObject = NULL, hToken = NULL;
	WCHAR lpIsoPath[DEFAULT_DATA_ALLOCATION_SIZE] = { 0 };
	WCHAR lpIsoAbstractedPath[DEFAULT_DATA_ALLOCATION_SIZE] = { 0 };
	PPEB Peb = (PPEB)RtlGetPeb();
	DWORD dwData = DEFAULT_DATA_ALLOCATION_SIZE;
	STARTUPINFOW Info = { 0 };
	PROCESS_INFORMATION ProcessInformation = { 0 };

	if (Peb->OSMajorVersion != 0x0a)
		goto FAILURE; 

	if (GetEnvironmentVariableW(L"USERPROFILE", lpIsoPath, DEFAULT_DATA_ALLOCATION_SIZE) == 0)
		goto FAILURE;
	else
		wcscat(lpIsoPath, L"\\Desktop\\Demo.iso");

	VirtualStorageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_ISO;
	VirtualStorageType.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

	Parameters.Version = OPEN_VIRTUAL_DISK_VERSION_1;
	Parameters.Version1.RWDepth = OPEN_VIRTUAL_DISK_RW_DEPTH_DEFAULT;

	if(OpenVirtualDisk(&VirtualStorageType, lpIsoPath, VIRTUAL_DISK_ACCESS_ATTACH_RO | VIRTUAL_DISK_ACCESS_GET_INFO, OPEN_VIRTUAL_DISK_FLAG_NONE, &Parameters, &VirtualObject) != ERROR_SUCCESS)
		goto FAILURE;

	AttachParameters.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
	if (AttachVirtualDisk(VirtualObject, 0, ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, 0, &AttachParameters, 0) != ERROR_SUCCESS)
		goto FAILURE;


	if (GetVirtualDiskPhysicalPath(VirtualObject, &dwData, lpIsoAbstractedPath) != ERROR_SUCCESS)
		goto FAILURE;
	else
		wcscat(lpIsoAbstractedPath, L"\\Target.exe");

	if (!CreateProcess(lpIsoAbstractedPath, NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &Info, &ProcessInformation))
		goto FAILURE;

	WaitForSingleObject(ProcessInformation.hProcess, INFINITE);

	if (ProcessInformation.hProcess)
		CloseHandle(ProcessInformation.hProcess);

	if (ProcessInformation.hThread)
		CloseHandle(ProcessInformation.hThread);

	if (VirtualObject)
		CloseHandle(VirtualObject);

	if (hToken)
		CloseHandle(hToken);
	
	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (ProcessInformation.hProcess)
		CloseHandle(ProcessInformation.hProcess);

	if (ProcessInformation.hThread)
		CloseHandle(ProcessInformation.hThread);

	if (VirtualObject)
		CloseHandle(VirtualObject);

	if (hToken)
		CloseHandle(hToken);

	return dwError;
}

PPEB RtlGetPeb(VOID)
{
	return (PPEB)__readgsqword(0x60);
}
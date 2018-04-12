#pragma once
#include<windows.h>

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#define Macro(type,base,offset) (type)((ULONG_PTR)base + offset)


typedef struct _HOOK_BLOCK_
{
	PVOID ImageBase;
	CHAR* FuncName;
	CHAR* DllName;
	PVOID FakeFunc;
	PVOID OriginFunc;
	PIMAGE_IMPORT_DESCRIPTOR Descriptor;
}HOOK_BLOCK,*PHOOK_BLOCK;

VOID InterLockedExchangeFuncPointer(IN PVOID Value1, IN PVOID Value2);
BOOL HookSingle(IN PHOOK_BLOCK pblock, IN PIMAGE_IMPORT_DESCRIPTOR importDescriptor, IN BOOL bHook);

BOOL IATHook(
	IN PVOID ImageBase,
	IN CHAR* DllName,
	IN CHAR* FuncName,
	IN PVOID FakeFunc,
	OUT HANDLE* hHook
);

VOID IatUnHook(IN HANDLE hHppk);
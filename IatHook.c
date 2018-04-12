#include"IatHook.h"
#include<ntstatus.h>

VOID InterLockedExchangeFuncPointer(IN PVOID Value1, IN PVOID Value2)
{
	DWORD OldProtect = 0;
	BOOL IsOk = FALSE;
	if (Value1 == NULL)
	{
		return;
	}
	if (!VirtualProtect(Value1, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		return;
	}
	InterlockedExchangePointer(Value1, Value2);
	VirtualProtect(Value1, sizeof(PVOID), OldProtect, &OldProtect);
}

BOOL HookSingle(IN PHOOK_BLOCK pblock,IN PIMAGE_IMPORT_DESCRIPTOR importDescriptor, IN BOOL bHook)
{
	PIMAGE_THUNK_DATA pOriginThunk = NULL;
	PIMAGE_THUNK_DATA pFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME  hintName = NULL;
	
	pOriginThunk = Macro(PIMAGE_THUNK_DATA, pblock->ImageBase, importDescriptor->OriginalFirstThunk);
	pFirstThunk = Macro(PIMAGE_THUNK_DATA, pblock->ImageBase, importDescriptor->FirstThunk);

	for(; pOriginThunk->u1.Ordinal!=0; pOriginThunk++, pFirstThunk++)
	if (IMAGE_SNAP_BY_ORDINAL(pOriginThunk->u1.Ordinal))		//最高位为1,则可以用GetProcAddress获得函数地址
	{
		if (atoi(pblock->FuncName) == LOWORD(pOriginThunk->u1.Ordinal))
		{
			if (bHook)
			{
				pblock->OriginFunc = (PVOID)pFirstThunk->u1.Function;
				InterLockedExchangeFuncPointer(&pFirstThunk->u1.Function, pblock->FakeFunc);
			}
			else
			{
				InterLockedExchangeFuncPointer(&pFirstThunk->u1.Function, pblock->OriginFunc);
			}
		}
		
	}
	else //最高位为0,则为hint/name结构
	{
		PIMAGE_IMPORT_BY_NAME pImportByName = Macro(PIMAGE_IMPORT_BY_NAME, pblock->ImageBase, pOriginThunk->u1.AddressOfData);

		if (stricmp(pImportByName->Name, pblock->FuncName) == 0)
		{
			if (bHook)
			{
				pblock->OriginFunc = (PVOID)pFirstThunk->u1.Function;
				InterLockedExchangeFuncPointer(&pFirstThunk->u1.Function, pblock->FakeFunc);
			}
			else
			{
				InterLockedExchangeFuncPointer(&pFirstThunk->u1.Function, pblock->OriginFunc);
			}
		}
	}
	return  (pblock->OriginFunc != NULL);
}


BOOL IATHook(
	IN PVOID ImageBase,
	IN CHAR* DllName,
	IN CHAR* FuncName,
	IN PVOID FakeFunc,
	OUT HANDLE* hHook
)
{
	BOOL bRet = FALSE;
	PIMAGE_DOS_HEADER dos_header = NULL;
	PIMAGE_NT_HEADERS nt_headers = NULL;
	IMAGE_DATA_DIRECTORY ImportTable={0};
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	PCHAR dllName = NULL;
	HOOK_BLOCK temp = { ImageBase ,FuncName ,DllName,FakeFunc,NULL };
	PHOOK_BLOCK pBlock = (PHOOK_BLOCK)malloc(sizeof(HOOK_BLOCK));
	memcpy(pBlock, &temp, sizeof(HOOK_BLOCK));
	do {
		if (ImageBase == NULL || FuncName == NULL || FakeFunc == NULL)
		{
			SetLastError(STATUS_INVALID_PARAMETER);
			break;
		}
		//PE格式检查

		dos_header = Macro(PIMAGE_DOS_HEADER, ImageBase,0);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			SetLastError(STATUS_INVALID_IMAGE_FORMAT);
			break;
		}

		nt_headers = Macro(PIMAGE_NT_HEADERS, ImageBase, dos_header->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		{
			SetLastError(STATUS_INVALID_IMAGE_FORMAT);
			break;
		}
		if (nt_headers->FileHeader.Machine!=HOST_MACHINE)
		{
			SetLastError(STATUS_INVALID_IMAGE_FORMAT);
			break;
		}


		ImportTable = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (ImportTable.VirtualAddress == 0 || ImportTable.VirtualAddress == 0 )
		{
			SetLastError(STATUS_INVALID_IMAGE_FORMAT);
			break;
		}
		//遍历各个模块
		importDescriptor = Macro(PIMAGE_IMPORT_DESCRIPTOR, ImageBase, ImportTable.VirtualAddress);
		for (; importDescriptor->Name!=NULL; importDescriptor++)
		{
			dllName = Macro(PCHAR, ImageBase, importDescriptor->Name);
			if (dllName != NULL)
			{
				if (_strcmpi(DllName, dllName) != 0)
				{
					continue;
				}
				if (HookSingle(pBlock, importDescriptor, TRUE))
				{
					pBlock->Descriptor = importDescriptor;
					if (hHook != NULL)
						*hHook= (HANDLE)pBlock;
					bRet = TRUE;
					break;
				}
			}
		}
	} while (FALSE);

	return bRet;
}

VOID IatUnHook(IN HANDLE hHppk)
{
	if (hHppk == 0)
	{
		return;
	}
	PHOOK_BLOCK pBlock = (PHOOK_BLOCK)hHppk;
	HookSingle(pBlock, pBlock->Descriptor, FALSE);

	free(pBlock);
	pBlock = NULL;
}
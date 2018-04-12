#include"IatHook.h"
#include<stdio.h>
int
WINAPI
FakeMessageBoxA(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType)
{
	printf("Faked\r\n");
	return 0;
}

int main()
{
	HANDLE hHook = NULL;
	BOOL IsOk = IATHook(GetModuleHandleA(NULL), "User32.dll", "MessageBoxA", FakeMessageBoxA, &hHook);
	MessageBoxA(NULL, "Hello", "Hello", MB_OK);
	IatUnHook(hHook);
	MessageBoxA(NULL, "Hello", "Hello", MB_OK);

}
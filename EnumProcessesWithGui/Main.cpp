#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam);

int main(VOID)
{
	EnumWindows(EnumWindowsProc, 0);
}


BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	WCHAR wcPath[MAX_PATH] = { 0 };
	DWORD dwThreadId = 0;
	HANDLE hHandle;

	GetWindowThreadProcessId(hWnd, &dwThreadId);

	hHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwThreadId);
	if (hHandle == NULL)
		goto FAILURE;

	if (GetProcessImageFileNameW(hHandle, wcPath, MAX_PATH) == 0)
		goto FAILURE;

	printf("%ws\r\n", wcPath);

	if (hHandle)
		CloseHandle(hHandle);

	return TRUE;

FAILURE:

	if (hHandle)
		CloseHandle(hHandle);

	return FALSE;
}
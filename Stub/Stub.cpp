#include "Stub.h"

// 融合区段
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/merge:.pdata=.text")
#pragma comment(linker, "/section:.text,RWE")

// 自建函数
int stubStrcmpA(const char* str1, const char* str2);
int stubStricmpW(const wchar_t* str1, const wchar_t* str2);
PVOID stubGetProcAddress(HMODULE hModule, LPCSTR lpszProcName);
HMODULE stubGetModuleHandle(LPCWSTR lpszModuleName);

typedef HMODULE(WINAPI* FnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef HMODULE(WINAPI* FnGetModuleHandleW)(_In_opt_ LPCWSTR lpModuleName);
typedef PVOID(WINAPI* FnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef BOOL(WINAPI* FnVirtualProtect)(_In_ LPVOID lpAddress, _In_  SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef int(WINAPI* FnMessageBox)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);

FnLoadLibraryA _LoadLibraryA = nullptr;
FnGetProcAddress _GetProcAddress = nullptr;
FnGetModuleHandleW _GetModuleHandleW = nullptr;
FnVirtualProtect _VirtualProtect = nullptr;
FnMessageBox _MessageBoxA = nullptr;

// 壳引导函数
void loader();

#ifdef __cplusplus
EXTERN_C_START
#endif

// Shell Stub Boot Context
typedef struct _BootContext {
    ULONG_PTR loaderFunc;           // Loader Function Address
    ULONG_PTR originalEP;	        // Original Entry Point
    ULONG_PTR originalReloc;        // Original Relocation Data RVA
    ULONG_PTR originalImageBase;    // Original Image Base
    ULONG_PTR executeTLSCallback;	// bool executeTLSCallback (8byte Alignment)
    ULONG_PTR originalTLSIndex;		// Original TLS Index
    ULONG_PTR originalTLSCallbacks;	// RVA to Pointer to PIMAGE_TLS_CALLBACK
} BootContext, * PBootContext;

__declspec(thread) DWORD _tls_support;
StubAPI BootContext _loader_context = { (ULONG_PTR)loader };

#ifdef __cplusplus
EXTERN_C_END
#endif

void loader() {

    // 使编译器产生TLS表，以接管宿主的TLS
    _tls_support;
    
    // 初始化函数地址和所需模块地址
#if 1
    // kernel32.dll
    wchar_t lpwszKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    HMODULE hKernel32 = stubGetModuleHandle(lpwszKernel32);

    // kernel32!GetProcAddress
    char lpszGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
    _GetProcAddress = (FnGetProcAddress)stubGetProcAddress(hKernel32, lpszGetProcAddress);

    // kernel32!LoadLibraryA
    char lpszLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    _LoadLibraryA = (FnLoadLibraryA)_GetProcAddress(hKernel32, lpszLoadLibraryA);

    // kernel32!GetModuleHandleW
    char lpszGetModuleHandleW[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'W', '\0' };
    _GetModuleHandleW = (FnGetModuleHandleW)_GetProcAddress(hKernel32, lpszGetModuleHandleW);

    char lpszVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
    _VirtualProtect = (FnVirtualProtect)_GetProcAddress(hKernel32, lpszVirtualProtect);

    // user32.dll
    char lpszUser32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' };
    HMODULE hUser32 = _LoadLibraryA(lpszUser32);

    // user32!MessageBoxA
    char lpszMessageBoxA[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', '\0' };
    _MessageBoxA = (FnMessageBox)_GetProcAddress(hUser32, lpszMessageBoxA);
#endif

    // 获取加载后的新ImageBase(防ASLR)
#if 1
    ULONG_PTR newImageBase = (ULONG_PTR)_GetModuleHandleW(nullptr);
#endif
    
    // 处理TLS
#if 1
    if (_loader_context.executeTLSCallback) {
        PIMAGE_TLS_CALLBACK* tlsCallbacks = (PIMAGE_TLS_CALLBACK*)(newImageBase + _loader_context.originalTLSCallbacks);
        while (*tlsCallbacks) {
            (*tlsCallbacks)((PVOID)newImageBase, DLL_PROCESS_ATTACH, nullptr);
            tlsCallbacks++;
        }
    }
#endif

    char lpszMsg[] = { 'A', 'y', 'i', 'n', 'P', 'r', 'o', 't', 'e', 'c', 't', 'o', 'r', '!', '\0' };
    _MessageBoxA(nullptr, lpszMsg, nullptr, MB_ICONINFORMATION);

    // 处理重定位(如果需要)
#if 1
    if (_loader_context.originalReloc) {
        IMAGE_BASE_RELOCATION* relocData = (IMAGE_BASE_RELOCATION*)(newImageBase + _loader_context.originalReloc);
        ULONG64 baseDelta = newImageBase - _loader_context.originalImageBase;

        while (relocData->VirtualAddress) {

            // 设置对应VirtualAddress那一页的保护属性为可读可写可执行
            DWORD originProt = 0;
            _VirtualProtect((LPVOID)(newImageBase + relocData->VirtualAddress), PAGE_SIZE, PAGE_EXECUTE_READWRITE, &originProt);

            DWORD sizeOfBlock = relocData->SizeOfBlock;
            DWORD numOfItems = (sizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / (sizeof(WORD) * 2);

            WORD* pType = (WORD*)(relocData + 1);
            WORD* pOffset = pType + 1;
            for (DWORD i = 0; i < numOfItems; i++) {

                if (RELOC_FLAG(*pType)) {
                    ULONG64* pFixPoint = (ULONG64*)(newImageBase + relocData->VirtualAddress + (*pOffset));
                    *pFixPoint += baseDelta;
                }

                pType += 2;
                pOffset += 2;
            }

            // 还原内存保护属性
            _VirtualProtect((LPVOID)(newImageBase + relocData->VirtualAddress), PAGE_SIZE, originProt, &originProt);

            // 转到下一个重定位块
            relocData = (IMAGE_BASE_RELOCATION*)((BYTE*)relocData + sizeOfBlock);
        }

    }
#endif

    // 跳回原程序OEP
    opJmp(newImageBase + _loader_context.originalEP);
}

int stubStrcmpA(const char* str1, const char* str2) {
    unsigned char c1 = 0;
    unsigned char c2 = 0;
    do {
        c1 = (unsigned char)*str1++;
        c2 = (unsigned char)*str2++;
        if (c1 == 0)
            return c1 - c2;
    } while (c1 == c2);
    return c1 - c2;
}

int stubStricmpW(const wchar_t* str1, const wchar_t* str2) {
    unsigned short c1 = 0;
    unsigned short c2 = 0;

    do {
        c1 = (unsigned short)*str1++;
        if (c1 >= 65 && c1 <= 90) {
            c1 = c1 + 32;
        }

        c2 = (unsigned short)*str2++;
        if (c2 > 65 && c2 < 90) {
            c2 = c2 + 32;
        }

        if (c1 == 0)
            return c1 - c2;
    } while (c1 == c2);

    return c1 - c2;
}

PVOID stubGetProcAddress(HMODULE hModule, LPCSTR lpszProcName) {
    if (!hModule || !lpszProcName)
        return NULL;

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImageNTHeaders = MakePointer(PIMAGE_NT_HEADERS, hModule, pImageDosHeader->e_lfanew);
    if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    if (pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =
        MakePointer(PIMAGE_EXPORT_DIRECTORY, hModule,
            pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pNameTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfNames);

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        if (!stubStrcmpA(lpszProcName, (char*)hModule + pNameTable[i])) {
            PWORD pOrdinalTable = MakePointer(PWORD, hModule, pImageExportDirectory->AddressOfNameOrdinals);
            PDWORD pAddressTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfFunctions);
            DWORD dwAddressOffset = pAddressTable[pOrdinalTable[i]];
            return MakePointer(PVOID, hModule, dwAddressOffset);
        }
    }

    return NULL;
}

HMODULE stubGetModuleHandle(LPCWSTR lpszModuleName) {
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING;
    typedef UNICODE_STRING* PUNICODE_STRING;
    typedef const UNICODE_STRING* PCUNICODE_STRING;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID BaseAddress;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        SHORT LoadCount;
        SHORT TlsIndex;
        LIST_ENTRY HashTableEntry;
        ULONG TimeDateStamp;
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

#ifdef _WIN64
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[21];
        PPEB_LDR_DATA Ldr;
        PVOID ProcessParameters;
        BYTE Reserved3[520];
        PVOID PostProcessInitRoutine;
        BYTE Reserved4[136];
        ULONG SessionId;
    } PEB, * PPEB;
#else
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PPEB_LDR_DATA Ldr;
        LPVOID ProcessParameters;
        PVOID Reserved4[3];
        PVOID AtlThunkSListPtr;
        PVOID Reserved5;
        ULONG Reserved6;
        PVOID Reserved7;
        ULONG Reserved8;
        ULONG AtlThunkSListPtr32;
        PVOID Reserved9[45];
        BYTE Reserved10[96];
        LPVOID PostProcessInitRoutine;
        BYTE Reserved11[128];
        PVOID Reserved12[1];
        ULONG SessionId;
    } PEB, * PPEB;
#endif

    // Get the base address of PEB struct
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (pPeb && pPeb->Ldr) {
        // Get pointer value of PEB_LDR_DATA
        PPEB_LDR_DATA pLdr = pPeb->Ldr;

        // And get header of the InLoadOrderModuleList
        PLIST_ENTRY pHeaderOfModuleList = &(pLdr->InLoadOrderModuleList);
        if (pHeaderOfModuleList->Flink != pHeaderOfModuleList) {
            PLDR_DATA_TABLE_ENTRY pEntry = NULL;
            PLIST_ENTRY pCur = pHeaderOfModuleList->Flink;

            // Find Entry of the fake module
            do {
                pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
                // OK, got it
                if (0 == stubStricmpW(pEntry->BaseDllName.Buffer, lpszModuleName)) {
                    return (HMODULE)(pEntry->BaseAddress);
                    break;
                }
                pEntry = NULL;
                pCur = pCur->Flink;
            } while (pCur != pHeaderOfModuleList);
        }
    }

    return NULL;
}

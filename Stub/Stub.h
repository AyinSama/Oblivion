#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define PAGE_SIZE 0x1000
#define MakePointer(_Ty, _Ptr, _Off) ((_Ty)((PBYTE)(_Ptr) + _Off))

#ifdef STUB_EXPORTS
#define StubAPI __declspec(dllexport)
#else
#define StubAPI __declspec(dllimport)
#endif

#define RELOC_FLAG32(RelInfo) (RelInfo == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) (RelInfo == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#define COMPILE_ARCHITECTURE IMAGE_FILE_MACHINE_AMD64
#else
#define RELOC_FLAG RELOC_FLAG32
#define COMPILE_ARCHITECTURE IMAGE_FILE_MACHINE_I386
#endif

// Ìø×ªº¯Êý(jmp rcx)
#ifdef __cplusplus
EXTERN_C void opJmp(UINT_PTR jmpAddr);
#else
extern void opJmp(UINT_PTR jmpAddr);
#endif

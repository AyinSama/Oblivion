#pragma once
#include "Pch.h"
#include "PEFile.h"

typedef struct _IATFunction {
	Dword ordinal = -1;		// 如果函数通过名称导入则ordinal为-1
	std::string name;
} IATFunction, *PIATFunction;

typedef struct _RelocBlock {
	Dword va = 0;		// VirtualAddress
	Dword size = 0;		// SizeOfBlock
	std::vector<std::pair<Word, Word>> items;	// Type / Offset
} RelocBlock, *PRelocBlock;

typedef struct _TlsChunk {
	UInt64 hasTLS;			// bool hasTLS (8byte Alignment)
	UInt64 startAddr;		// StartAddressOfRawData
	UInt64 endAddr;			// EndAddressOfRawData
	UInt64 tlsIndex;		// Index -> tlsIndex = *(DWORD*)AddressOfIndex
	UInt64 tlsCallbacks;	// RVA to AddressOfCallBacks
	Dword sizeOfZero;		// SizeOfZeroFill
	Dword characteristics;	// Characteristics
} TlsChunk, *PTlsChunk;

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

using IATThunk = std::vector<IATFunction>;					// Thunk指代一个被引用的DLL的所有导入函数的集合
using IATChunk = std::unordered_map<std::string, IATThunk>;	// Chunk指代所有被引用的DLL的集合

using RelChunk = std::vector<RelocBlock>;					// 指代一个DLL所有重定位项的集合

constexpr char SHELLSTUB_SEGMENT_NAME_ANSI[] = {'.', 'a', 'y', 'i', 'n', '\0'};
constexpr wchar_t SHELLSTUB_SEGMENT_NAME_UNICODE[] = {'.', 'a', 'y', 'i', 'n', '\0'};
constexpr char SHELLDATA_SEGMENT_NAME_ANSI[] = { '.', 's', 'a', 'm', 'a', '\0' };
constexpr wchar_t SHELLDATA_SEGMENT_NAME_UNICODE[] = { '.', 's', 'a', 'm', 'a', '\0' };

class Protector : public Singleton<Protector> {
public:
	SingleObject(Protector);
	
	void release();

	void procIAT(PEFile& pe);
	void procReloc(PEFile& pe);
	void procTLS(PEFile& pe);

	void removeIAT(PEFile& pe);
	void removeReloc(PEFile& pe);

	bool loadShellStub(Byte** allocatedStub, Size* stubSize);
	bool fixPETLS(PEFile& pe);
	bool fixShellStubReloc(PEFile& pe);
	bool setupStubBootContext(PEFile& pe);
	bool writeShellStub(Byte* stubSectionData);

	Size getEncryptedDataSize();
	bool writeShellEncryptedData(Byte* encryptedData);

private:

	IATChunk iatChunk;
	RelChunk relChunk;
	TlsChunk tlsChunk;

	Byte* pShellStub = nullptr;
	Size shellStubSize = 0;

};


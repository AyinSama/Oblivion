#include "Pch.h"
#include "Protector.h"

void Protector::release() {

	// 清理保存的IAT
	for (auto& chunk : this->iatChunk) {
		{	// 加作用域是让emptyThunk在退出作用域时析构
			IATThunk emptyThunk;
			chunk.second.swap(emptyThunk);
		}
	}
	{
		IATChunk emptyChunk;
		this->iatChunk.swap(emptyChunk);
	}

	// 清理保存的重定位块
	{
		RelChunk emptyChunk;
		this->relChunk.swap(emptyChunk);
	}

}

void Protector::procIAT(PEFile& pe) {

	IMAGE_DATA_DIRECTORY& importIDD = pe.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* importIID = pe.rva<IMAGE_IMPORT_DESCRIPTOR>(importIDD.VirtualAddress);	

	// 保存IAT
	while (importIID->Name) {
		
		IATThunk curThunk;
		char* szModuleName = pe.rva<char>(importIID->Name);
		DWORD intRva = importIID->OriginalFirstThunk;
		if (!intRva) intRva = importIID->FirstThunk;

		IMAGE_THUNK_DATA* curFnData = pe.rva<IMAGE_THUNK_DATA>(intRva);
		while (curFnData->u1.AddressOfData) {
			
			IATFunction curFunction;
			IMAGE_IMPORT_BY_NAME* curFnName = pe.rva<IMAGE_IMPORT_BY_NAME>(curFnData->u1.AddressOfData);
			if (IMAGE_SNAP_BY_ORDINAL(curFnData->u1.Ordinal)) {
				curFunction.ordinal = IMAGE_ORDINAL(curFnData->u1.Ordinal);
				curFunction.name = std::string("");
			}
			else {
				curFunction.ordinal = 0xFFFFFFFF;
				curFunction.name = std::string(curFnName->Name);
			}

			curThunk.push_back(std::move(curFunction));
			curFnData++;
		}

		this->iatChunk.insert(std::make_pair(szModuleName, std::move(curThunk)));
		importIID++;
	}
	
	printf("[Oblivion] IAT proc finished.\n");
}

void Protector::removeIAT(PEFile& pe) {

	// 抹除IAT
	IMAGE_DATA_DIRECTORY& importIDD = pe.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* importIID = pe.rva<IMAGE_IMPORT_DESCRIPTOR>(importIDD.VirtualAddress);
	while (importIID->Name) {

		// 抹除INT
		if (importIID->OriginalFirstThunk) {
			IMAGE_THUNK_DATA* pThunk = pe.rva<IMAGE_THUNK_DATA>(importIID->OriginalFirstThunk);
			while (pThunk->u1.AddressOfData) {
				if (!IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
					IMAGE_IMPORT_BY_NAME* curFnName = pe.rva<IMAGE_IMPORT_BY_NAME>(pThunk->u1.AddressOfData);
					memset(curFnName, 0, sizeof(curFnName->Hint) + strlen(curFnName->Name));
				}
				memset(pThunk, 0, sizeof(IMAGE_THUNK_DATA));
				pThunk++;
			}
		}

		// 抹除IAT
		IMAGE_THUNK_DATA* firstThunk = pe.rva<IMAGE_THUNK_DATA>(importIID->FirstThunk);
		while (firstThunk->u1.Function) {
			memset(firstThunk, 0, sizeof(IMAGE_THUNK_DATA));
			firstThunk++;
		}

		// 抹除IID
		char* szModuleName = pe.rva<char>(importIID->Name);
		memset(szModuleName, 0, strlen(szModuleName));
		memset(importIID, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

		importIID++;
	}

	printf("[Oblivion] IAT removed.\n");
}

void Protector::procReloc(PEFile& pe) {

	IMAGE_DATA_DIRECTORY& relocIDD = pe.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!relocIDD.Size) {
		printf("[Oblivion] No relocation block.\n");
		return;
	}
	
	IMAGE_BASE_RELOCATION* baseReloc = pe.rva<IMAGE_BASE_RELOCATION>(relocIDD.VirtualAddress);
	while (baseReloc->VirtualAddress) {
		Dword blockSize = baseReloc->SizeOfBlock;
		Dword relocItemCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		Word* pRelocItem = (Word*)((Byte*)baseReloc + sizeof(IMAGE_BASE_RELOCATION));
		RelocBlock relBlock;
		relBlock.va = baseReloc->VirtualAddress;
		relBlock.size = baseReloc->SizeOfBlock;

		while (relocItemCount) {
			Word typeOffset = *pRelocItem;
			pRelocItem++;
			relocItemCount--;

			Word type = typeOffset >> 12;
			Word offset = typeOffset & 0xFFF;
			
			relBlock.items.push_back(std::make_pair(type, offset));
		}

		this->relChunk.push_back(std::move(relBlock));
		baseReloc = (IMAGE_BASE_RELOCATION*)((Byte*)baseReloc + blockSize);
	}

	printf("[Oblivion] Reloc proc finished.\n");
}

void Protector::removeReloc(PEFile& pe) {

	IMAGE_DATA_DIRECTORY& relocIDD = pe.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!relocIDD.Size)
		return;		// 没有重定位数据则不处理

	IMAGE_BASE_RELOCATION* baseReloc = pe.rva<IMAGE_BASE_RELOCATION>(relocIDD.VirtualAddress);
	while (baseReloc->VirtualAddress) {
		Dword blockSize = baseReloc->SizeOfBlock;
		memset(baseReloc, 0, blockSize);
		baseReloc = (IMAGE_BASE_RELOCATION*)((Byte*)baseReloc + blockSize);
	}

	printf("[Oblivion] Reloc removed.\n");
}

bool Protector::loadShellStub(Byte** allocatedStub, Size* stubSize) {
	
	// 加载到内存中
#ifdef UNICODE
	wchar_t lpszStubFileName[] = { 'S', 't', 'u', 'b', '.', 'd', 'l', 'l', '\0' };
#else
	char lpszStubFileName[] = { 'S', 't', 'u', 'b', '.', 'd', 'l', 'l', '\0' };
#endif
	this->pShellStub = (Byte*)LoadLibraryEx(lpszStubFileName, nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (!(this->pShellStub)) {
		printf_s("[Oblivion] Can not load shell stub in memory!\n");
		return false;
	}

	IMAGE_DOS_HEADER* pStubDosHeader = (IMAGE_DOS_HEADER*)this->pShellStub;
	IMAGE_NT_HEADERS* pStubNtHeaders = (IMAGE_NT_HEADERS*)(this->pShellStub + pStubDosHeader->e_lfanew);

	*allocatedStub = this->pShellStub;
	*stubSize = pStubNtHeaders->OptionalHeader.SizeOfImage;

	return true;
}

bool Protector::fixShellStubReloc(PEFile& pe) {
	
	if (!(this->pShellStub)) {
		printf_s("[Oblivion] Shell stub is not loaded.\n");
		return false;
	}

	IMAGE_DOS_HEADER* pStubDosHeader = (IMAGE_DOS_HEADER*)this->pShellStub;
	IMAGE_NT_HEADERS* pStubNtHeaders = (IMAGE_NT_HEADERS*)(this->pShellStub + pStubDosHeader->e_lfanew);

	// 修复重定位
	IMAGE_DATA_DIRECTORY& peRelocIDD = pe.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	IMAGE_DATA_DIRECTORY& stubRelocIDD = pStubNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	typedef struct _RelocItem {
		WORD offset : 12;
		WORD type : 4;
	} RelocItem, *PRelocItem;

	// ShellStub基址 = 原PE文件基址 + ShellStub区段.VirtualAddress
	std::pair<IMAGE_SECTION_HEADER*, Byte*>& stubSection = pe.additionSections[SHELLSTUB_SEGMENT_NAME_ANSI];
	UInt64 stubImageBase = pe.pNtHeaders->OptionalHeader.ImageBase + stubSection.first->VirtualAddress;
	UInt64 baseDelta = stubImageBase - pStubNtHeaders->OptionalHeader.ImageBase;

	IMAGE_BASE_RELOCATION* relocBlock = (IMAGE_BASE_RELOCATION*)(this->pShellStub + stubRelocIDD.VirtualAddress);

	while (relocBlock->VirtualAddress) {

		Dword originProt = 0;
		VirtualProtect(this->pShellStub + relocBlock->VirtualAddress, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &originProt);
		
		Dword numOfItems = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		RelocItem* relocItem = (RelocItem*)(relocBlock + 1);
		for (Dword i = 0; i < numOfItems; i++, relocItem++) {
			if (RELOC_FLAG(relocItem->type)) {
				UInt64* pFixPoint = (UInt64*)(this->pShellStub + relocBlock->VirtualAddress + relocItem->offset);
				*pFixPoint += baseDelta;
			}
		}
		
		Dword originProt1 = 0;
		VirtualProtect(&(relocBlock->VirtualAddress), sizeof(Dword), PAGE_EXECUTE_READWRITE, &originProt1);
		relocBlock->VirtualAddress += stubSection.first->VirtualAddress;
		VirtualProtect(&(relocBlock->VirtualAddress), sizeof(Dword), originProt1, &originProt1);

		VirtualProtect(this->pShellStub + relocBlock->VirtualAddress, PAGE_SIZE, originProt, &originProt);

		relocBlock = (IMAGE_BASE_RELOCATION*)(((Byte*)relocBlock) + relocBlock->SizeOfBlock);
	}

	peRelocIDD.VirtualAddress = stubSection.first->VirtualAddress + stubRelocIDD.VirtualAddress;
	peRelocIDD.Size = stubRelocIDD.Size;

	Dword originProt = 0;
	VirtualProtect(&(pStubNtHeaders->OptionalHeader.ImageBase), sizeof(UInt64), PAGE_EXECUTE_READWRITE, &originProt);
	pStubNtHeaders->OptionalHeader.ImageBase = stubImageBase;
	VirtualProtect(&(pStubNtHeaders->OptionalHeader.ImageBase), sizeof(UInt64), originProt, &originProt);

	return true;
}

bool Protector::setupStubBootContext(PEFile& pe) {

	if (!(this->pShellStub)) {
		printf_s("[Oblivion] Shell stub is not loaded.\n");
		return false;
	}

	UInt64& peImageBase = pe.pNtHeaders->OptionalHeader.ImageBase;
	Dword& peEP = pe.pNtHeaders->OptionalHeader.AddressOfEntryPoint;

	BootContext* loaderContext = (BootContext*)GetProcAddress((HMODULE)this->pShellStub, "_loader_context");
	
	// 设置原PE的默认镜像基址
	loaderContext->originalImageBase = peImageBase;

	// 设置原PE的入口点
	loaderContext->originalEP = peEP;

	// 设置已加密的重定位数据RVA
	if (this->relChunk.empty())
		loaderContext->originalReloc = 0;
	else
		loaderContext->originalReloc = pe.additionSections[SHELLDATA_SEGMENT_NAME_ANSI].first->VirtualAddress;

	// TLS
	if (this->tlsChunk.hasTLS) {
		// 设置Stub是否手动调用宿主TLS回调
		loaderContext->executeTLSCallback = true;

		// 设置原PE TLS Index
		loaderContext->originalTLSIndex = this->tlsChunk.tlsIndex;

		// 设置原PE TLS数据
		loaderContext->originalTLSCallbacks = this->tlsChunk.tlsCallbacks;
	}
	else {
		loaderContext->executeTLSCallback = false;
		loaderContext->originalTLSIndex = 0;
		loaderContext->originalTLSCallbacks = 0;
	}

	// 设置宿主EP到壳引导函数
	peEP = (Dword)(loaderContext->loaderFunc - peImageBase);

	return true;
}

bool Protector::writeShellStub(Byte* stubSectionData) {
	
	if (!(this->pShellStub)) {
		printf_s("[Oblivion] Shell stub is not loaded.\n");
		return false;
	}

	IMAGE_DOS_HEADER* pStubDosHeader = (IMAGE_DOS_HEADER*)this->pShellStub;
	IMAGE_NT_HEADERS* pStubNtHeaders = (IMAGE_NT_HEADERS*)(this->pShellStub + pStubDosHeader->e_lfanew);

	// 写入PE头
	RtlCopyMemory(stubSectionData, this->pShellStub, pStubNtHeaders->OptionalHeader.SizeOfHeaders);

	// 写入各区段数据(直接按内存对齐写)
	IMAGE_SECTION_HEADER* pStubFirstSection = IMAGE_FIRST_SECTION(pStubNtHeaders);
	Word numOfSections = pStubNtHeaders->FileHeader.NumberOfSections;
	for (Word i = 0; i < numOfSections; i++, pStubFirstSection++) {
		RtlCopyMemory(stubSectionData + pStubFirstSection->VirtualAddress, this->pShellStub + pStubFirstSection->VirtualAddress, pStubFirstSection->SizeOfRawData);
	}

	return true;
}

Size Protector::getEncryptedDataSize() {
	Size size = 0;

	for (auto& chunk : this->relChunk) {
		size += sizeof(IMAGE_BASE_RELOCATION);
		size += chunk.items.size() * sizeof(Word) * 2;
	}

	return size;
}

bool Protector::writeShellEncryptedData(Byte* encryptedData) {
	
	Byte* data = encryptedData;

	// Relocations
	// [4 VirtualAddress] | [4 SizeOfBlock] | [2.. Type] | [2.. Offset]
	for (auto& chunk : this->relChunk) {
		
		// VirtualAddress
		*((Dword*)data) = chunk.va;
		data += sizeof(Dword);

		// SizeOfBlock
		*((Dword*)data) = UInt32x32To64(chunk.size, 2) - sizeof(IMAGE_BASE_RELOCATION);
		data += sizeof(Dword);

		// Types & Offsets
		for (auto& relocItem : chunk.items) {
			
			// Type
			*((Word*)data) = relocItem.first;
			data += sizeof(Word);

			// Offset
			*((Word*)data) = relocItem.second;
			data += sizeof(Word);

		}

	}

	// 以一个空的IMAGE_BASE_RELOCATION结束
	// 否则Stub shellcode在遍历的时候有可能会找不到结束点
	*(UInt64*)data = 0ui64;
	data += sizeof(UInt64);

	return true;
}

void Protector::procTLS(PEFile& pe) {

	IMAGE_DATA_DIRECTORY& tlsIDD = pe.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	this->tlsChunk.hasTLS = false;
	if (!tlsIDD.VirtualAddress) {
		printf_s("[Oblivion] No tls.\n");
		return;
	}

	IMAGE_TLS_DIRECTORY* tlsDir = pe.rva<IMAGE_TLS_DIRECTORY>(tlsIDD.VirtualAddress);

	this->tlsChunk.startAddr = tlsDir->StartAddressOfRawData;
	this->tlsChunk.endAddr = tlsDir->EndAddressOfRawData;
	this->tlsChunk.sizeOfZero = tlsDir->SizeOfZeroFill;
	this->tlsChunk.characteristics = tlsDir->Characteristics;

	// 保存TLS Index
	// 如果根据TLS目录表内的AddressOfIndex，没有对应的FOA，则index是初始化为0的
	if (pe.vaToOffset(tlsDir->AddressOfIndex) != -1)
		this->tlsChunk.tlsIndex = (UInt64)pe.va<Dword>(tlsDir->AddressOfIndex);
	else
		this->tlsChunk.tlsIndex = 0;

	// TLS Callback数组
	this->tlsChunk.tlsCallbacks = tlsDir->AddressOfCallBacks - pe.imageBase;

	this->tlsChunk.hasTLS = true;
	printf("[Oblivion] TLS proc finished.\n");
}

bool Protector::fixPETLS(PEFile& pe) {

	if (!(this->pShellStub)) {
		printf_s("[Oblivion] Shell stub is not loaded.\n");
		return false;
	}

	if (!(this->tlsChunk.hasTLS))
		return true;

	// 由Stub接管宿主TLS
	std::pair<IMAGE_SECTION_HEADER*, Byte*>& stubSection = pe.additionSections[SHELLSTUB_SEGMENT_NAME_ANSI];
	IMAGE_DOS_HEADER* pStubDosHeader = (IMAGE_DOS_HEADER*)this->pShellStub;
	IMAGE_NT_HEADERS* pStubNtHeaders = (IMAGE_NT_HEADERS*)(this->pShellStub + pStubDosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY& stubTlsIDD = pStubNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	IMAGE_TLS_DIRECTORY* stubTlsDir = (IMAGE_TLS_DIRECTORY*)(this->pShellStub + stubTlsIDD.VirtualAddress);
	BootContext* loaderContext = (BootContext*)GetProcAddress((HMODULE)this->pShellStub, "_loader_context");

	Dword originProt = 0;
	VirtualProtect(stubTlsDir, sizeof(IMAGE_TLS_DIRECTORY), PAGE_EXECUTE_READWRITE, &originProt);

	// TLS区段其实结束地址，必须原封不动与宿主的保持一致
	stubTlsDir->StartAddressOfRawData = this->tlsChunk.startAddr;
	stubTlsDir->EndAddressOfRawData = this->tlsChunk.endAddr;

	UIntPtr tlsIndexVa = (UIntPtr)&(loaderContext->originalTLSIndex);
	tlsIndexVa -= ((UIntPtr)this->pShellStub);

	// 宿主TLS Index，交由BootContext保存
	stubTlsDir->AddressOfIndex = pe.imageBase + stubSection.first->VirtualAddress + tlsIndexVa;

	// 由Stub修复，但是不能置0，否则启动会很慢，而且调试的时候会一直卡在ntdll里面
	stubTlsDir->AddressOfCallBacks = pe.imageBase + this->tlsChunk.tlsCallbacks;

	stubTlsDir->SizeOfZeroFill = this->tlsChunk.sizeOfZero;
	stubTlsDir->Characteristics = this->tlsChunk.characteristics;

	VirtualProtect(stubTlsDir, sizeof(IMAGE_TLS_DIRECTORY), originProt, &originProt);

	// 将宿主的TLS目录表VirtualAddress指向Stub的TLS Directory
	IMAGE_DATA_DIRECTORY& peTlsIDD = pe.pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	peTlsIDD.VirtualAddress = stubSection.first->VirtualAddress + stubTlsIDD.VirtualAddress;
	peTlsIDD.Size = stubTlsIDD.Size;

	return true;
}

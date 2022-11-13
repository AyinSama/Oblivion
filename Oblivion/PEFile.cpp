#include "Pch.h"
#include "PEFile.h"
#include "Util.h"

PEFile::PEFile(std::filesystem::path fileFullPath) : fileFullPath(fileFullPath) {
	resetData();
}

void PEFile::resetData() {
	this->pImage = nullptr;
	this->imageSize = 0;
	this->entryPointRVA = 0;
	this->imageBase = 0;
	this->sizeOfFile = 0;
	this->sizeOfImage = 0;
	this->sizeOfPEHeaders = 0;
	this->pDosHeader = nullptr;
	this->pNtHeaders = nullptr;
	this->pFirstSec = nullptr;
	this->fileAlignment = 0;
	this->sectionAlignment = 0;
	this->numOfSections = 0;

	this->pExtraData = nullptr;
	this->sizeOfExtraData = 0;
}

bool PEFile::isValidPEFile() const {
	return isValidPEFile(this->pDosHeader->e_magic, this->pNtHeaders->Signature);
}

bool PEFile::isValidPEFile(Word dosSig, Dword ntSig) const {
	return dosSig == IMAGE_DOS_SIGNATURE
		&& ntSig == IMAGE_NT_SIGNATURE;
}

bool PEFile::resolve() {
	std::ifstream ifs(fileFullPath, std::ios::in | std::ios::binary);
	if (!ifs.is_open()) {
		printf("[Oblivion] Invalid path or file!\n");
		return false;
	}

	// 文件大小
	ifs.seekg(0, std::ios::end);
	this->sizeOfFile = (Size)ifs.tellg();

	// DOS头
	ifs.seekg(0, std::ios::beg);
	IMAGE_DOS_HEADER tmpDosHeader{ 0 };
	ifs.read((char*)&tmpDosHeader, sizeof(IMAGE_DOS_HEADER));
	
	ifs.seekg(tmpDosHeader.e_lfanew, std::ios::beg);
	IMAGE_NT_HEADERS tmpNtHeader{ 0 };
	ifs.read((char*)&tmpNtHeader, sizeof(IMAGE_NT_HEADERS));

	// 判断是否是标准PE文件
	if (!isValidPEFile(tmpDosHeader.e_magic, tmpNtHeader.Signature)) {
		printf("[Oblivion] Invalid PE format file!\n");
		return false;
	}

	this->sizeOfImage = tmpNtHeader.OptionalHeader.SizeOfImage;
	this->fileAlignment = tmpNtHeader.OptionalHeader.FileAlignment;
	this->sectionAlignment = tmpNtHeader.OptionalHeader.SectionAlignment;
	this->numOfSections = tmpNtHeader.FileHeader.NumberOfSections;
	this->sizeOfPEHeaders = tmpNtHeader.OptionalHeader.SizeOfHeaders;
	this->entryPointRVA = tmpNtHeader.OptionalHeader.AddressOfEntryPoint;
	this->imageBase = tmpNtHeader.OptionalHeader.ImageBase;

	this->imageSize = Util::alignTo(this->sizeOfImage, this->sectionAlignment);
	this->pImage = new Byte[this->imageSize];
	memset(this->pImage, 0, this->imageSize);

	// 读取整个PE头到pImage
	ifs.seekg(0, std::ios::beg);
	ifs.read((char*)this->pImage, this->sizeOfPEHeaders);

	// 初始化PE头各指针
	this->pDosHeader = (IMAGE_DOS_HEADER*)this->pImage;
	this->pNtHeaders = (IMAGE_NT_HEADERS*)(this->pImage + this->pDosHeader->e_lfanew);
	this->pFirstSec = IMAGE_FIRST_SECTION(this->pNtHeaders);

	// 映射各区块数据到pImage中
	queryAllSections([&](Byte* base, IMAGE_SECTION_HEADER* curSec) -> bool {
		ifs.seekg(curSec->PointerToRawData, std::ios::beg);
		ifs.read((char*)(this->pImage + curSec->VirtualAddress), curSec->SizeOfRawData);
		return false;
	});

	// 存储附加数据(如果有)
	IMAGE_SECTION_HEADER* lastSectionHeader = this->pFirstSec + (this->numOfSections - 1);
	UInt64 lastSectionEndAddr = (UInt64)lastSectionHeader->PointerToRawData + (UInt64)lastSectionHeader->SizeOfRawData;
	this->sizeOfExtraData = this->sizeOfFile - lastSectionEndAddr;
	if (this->sizeOfExtraData) {
		this->pExtraData = new Byte[this->sizeOfExtraData];
		memset(this->pExtraData, 0, this->sizeOfExtraData);
		ifs.seekg(lastSectionEndAddr, std::ios::beg);
		ifs.read((char*)this->pExtraData, this->sizeOfExtraData);
	}

	ifs.close();
	printf("[Oblivion] PE file resolve finished.\n");
	return true;
}

void PEFile::queryAllSections(QuerySectionCallback callback) {
	IMAGE_SECTION_HEADER* pSec = this->pFirstSec;
	Dword secCount = this->numOfSections;
	while (secCount--) {
		if (callback(this->pImage, pSec))
			return;
		pSec++;
	}
}

IMAGE_SECTION_HEADER* PEFile::getSectionByRva(Dword rva) {
	IMAGE_SECTION_HEADER* section = nullptr;
	queryAllSections([&](Byte* base, IMAGE_SECTION_HEADER* curSec) -> bool {
		Dword endAddr = curSec->VirtualAddress + curSec->Misc.VirtualSize;
		if (rva >= curSec->VirtualAddress && rva < endAddr) {
			section = curSec;
			return true;
		}
		return false;
	});
	return section;
}

bool PEFile::save() {

	std::filesystem::path outputFileFullPath = this->fileFullPath.parent_path()
		/ std::filesystem::path(this->fileFullPath.stem().wstring()
		+ OutputFileSuffix
		+ this->fileFullPath.extension().wstring());

	std::ofstream stream(outputFileFullPath, std::ios::binary);
	if (!stream.is_open()) {
		printf_s("[Oblivion] Fatal error when writing protected file!\n");
		return false;
	}

	// 写入PE头
	stream.seekp(0, std::ios::beg);
	stream.write((CString)this->pImage, this->sizeOfPEHeaders);
	stream.flush();

	// 按文件对齐写入各个区段的数据，新增的区段需单独处理
	queryAllSections([&](Byte* base, IMAGE_SECTION_HEADER* curSec) -> bool {

		std::string secName = std::string((char*)curSec->Name);
		if (this->additionSections.find(secName) != this->additionSections.end()) {

			bool newAllocate = false;
			Byte* allocatedData = this->additionSections[secName].second;

			if (!allocatedData) {
				allocatedData = new Byte[curSec->SizeOfRawData];
				newAllocate = true;
			}

			std::streamoff off = std::streamoff(curSec->PointerToRawData);
			stream.seekp(off, std::ios::beg);
			stream.write((CString)allocatedData, curSec->SizeOfRawData);
			stream.flush();

			if (newAllocate)
				delete[] allocatedData;

		}
		else {
			std::streamoff off = std::streamoff(curSec->PointerToRawData);
			stream.seekp(off, std::ios::beg);
			stream.write((CString)rva<String>(curSec->VirtualAddress), curSec->SizeOfRawData);
			stream.flush();
		}

		return false;
	});

	// 写入附加数据
	stream.write((CString)this->pExtraData, this->sizeOfExtraData);
	stream.flush();

	stream.close();
	printf_s("[Oblivion] Protected file saved.\n");
	return true;
}

void PEFile::release() {
	if (this->pImage)
		delete[] this->pImage;
	if (this->pExtraData)
		delete[] this->pExtraData;
	for (auto& additionSec : this->additionSections) {
		if (additionSec.second.second)
			delete[] additionSec.second.second;
	}
	resetData();
}

bool PEFile::addSectionHeader(const std::string& name, Size rawSize, IMAGE_SECTION_HEADER** outSectionHeader, Byte** allocate) {

	if (name.length() > IMAGE_SIZEOF_SHORT_NAME) {
		printf_s("[Oblivion] Section name is too long. (Name <= 8)\n");
		return false;
	}

	// 计算最后一个区段后面的00空间是否足够
	IMAGE_SECTION_HEADER* lastSec = this->pFirstSec + this->numOfSections - 1;
	Byte* emptyMemStartAddr = ((Byte*)lastSec) + sizeof(IMAGE_SECTION_HEADER);
	Dword emptyMemSize = 0;
	if (*emptyMemStartAddr) {
		printf_s("[Oblivion] No enough memory to add a new section header.\n");
		return false;
	}

	// 由于加载到内存的镜像是拉伸后的，所以文件中的00内存大小和内存中的00内存大小是不一致的
	// 但是最后一个区段头后99%的情况都是接着第一个区段的数据，防止有些exe的区段数据的存放顺序和他区段头的存放顺序不一致
	// 所以这里要求出来一个最小的PointerToRawData，也就是离最后一个区段头最近的一块数据，他们中间的00内存的大小就是文件中实际的00内存的大小了
	Dword firstSectionDataRva = MAXDWORD;
	queryAllSections([&](Byte* base, IMAGE_SECTION_HEADER* curSec) -> bool {
		if (curSec->PointerToRawData < firstSectionDataRva)
			firstSectionDataRva = curSec->PointerToRawData;
		return false;
	});

	Byte* endAddr = this->pImage + firstSectionDataRva;
	while ((*emptyMemStartAddr) == 0x00 && emptyMemStartAddr < endAddr) {
		emptyMemStartAddr++;
		emptyMemSize++;
	}

	if (emptyMemSize < sizeof(IMAGE_SECTION_HEADER)) {
		printf_s("[Oblivion] No enough memory to add a new section header. Empty memory Size: 0x%X\n", emptyMemSize);
		return false;
	}

	// 新区段开始地址
	IMAGE_SECTION_HEADER* pNewSec = (IMAGE_SECTION_HEADER*)(((Byte*)lastSec) + sizeof(IMAGE_SECTION_HEADER));
	RtlCopyMemory(pNewSec, name.data(), name.length());
	pNewSec->Characteristics |= IMAGE_SCN_MEM_READ;
	pNewSec->Characteristics |= IMAGE_SCN_MEM_WRITE;
	pNewSec->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	pNewSec->Characteristics |= IMAGE_SCN_CNT_CODE;
	pNewSec->Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
	pNewSec->Characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
	if (rawSize) {
		pNewSec->SizeOfRawData = (Dword)Util::alignTo(rawSize, this->fileAlignment);
		pNewSec->Misc.VirtualSize = pNewSec->SizeOfRawData;
	}
	pNewSec->VirtualAddress = lastSec->VirtualAddress + Util::alignTo(lastSec->SizeOfRawData, this->sectionAlignment);
	pNewSec->PointerToRawData = lastSec->PointerToRawData + lastSec->SizeOfRawData;

	this->sizeOfImage += pNewSec->Misc.VirtualSize;
	this->pNtHeaders->OptionalHeader.SizeOfImage += pNewSec->Misc.VirtualSize;
	this->numOfSections++;
	this->pNtHeaders->FileHeader.NumberOfSections++;

	if (allocate) {
		*allocate = new Byte[pNewSec->SizeOfRawData];
		RtlZeroMemory(*allocate, pNewSec->SizeOfRawData);
		this->additionSections.insert(std::make_pair(name, std::make_pair(pNewSec, *allocate)));
	}
	else {
		this->additionSections.insert(std::make_pair(name, std::make_pair(pNewSec, nullptr)));
	}

	if (outSectionHeader)
		*outSectionHeader = pNewSec;
	return true;
}

Size PEFile::rvaToOffset(Size rva) {
	Size offset = -1;
	queryAllSections([&](Byte* base, IMAGE_SECTION_HEADER* curSec) -> bool {
		Size endRva = ((Size)curSec->VirtualAddress) + ((Size)curSec->SizeOfRawData);
		if (rva >= curSec->VirtualAddress && rva < endRva)
			offset = curSec->PointerToRawData + (rva - curSec->VirtualAddress);
		return false;
	});
	return offset;
}

Size PEFile::vaToOffset(Size va) {
	Size rva = va - this->imageBase;
	return rvaToOffset(rva);
}

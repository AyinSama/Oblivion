#pragma once
#include "Pch.h"

constexpr wchar_t OutputFileSuffix[] = TEXT("_lalala");

// 返回true则不在遍历剩下的区块
using QuerySectionCallback = std::function<bool(Byte*, IMAGE_SECTION_HEADER*)>;

enum class PEInformation : UInt {
	AddressOfEntryPoint = 0,
	ImageBase,
};

class PEFile {
public:
	friend class Protector;

	PEFile(std::filesystem::path fileFullPath);

	bool resolve();
	bool save();
	void release();

	void queryAllSections(QuerySectionCallback callback);
	IMAGE_SECTION_HEADER* getSectionByRva(Dword rva);
	bool addSectionHeader(const std::string& name, Size rawSize, 
		IMAGE_SECTION_HEADER** outSectionHeader = nullptr, Byte** allocate = nullptr);
	Size rvaToOffset(Size rva);
	Size vaToOffset(Size va);

	template <class _Ptr, class _TyRva>
	_Ptr* rva(_TyRva rva) const;

	template <class _Ptr, class _TyVa>
	_Ptr* va(_TyVa va);

	template <class _Retn>
	_Retn get(PEInformation infoClass);

	template <class _TyData>
	void set(PEInformation infoClass, _TyData data);

private:
	void resetData();
	bool isValidPEFile() const;
	bool isValidPEFile(Word dosSig, Dword ntSig) const;

	Byte* pImage;							// 映射到内存中的镜像
	Size imageSize;							// pImage的大小(对齐后)
	Dword entryPointRVA;					// AddressOfEntryPoint
	UInt64 imageBase;						// ImageBase
	Size sizeOfFile;						// 原文件大小
	Size sizeOfImage;						// 原文件镜像大小(SizeOfImage)
	Size sizeOfPEHeaders;					// 整个PE头大小(Dos头开始到区块头结尾)
	Dword fileAlignment;					// 文件对齐
	Dword sectionAlignment;					// 区块对齐
	Dword numOfSections;					// 区块数
	Byte* pExtraData;						// 附加数据
	Size sizeOfExtraData;					// 附加数据大小

public:
	std::filesystem::path fileFullPath;		// 文件全路径

	std::unordered_map<std::string,			// 新增加的区段
		std::pair<IMAGE_SECTION_HEADER*, Byte*>> additionSections;

	IMAGE_DOS_HEADER* pDosHeader;			// DOS头指针
	IMAGE_NT_HEADERS* pNtHeaders;			// Nt头指针
	IMAGE_SECTION_HEADER* pFirstSec;		// 第一个区块头指针

};

template <class _Ptr, class _TyRva>
_Ptr* PEFile::rva(_TyRva rva) const {
	return reinterpret_cast<_Ptr*>(this->pImage + rva);
}

template <class _Ptr, class _TyVa>
_Ptr* PEFile::va(_TyVa va) {
	_TyVa rva = va - this->imageBase;
	return this->rva<_Ptr>(rva);
}

template <class _Retn>
_Retn PEFile::get(PEInformation infoClass) {
	if (infoClass == PEInformation::AddressOfEntryPoint)
		return (_Retn)this->entryPointRVA;
	else if (infoClass == PEInformation::ImageBase)
		return (_Retn)this->imageBase;
	return (_Retn)0;
}

template <class _TyData>
void PEFile::set(PEInformation infoClass, _TyData data) {
	if (infoClass == PEInformation::AddressOfEntryPoint) {
		this->entryPointRVA = (decltype(this->entryPointRVA))data;
		this->pNtHeaders->OptionalHeader.AddressOfEntryPoint = (decltype(this->entryPointRVA))data;
	}
	else if (infoClass == PEInformation::ImageBase) {
		this->imageBase = (decltype(this->imageBase))data;
		this->pNtHeaders->OptionalHeader.ImageBase = (decltype(this->imageBase))data;
	}
}

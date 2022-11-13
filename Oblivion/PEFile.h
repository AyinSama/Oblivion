#pragma once
#include "Pch.h"

constexpr wchar_t OutputFileSuffix[] = TEXT("_lalala");

// ����true���ڱ���ʣ�µ�����
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

	Byte* pImage;							// ӳ�䵽�ڴ��еľ���
	Size imageSize;							// pImage�Ĵ�С(�����)
	Dword entryPointRVA;					// AddressOfEntryPoint
	UInt64 imageBase;						// ImageBase
	Size sizeOfFile;						// ԭ�ļ���С
	Size sizeOfImage;						// ԭ�ļ������С(SizeOfImage)
	Size sizeOfPEHeaders;					// ����PEͷ��С(Dosͷ��ʼ������ͷ��β)
	Dword fileAlignment;					// �ļ�����
	Dword sectionAlignment;					// �������
	Dword numOfSections;					// ������
	Byte* pExtraData;						// ��������
	Size sizeOfExtraData;					// �������ݴ�С

public:
	std::filesystem::path fileFullPath;		// �ļ�ȫ·��

	std::unordered_map<std::string,			// �����ӵ�����
		std::pair<IMAGE_SECTION_HEADER*, Byte*>> additionSections;

	IMAGE_DOS_HEADER* pDosHeader;			// DOSͷָ��
	IMAGE_NT_HEADERS* pNtHeaders;			// Ntͷָ��
	IMAGE_SECTION_HEADER* pFirstSec;		// ��һ������ͷָ��

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

#include "Pch.h"
#include "Protector.h"

int wmain(int argc, wchar_t** argv) {

	bool status = false;

#ifdef _DEBUG
	// PEFile pe(TEXT("G:\\CppProjs\\Tests\\Tests\\x64\\Release\\target.exe"));
	PEFile pe(TEXT("F:\\010 Editor\\010Editor.exe"));
#else
	if (argv[1] == nullptr) {
		printf_s("[Oblivion] Please enter the path of the file to be protected.\n");
		return 0;
	}

	PEFile pe(argv[1]);
#endif
	
	status = pe.resolve();
	if (!status)
		return 0;

	printf_s("[Oblivion] Protecting file: %s\n", pe.fileFullPath.generic_string().c_str());

	// 去ASLR
	// pe.pNtHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	Protector protector = Protector::getInstance();

	protector.procIAT(pe);
	// protector.removeIAT(pe);

	protector.procReloc(pe);
	// protector.removeReloc(pe);

	protector.procTLS(pe);

	Byte* pShellStub = nullptr;
	Size shellStubSize = 0;
	status = protector.loadShellStub(&pShellStub, &shellStubSize);
	if (!status)
		return 0;

	Byte* pShellData = nullptr;
	IMAGE_SECTION_HEADER* pShellSection;
	status = pe.addSectionHeader(SHELLSTUB_SEGMENT_NAME_ANSI, shellStubSize , &pShellSection, &pShellData);
	if (!status)
		return 0;

	Size encryptedDataSize = protector.getEncryptedDataSize();
	Byte* pEncryptedData = nullptr;
	IMAGE_SECTION_HEADER* pEncryptedDataSection;
	status = pe.addSectionHeader(SHELLDATA_SEGMENT_NAME_ANSI, encryptedDataSize, &pEncryptedDataSection, &pEncryptedData);
	if (!status)
		return 0;

	protector.writeShellEncryptedData(pEncryptedData);

	// 一定要先修复重定位再接管TLS
	// 否则StartAddressOfRawData和EndAddressOfRawData会被改掉
	protector.fixShellStubReloc(pe);
	protector.fixPETLS(pe);

	protector.setupStubBootContext(pe);
	protector.writeShellStub(pShellData);

	pe.save();

	pe.release();
	protector.release();
	return 0;
}


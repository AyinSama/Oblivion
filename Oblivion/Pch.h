#pragma once

#include <iostream>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <unordered_map>

#define PAGE_SIZE 0x1000

#define RELOC_FLAG32(RelInfo) (RelInfo == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) (RelInfo == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#define COMPILE_ARCHITECTURE IMAGE_FILE_MACHINE_AMD64
#else
#define RELOC_FLAG RELOC_FLAG32
#define COMPILE_ARCHITECTURE IMAGE_FILE_MACHINE_I386
#endif

#include "BasicTypes.h"
#include "Singleton.hpp"



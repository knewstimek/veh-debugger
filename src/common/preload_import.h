#pragma once
#include <cstdint>

namespace veh {

// injectionMethod=importTable: the launcher points the suspended EXE's import
// directory at a new block outside the image. This header sits immediately
// before the block's descriptor array and keeps the original directory.
struct PreloadImportHeader {
	uint32_t magic;
	uint32_t flags;
	uint32_t importRva;
	uint32_t importSize;
};
static_assert(sizeof(PreloadImportHeader) == 16, "PreloadImportHeader layout");

constexpr uint32_t kPreloadImportMagic = 0x504C4856;    // "VHLP"
constexpr uint32_t kPreloadRestoreImports = 1u;         // DLL restores the directory in DllMain
constexpr uint16_t kPreloadExportOrdinal = 1;           // payload DLL export the descriptor imports

} // namespace veh

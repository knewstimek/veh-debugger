#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace veh {

struct DisasmInstruction {
	uint64_t    address;
	uint8_t     length;
	std::string bytes;      // hex string "CC 90 ..."
	std::string mnemonic;   // full: "mov rax, [rbp-0x10]" (Zydis) or short: "mov" (Simple)
};

// 디스어셈블러 인터페이스
class IDisassembler {
public:
	virtual ~IDisassembler() = default;

	virtual std::vector<DisasmInstruction> Disassemble(
		const uint8_t* data, uint32_t size,
		uint64_t baseAddress, uint32_t maxInstructions = 50) = 0;

	// 어떤 백엔드인지
	virtual const char* Name() const = 0;
};

// 간단한 x86/x64 길이 디코더 (외부 의존성 없음)
// 명령어 길이는 정확하지만 오퍼랜드 디테일 없음 (니모닉만: "mov", "call", ...)
class SimpleDisassembler : public IDisassembler {
public:
	std::vector<DisasmInstruction> Disassemble(
		const uint8_t* data, uint32_t size,
		uint64_t baseAddress, uint32_t maxInstructions = 50) override;

	const char* Name() const override { return "simple"; }
};

// Zydis 기반 완전한 디스어셈블러
// 오퍼랜드 포함한 전체 어셈블리 출력: "mov rax, qword ptr [rbp-0x10]"
class ZydisDisassembler : public IDisassembler {
public:
	explicit ZydisDisassembler(bool is64bit = true);

	std::vector<DisasmInstruction> Disassemble(
		const uint8_t* data, uint32_t size,
		uint64_t baseAddress, uint32_t maxInstructions = 50) override;

	const char* Name() const override { return "zydis"; }

private:
	bool is64bit_;
};

// 팩토리 — 기본값 Zydis
std::unique_ptr<IDisassembler> CreateDisassembler(bool is64bit = true);

} // namespace veh

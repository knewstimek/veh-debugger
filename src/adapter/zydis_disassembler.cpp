#include "disassembler.h"
#include <Zydis/Zydis.h>
#include <cstdio>

namespace veh {

ZydisDisassembler::ZydisDisassembler(bool is64bit)
	: is64bit_(is64bit) {}

std::vector<DisasmInstruction> ZydisDisassembler::Disassemble(
	const uint8_t* data, uint32_t size,
	uint64_t baseAddress, uint32_t maxInstructions)
{
	std::vector<DisasmInstruction> result;
	result.reserve(maxInstructions);

	ZydisDecoder decoder;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
			is64bit_ ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
			is64bit_ ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32))) {
		return result;
	}

	ZydisFormatter formatter;
	if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
		return result;
	}

	uint32_t offset = 0;
	uint32_t count = 0;

	while (offset < size && count < maxInstructions) {
		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		ZyanStatus status = ZydisDecoderDecodeFull(
			&decoder, data + offset, size - offset,
			&instruction, operands);

		DisasmInstruction insn;
		insn.address = baseAddress + offset;

		if (ZYAN_SUCCESS(status)) {
			insn.length = instruction.length;

			// hex bytes
			std::string bytes;
			bytes.reserve(instruction.length * 3);
			for (uint8_t i = 0; i < instruction.length; i++) {
				char buf[4];
				snprintf(buf, sizeof(buf), "%02X ", data[offset + i]);
				bytes += buf;
			}
			if (!bytes.empty()) bytes.pop_back();
			insn.bytes = std::move(bytes);

			// 완전한 니모닉 + 오퍼랜드
			char formatted[256];
			if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
				&formatter, &instruction, operands,
				instruction.operand_count_visible,
				formatted, sizeof(formatted),
				baseAddress + offset, ZYAN_NULL))) {
				insn.mnemonic = formatted;
			} else {
				insn.mnemonic = "???";
			}

			offset += instruction.length;
		} else {
			// 디코딩 실패 — 1바이트 스킵
			insn.length = 1;
			char buf[4];
			snprintf(buf, sizeof(buf), "%02X", data[offset]);
			insn.bytes = buf;
			insn.mnemonic = "db " + insn.bytes;
			offset += 1;
		}

		result.push_back(std::move(insn));
		count++;
	}

	return result;
}

// 팩토리 — 기본값 Zydis
std::unique_ptr<IDisassembler> CreateDisassembler(bool is64bit) {
	return std::make_unique<ZydisDisassembler>(is64bit);
}

} // namespace veh

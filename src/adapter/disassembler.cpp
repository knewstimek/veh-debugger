#include "disassembler.h"
#include <cstdio>
#include <cstring>

namespace veh {

// SimpleDisassembler: 간단한 x86/x64 길이 디코더 + 주요 명령어 인식
// 외부 의존성 없음. 명령어 길이는 정확하나 오퍼랜드 디테일 없음.
// 완전한 디스어셈블리가 필요하면 ZydisDisassembler 사용 (기본값)

namespace {

// x86-64 명령어 길이 디코딩 (단순화된 버전)
struct InsnInfo {
	uint8_t length;
	const char* mnemonic;
};

// 단순 옵코드 테이블 (가장 흔한 명령어만)
InsnInfo DecodeInstruction(const uint8_t* code, uint32_t maxLen) {
	if (maxLen == 0) return {0, "???"};

	uint8_t b = code[0];
	const uint8_t* p = code;
	int prefixLen = 0;

	// REX prefix
	bool hasRex = false;
	uint8_t rex = 0;

	// 레거시 프리픽스 스킵
	while (prefixLen < 4 && maxLen > (uint32_t)prefixLen) {
		uint8_t c = p[prefixLen];
		if (c == 0x66 || c == 0x67 || c == 0xF0 || c == 0xF2 || c == 0xF3 ||
			c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 || c == 0x64 || c == 0x65) {
			prefixLen++;
		} else {
			break;
		}
	}

	if (prefixLen >= (int)maxLen) return {1, "???"};

	b = p[prefixLen];

	// REX prefix (0x40~0x4F)
	if (b >= 0x40 && b <= 0x4F) {
		hasRex = true;
		rex = b;
		prefixLen++;
		if (prefixLen >= (int)maxLen) return {1, "???"};
		b = p[prefixLen];
	}

	int opOff = prefixLen;

	// 공통 명령어
	switch (b) {
	case 0xCC: return {(uint8_t)(opOff + 1), "int3"};
	case 0x90: return {(uint8_t)(opOff + 1), "nop"};
	case 0xC3: return {(uint8_t)(opOff + 1), "ret"};
	case 0xCB: return {(uint8_t)(opOff + 1), "retf"};
	case 0xC2: return {(uint8_t)(opOff + 3), "ret"};  // ret imm16
	case 0xCD: return {(uint8_t)(opOff + 2), "int"};   // int imm8
	case 0xEB: return {(uint8_t)(opOff + 2), "jmp"};   // jmp rel8
	case 0xE9: return {(uint8_t)(opOff + 5), "jmp"};   // jmp rel32
	case 0xE8: return {(uint8_t)(opOff + 5), "call"};  // call rel32
	case 0xFF: {
		// FF /2 = call, /4 = jmp, /6 = push
		if (opOff + 1 < (int)maxLen) {
			uint8_t modrm = p[opOff + 1];
			uint8_t reg = (modrm >> 3) & 7;
			const char* mn = "???";
			if (reg == 2) mn = "call";
			else if (reg == 4) mn = "jmp";
			else if (reg == 6) mn = "push";
			// ModRM 길이 계산 간소화
			uint8_t mod = modrm >> 6;
			int extra = 2; // opcode + modrm
			if (mod == 0 && (modrm & 7) == 5) extra += 4; // [rip+disp32]
			else if (mod == 1) extra += 1;
			else if (mod == 2) extra += 4;
			if ((modrm & 7) == 4 && mod != 3) extra += 1; // SIB (한 번만)
			return {(uint8_t)(opOff + extra), mn};
		}
		return {(uint8_t)(opOff + 2), "???"};
	}

	// push/pop reg
	case 0x50: case 0x51: case 0x52: case 0x53:
	case 0x54: case 0x55: case 0x56: case 0x57:
		return {(uint8_t)(opOff + 1), "push"};
	case 0x58: case 0x59: case 0x5A: case 0x5B:
	case 0x5C: case 0x5D: case 0x5E: case 0x5F:
		return {(uint8_t)(opOff + 1), "pop"};

	// mov imm to reg (B0~BF)
	case 0xB0: case 0xB1: case 0xB2: case 0xB3:
	case 0xB4: case 0xB5: case 0xB6: case 0xB7:
		return {(uint8_t)(opOff + 2), "mov"};
	case 0xB8: case 0xB9: case 0xBA: case 0xBB:
	case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		return {(uint8_t)(opOff + (hasRex && (rex & 0x08) ? 9 : 5)), "mov"};

	// conditional jumps (short)
	case 0x70: case 0x71: case 0x72: case 0x73:
	case 0x74: case 0x75: case 0x76: case 0x77:
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F:
		return {(uint8_t)(opOff + 2), "jcc"};

	// 2-byte opcodes
	case 0x0F: {
		if (opOff + 1 >= (int)maxLen) return {(uint8_t)(opOff + 1), "???"};
		uint8_t b2 = p[opOff + 1];
		// long conditional jumps
		if (b2 >= 0x80 && b2 <= 0x8F)
			return {(uint8_t)(opOff + 6), "jcc"};
		// setcc
		if (b2 >= 0x90 && b2 <= 0x9F)
			return {(uint8_t)(opOff + 3), "setcc"};
		// nop (0F 1F)
		if (b2 == 0x1F) {
			if (opOff + 2 < (int)maxLen) {
				uint8_t modrm = p[opOff + 2];
				uint8_t mod = modrm >> 6;
				int extra = 3;
				if ((modrm & 7) == 4) extra++;
				if (mod == 1) extra += 1;
				else if (mod == 2) extra += 4;
				return {(uint8_t)(opOff + extra), "nop"};
			}
		}
		// syscall
		if (b2 == 0x05) return {(uint8_t)(opOff + 2), "syscall"};
		// movzx, movsx etc - 대략적 길이
		return {(uint8_t)(opOff + 3), "???"};
	}

	default:
		break;
	}

	// 범용 ModRM 기반 명령어 (대략적 길이)
	// ADD/OR/ADC/SBB/AND/SUB/XOR/CMP rm, r  또는  r, rm
	if ((b >= 0x00 && b <= 0x03) || (b >= 0x08 && b <= 0x0B) ||
		(b >= 0x10 && b <= 0x13) || (b >= 0x18 && b <= 0x1B) ||
		(b >= 0x20 && b <= 0x23) || (b >= 0x28 && b <= 0x2B) ||
		(b >= 0x30 && b <= 0x33) || (b >= 0x38 && b <= 0x3B) ||
		(b >= 0x88 && b <= 0x8B) || b == 0x84 || b == 0x85 || b == 0x86 || b == 0x87) {
		const char* names[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
		const char* mn = "???";
		if (b >= 0x88 && b <= 0x8B) mn = "mov";
		else if (b == 0x84 || b == 0x85) mn = "test";
		else if (b == 0x86 || b == 0x87) mn = "xchg";
		else mn = names[(b >> 3) & 7];

		if (opOff + 1 < (int)maxLen) {
			uint8_t modrm = p[opOff + 1];
			uint8_t mod = modrm >> 6;
			int extra = 2;
			if (mod == 0 && (modrm & 7) == 5) extra += 4;
			else if (mod == 1) extra += 1;
			else if (mod == 2) extra += 4;
			if ((modrm & 7) == 4 && mod != 3) extra += 1;
			return {(uint8_t)(opOff + extra), mn};
		}
	}

	// 즉시값 연산 (80~83)
	if (b >= 0x80 && b <= 0x83) {
		if (opOff + 1 < (int)maxLen) {
			uint8_t modrm = p[opOff + 1];
			uint8_t mod = modrm >> 6;
			uint8_t reg = (modrm >> 3) & 7;
			const char* names[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
			int extra = 2;
			if (mod == 0 && (modrm & 7) == 5) extra += 4;
			else if (mod == 1) extra += 1;
			else if (mod == 2) extra += 4;
			if ((modrm & 7) == 4 && mod != 3) extra += 1;
			// 즉시값 크기
			if (b == 0x80 || b == 0x82 || b == 0x83) extra += 1;
			else extra += 4;
			return {(uint8_t)(opOff + extra), names[reg]};
		}
	}

	// 기본 폴백: 최소 1바이트
	return {(uint8_t)(opOff + 1), "???"};
}

std::string BytesToHex(const uint8_t* data, uint8_t len) {
	std::string result;
	result.reserve(len * 3);
	for (uint8_t i = 0; i < len; i++) {
		char buf[4];
		snprintf(buf, sizeof(buf), "%02X ", data[i]);
		result += buf;
	}
	if (!result.empty()) result.pop_back(); // 마지막 공백 제거
	return result;
}

} // anonymous namespace

std::vector<DisasmInstruction> SimpleDisassembler::Disassemble(
	const uint8_t* data, uint32_t size,
	uint64_t baseAddress, uint32_t maxInstructions)
{
	std::vector<DisasmInstruction> result;
	result.reserve(maxInstructions);

	uint32_t offset = 0;
	uint32_t count = 0;

	while (offset < size && count < maxInstructions) {
		auto info = DecodeInstruction(data + offset, size - offset);
		if (info.length == 0 || offset + info.length > size) break;

		DisasmInstruction insn;
		insn.address = baseAddress + offset;
		insn.length = info.length;
		insn.bytes = BytesToHex(data + offset, info.length);
		insn.mnemonic = info.mnemonic;

		result.push_back(std::move(insn));
		offset += info.length;
		count++;
	}

	return result;
}

} // namespace veh

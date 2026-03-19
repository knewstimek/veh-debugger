# VEH Debugger for VSCode

**한국어** | [English](README.en.md)

Windows VEH(Vectored Exception Handler) 기반 디버거. DAP(Debug Adapter Protocol) 완전 지원.

## 왜 VEH Debugger인가?

### 안티디버그 우회에 유리
Windows Debug API(`NtSetInformationThread`, `IsDebuggerPresent` 등)를 사용하지 않으므로 `PEB.BeingDebugged = 0` 상태를 유지합니다. **Themida, VMProtect** 등 PEB/NtQuery 기반 안티디버그 체크를 자연스럽게 우회합니다. 단, VEH 자체를 검사하는 보호(EAC 등 커널 안티치트)는 감지될 수 있습니다.

### 🤝 기존 디버거와 동시 사용 가능
Windows Debug API 디버거(x64dbg, WinDbg, Visual Studio 등)는 프로세스당 하나만 붙을 수 있지만, VEH Debugger는 **Windows 디버거와 동시에 같은 프로세스에 붙을 수 있습니다.** 커널 디버거나 다른 유저모드 디버거로 분석하면서, VEH Debugger로 보조 브레이크포인트/메모리 감시를 병행할 수 있습니다.

### 🤖 AI 에이전트 네이티브 지원
MCP(Model Context Protocol) 도구 서버를 내장하여 **Claude, Cursor, Windsurf, Codex** 등 AI 에이전트가 디버거를 직접 제어합니다. "이 함수에 브레이크포인트 걸고 RAX 값 확인해줘"처럼 자연어로 디버깅을 지시할 수 있습니다.

### 🖥️ VSCode 환경 통합
별도 디버거 GUI 없이 **VSCode 디버그 패널에서 모든 것을 수행합니다.** 디스어셈블리 뷰, 레지스터 조회/수정, 메모리 읽기/쓰기, 하드웨어 브레이크포인트까지 VSCode 안에서 완결됩니다.

---

## 특징

- **VEH 기반**: Windows Debug API 대신 VEH를 사용하여 안티디버그 우회에 유리
- **DAP 전체 지원**: VSCode, MCP debug 도구 등 모든 DAP 호환 클라이언트에서 사용 가능
- **MCP 도구 서버**: AI 에이전트(Claude, Codex 등)가 직접 디버거를 제어하는 26개 도구 제공
- **TCP 모드**: `--tcp --port=PORT`로 원격 디버깅/MCP 연동 지원
- **원격 접속**: `--remote` / `--bind=0.0.0.0`으로 VM/네트워크 너머 디버깅
- **32/64비트 지원**: x86/x64 프로세스 모두 디버깅 가능 (별도 32비트 DLL 빌드)
- **소프트웨어 브레이크포인트**: INT3 (0xCC) 패치
- **하드웨어 브레이크포인트**: DR0~DR3 (메모리 읽기/쓰기 감시 = Find What Writes/Accesses)
- **PDB 심볼 지원**: 소스 파일/줄 번호 매핑, 함수 이름으로 브레이크포인트
- **디스어셈블리**: Zydis x86/x64 디스어셈블러 (기본) + 내장 경량 디코더 (폴백)
- **메모리 읽기/쓰기**: DAP readMemory/writeMemory 지원
- **MT(정적 CRT) 빌드**: DLL 인젝션 시 vcruntime 의존성 없음

## 아키텍처

```
VSCode / DAP Client                Claude / AI Agent
    ↕ DAP (stdin/stdout or TCP)        ↕ MCP (stdin/stdout, JSON-RPC 2.0)
veh-debug-adapter.exe              veh-mcp-server.exe
    ↕ Named Pipe IPC                   ↕ Named Pipe IPC
    └──────── veh-debugger.dll (타겟 프로세스 내부) ────────┘
```

### 컴포넌트 설명

| 컴포넌트 | 역할 |
|---------|------|
| `veh-debugger.dll` (`vcruntime_net.dll`) | 타겟 프로세스에 인젝션. VEH 핸들러 등록, 브레이크포인트 관리, 스레드/스택/메모리 조회 |
| `veh-debug-adapter.exe` | DAP 프로토콜 서버. DLL 인젝션, Named Pipe 통신, JSON-RPC 처리 |
| `veh-mcp-server.exe` | MCP 도구 서버. AI 에이전트가 26개 도구로 디버거 직접 제어 |
| VSCode Extension | launch.json 스키마 정의, 어댑터 경로 설정 (최소 래퍼) |

## 빌드

### 요구사항
- Windows 10+ x64
- CMake 3.20+
- Visual Studio 2022 (MSVC)
- Node.js 18+ (VSCode 익스텐션용, 선택)

### C++ 빌드 (64비트)

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

출력물:
- `build/bin/Release/veh-debug-adapter.exe` — DAP 어댑터
- `build/bin/Release/veh-mcp-server.exe` — MCP 도구 서버
- `build/bin/Release/vcruntime_net.dll` — VEH 디버거 DLL (위장 이름)

### C++ 빌드 (32비트 DLL)

32비트 프로세스 디버깅 시 필요:

```bash
cmake -B build32 -G "Visual Studio 17 2022" -A Win32
cmake --build build32 --config Release --target veh-debugger
# 출력: build32/bin/Release/vcruntime_net32.dll
# build/bin/Release/ 에 복사하여 사용
copy build32\bin\Release\vcruntime_net32.dll build\bin\Release\
```

### VSCode 익스텐션 빌드

```bash
cd extension
npm install
npm run compile
```

## 사용법

### 1. VSCode에서 사용 (stdio 모드)

`.vscode/launch.json`에 추가:

**프로세스 실행 (Launch)**
```json
{
    "type": "veh",
    "request": "launch",
    "name": "VEH Debug - Launch",
    "program": "C:/path/to/target.exe",
    "args": ["arg1", "arg2"],
    "stopOnEntry": true
}
```
- `program`: 디버깅할 실행 파일 경로
- `args`: 실행 인자 (선택)
- `stopOnEntry`: 진입점에서 정지 여부

**실행 중인 프로세스에 붙기 (Attach)**
```json
{
    "type": "veh",
    "request": "attach",
    "name": "VEH Debug - Attach",
    "processId": 1234
}
```
- `processId`: 대상 프로세스 PID (작업 관리자에서 확인)

### 2. TCP 모드 (로컬)

어댑터를 별도 프로세스로 실행한 뒤 DAP 클라이언트에서 TCP로 연결:

```bash
veh-debug-adapter.exe --tcp --port=4711
```

기본적으로 `127.0.0.1`에만 바인딩되어 로컬에서만 접속 가능.

### 3. TCP 원격 모드 (VM/네트워크)

VM 내부나 원격 머신에서 실행하고 호스트/외부에서 접속:

```bash
# 대상 머신에서 실행 (0.0.0.0 바인딩)
veh-debug-adapter.exe --tcp --port=4711 --remote
# 또는
veh-debug-adapter.exe --tcp --port=4711 --bind=0.0.0.0
```

외부에서 DAP 클라이언트로 `<대상머신IP>:4711`에 연결.

**보안 주의**: `--remote`는 모든 네트워크 인터페이스에 바인딩합니다. 신뢰할 수 있는 네트워크에서만 사용하거나 방화벽으로 접근을 제한하세요.

### 4. MCP debug 도구 연동 (DAP over TCP)

```
# TCP 모드로 어댑터 실행
veh-debug-adapter.exe --tcp --port=4711

# MCP debug 도구에서 TCP 연결
debug(operation: "launch", address: "localhost:4711", ...)
```

### 5. MCP 도구 서버 (AI 에이전트 직접 제어)

DAP 프로토콜을 모르는 AI 에이전트가 함수 호출처럼 디버거를 제어할 수 있는 별도 MCP 서버.

**자동 설치 (권장)**
```bash
# 모든 에이전트에 한 번에 설치
veh-mcp-server.exe --install

# 특정 에이전트만 설치
veh-mcp-server.exe --install claude-code
veh-mcp-server.exe --install cursor

# 제거
veh-mcp-server.exe --uninstall
```

지원 에이전트: `claude-code`, `claude-desktop`, `cursor`, `windsurf`, `codex`

자기 자신의 절대경로를 자동 감지하여 각 에이전트의 설정 파일에 등록합니다.

| 에이전트 | 설정 파일 | 형식 |
|---------|----------|------|
| Claude Code | `~/.claude/settings.json` | JSON (`mcpServers`) |
| Claude Desktop | `%APPDATA%/Claude/claude_desktop_config.json` | JSON (`mcpServers`) |
| Cursor | `~/.cursor/mcp.json` | JSON (`mcpServers`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON (`mcpServers`) |
| Codex CLI | `~/.codex/config.toml` | TOML (`mcp_servers`) |

**수동 설치** (설정 파일 직접 편집)

Claude Code / Claude Desktop / Cursor / Windsurf (JSON 형식):
```json
{
  "mcpServers": {
    "veh-debugger": {
      "command": "C:/path/to/veh-mcp-server.exe",
      "args": ["--log=veh-mcp.log"]
    }
  }
}
```

Codex CLI (TOML 형식):
```toml
[mcp_servers.veh-debugger]
command = "C:/path/to/veh-mcp-server.exe"
args = ["--log=veh-mcp.log"]
enabled = true
```

설정 후 에이전트/IDE를 재시작하면 활성화됩니다.

**MCP 도구 목록 (26개)**

| 도구 | 인자 | 설명 |
|------|------|------|
| `veh_attach` | `pid` | 프로세스에 DLL 인젝션 + 파이프 연결 |
| `veh_launch` | `program, args?, stopOnEntry?` | 프로세스 생성 + 인젝션 |
| `veh_detach` | - | 디버거 분리 |
| `veh_set_breakpoint` | `address, condition?, hitCondition?, logMessage?` | 소프트웨어 BP (조건부/로그포인트 지원) |
| `veh_remove_breakpoint` | `id` | 소프트웨어 BP 제거 |
| `veh_set_source_breakpoint` | `source, line, condition?, hitCondition?, logMessage?` | 소스 파일+줄번호 BP (PDB 필요) |
| `veh_set_function_breakpoint` | `name, condition?, hitCondition?, logMessage?` | 함수명 BP (PDB 필요) |
| `veh_list_breakpoints` | - | 활성 SW/HW BP 목록 조회 |
| `veh_set_data_breakpoint` | `address, type, size` | HW BP (write/readwrite/execute) |
| `veh_remove_data_breakpoint` | `id` | HW BP 제거 |
| `veh_continue` | `threadId?` | 실행 계속 |
| `veh_step_in` | `threadId` | Step Into |
| `veh_step_over` | `threadId` | Step Over |
| `veh_step_out` | `threadId` | Step Out |
| `veh_pause` | `threadId?` | 일시정지 |
| `veh_threads` | - | 스레드 목록 |
| `veh_stack_trace` | `threadId, maxFrames?` | 스택 트레이스 |
| `veh_registers` | `threadId` | 레지스터 조회 |
| `veh_set_register` | `threadId, name, value` | 레지스터 값 변경 |
| `veh_evaluate` | `expression, threadId` | 레지스터/메모리/포인터 평가 |
| `veh_read_memory` | `address, size` | 메모리 읽기 (hex) |
| `veh_write_memory` | `address, data` | 메모리 쓰기 (hex) |
| `veh_modules` | - | 모듈 목록 |
| `veh_disassemble` | `address, count?` | 디스어셈블리 (Zydis) |
| `veh_exception_info` | - | 마지막 예외 정보 조회 |
| `veh_trace_callers` | `address, duration_sec?` | 함수 호출자 추적 (N초간 모든 caller 수집) |

> **Tip**: 숫자 인자(`threadId`, `pid`, `address`, `size` 등)는 숫자와 문자열 모두 허용하며, hex 형식도 지원합니다 (예: `"0x401000"` 또는 `4198400`). 불리언 인자는 `true`/`false` 또는 `"true"`/`"false"` 모두 허용합니다.

### 커맨드라인 옵션

**veh-mcp-server.exe**

| 옵션 | 설명 |
|------|------|
| `--install [AGENT]` | AI 에이전트 설정에 MCP 서버 등록 (전체 또는 특정) |
| `--uninstall [AGENT]` | AI 에이전트 설정에서 MCP 서버 제거 |
| `--log=FILE` | 로그 파일 경로 |
| `--log-level=LEVEL` | 로그 레벨: debug, info, warn, error |
| `--help` | 도움말 출력 |

**veh-debug-adapter.exe**

| 옵션 | 설명 |
|------|------|
| `--tcp` | TCP 전송 모드 (기본: stdin/stdout) |
| `--port=PORT` | TCP 포트 번호 (기본: 4711) |
| `--remote` | 0.0.0.0에 바인딩 (원격 접속 허용) |
| `--bind=0.0.0.0` | `--remote`와 동일 |
| `--log=FILE` | 로그 파일 경로 |
| `--log-level=LEVEL` | 로그 레벨: debug, info, warn, error (기본: info) |
| `--help` | 도움말 출력 |

## 기능 상세

### 브레이크포인트

**소프트웨어 브레이크포인트 (INT3)**
- `setBreakpoints` — 소스 파일:줄 번호 기반 (PDB 필요)
- `setFunctionBreakpoints` — 함수 이름 기반 (PDB 필요)
- `setInstructionBreakpoints` — 주소 기반 (PDB 불필요)

**하드웨어 브레이크포인트 (DR0~DR3)**
- `setDataBreakpoints` — 메모리 주소 읽기/쓰기 감시
  - 치트엔진의 "Find out what writes/accesses to this address"와 동일 원리
  - 최대 4개 동시 감시 (CPU 하드웨어 제한)
  - 감시 크기: 1/2/4/8 바이트

### PDB 심볼 지원

타겟 프로세스의 PDB 파일이 있으면:
- 소스 파일명 + 줄 번호로 브레이크포인트 설정
- 함수 이름으로 브레이크포인트 설정
- 스택 트레이스에서 함수명/소스 파일/줄 번호 표시

PDB 없이도 주소 기반 디버깅은 가능.

### 싱글스텝

| 명령 | 동작 |
|------|------|
| `next` (F10) | Step Over — 한 줄/명령어 실행 (호출 건너뜀) |
| `stepIn` (F11) | Step Into — 함수 내부로 진입 |
| `stepOut` (Shift+F11) | Step Out — 현재 함수 완료까지 실행 |

### 프로세스 실행 디버깅 (Launch)

Windows 디버거의 "실행하며 디버깅" 기능과 동일. DAP(`launch` 요청)와 MCP(`veh_launch`) 모두 지원.

동작 순서:
1. `CreateProcess` + `CREATE_SUSPENDED` — 프로세스를 정지 상태로 생성
2. DLL 인젝션 — VEH 핸들러 등록, Named Pipe 서버 시작
3. `stopOnEntry=true`이면 진입점에서 정지 유지, `false`이면 `ResumeThread`로 실행 계속

이미 실행 중인 프로세스에는 `attach` / `veh_attach`로 연결.

### DLL 인젝션

4가지 인젝션 방식 지원 (자동 선택):
1. **CreateRemoteThread** — 기본 방식
2. **NtCreateThreadEx** — 보호된 프로세스 대응
3. **Thread Hijacking** — 기존 스레드 하이재킹
4. **QueueUserAPC** — APC 큐 방식

### 메모리 & 디스어셈블리

- `readMemory` / `writeMemory` — 임의 메모리 읽기/쓰기
- `disassemble` — x86/x64 디스어셈블리
  - **Zydis 백엔드** (기본): 완전한 오퍼랜드 표시 (`mov rax, qword ptr [rbp-0x10]`)
  - **Simple 백엔드** (폴백): 니모닉만 (`mov`, `call` — 외부 의존성 없음)
  - `IDisassembler` 인터페이스로 추상화, `CreateDisassembler()` 팩토리로 생성
- `evaluate` — 메모리 주소 표현식 평가

## DAP 지원 명령 전체 목록

| 카테고리 | 명령 |
|---------|------|
| 라이프사이클 | initialize, launch, attach, disconnect, terminate |
| 브레이크포인트 | setBreakpoints, setFunctionBreakpoints, setExceptionBreakpoints, setInstructionBreakpoints, setDataBreakpoints, dataBreakpointInfo |
| 실행 제어 | configurationDone, continue, next, stepIn, stepOut, pause |
| 상태 조회 | threads, stackTrace, scopes, variables, evaluate |
| 메모리/디스어셈블리 | readMemory, writeMemory, disassemble |
| 기타 | modules, loadedSources, exceptionInfo, completions, source, cancel, gotoTargets |

## 프로젝트 구조

```
├── CMakeLists.txt              # 루트 CMake (MT 정적 CRT)
├── src/
│   ├── dll/                    # VEH 디버거 DLL
│   │   ├── dllmain.cpp         # DLL 진입점
│   │   ├── veh_handler.*       # VEH 예외 핸들러
│   │   ├── breakpoint.*        # 소프트웨어 BP 관리
│   │   ├── hw_breakpoint.*     # 하드웨어 BP (DR0~DR3)
│   │   ├── memory.*            # 메모리 읽기/쓰기
│   │   ├── threads.*           # 스레드 열거/제어
│   │   ├── stack_walk.*        # 스택 워킹 (DbgHelp)
│   │   └── pipe_server.*       # Named Pipe IPC 서버
│   ├── adapter/                # DAP 어댑터 EXE
│   │   ├── main.cpp            # 진입점 (모드 파싱)
│   │   ├── dap_server.*        # DAP 프로토콜 핸들러
│   │   ├── dap_types.h         # DAP 타입 정의
│   │   ├── transport.*         # stdin/stdout & TCP 전송
│   │   ├── injector.*          # DLL 인젝션 (4가지 방식)
│   │   ├── pipe_client.*       # Named Pipe IPC 클라이언트
│   │   ├── disassembler.h      # IDisassembler 인터페이스
│   │   ├── disassembler.cpp    # SimpleDisassembler (내장 경량 디코더)
│   │   └── zydis_disassembler.cpp # ZydisDisassembler (Zydis v4 기반)
│   ├── mcp/                    # MCP 도구 서버
│   │   ├── main.cpp            # 진입점 (--install, --log 등)
│   │   ├── mcp_server.*        # MCP 프로토콜 + 26개 도구 구현
│   │   └── installer.*         # 에이전트별 자동 설치/제거
│   └── common/                 # 공유 코드
│       ├── ipc_protocol.h      # IPC 명령/응답 정의
│       └── logger.h            # 로깅 유틸리티
├── third_party/                # 외부 라이브러리
│   └── nlohmann/json.hpp       # JSON 파서 (MIT)
│   # Zydis v4.1 (vendored in third_party/)
└── extension/                  # VSCode 익스텐션
    ├── package.json
    ├── tsconfig.json
    └── src/extension.ts
```

## 문제 해결

### DLL 인젝션 실패
- 관리자 권한으로 VSCode/어댑터 실행
- 타겟 프로세스의 비트 수(32/64) 확인 — DLL 비트가 일치해야 함
- 안티바이러스가 인젝션을 차단하는지 확인

### 파이프 연결 타임아웃
- 기본 타임아웃은 7초. 느린 시스템에서는 DLL 로드에 시간이 걸릴 수 있음
- 로그 파일로 진행 상황 확인: `--log=debug.log --log-level=debug`

### 브레이크포인트가 안 걸림
- PDB 파일이 타겟 EXE와 같은 디렉토리에 있는지 확인
- PDB 없이는 주소 기반 BP(`setInstructionBreakpoints`)만 가능
- 하드웨어 BP는 최대 4개 제한

### 원격 접속이 안 됨
- `--remote` 또는 `--bind=0.0.0.0` 옵션을 사용했는지 확인
- 방화벽에서 해당 포트가 열려있는지 확인
- VM의 네트워크 어댑터가 브릿지 모드인지 확인

## 의존성

| 라이브러리 | 용도 | 라이선스 |
|-----------|------|---------|
| [nlohmann/json](https://github.com/nlohmann/json) | JSON 파싱 (header-only) | MIT |
| [Zydis v4.1](https://github.com/zyantific/zydis) | x86/x64 디스어셈블리 (third_party에 포함) | MIT |

## 라이선스

MIT License

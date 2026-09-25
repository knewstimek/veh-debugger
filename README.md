# VEH Debugger for VSCode

**한국어** | [English](README.en.md)

Windows 프로세스를 VEH(Vectored Exception Handler)로 디버깅하는 인-프로세스 디버거. 브레이크포인트, 하드웨어 워치포인트, 메모리/레지스터 조회, 포인터 체인과 런타임 call 추적 — **모든 디버깅 연산을 호출 가능한 headless primitive로 노출한다.** GUI를 조작할 필요 없이 AI 에이전트는 이걸 MCP 함수로 직접 호출하고, 사람은 같은 엔진을 VSCode의 DAP로 쓴다.

## 왜 VEH인가

Windows Debug API를 쓰지 않는다. `DebugActiveProcess` / `NtSetInformationThread` 대신 타겟 안에서 VEH로 예외를 잡으므로 `PEB.BeingDebugged`가 0으로 유지된다. Themida, VMProtect의 PEB/NtQuery 기반 안티디버그 체크에 디버거가 보이지 않는다. (VEH 등록 자체를 스캔하는 EAC류 커널 안티치트는 예외.)

in-process라는 점에서 하나 더. Windows Debug API 디버거는 프로세스당 하나만 붙지만, VEH는 **x64dbg가 이미 붙은 프로세스에도 동시에** 붙는다. 커널/유저 디버거로 분석하면서 워치포인트만 VEH로 병행할 수 있다.

## 제어 경로: DAP와 MCP

같은 디버깅 엔진을 지원되는 클라이언트 인터페이스로 노출한다.

- **DAP**: VSCode 디버그 패널에서 직접. 소스 BP, 스텝, 디스어셈블리, 레지스터 편집.
- **MCP**: Claude, Cursor, Codex 등이 공개된 디버깅 도구를 직접 호출. GUI를 거치지 않고 디버깅 연산을 함수처럼 조합·자동화한다 — 에이전트가 디버거를 '조종'하는 게 아니라 primitive로 '프로그래밍'한다.

## 실전 시나리오

자연어 요청이 실제로 어떤 도구 시퀀스로 풀리는지.

**모듈 로드 시점에 내부로 BP**

Game.dll이 로드되는 순간 정지시키고, 그 안 오프셋에 BP를 건다.
```
veh_set_module_breakpoint(module="Game.dll")   # 로드 시점에 정지
veh_continue(wait=true)
veh_set_breakpoint(address="Game.dll+0x1234")
veh_continue(wait=true)
veh_registers(threadId=...)
```
언패킹 후에야 나타나는 모듈, 지연 로드 DLL을 로드 시점에 잡는다. `module+RVA` 주소라 ASLR 베이스 계산이 없다.

**이 값에 쓰는 코드 찾기 (Find What Writes)**

감시 주소에 쓰기가 일어난 명령을 찾는다.
```
veh_set_data_breakpoint(address="0x...", type="write", size=4, condition="value != 0")
veh_continue(wait=true)
veh_registers(threadId=...)            # 쓴 명령의 RIP
veh_disassemble(address=<위 RIP 값>)
```
DR0~DR3 하드웨어 워치포인트라 코드에 INT3를 심지 않아 무결성 검사에 안 걸린다. `value != 0`으로 0-write 노이즈를 건너뛴다.

**N스텝 동안 레지스터 변화 추적**

특정 지점부터 100스텝 동안 EAX 값이 바뀌는 지점만 모은다.
```
veh_trace_register(threadId=..., register="eax", max_steps=100)
```
스텝 루프가 타겟 DLL 안에서 돌아 스텝마다 IPC 왕복이 없다. 값이 바뀐 스텝만 반환한다.

**포인터 체인 한 번에 풀기**

base에서 오프셋을 차례로 따라가 최종 값을 읽는다.
```
veh_read_pointer_chain(base="game.exe+0x1F00", offsets=[0x10, 0x8, 0x34], size=4)
```
각 홉을 역참조(x86/x64 포인터 크기 자동)해 홉마다 주소와 최종 값을 반환한다. 홉당 왕복하던 걸 1콜로. HP/좌표/엔티티 포인터 추적.

**난독화된 import 일괄 해석**

thunk 주소들이 실제로 어느 API로 가는지 한 번에 푼다.
```
veh_resolve_imports(threadId=..., addresses=[...], follow_exceptions=true, system_only=true)
```
각 thunk에서 DLL 안까지 스텝으로 따라가 실제 API를 알아낸다(최대 2000). 예외 기반 난독화도 `follow_exceptions`로 추적. IAT가 밀린 바이너리의 import 복원.

**패킹된 바이너리의 런타임 call 타겟 수집**

콜사이트들이 실행 중 실제로 어디로 도달하는지 5초간 모은다.
```
veh_trace_calls(addresses=[...], duration_sec=5, resolve=true, system_only=true)
```
콜/점프가 런타임에 도달하는 주소 + API 이름을 수집한다. `resolve=true`는 thunk/트램폴린을 끝까지 따라간다. 패킹 바이너리의 IAT 재구성용.

**미지의 보호 코드 실행 경로 발견**

보호 코드 진입점에서 정지한 뒤, 지정 범위를 벗어나거나 제한에 도달할 때까지 basic block과 edge coverage를 수집한다.
```
veh_trace_basic_blocks(threadId=..., start="game.exe+0x12000", end="game.exe+0x14000",
                       max_steps=100000, timeout_ms=10000, follow_exceptions=true,
                       collect_memory_writes=true, max_memory_writes=4096,
				       collect_memory_reads=true,
				       collect_memory_events=true, max_memory_events=8192,
				       collect_register_events=true, max_register_events=8192,
				       collect_events=true, max_events=8192,
				       collect_code=true, max_code_bytes=262144, max_code_versions=4096,
                       dependency_sources=["rcx", {"address":"game.exe+0x5000","size":4,"label":"input"}])
```
명령마다 MCP로 보내지 않고 타겟 DLL 안에서 TF single-step과 bounded 집계를 수행한다. unique block/edge, register delta, hot path, indirect target profile을 반환하며, `collect_memory_writes=true`이면 명령 실행 전후의 메모리 write 값을 최대 `max_memory_writes`개 unique transition으로 압축한다. 실행 가능 페이지에 대한 write와 이후 변경 범위 실행도 연결해서 표시한다. REP 계열, 16바이트 초과 operand, FS/GS segment write처럼 정확히 모델링하지 못한 경우는 `unsupported_memory_writes`에 집계하며 누락을 숨기지 않는다. 최초 진입과 새로운 edge에서만 레지스터 및 제한된 스택 snapshot을 저장하고, 처리된 예외 continuation도 edge로 기록한다. 현재는 VEH로 정지된 단일 스레드가 대상이며 범위를 벗어나면 정지한다. `veh_batch` step과 breakpoint `action`에서도 같은 결과 형식을 사용한다.

응답은 `schema_version=4`, `mode=aggregated`, `thread_id`로 집계 의미와 스레드 범위를 명시한다. 기본 집계만으로는 실행 순서를 복원할 수 없다. `collect_events=true`를 사용하면 initial block entry와 이후 모든 block transition을 event-schema-v1의 `events` 배열에 실행 순서대로 기록하며 각 항목에 trace-step `sequence`와 OS `thread_id`가 포함된다. 이 스트림은 명령어 단위가 아닌 basic-block transition 단위이고, `max_events`를 넘으면 집계는 계속하면서 `events_truncated=true` 및 `ordering.complete=false`를 반환한다.

trace IPC는 request/header size를 협상하고 legacy schema-v3/v4 및 직전 wire-v5 layout을 판별하므로 실행 중 MCP와 새로 주입된 DLL의 교체 시점이 달라도 배열 offset을 보존한다. 현재 collector가 시작을 거부하면 `failure`에 `status`, 구체적인 `reason`, stopped 판정, normalized IP/start/end, decode 성공 여부와 decoded instruction 수를 반환한다.

`collect_memory_events=true`는 ordered block event 수집을 함께 활성화하고 동일한 trace-step sequence 공간에 per-occurrence read/write를 보존한다. 각 `memory_events` 항목은 thread/instruction/effective address/size와 logical `access_index`, read value 또는 write before/after, dependency origin을 포함한다. 별도 `max_memory_events` 예산을 넘겨도 aggregate trace는 계속되며 `memory_events_truncated`, 정확한 `memory_events_dropped`, `memory_ordering.complete=false`로 손실을 표시한다. 동일 명령에서 여러 operand 또는 read-modify-write가 발생해도 kind와 access index로 구분된다.

`collect_register_events=true`도 ordered block event를 함께 활성화하고 수집 구간에서 정상 완료된 모든 instruction occurrence를 `register_events`에 보존한다. 각 항목은 동일한 sequence, OS thread ID, instruction address와 변경된 GPR/SP/EFLAGS의 before/after를 포함하며, 변화가 없는 명령도 빈 `changes` event로 실행 occurrence를 남긴다. faulting instruction은 완료된 delta로 추측하지 않고 exception stream이 담당한다. 독립된 `max_register_events`를 넘으면 `register_events_truncated`, 정확한 `register_events_dropped`, `register_ordering.complete=false`로 손실 범위를 명시한다.

`collect_code=true`는 ordered event 수집도 활성화하고 실행 시점 block bytes를 unique `(block, version)`으로 보존한다. event-schema-v2의 `code_version`이 각 version ID와 연결되므로 self-modifying code도 어느 sequence에서 어느 bytes가 실행됐는지 구분할 수 있다. 기본 `code_output="inline"`은 기존 `code_versions` JSON을 그대로 반환하며 `max_code_bytes`는 최대 16 MiB다.

큰 VM trace는 `code_output="file"`을 사용하면 된다. DLL의 VEH 경로는 사전 할당된 ring buffer에만 기록하고 별도 writer가 256 KiB~8 MiB의 `code_chunk_bytes`(기본 4 MiB)로 MCP의 one-shot data pipe에 전송한다. MCP는 portable little-endian `.vtc` artifact를 기록하고 경로, 크기, SHA-256, 실제 byte/version/chunk 수만 반환한다. 총 `max_code_bytes`는 최대 400 MiB이며 기존 파일은 덮어쓰지 않는다. `code_output_path`를 생략하면 MCP host의 임시 디렉터리에 고유 파일을 만든다. 예산 또는 backpressure 한도 초과는 집계를 중단하지 않고 `code_truncated=true`, `code_capture.complete=false`로 표시한다. artifact는 64비트 offset을 사용하므로 Windows에서 수집한 x86/x64 결과를 다른 OS의 Analyzer도 읽을 수 있다.

전체 trace JSON 응답이 커지는 경우에는 별도의 `output_file`과 `output_format="json"|"jsonl"`을 지정할 수 있다. 서버가 전체 결과를 새 파일에 기록하고 MCP 응답에는 경로, SHA-256, 크기, 배열별 count, truncation/error만 반환한다. 기존 파일은 덮어쓰지 않으며 direct, `veh_batch`, breakpoint action 모두 같은 의미를 사용한다. `occurrence_window={address,from,to}`는 지정 명령의 N번째 방문 직전부터 M번째 다음 방문 직전까지 entry-to-entry로 수집한다. 이 gate는 `start_condition` 및 `collect_condition`과 AND 결합하며, `to=0`은 상한을 열어 둔다.

handler occurrence만 필요하면 `target_window={address,occurrence,before_steps,after_steps}`로 trigger 전 ordered ring과 trigger 후 bounded 구간만 남길 수 있다. `veh_targeted_capture`는 이를 입력 matrix로 확장해 각 `$input`의 batch setup을 실행하고 TEB/FS·GS 및 선택 memory snapshot을 trace JSON에 포함한 뒤, 입력별 고유 파일 경로·SHA-256·크기·event count·정확한 drop·truncation·matched occurrence를 반환한다. 이 고수준 orchestrator는 이미 attach된 한 세션에서 직접 호출하며 `veh_batch`/breakpoint action 안에 중첩하지 않는다. 저수준 `target_window`는 direct/batch/action에서 동일하게 지원된다.

함수 단위 근거가 필요하면 `stop_on_return=true`를 사용한다. trace는 진입 시점의 stack pointer와 return address를 고정하고, decoded range 밖의 외부 호출을 single-step으로 통과하되 그 구간의 memory/register/code event는 수집하지 않는다. 원래 frame의 반환을 확인하면 `stop_reason="function_return"`, return edge, 반환 시점의 전체 snapshot을 돌려준다. 외부 구간도 `max_steps`와 `timeout_ms`에는 포함된다.

`collect_memory_reads=true`는 주소·크기·값을 `max_memory_reads` 한도에서 deduplicate한다. `dependency_sources`에는 최대 32개의 레지스터 이름 또는 `{address,size,label?}` 메모리 범위를 지정할 수 있고, 결과의 edge/read/write/final register에는 conservative origin bitset을 label 배열로 반환한다. 이는 full symbolic taint가 아니라 GPR·flags와 동일 주소/크기의 memory flow만 추적하는 실험 기능이다. REP, 16바이트 초과, FS/GS 및 지원하지 않는 vector flow는 unsupported count로 드러내며, 조건부 수집 공백이 있으면 `dependency_incomplete=true`로 완전성을 보장하지 않음을 알린다.

`start_condition`, `stop_condition`, `collect_condition`은 `r12 == 0x1234`, `[r13-8] != 0`, `rip < 0x140000000 || rip >= 0x150000000` 형태를 지원한다. 비교 연산은 `== != < <= > >=`, 메모리 폭은 `byte/word/dword/qword [reg±offset]`으로 지정할 수 있고 기본값은 포인터 폭이다. 한 조건에서 최대 4개 절을 같은 `&&` 또는 `||`로 연결할 수 있으며 두 논리 연산자의 혼합은 거부한다. 결과의 주소에는 가능한 경우 `image`, `mapped`, `private`, `stack` 및 protection/guard 분류가 붙고, `loop_folds`는 반복 진입 block 후보만 제공하며 dispatcher 의미 판정은 하지 않는다. `exceptions`에는 code, fault RIP/address, continuation, fault/continuation snapshot이 포함된다. 실제로 실행된 SEH handler 주소는 안정적으로 관측되지 않으므로 추측해 반환하지 않는다.

---

## 특징

- **VEH 기반**: Windows Debug API 대신 VEH를 사용하여 안티디버그 우회에 유리
- **DAP 전체 지원**: VSCode, MCP debug 도구 등 모든 DAP 호환 클라이언트에서 사용 가능
- **MCP 도구 서버**: AI 에이전트(Claude, Codex 등)가 공개된 MCP 도구로 디버거를 직접 제어
- **TCP 모드**: `--tcp --port=PORT`로 원격 디버깅/MCP 연동 지원
- **원격 접속**: `--remote` / `--bind=0.0.0.0`으로 VM/네트워크 너머 디버깅
- **32/64비트 지원**: x86/x64 프로세스 모두 디버깅 (32비트 타겟은 별도 32비트 DLL 빌드 + WoW64 인젝션)
- **소프트웨어 브레이크포인트**: INT3 (0xCC) 패치 (ReadMemory에서 원본 바이트 마스킹)
- **조건부 브레이크포인트**: 조건식 만족 시에만 정지 (예: `RAX==0x1234`, `*0x7FF600!=0`)
- **힐 카운트 브레이크포인트**: N번째 히트에서만 정지
- **로그 포인트**: 정지 없이 Debug Console에 로깅 (예: `RAX={RAX}, ptr={*0x7FF600}`)
- **하드웨어 브레이크포인트**: DR0~DR3 (메모리 읽기/쓰기 감시 = Find What Writes/Accesses)
- **PDB 심볼 지원**: 소스 파일/줄 번호 매핑, 함수 이름으로 브레이크포인트
- **PDB 기반 O(1) StepOver**: `SymGetLineFromAddrW64`로 다음 소스 줄 주소를 계산 — O(n) 싱글스텝 대신 임시 BP 하나
- **레지스터 편집**: Variables 패널에서 레지스터 값 더블클릭 수정
- **디스어셈블리**: Zydis x86/x64 디스어셈블러 (기본) + 내장 경량 디코더 (폴백)
- **메모리 읽기/쓰기**: DAP readMemory/writeMemory 지원
- **detach/재부착**: detach 후에도 DLL 파이프 서버 유지 — 타겟 재시작 없이 재부착 가능
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
| `veh-mcp-server.exe` | MCP 도구 서버. AI 에이전트가 공개된 디버깅 도구를 직접 호출 |
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
- `runAsInvoker`: UAC 권한 상승 프롬프트 없이 현재 권한으로 실행 (기본: false)

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

> TCP로 열어둔 어댑터에는 DAP를 지원하는 클라이언트라면 무엇이든 붙을 수 있습니다. 예를 들어 agent-tool의 `debug` 도구로 `debug(operation: "launch", address: "localhost:4711", ...)` 처럼 연결합니다.

### 4. MCP 도구 서버 (AI 에이전트 직접 제어)

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

기본 `lite` 프로필은 `veh_toolbox`, launch/attach/continue/batch/terminate/registers만 먼저 노출하여 매 요청의 도구 스키마 비용을 줄입니다. 나머지는 `veh_toolbox`로 검색 → schema 확인 → 호출하며, 이름을 아는 자동화는 숨겨진 도구도 기존처럼 직접 호출할 수 있습니다. BP/inspection 중심은 `--profile=interactive`, VM trace/checkpoint 중심은 `--profile=capture`, 기존 전체 목록은 `--profile=full`을 사용하세요.

**MCP 도구 목록**

아래 표는 전체 공개 도구를 설명합니다. 실행 중인 서버의 현재 eager 목록은 MCP `tools/list` 응답을 기준으로 확인하세요.

| 도구 | 인자 | 설명 |
|------|------|------|
| `veh_toolbox` | `operation, tool?, arguments?, profile?, query?, schema_handle?` | 현재 프로필에 eager 노출되지 않은 도구를 검색·설명·호출하는 lazy gateway. `describe`가 반환한 `schema_handle`을 재사용하면 변경 없음만 짧게 확인한다. |
| `veh_attach` | `pid` | 프로세스에 DLL 인젝션 + 파이프 연결 |
| `veh_launch` | `program, args?, stopOnEntry?, cwd?, env?` | 프로세스 생성 + 인젝션. `cwd`로 타겟 작업 디렉토리 지정(생략 시 디버거 cwd 상속). `env`로 타겟에 환경변수 전달 (`{"KEY":"VAL"}` 또는 `["KEY=VALUE"]`, 부모 환경 위에 덮어씀) |
| `veh_detach` | - | 디버거 분리 (타겟은 계속 실행) |
| `veh_terminate` | `exitCode?` | 타겟을 **내부에서** 강제 종료 (주입된 DLL이 자기 프로세스에 `TerminateProcess` 호출). 외부 `taskkill`/`OpenProcess`를 막는 자기보호 타겟(deny-DACL/상위 무결성)도 확실히 종료 -- 프로세스 자기 핸들은 항상 종료 권한 보유. 종료 후 자동 detach. `WM_CLOSE->detach->taskkill` 수순 대체 |
| `veh_set_breakpoint` | `address, condition?, hitCondition?, logMessage?, action?` | 소프트웨어 BP. `action`으로 히트 시 자동 실행 (veh_batch 형식) |
| `veh_remove_breakpoint` | `id` | 소프트웨어 BP 제거 |
| `veh_set_source_breakpoint` | `source, line, condition?, hitCondition?, logMessage?` | 소스 파일+줄번호 BP (PDB 필요; 미로드 모듈은 `pending` 후 모듈 로드 시 자동 바인딩) |
| `veh_set_function_breakpoint` | `name, condition?, hitCondition?, logMessage?` | 함수명 BP (PDB 필요; 미로드 모듈은 `pending` 후 자동 바인딩) |
| `veh_list_breakpoints` | - | 활성 SW/HW BP 목록 조회 |
| `veh_set_data_breakpoint` | `address, type, size, condition?, hitCondition?` | HW BP (write/readwrite/execute). `condition`의 `value` 토큰=감시 주소 현재값 (예: `value != 0`으로 0-write 노이즈 필터), `hitCondition:"5"`=5번째 hit에서만 정지 |
| `veh_remove_data_breakpoint` | `id` | HW BP 제거 |
| `veh_set_module_breakpoint` | `module, enabled?, clear?` | 모듈(DLL) 로드 시 정지. 이름 부분일치(대소문자 무시, 예: `"D2Common"`). 매핑 직후 로더 스레드 정지(LdrRegisterDllNotification, INT3/패치 없음) -> 내부 함수에 BP 설치나 덤프 가능. 모던 Windows에선 DllMain 실행 후 발화. `enabled:false`로 패턴 제거, `clear:true`로 전체 제거 |
| `veh_continue` | `threadId?, wait?, timeout?, pass_exception?, ignore_exceptions?` | 실행 계속. `ignore_exceptions=[0x80000003]`으로 특정 예외만 SEH 전달 |
| `veh_step_in` | `threadId` | Step Into |
| `veh_step_over` | `threadId` | Step Over |
| `veh_step_out` | `threadId` | Step Out |
| `veh_pause` | `threadId?` | 일시정지 |
| `veh_threads` | - | 스레드 목록 (얼린 스레드는 `frozen` 표시) |
| `veh_freeze_thread` | `threadId, frozen?` | 스레드 하나를 얼리거나 푼다. 얼린 스레드는 `veh_continue` 후에도 멈춰 있고(일시정지와 별도 카운트), detach 시 자동으로 풀린다. `threadId:0, frozen:false`는 전체 해제 |
| `veh_stack_trace` | `threadId, maxFrames?` | 스택 트레이스. PDB 없는 모듈은 PE export 테이블을 직접 파싱해 정확한 함수명 제공 (DbgHelp의 부정확한 `OrdinalNNNNN` 라벨 대신) |
| `veh_enum_locals` | `threadId, instructionAddress?, frameBase?` | 정지된 스레드의 스택 프레임에서 지역변수/파라미터 열거 (이름/타입/주소/값). 생략 시 최상위 프레임 자동 감지 (PDB 필요) |
| `veh_display_type` | `type, address?, depth?, max_members?` | WinDbg `dt`처럼 PDB 구조체 레이아웃 표시 (오프셋/타입/크기/비트필드/기본 클래스/중첩 멤버). `address`를 주면 스칼라/포인터/enum/비트필드 값까지 읽음. `module!Type` 형식 지원 (PDB 필요) |
| `veh_symbolize` | `address` 또는 `addresses` | 주소를 `module!function+offset`으로 변환 (PDB 심볼, 없으면 export, 없으면 module+RVA) + 소스 파일/줄. 최대 256개 |
| `veh_registers` | `threadId` | 레지스터 조회 |
| `veh_set_register` | `threadId, name, value` | 레지스터 값 변경 |
| `veh_evaluate` | `expression, threadId` | 레지스터/메모리/포인터/세그먼트 평가 (`[reg+offset]`, `gs:[0x60]` 등) |
| `veh_read_memory` | `address, size` | 메모리 읽기 (hex) |
| `veh_read_pointer_chain` | `base, offsets[], derefFinal?, size?` | 다단계 포인터 체인을 1콜로 추적 (N번 왕복 대신). 각 홉마다 `*(cur+offset)` 역참조 (x86/x64 포인터 크기 자동 판정), 각 홉과 최종 주소 반환. `derefFinal:false`면 마지막 오프셋은 역참조 없이 주소만 반환, `size>0`이면 최종 주소에서 바이트도 읽음 |
| `veh_write_memory` | `address, data` 또는 `patches` | 메모리 쓰기. 배치: `patches=[{address,data},...]` |
| `veh_dump_memory` | `address, size, output_path` | 메모리를 바이너리 파일로 덤프 (최대 64MB) |
| `veh_memory_map` | `start?, end?, module?, include_free?, max_regions?` | 가상 메모리 영역 목록 (상태/보호/타입/소유 모듈). 잘리면 `next_start`로 이어서 조회 |
| `veh_search_memory` | `pattern` 또는 `string` 또는 `value`, `start?, end?, module?, writable?, executable?, type?, alignment?, max_results?` | 타겟 내부에서 메모리 검색. AOB(`??`, `4?` 와일드카드), 문자열(ascii/utf8/utf16), 숫자 값. BP 바이트는 원본으로 비교 |
| `veh_value_scan` | `operation, value_type?, compare?, value?, value2?, ...` | 치트엔진식 값 스캔 세션 (`first`/`next`/`results`/`reset`). exact/between/greater/less/unknown 첫 스캔, changed/unchanged/increased/decreased 다음 스캔. 후보는 타겟 DLL 안에 유지 |
| `veh_assemble` | `code, address?, arch?, write?` | Intel 문법 x86/x64 어셈블 (AsmJit+AsmTK). 주소 기준으로 상대 jmp/call/rip 오프셋 계산, `;`/줄바꿈 구분, 레이블 지원, 디코딩 목록 반환. `write:true`로 타겟에 패치. 타겟 없이도 동작 |
| `veh_allocate_memory` | `size?, protection?` | 타겟 프로세스에 메모리 할당 (VirtualAlloc) |
| `veh_free_memory` | `address` | 할당된 메모리 해제 (VirtualFree) |
| `veh_execute_shellcode` | `shellcode, timeout_ms?` | 셸코드 실행 (RWX 할당+복사+스레드 생성+대기+해제) |
| `veh_modules` | - | 모듈 목록 |
| `veh_disassemble` | `address, count?` | 디스어셈블리 (Zydis) |
| `veh_exception_info` | - | 마지막 예외 정보 조회 |
| `veh_trace_register` | `threadId, register, mode?, value?, max_steps?` | 레지스터 변화 추적 (DLL 내부 스텝 루프, IPC 오버헤드 0) |
| `veh_trace_memory` | `address, size?, timeout_ms?` | 메모리 쓰기 추적 (임시 HW BP로 빠르게 감지) |
| `veh_resolve_imports` | `threadId, addresses, max_steps?, follow_exceptions?, system_only?, target_modules?` | 난독화 import 일괄 해석 (thunk -> DLL 스텝 추적, 최대 2000개) |
| `veh_batch` | `steps, inputs?, input_variable?, stop_on_error?` | 다중 명령 일괄 실행 및 동일 세션의 입력별 순차 실행. 결과 참조, 제어 흐름, 입력별 status/count/첫 실패/trace artifact 요약을 반환한다. |
| `veh_trace_callers` | `address, duration_sec?` | 함수 호출자 프로파일링 (자동 resume -> N초간 caller 수집 -> 자동 pause). 유니크 caller별 히트 카운트 반환. x64: RtlVirtualUnwind (정확). x86: [ESP] (함수 진입점에서만 정확) |
| `veh_trace_calls` | `addresses, duration_sec?, resolve?, system_only?` | call/jmp 명령이 런타임에 어디로 가는지 모니터링. 콜 사이트에 BP 설치 후 N초간 실행, 실제 타겟 주소 + API 이름 수집. `resolve=true`: thunk/trampoline을 자연스러운 call 컨텍스트에서 따라가 최종 API까지 추적 (예외 기반 난독화 대응). `system_only=true`: 시스템 DLL 타겟만 반환. 패킹된 바이너리의 IAT 복원용. |
| `veh_trace_basic_blocks` | `threadId, start, end, ..., stop_on_return?, collect_events?, collect_memory_events?, collect_register_events?, collect_code?, ...` | DLL 내부 bounded trace. 선택적 function-return scope, ordered block/code/memory/register occurrence stream 및 block/edge, delta, memory, dependency, region, exception을 반환한다. |
| `veh_targeted_capture` | `inputs, steps?, trace, trigger, window, environment?, output_directory, stop_on_error?` | 입력별 setup 후 occurrence 전후 ordered trace와 환경 snapshot을 서버 파일에 저장한다. instruction이 1개 이상 완료되고 요청한 target-window stop으로 끝난 입력만 성공으로 집계한다. |
| `veh_checkpoint_create` | `threadId, regions?, capture_teb?, teb_size?` | GPR/flags(x64는 XMM 포함), TEB 및 FS/GS 환경과 선택 메모리를 저장한다. TEB bytes는 비교 전용이며 stack region은 saved SP부터의 안전한 복원 범위를 표시한다. |
| `veh_checkpoint_restore` | `id` | 동일 스레드가 VEH 정지된 상태에서 context와 선택 메모리를 복원한다. saved SP 아래의 live VEH stack frame은 보존하며 변경된 매핑은 거부하고 실패 시 rollback한다. |
| `veh_checkpoint_diff` | `id, other_id?` | checkpoint와 현재 상태 또는 다른 checkpoint의 register 및 변경 메모리 구간을 비교한다. |
| `veh_checkpoint_delete` | `id` | checkpoint를 삭제하고 서버 메모리 예산을 반환한다. |

> **Non-stop 조회 (타겟 정지 불필요)**: `veh_read_memory` / `veh_read_pointer_chain` / `veh_write_memory` / `veh_dump_memory` / `veh_disassemble` / `veh_modules` / `veh_memory_map` / `veh_search_memory` / `veh_value_scan` / `veh_symbolize` / `veh_display_type` 는 타겟이 **실행 중에도** 동작합니다 (DLL 내 전용 파이프 스레드가 처리 -- 다른 스레드를 멈추지 않음). GUI를 조작하면서 라이브 값을 읽을 때 BP를 걸거나 detach/attach를 왕복할 필요가 없습니다. 반대로 `veh_registers` / `veh_stack_trace` / `veh_enum_locals` / `veh_step_*` 는 스레드 컨텍스트가 필요하므로 BP 히트나 `veh_pause`로 정지된 상태에서만 동작합니다.

> **Tip**: 주소 인자는 hex (`"0x401000"`), 10진수 (`4198400`), **모듈+RVA** (`"crackme.exe+0x1000"`) 모두 허용합니다. 모듈+RVA는 ASLR 계산 없이 사용 가능합니다.

### 커맨드라인 옵션

**veh-mcp-server.exe**

| 옵션 | 설명 |
|------|------|
| `--install [AGENT]` | AI 에이전트 설정에 MCP 서버 등록 (전체 또는 특정) |
| `--uninstall [AGENT]` | AI 에이전트 설정에서 MCP 서버 제거 |
| `--profile=PROFILE` | eager 도구 노출 범위: `lite`(기본), `interactive`, `capture`, `full` |
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
| [AsmJit](https://github.com/asmjit/asmjit) + [AsmTK](https://github.com/asmjit/asmtk) | `veh_assemble` 텍스트 어셈블러 (x86 백엔드만 third_party에 포함) | Zlib |

## 라이선스

MIT License

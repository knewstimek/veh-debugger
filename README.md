# VEH Debugger for VSCode

**한국어** | [English](README.en.md)

Windows 프로세스를 VEH(Vectored Exception Handler)로 디버깅하는 인-프로세스 디버거. 브레이크포인트, 하드웨어 워치포인트, 메모리/레지스터 조회, 포인터 체인과 런타임 call 추적 — **모든 디버깅 연산을 호출 가능한 headless primitive로 노출한다.** GUI를 조작할 필요 없이 AI 에이전트는 이걸 MCP 함수로 직접 호출하고, 사람은 같은 엔진을 VSCode의 DAP로 쓴다.

## 모듈과 심볼 선택

`veh_symbolize(name="Function", max_results=10)`으로 심볼 후보를 조회할 수 있습니다. 후보와 `veh_modules`는 모듈 경로·베이스·확인 가능한 32/64비트를 표시하며, 알 수 없는 비트수는 unknown입니다. 동명 모듈은 `module_base="0x..."`로 지정하거나 주소에 `0xBASE!Function`을 사용합니다. 이름만으로 모호한 후보를 자동 선택하지 않습니다. 외부 백엔드는 해당 조회 기능을 지원해야 하며, 모듈 선택이 세션의 실행 모드를 바꾸지는 않습니다.

분석 코멘트·라벨은 기존 `veh_symbolize(analysis=...)`로 관리하고 MCP 디스어셈블·심볼 결과에서 확인합니다. 지정한 폴더의 JSON에 자동 저장하며, 빌드 변경·코드 변경·수정 충돌을 구분합니다. [분석 메모 사용법](docs/ANALYSIS_NOTES.md).

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

경로만 필요하면 `collect_snapshots=false`로 최초 block/edge 및 예외의 레지스터·스택 수집과 snapshot 버퍼 할당을 생략할 수 있다. `stack_bytes=0`은 스택 읽기만 끄고 레지스터 snapshot은 유지한다. 명령별 `collect_register_events`는 별도 옵션이다.

`compress_paths=true, collect_code=true`는 inline 및 `events_output="file"`에서 실제 관측한 연속 반복 경로를 무손실로 압축한다. 실행 순서·분기 선택·반복 횟수·sequence 간격을 보존하며, 수집 제외·유실·예외·관측 코드 버전 변경 경계를 넘어 합치지 않는다. 코드 수집 비용은 남고 TF single-step 예외 횟수는 줄지 않는다. ordered memory/register event 및 `target_window`와 함께 사용할 수 없으며, 일반 VEH에서는 활성 HW 중단점과의 충돌을 실행 전에 거부한다. 기본 동작은 유지되며 새 옵션은 백엔드의 명시적 지원이 필요하다. [사용법·백엔드 도입 규약](docs/DEVELOPMENT_TOOLS.md#basic-block-collection-policies-and-repeated-paths)을 참고한다.

기본 집계 응답은 `schema_version=4`, `mode=aggregated`, `thread_id`로 집계 의미와 스레드 범위를 명시한다. 기본 집계만으로는 실행 순서를 복원할 수 없다. `collect_events=true`를 사용하면 initial block entry와 이후 모든 block transition을 event-schema-v1의 `events` 배열에 실행 순서대로 기록하며 각 항목에 trace-step `sequence`와 OS `thread_id`가 포함된다. 이 스트림은 명령어 단위가 아닌 basic-block transition 단위이고, `max_events`를 넘으면 집계는 계속하면서 `events_truncated=true` 및 `ordering.complete=false`를 반환한다.

trace IPC는 request/header size를 협상하고 legacy schema-v3/v4 및 직전 wire-v5 layout을 판별하므로 실행 중 MCP와 새로 주입된 DLL의 교체 시점이 달라도 배열 offset을 보존한다. 현재 collector가 시작을 거부하면 `failure`에 `status`, 구체적인 `reason`, stopped 판정, normalized IP/start/end, decode 성공 여부와 decoded instruction 수를 반환한다.

`collect_memory_events=true`는 ordered block event 수집을 함께 활성화하고 동일한 trace-step sequence 공간에 per-occurrence read/write를 보존한다. 각 `memory_events` 항목은 thread/instruction/effective address/size와 logical `access_index`, read value 또는 write before/after, dependency origin을 포함한다. 별도 `max_memory_events` 예산을 넘겨도 aggregate trace는 계속되며 `memory_events_truncated`, 정확한 `memory_events_dropped`, `memory_ordering.complete=false`로 손실을 표시한다. 동일 명령에서 여러 operand 또는 read-modify-write가 발생해도 kind와 access index로 구분된다.

`collect_register_events=true`도 ordered block event를 함께 활성화하고 수집 구간에서 정상 완료된 모든 instruction occurrence를 `register_events`에 보존한다. 각 항목은 동일한 sequence, OS thread ID, instruction address와 변경된 GPR/SP/EFLAGS의 before/after를 포함하며, 변화가 없는 명령도 빈 `changes` event로 실행 occurrence를 남긴다. faulting instruction은 완료된 delta로 추측하지 않고 exception stream이 담당한다. 독립된 `max_register_events`를 넘으면 `register_events_truncated`, 정확한 `register_events_dropped`, `register_ordering.complete=false`로 손실 범위를 명시한다.

`collect_code=true`는 ordered event 수집도 활성화하고 실행 시점 block bytes를 unique `(block, version)`으로 보존한다. event-schema-v2의 `code_version`은 블록 진입 시 관측한 bytes의 version ID와 연결된다. 이미 알려진 명령 메타데이터를 매 명령마다 다시 디코딩하지 않으므로 임의의 동시 자기 수정 코드에 대한 완전성은 보장하지 않는다. 반복 압축 시에는 event-schema-v3를 사용한다. 기본 `code_output="inline"`은 기존 `code_versions` JSON을 그대로 반환하며 `max_code_bytes`는 최대 16 MiB다.

큰 VM trace는 `code_output="file"`을 사용하면 된다. DLL의 VEH 경로는 사전 할당된 ring buffer에만 기록하고 별도 writer가 256 KiB~8 MiB의 `code_chunk_bytes`(기본 4 MiB)로 MCP의 one-shot data pipe에 전송한다. MCP는 portable little-endian `.vtc` artifact를 기록하고 경로, 크기, SHA-256, 실제 byte/version/chunk 수만 반환한다. 총 `max_code_bytes`는 최대 400 MiB이며 기존 파일은 덮어쓰지 않는다. `code_output_path`를 생략하면 MCP host의 임시 디렉터리에 고유 파일을 만든다. 예산 또는 backpressure 한도 초과는 집계를 중단하지 않고 `code_truncated=true`, `code_capture.complete=false`로 표시한다. artifact는 64비트 offset을 사용하므로 Windows에서 수집한 x86/x64 결과를 다른 OS의 Analyzer도 읽을 수 있다.

전체 trace JSON 응답이 커지는 경우에는 별도의 `output_file`과 `output_format="json"|"jsonl"`을 지정할 수 있다. 서버가 전체 결과를 새 파일에 기록하고 MCP 응답에는 경로, SHA-256, 크기, 배열별 count, truncation/error만 반환한다. 기존 파일은 덮어쓰지 않으며 direct, `veh_batch`, breakpoint action 모두 같은 의미를 사용한다. `occurrence_window={address,from,to}`는 지정 명령의 N번째 방문 직전부터 M번째 다음 방문 직전까지 entry-to-entry로 수집한다. 이 gate는 `start_condition` 및 `collect_condition`과 AND 결합하며, `to=0`은 상한을 열어 둔다.

handler occurrence만 필요하면 `target_window={address,occurrence,before_steps,after_steps}`로 trigger 전 ordered ring과 trigger 후 bounded 구간만 남길 수 있다. `veh_targeted_capture`는 이를 입력 matrix로 확장해 각 `$input`의 batch setup을 실행하고 TEB/FS·GS 및 선택 memory snapshot을 trace JSON에 포함한 뒤, 입력별 고유 파일 경로·SHA-256·크기·event count·정확한 drop·truncation·matched occurrence를 반환한다. 이 고수준 orchestrator는 이미 attach된 한 세션에서 직접 호출하며 `veh_batch`/breakpoint action 안에 중첩하지 않는다. 저수준 `target_window`는 direct/batch/action에서 동일하게 지원된다.

함수 단위 근거가 필요하면 `stop_on_return=true`를 사용한다. trace는 진입 시점의 stack pointer와 return address를 고정하고, decoded range 밖의 외부 호출을 single-step으로 통과하되 그 구간의 memory/register/code event는 수집하지 않는다. 원래 frame의 반환을 확인하면 `stop_reason="function_return"`, return edge, snapshot 수집이 켜져 있으면 반환 시점의 snapshot도 돌려준다. 외부 구간도 `max_steps`와 `timeout_ms`에는 포함된다.

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

**외부 게스트 프로세스에 DAP 연결**

```json
{
    "type": "veh",
    "request": "attach",
    "name": "Guest process",
    "targetScope": "guest",
    "processId": 1234,
    "agent": "C:\\path\\to\\guest-agent.exe",
    "agentArgs": ["--vm", "configured-vm"]
}
```

어댑터는 agent를 `--pid <guest PID> --pipe <고유 파이프>`로 시작하고,
연결 상대의 프로세스 ID와 게스트 범위·PID·32/64비트 주소 폭을 확인합니다.
게스트 DAP는 백엔드가 광고한 명령에 따라 스레드·메모리·레지스터 조회,
메모리 쓰기, 계속·정지, 명령어 단위 스텝·step out, 실행·데이터 중단점,
식 평가·변수 변경·종료를 지원합니다. 소스·함수 중단점은 백엔드의 심볼 해석을
사용하며, 미지원 명령은 오류를 반환합니다. 정지 이벤트는 선택된 스레드만
멈췄다고 표시합니다. 게스트 프로세스 생성(`veh_launch`/DAP `launch`)과
`stopOnEntry`는 아직 미지원이므로 기존 프로세스에 attach해야 합니다.
`stopOnModuleLoad`는 게스트 DAP 연결에서 사용할 수 없습니다.

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

### 외부 백엔드와 VM 안의 프로세스 연결 (MCP)

등록 백엔드의 `remote` 설정으로 인증된 TCP 연결도 사용할 수 있습니다. `veh-remote-runner`가 분석 VM에서 에이전트 시작·호스트 프로세스 생성·재연결을 맡습니다. VirtualBox/WHPX에서는 분석 호스트 VM에만 실행기를 두며 내부 게스트에는 설치하지 않습니다. 게스트 launch는 미지원입니다. 설정과 제한은 [원격 전송 문서](docs/REMOTE_TRANSPORT.md)를 참고하세요. 기존 프로필·게이트웨이 도구 수와 명령별 입력은 늘어나지 않습니다.

기본 `backend="veh"`는 호스트 프로세스에 VEH DLL을 주입합니다. 외부 백엔드는
`backend` 이름이나 `agent` 실행 파일로 선택하며, 도구 지원 범위는 attach 응답의
`backend.unsupported`로 확인합니다. `noTargetFootprint`만으로 게스트 대상 여부나
모든 도구의 지원을 판단하지 않습니다. 현재 capability 응답은 명령·기능 지원만 알리며,
중단점 최대 개수·사용량·남은 슬롯은 제공하지 않습니다. 백엔드가 슬롯 부족을
`LimitReached`로 반환하면 명시적인 오류로 안내하므로 기존 중단점을 해제한 뒤 재시도합니다.

VM용 백엔드는 서버 옆 `veh-backends.json`에 다음처럼 등록합니다. `VEH_BACKENDS`
환경변수로 다른 설정 파일을 지정할 수도 있습니다. 상대 실행 파일 경로는 설정 파일
디렉터리를 기준으로 하고, `args`에는 해당 백엔드의 VM 선택·접속 인자를 넣습니다.

```json
{"guest-lab":{"path":"guest-backend.exe","args":[],"target_scope":"guest"}}
```

이후 `veh_attach(pid=1234, backend="guest-lab")`로 기존 게스트 PID에 연결합니다.
직접 지정할 때는 `agent`, `agent_args`, `target_scope="guest"`를 전달합니다.
PID와 32·64비트 정보는 백엔드가 검증하며, 게스트 연결은 호스트 프로세스 핸들이나
호스트 PID 종료 감시를 사용하지 않습니다. 정지된 VM을 요구하는 백엔드는 연결 전에
그 조건을 충족해야 합니다. 게스트 프로세스 목록·선택은 이 기능이 제공하지 않습니다.

**게스트 `veh_launch`와 `stopOnEntry`는 아직 지원하지 않습니다.** 요청은 호스트에서
프로그램을 실행하거나 현재 세션을 끊기 전에 거부됩니다. 정지·스텝·트레이스는 각
백엔드가 지원한다고 보고한 명령만 사용할 수 있습니다. 이 설정은 MCP용이며 VSCode
DAP의 게스트 연결 설정은 추가하지 않습니다. 실행 중 서버의 도구 설명은
`veh_toolbox(operation="describe", tool="veh_attach")`로 확인할 수 있습니다.

**MCP 도구 목록**

아래 표는 전체 공개 도구를 설명합니다. 실행 중인 서버의 현재 eager 목록은 MCP `tools/list` 응답을 기준으로 확인하세요.

| 도구 | 인자 | 설명 |
|------|------|------|
| `veh_toolbox` | `operation, tool?, arguments?, profile?, query?, schema_handle?` | 현재 프로필에 eager 노출되지 않은 도구를 검색·설명·호출하는 lazy gateway. `describe`가 반환한 `schema_handle`을 재사용하면 변경 없음만 짧게 확인한다. |
| `veh_virtual_machine` | `operation, cpu?, max_instructions?, duration_ms?, cpl_mask?, cr3_roots?, rip_begin?, rip_end?` | 명시적 VM 전체 제어·정지 상태 vCPU 트레이스. 수동 호출 전용 |
| `veh_processes` | - | 지원하는 게스트/VM 백엔드에서 OS 프로세스 목록(PID, 주소 폭, 짧은 이미지명)을 한 스냅샷으로 조회. 기본 프로필에선 `veh_toolbox`로 호출 |
| `veh_attach` | `pid?, backend?/agent?, agent_args?, target_scope?` | VEH 주입 또는 외부 백엔드 연결. VM PID는 `target_scope="guest"`와 백엔드 검증 필요. VM 자체 연결은 pid를 생략합니다. |
| `veh_launch` | `program, args?, stopOnEntry?, cwd?, env?, backend?/agent?, target_scope?` | 호스트 프로세스 생성·연결. `cwd`/`env` 지원. 게스트 launch/stopOnEntry는 미지원이며 기존 세션을 보존하고 거부 |
| `veh_detach` | - | 디버거 분리 (타겟은 계속 실행). 백엔드 정리 실패 시 오류를 반환하고 세션을 유지해 재시도 가능 |
| `veh_terminate` | `exitCode?` | 타겟을 **내부에서** 강제 종료 (주입된 DLL이 자기 프로세스에 `TerminateProcess` 호출). 외부 `taskkill`/`OpenProcess`를 막는 자기보호 타겟(deny-DACL/상위 무결성)도 확실히 종료 -- 프로세스 자기 핸들은 항상 종료 권한 보유. 종료 후 자동 detach. `WM_CLOSE->detach->taskkill` 수순 대체 |
| `veh_set_breakpoint` | `address, condition?, hitCondition?, logMessage?, action?` | 소프트웨어 BP. `action`으로 히트 시 자동 실행 (veh_batch 형식) |
| `veh_remove_breakpoint` | `id` | 소프트웨어 BP 제거 |
| `veh_set_source_breakpoint` | `source, line, condition?, hitCondition?, logMessage?` | 소스 파일+줄번호 BP (PDB 필요; 미로드 모듈은 `pending` 후 모듈 로드 시 자동 바인딩) |
| `veh_set_function_breakpoint` | `name, condition?, hitCondition?, logMessage?` | 함수명 BP (PDB 필요; 미로드 모듈은 `pending` 후 자동 바인딩) |
| `veh_list_breakpoints` | - | 활성 SW/HW BP 목록 조회 |
| `veh_set_data_breakpoint` | `address, type, size, condition?, hitCondition?` | HW BP (write/readwrite/execute). `condition`의 `value` 토큰=감시 주소 현재값 (예: `value != 0`으로 0-write 노이즈 필터), `hitCondition:"5"`=5번째 hit에서만 정지 |
| `veh_remove_data_breakpoint` | `id` | HW BP 제거 |
| `veh_set_module_breakpoint` | `module, enabled?, clear?` | 모듈(DLL) 로드 시 정지. 이름 부분일치(대소문자 무시, 예: `"D2Common"`). 매핑 직후 로더 스레드 정지(LdrRegisterDllNotification, INT3/패치 없음) -> 내부 함수에 BP 설치나 덤프 가능. 모던 Windows에선 DllMain 실행 후 발화. `enabled:false`로 패턴 제거, `clear:true`로 전체 제거 |
| `veh_execution` | `operation?, threadId?, address?, enabled?` | 정지/실행/미확인 상태 조회, 단일 스레드 Run Till, 임시 BP 취소, 선택적 정지 알림. 지연 도구 검색으로 조회 |
| `veh_value_freeze` | `operation?, address?, data?, interval_ms?, lease_seconds?, id?` | 명시한 임대 시간 동안 주기적 값 쓰기. 최대 16작업·64바이트, 읽기·쓰기 지원 필요. 스레드 freeze와 별개 |
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
| `veh_symbolize` | `address`/`addresses` 또는 `name, max_results?` | 이름 검색은 최대 10개 후보와 중복·잘림 여부 반환. 유일한 후보만 자동 주소 해석. 주소를 `module!function+offset`으로 변환 (PDB 심볼, 없으면 export, 없으면 module+RVA) + 소스 파일/줄. 최대 256개 |
| `veh_registers` | `threadId` | 레지스터 조회 |
| `veh_set_register` | `threadId, name, value` | 레지스터 값 변경 |
| `veh_evaluate` | `expression, threadId` | 레지스터/메모리/포인터/세그먼트 평가 (`[reg+offset]`, `gs:[0x60]` 등) |
| `veh_read_memory` | `address, size` | 메모리 읽기 (hex) |
| `veh_read_pointer_chain` | `base, offsets[], derefFinal?, size?` | 다단계 포인터 체인을 1콜로 추적 (N번 왕복 대신). 각 홉마다 `*(cur+offset)` 역참조 (x86/x64 포인터 크기 자동 판정), 각 홉과 최종 주소 반환. `derefFinal:false`면 마지막 오프셋은 역참조 없이 주소만 반환, `size>0`이면 최종 주소에서 바이트도 읽음 |
| `veh_write_memory` | `address, data` 또는 `patches` | 메모리 쓰기. 배치: `patches=[{address,data},...]` |
| `veh_dump_memory` | `address, size, output_path` | 메모리를 바이너리 파일로 덤프 (최대 64MB) |
| `veh_memory_map` | `start?, end?, module?, include_free?, max_regions?` | 가상 메모리 영역 목록 (상태/보호/타입/소유 모듈). 잘리면 `next_start`로 이어서 조회 |
| `veh_protect_memory` | `address, size, protection, method?` | 타겟 내부에서 페이지 보호를 변경하고 이전 보호를 반환. `api`(기본값), `nt`, `syscall` 방식 지원; syscall을 사용할 수 없으면 nt로 폴백 |
| `veh_search_memory` | `pattern` 또는 `string` 또는 `value`, `start?, end?, module?, writable?, executable?, type?, alignment?, max_results?` | 타겟 내부에서 메모리 검색. AOB(`??`, `4?` 와일드카드), 문자열(ascii/utf8/utf16), 숫자 값. BP 바이트는 원본으로 비교 |
| `veh_value_scan` | `operation, value_type?, compare?, value?, value2?, ...` | 값 스캔 `first`/`next`·`undo`·`results`·`status`·`cancel`·`reset`. v2는 비동기 이벤트 완료, 32개 초과 개수 위주 출력, 예산 내 임시 디스크 저장과 기준값 undo 지원. [사용법·백엔드 규약](docs/VALUE_SCAN.md) |
| `veh_assemble` | `code, address?, arch?, write?` | Intel 문법 x86/x64 어셈블 (AsmJit+AsmTK). 주소 기준으로 상대 jmp/call/rip 오프셋 계산, `;`/줄바꿈 구분, 레이블 지원, 디코딩 목록 반환. `write:true`로 타겟에 패치. 타겟 없이도 동작 |
| `veh_allocate_memory` | `size?, protection?` | 타겟 프로세스에 메모리 할당 (VirtualAlloc) |
| `veh_free_memory` | `address` | 할당된 메모리 해제 (VirtualFree) |
| `veh_execute_shellcode` | `shellcode, timeout_ms?` | 셸코드 실행 (RWX 할당+복사+스레드 생성+대기+해제) |
| `veh_modules` | - | 모듈 목록 |
| `veh_disassemble` | `address, count?` | 디스어셈블리 (Zydis) |
| `veh_exception_info` | - | 마지막 예외 정보 조회 |
| `veh_trace_register` | `threadId, register, mode?, value?, max_steps?` | 레지스터 변화 추적 (DLL 내부 스텝 루프, IPC 오버헤드 0) |
| `veh_trace_memory` | `address, size?, timeout_ms?, duration_ms?, access?, max_entries?` | 기본은 첫 쓰기 감지. `duration_ms` 지정 시 쓰기 또는 읽기·쓰기 접근 횟수 수집 |
| `veh_resolve_imports` | `threadId, addresses, max_steps?, follow_exceptions?, system_only?, target_modules?` | 난독화 import 일괄 해석 (thunk -> DLL 스텝 추적, 최대 2000개) |
| `veh_batch` | `steps, inputs?, input_variable?, stop_on_error?` | 다중 명령 일괄 실행 및 동일 세션의 입력별 순차 실행. 결과 참조, 제어 흐름, 입력별 status/count/첫 실패/trace artifact 요약을 반환한다. |
| `veh_trace_callers` | `address?, duration_sec?, duration_ms?, mode?, operation?` | 기본 호출자별 횟수 수집. 명시적 `mode="detour"`는 별도 계측·요약·페이지 조회([규약](docs/INSTRUMENTATION.md), 백엔드 지원 필요). `duration_ms` 우선, 호출 0회도 정상 결과. VEH만 수집 전 재개·후 정지하며 하이퍼바이저는 실행 상태 유지. x64: unwind, x86: 함수 진입점의 [ESP] |
| `veh_trace_calls` | `addresses, duration_sec?, duration_ms?, resolve?, system_only?` | call/jmp 명령이 런타임에 어디로 가는지 모니터링. 콜 사이트에 BP 설치 후 N초간 실행, 실제 타겟 주소 + API 이름 수집. `resolve=true`: thunk/trampoline을 자연스러운 call 컨텍스트에서 따라가 최종 API까지 추적 (예외 기반 난독화 대응). `system_only=true`: 시스템 DLL 타겟만 반환. 패킹된 바이너리의 IAT 복원용. |
| `veh_trace_basic_blocks` | `threadId, start, end, ..., collect_snapshots?, compress_paths?, stop_on_return?, collect_events?, collect_memory_events?, collect_register_events?, collect_code?, ...` | DLL 내부 bounded trace. 선택적 function-return scope, ordered block/code/memory/register occurrence stream 및 block/edge, delta, memory, dependency, region, exception을 반환한다. |
| `veh_targeted_capture` | `inputs, steps?, trace, trigger, window, environment?, output_directory, stop_on_error?` | 입력별 setup 후 occurrence 전후 ordered trace와 환경 snapshot을 서버 파일에 저장한다. instruction이 1개 이상 완료되고 요청한 target-window stop으로 끝난 입력만 성공으로 집계한다. |
| `veh_checkpoint_create` | `threadId, regions?, capture_teb?, teb_size?` | GPR/flags(x64는 XMM 포함), TEB 및 FS/GS 환경과 선택 메모리를 저장한다. TEB bytes는 비교 전용이며 stack region은 saved SP부터의 안전한 복원 범위를 표시한다. |
| `veh_checkpoint_restore` | `id` | 동일 스레드가 VEH 정지된 상태에서 context와 선택 메모리를 복원한다. saved SP 아래의 live VEH stack frame은 보존하며 변경된 매핑은 거부하고 실패 시 rollback한다. |
| `veh_checkpoint_diff` | `id, other_id?` | checkpoint와 현재 상태 또는 다른 checkpoint의 register 및 변경 메모리 구간을 비교한다. |
| `veh_checkpoint_delete` | `id` | checkpoint를 삭제하고 서버 메모리 예산을 반환한다. |

**메모리 접근 수집**

`veh_trace_memory`는 `duration_ms`를 생략하면 기존 첫 쓰기 감지 모드로
동작합니다. 필수 인자는 `address`뿐이며 `size`는 기본 4바이트,
`timeout_ms`는 기본 10000ms입니다. `duration_ms`를 지정하면 실행을 계속하며
지정 시간(10~60000ms) 동안 위치별 접근 횟수를 수집하고 `timeout_ms`는 무시합니다.
`access`는 기본 `write`이며 `readwrite`는 읽기와 쓰기를 합쳐 수집합니다.
각 적중의 읽기·쓰기를 분류하거나 읽기만 수집하지는 않습니다.
`max_entries`는 기본 64개, 최대 1024개이며 저장하지 못한 위치의 적중 횟수는
`dropped_hits`로 반환합니다.

```json
{"address":"sample.exe+0x2000"}
{"address":"sample.exe+0x2000","duration_ms":1000,"access":"readwrite"}
```

VEH 수집은 하드웨어 데이터 중단점 슬롯 하나를 사용하며 주소는 감시 크기에 맞춰
정렬돼야 합니다. `instructionAddress`는 **접근 명령 실행 후 IP**이며
`addressIs="next_instruction"`으로 표시됩니다. 첫 적중의 레지스터도 실행 후
상태입니다. 모든 적중의 컨텍스트를 보존하는 대신 해당 위치별 횟수를 집계합니다.
외부 백엔드에서 이 모드를 사용하려면 `TraceMemoryCollect` 구현이 필요합니다.

**시스템 이벤트와 숨은 훅** (OS 아래에서 도는 하이퍼바이저 백엔드에 attach했을 때만 동작, 다른 백엔드는 사용 불가로 응답)

| 도구 | 주요 인자 | 설명 |
|------|-----------|------|
| `veh_event` | `operation, type, value?/low?/high?, address?, size?, pid?, tid?, cpu?, mode?, action?` | 머신 전체 이벤트: `cpuid`, `msr_read`/`msr_write`, `exception`, `port_in`/`port_out`, `syscall`/`sysret`, `hypercall`, `xsetbv`, `rdtsc`, `dr_access`(디버그 레지스터 접근), `interrupt`(외부 인터럽트, 기록 뒤 그대로 전달), `memory_read`/`memory_write`/`memory_execute`. 조건(pid/tid/CPU/커널·유저/값 범위)에 맞으면 레지스터와 함께 기록. 가로챈 명령은 그대로 한 번 실제 실행되므로 대상은 차이를 보지 못한다. `action=stop`은 커널 디버거가 연결돼 있으면 머신 전체를 정지 |
| `veh_event_records` | `max?, registers?` | 이벤트 기록 가져오기 (CPU, 프로세스/스레드, 모드, 값, rip/rsp/cr3, 타임스탬프) |
| `veh_branch_trace` | `operation?, kind?, threadId?, buffer_kb?, max?` | 명시적 `kind="ptwrite"`는 값·명령 주소·유실 요약 수집([규약](docs/INSTRUMENTATION.md), 기본 상세 미반환). 기존 하드웨어 분기 기록: `last`(LBR: 스레드가 멈추기 직전 분기들), `full`(Intel PT: 대상 프로세스의 전체 실행 경로를 분기 목록으로 복원). `status`는 이 기계에서 무엇을 쓸 수 있는지, 못 쓰면 이유(제조사, 하위 하이퍼바이저 미노출, 비활성)와 대안을 알려준다 |
| `veh_hidden_hook` | `operation, address, pid?, set?, return?, pop?` | 숨은 실행 훅: 주소가 실행될 때 레지스터를 바꾸거나(`set`) 함수를 즉시 반환값과 함께 돌려보냄(`return`, stdcall은 `pop`). 코드 바이트는 그대로, 스레드도 멈추지 않음. `pid` 생략 시 커널 주소 |

**정지형 커널 디버깅** (GDB 원격 시리얼 프로토콜 스텁에 연결, 대상 프로세스 attach와 무관)

| 도구 | 주요 인자 | 설명 |
|------|-----------|------|
| `veh_kd_connect` | `transport, address, baud?` | `pipe`(VM의 COM 포트를 연결한 호스트 named pipe), `com`, `tcp`, `udp`(디버거 전용 NIC, `ip:port`, 유실·재정렬은 재전송으로 복구). 연결하면 대상 머신의 모든 CPU가 정지 |
| `veh_kd_continue` / `veh_kd_wait` / `veh_kd_break` | `wait?, timeout_ms?` | 재개, 다음 정지(브레이크포인트)까지 대기, 실행 중 정지(break-in) |
| `veh_kd_step` | `cpu?, count?` | 한 CPU만 한 명령씩 실행 (나머지 CPU는 정지 유지) |
| `veh_kd_registers` / `veh_kd_set_register` | `cpu?, name, value` | 정지한 CPU의 레지스터 (스텁이 주면 cr3, GS/FS base, IDT, CPL 포함) |
| `veh_kd_memory` | `operation, address, size?/count?/data?, cpu?` | 정지한 CPU의 페이지 테이블로 커널/유저 메모리 읽기, 쓰기, 디스어셈블 |
| `veh_kd_breakpoint` | `action, address` | 커널 실행 브레이크포인트. 하이퍼바이저 스텁은 코드를 바꾸지 않는 숨은 방식으로 건다 |
| `veh_kd_monitor` / `veh_kd_disconnect` | `command` | 스텁 전용 명령 (gdb `monitor`), 연결 해제 시 브레이크포인트 제거 후 재개 |

> **Non-stop 조회 (타겟 정지 불필요)**: `veh_read_memory` / `veh_read_pointer_chain` / `veh_write_memory` / `veh_dump_memory` / `veh_disassemble` / `veh_modules` / `veh_memory_map` / `veh_protect_memory` / `veh_search_memory` / `veh_value_scan` / `veh_symbolize` / `veh_display_type` 는 타겟이 **실행 중에도** 동작합니다 (DLL 내 전용 파이프 스레드가 처리 -- 다른 스레드를 멈추지 않음). GUI를 조작하면서 라이브 값을 읽을 때 BP를 걸거나 detach/attach를 왕복할 필요가 없습니다. 반대로 `veh_registers` / `veh_stack_trace` / `veh_enum_locals` / `veh_step_*` 는 스레드 컨텍스트가 필요하므로 BP 히트나 `veh_pause`로 정지된 상태에서만 동작합니다.

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


백엔드가 지원하면 `veh_virtual_machine(operation="status"|"pause"|"resume"|"trace")`로
VM 전체 상태 조회·정지·재개와 제한된 가상 CPU 트레이스를 요청할 수 있습니다.
트레이스는 다른 CPU가 멈춘 상태에서 선택한 CPU만 실행하며 CR3/CPL/RIP 경계,
실행·시간 한도, 인터프리터 엔진과 손실 개수를 보고합니다. 연결한 게스트 PID와
별개로 VM 전체에 영향을 줍니다. 선택한 OS 스레드만 정지시키는 기능은 아닙니다.
`veh_toolbox`에서 설명을 조회하고 수동 호출할 수 있습니다. 프로세스 범위 자동화가
VM 전체를 재개하지 않도록 batch·capture setup·브레이크포인트 actions에서는 제외합니다.


VM 자체에 연결할 때는 외부 백엔드를 VM 범위로 등록한 뒤
`veh_attach(target_scope="vm", backend="machine")`을 호출하고 `pid`는 생략합니다.
백엔드는 PID0/addressBits0인 VM 메타데이터를 확인해 줘야 합니다. VM 세션에는
호스트 대상 프로세스·OS 스레드 ID·단일 프로세스 주소 폭이 없습니다. VM agent는
`--pipe`와 설정 인자를 받고, 프로세스 agent에만 `--pid`도 전달됩니다.
`veh_virtual_machine`으로 VM 전체 제어와 제한된 가상 CPU 기록을 요청합니다.
물리 메모리 읽기·쓰기는 capability에 따라 제공하며 VM 범위 검색·덤프는 미지원입니다.
지원 백엔드에 VM 범위로 연결한 뒤 `veh_processes`로 게스트 PID를 찾고,
`veh_attach(target_scope="guest", pid=...)`로 해당 프로세스에 연결합니다.
짧은 이미지명에 포함된 비 ASCII 바이트는 `\\xNN`으로 표시합니다.
게스트 프로세스에 연결하는 기존 `target_scope="guest"`는 검증된 비영 PID를 사용합니다.

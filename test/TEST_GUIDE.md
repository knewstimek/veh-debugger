# VEH Debugger v1.0.4 수동 테스트 가이드

## 사전 준비

1. **관리자 권한**으로 VSCode 실행 (DLL 인젝션에 필요)
2. vsix 설치: `code --install-extension veh-debugger-win32-x64-1.0.4.vsix`
   또는 Extensions 패널 → ... → Install from VSIX

## 테스트 방법

### 방법 A: Launch (자동 실행)
1. VSCode에서 `test/` 폴더를 열기
2. F5 → "VEH: Launch test_target" 선택
3. stopOnEntry=true이므로 진입점에서 자동 중단

### 방법 B: Attach (직접 붙이기)
1. 관리자 CMD에서 `test\build\Release\test_target.exe` 실행
2. 출력된 PID 확인
3. VSCode F5 → "VEH: Attach to PID" → PID 입력
4. 중단 후 Pause(F6) 누르면 현재 위치에서 정지

## 테스트 항목

### 1. Hover 미리보기
- Disassembly 뷰 열기: Command Palette → "Open Disassembly View"
- 레지스터 이름(RAX, RCX 등)에 마우스 올리기 → 값 표시되는지 확인
- 주소(0x...)에 마우스 올리기 → 메모리 값 표시되는지 확인

### 2. 레지스터 수정
- Variables 패널에서 "Registers" scope 확인
- 레지스터 값 더블클릭 → 새 값 입력 (예: 0x1234)
- ⚠ DLL에 SetRegister 핸들러가 없으면 에러 메시지 표시됨 (정상)

### 3. 조건부 브레이크포인트
- Disassembly에서 주소 클릭 → BP 설정
- BP 우클릭 → "Edit Condition..." → `RAX==0x0` 같은 조건 입력
- Continue → 조건 만족 시에만 중단되는지 확인
- 조건 불만족 시 자동 계속 실행

### 4. Hit Count 브레이크포인트
- BP 우클릭 → "Edit Condition..." → Hit Count 탭 → 숫자 입력 (예: 5)
- Continue 반복 → N번째 히트에서 중단되는지 확인

### 5. Log Points
- Disassembly에서 라인 번호 옆 우클릭 → "Add Logpoint..."
- 메시지 입력: `counter hit! RAX={RAX} RCX={RCX}`
- Continue → Debug Console에 메시지 출력되는지 확인 (중단 없이)

## 기대 결과

| 기능 | 예상 동작 |
|------|-----------|
| Hover (레지스터) | 레지스터 값 hex로 표시 |
| Hover (주소) | [0xADDR] = 0x... 형태로 메모리 값 표시 |
| 레지스터 수정 | DLL 미지원시 에러 메시지 |
| 조건부 BP | 조건 불만족 → 자동 Continue |
| Hit Count | N번째에서 정지 |
| Log Point | Debug Console에 치환된 메시지 출력 |

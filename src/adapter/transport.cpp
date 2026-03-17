#include "transport.h"
#include "logger.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#pragma comment(lib, "ws2_32.lib")
#endif

namespace veh::dap {

// --- Transport base ---

std::string Transport::FormatMessage(const std::string& json) {
	std::ostringstream oss;
	oss << "Content-Length: " << json.size() << "\r\n\r\n" << json;
	return oss.str();
}

bool Transport::ParseMessage(const char* data, size_t len, size_t& consumed, std::string& message) {
	// Content-Length: <number>\r\n\r\n<json>
	const char* headerEnd = strstr(data, "\r\n\r\n");
	if (!headerEnd) return false;

	size_t headerLen = headerEnd - data + 4;
	const char* clHeader = strstr(data, "Content-Length:");
	if (!clHeader || clHeader >= headerEnd) return false;

	long long cl = strtoll(clHeader + 15, nullptr, 10);
	if (cl <= 0 || cl > 10 * 1024 * 1024) return false;  // 10MB 상한
	int contentLength = static_cast<int>(cl);

	if (len < headerLen + contentLength) return false;

	message.assign(data + headerLen, contentLength);
	consumed = headerLen + contentLength;
	return true;
}

// --- StdioTransport ---

bool StdioTransport::Start() {
#ifdef _WIN32
	// stdin/stdout을 바이너리 모드로 설정
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
	// stdin 버퍼링 비활성화 (파이프에서 fread 블로킹 방지)
	setvbuf(stdin, NULL, _IONBF, 0);
#endif

	running_ = true;
	readThread_ = std::thread(&StdioTransport::ReadThread, this);
	LOG_INFO("Stdio transport started");
	return true;
}

void StdioTransport::Stop() {
	running_ = false;
	// stdin을 닫아서 _read가 반환되게 함
	_close(_fileno(stdin));
	if (readThread_.joinable()) {
		readThread_.join();
	}
}

bool StdioTransport::Send(const std::string& json) {
	std::lock_guard<std::mutex> lock(writeMutex_);
	std::string msg = FormatMessage(json);
	size_t written = fwrite(msg.c_str(), 1, msg.size(), stdout);
	fflush(stdout);
	return written == msg.size();
}

void StdioTransport::ReadThread() {
	char buf[4096];
	int stdinFd = _fileno(stdin);
	while (running_) {
		// _read: unbuffered, 파이프에서 즉시 반환
		int n = _read(stdinFd, buf, sizeof(buf));
		if (n <= 0) {
			LOG_INFO("stdin EOF or error (n=%d), stopping", n);
			running_ = false;
			break;
		}

		readBuffer_.append(buf, n);

		// 버퍼에서 완전한 메시지 추출
		while (!readBuffer_.empty()) {
			size_t consumed = 0;
			std::string message;
			if (ParseMessage(readBuffer_.c_str(), readBuffer_.size(), consumed, message)) {
				readBuffer_.erase(0, consumed);
				if (callback_) callback_(message);
			} else {
				break;
			}
		}
	}
}

// --- TcpTransport ---

bool TcpTransport::Start() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		LOG_ERROR("WSAStartup failed");
		return false;
	}
	wsaInitialized_ = true;

	listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listenSocket_ == INVALID_SOCKET) {
		LOG_ERROR("socket() failed: %d", WSAGetLastError());
		return false;
	}

	// SO_REUSEADDR
	int opt = 1;
	setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(allowRemote_ ? INADDR_ANY : INADDR_LOOPBACK);
	addr.sin_port = htons(port_);

	if (bind(listenSocket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		LOG_ERROR("bind() failed on port %d: %d", port_, WSAGetLastError());
		closesocket(listenSocket_);
		return false;
	}

	if (listen(listenSocket_, 1) == SOCKET_ERROR) {
		LOG_ERROR("listen() failed: %d", WSAGetLastError());
		closesocket(listenSocket_);
		return false;
	}

	running_ = true;
	acceptThread_ = std::thread(&TcpTransport::AcceptThread, this);
	LOG_INFO("TCP transport listening on port %d", port_);

	// DAP 클라이언트에 포트 알림 (stderr로)
	fprintf(stderr, "VEH Debug Adapter listening on port %d\n", port_);
	fflush(stderr);

	return true;
}

void TcpTransport::Stop() {
	running_ = false;
	if (listenSocket_ != INVALID_SOCKET) {
		closesocket(listenSocket_);
		listenSocket_ = INVALID_SOCKET;
	}
	if (clientSocket_ != INVALID_SOCKET) {
		closesocket(clientSocket_);
		clientSocket_ = INVALID_SOCKET;
	}
	if (acceptThread_.joinable()) acceptThread_.join();
	if (readThread_.joinable()) readThread_.join();
	if (wsaInitialized_) {
		WSACleanup();
		wsaInitialized_ = false;
	}
}

bool TcpTransport::Send(const std::string& json) {
	if (clientSocket_ == INVALID_SOCKET) return false;

	std::lock_guard<std::mutex> lock(writeMutex_);
	std::string msg = FormatMessage(json);
	const char* ptr = msg.c_str();
	int remaining = (int)msg.size();
	while (remaining > 0) {
		int sent = send(clientSocket_, ptr, remaining, 0);
		if (sent <= 0) return false;
		ptr += sent;
		remaining -= sent;
	}
	return true;
}

void TcpTransport::AcceptThread() {
	while (running_) {
		sockaddr_in clientAddr = {};
		int addrLen = sizeof(clientAddr);
		SOCKET client = accept(listenSocket_, (sockaddr*)&clientAddr, &addrLen);
		if (client == INVALID_SOCKET) {
			if (running_) LOG_ERROR("accept() failed: %d", WSAGetLastError());
			break;
		}

		LOG_INFO("DAP client connected");
		clientSocket_ = client;

		// 읽기 스레드 시작
		if (readThread_.joinable()) readThread_.join();
		readThread_ = std::thread(&TcpTransport::ReadThread, this);
		break; // 단일 클라이언트만 허용 — VSCode가 세션마다 새 어댑터 프로세스를 spawn하므로 재연결 불필요
	}
}

void TcpTransport::ReadThread() {
	char buf[8192];
	while (running_ && clientSocket_ != INVALID_SOCKET) {
		int n = recv(clientSocket_, buf, sizeof(buf), 0);
		if (n <= 0) {
			if (n == 0) LOG_INFO("DAP client disconnected");
			else LOG_ERROR("recv() error: %d", WSAGetLastError());
			running_ = false; // 클라이언트 끊김 → 어댑터 프로세스 종료 (VSCode가 세션 종료로 처리)
			break;
		}

		readBuffer_.append(buf, n);

		while (!readBuffer_.empty()) {
			size_t consumed = 0;
			std::string message;
			if (ParseMessage(readBuffer_.c_str(), readBuffer_.size(), consumed, message)) {
				readBuffer_.erase(0, consumed);
				if (callback_) callback_(message);
			} else {
				break;
			}
		}
	}
}

} // namespace veh::dap

#pragma once
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace veh::dap {

// Transport interface for DAP communication
class Transport {
public:
	virtual ~Transport() = default;

	virtual bool Start() = 0;
	virtual void Stop() = 0;

	// Send a complete DAP message (adds Content-Length header)
	virtual bool Send(const std::string& json) = 0;

	// Set callback for received messages
	using MessageCallback = std::function<void(const std::string& json)>;
	void SetMessageCallback(MessageCallback cb) { callback_ = std::move(cb); }

protected:
	MessageCallback callback_;

	// Parse DAP messages from raw stream
	bool ParseMessage(const char* data, size_t len, size_t& consumed, std::string& message);
	std::string FormatMessage(const std::string& json);

	std::string readBuffer_;
};

// stdin/stdout transport (default for VSCode)
class StdioTransport : public Transport {
public:
	bool Start() override;
	void Stop() override;
	bool Send(const std::string& json) override;

private:
	void ReadThread();

	std::thread readThread_;
	std::atomic<bool> running_{false};
	std::mutex writeMutex_;
};

// TCP transport (for remote/MCP debugging)
class TcpTransport : public Transport {
public:
	explicit TcpTransport(uint16_t port, bool allowRemote = false)
		: port_(port), allowRemote_(allowRemote) {}

	bool Start() override;
	void Stop() override;
	bool Send(const std::string& json) override;

private:
	void AcceptThread();
	void ReadThread();

	uint16_t port_;
	bool allowRemote_ = false;
	SOCKET listenSocket_ = INVALID_SOCKET;
	SOCKET clientSocket_ = INVALID_SOCKET;
	std::thread acceptThread_;
	std::thread readThread_;
	std::atomic<bool> running_{false};
	std::mutex writeMutex_;
	bool wsaInitialized_ = false;
};

// MCP stdio transport (newline-delimited JSON, no Content-Length header)
class McpStdioTransport : public Transport {
public:
	bool Start() override;
	void Stop() override;
	bool Send(const std::string& json) override;

private:
	void ReadThread();

	std::thread readThread_;
	std::atomic<bool> running_{false};
	std::mutex writeMutex_;
};

} // namespace veh::dap

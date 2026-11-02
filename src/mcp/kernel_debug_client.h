#pragma once
// Client for a halting kernel debugger that speaks the GDB remote serial
// protocol (RSP): a hypervisor stub, a VM's gdbstub, or anything gdb could
// attach to. Transports: a named pipe (e.g. a VM's COM port mapped to a host
// pipe), a serial port, or TCP.
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace veh {

class KdTransport {
public:
	virtual ~KdTransport() = default;
	virtual bool Write(const void* data, size_t size) = 0;
	// Bytes received within timeout_ms (0 = only what is already there); -1 on a broken link.
	virtual int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) = 0;
};

// "pipe" (\\.\pipe\name), "com" (COM1, baud), "tcp" (host:port), "udp" (ip:port, stop-and-wait reliable).
std::unique_ptr<KdTransport> OpenKdTransport(const std::string& kind, const std::string& address, uint32_t baud,
	std::string* error);

class KernelDebugClient {
public:
	explicit KernelDebugClient(std::unique_ptr<KdTransport> transport) : transport_(std::move(transport)) {}

	// qSupported, no-ack mode, initial stop reason; halts the target if it was running.
	bool Handshake(std::string* stop, std::string* error);
	// One request, one reply (empty reply = unsupported); false on timeout or a broken link.
	bool Request(const std::string& packet, std::string* reply, uint32_t timeout_ms = 5000);
	// qRcmd: the console output, collected from O packets until OK (or one
	// hex reply from stubs that answer in a single packet).
	bool Monitor(const std::string& hex_command, std::string* hex_output, uint32_t timeout_ms = 10000);
	// Resume (c / vCont;s:N): no reply until the target stops again.
	bool Resume(const std::string& packet);
	// Stop reply after Resume; false on timeout (the target keeps running).
	bool WaitStop(std::string* stop, uint32_t timeout_ms);
	bool Interrupt(std::string* stop, uint32_t timeout_ms); // 0x03
	// '?' after a lost stop reply: true when the stub answers a stop reason.
	bool QueryStop(std::string* stop, uint32_t timeout_ms);
	bool running() const { return running_; }
	const std::string& last_stop() const { return last_stop_; }
	// Why the last WaitStop failed (the server's stderr is not kept).
	const std::string& wait_diagnostic() const { return wait_diagnostic_; }

private:
	bool Send(const std::string& payload);
	bool Receive(std::string* payload, uint32_t timeout_ms);
	bool CompletePending(std::string* output, uint64_t deadline, bool& success);
	bool DrainPending(uint64_t deadline);
	enum class PendingReply { None, Request, Monitor };
	PendingReply pending_reply_ = PendingReply::None;
	bool pending_asks_stop_ = false;
	bool pending_monitor_invalid_ = false;
	bool transport_usable_ = true;

	std::unique_ptr<KdTransport> transport_;
	std::string buffer_;
	std::string unacked_frame_;
	unsigned nak_retries_ = 0;
	bool ack_ = true;
	bool running_ = false;
	std::string last_stop_;
	std::string wait_diagnostic_;
	// The last bytes on the link (">" sent, "<" received), for diagnostics.
	std::string trace_;
	void Trace(char dir, const char* data, size_t n);
public:
	const std::string& trace() const { return trace_; }
};

} // namespace veh

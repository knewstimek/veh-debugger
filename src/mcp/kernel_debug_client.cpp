#include "kernel_debug_client.h"
#include <cctype>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdio>

namespace veh {
namespace {

uint64_t NowMs()
{
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count());
}

// Overlapped: a read waits for data or the timeout, without polling.
class PipeTransport : public KdTransport {
public:
	explicit PipeTransport(HANDLE h) : h_(h), ev_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}
	~PipeTransport() override
	{
		CloseHandle(h_);
		if (ev_)
			CloseHandle(ev_);
	}
	bool Write(const void* data, size_t size) override
	{
		DWORD n = 0;
		return Io(false, const_cast<void*>(data), size, INFINITE, &n) && n == size;
	}
	int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) override
	{
		DWORD n = 0;
		return Io(true, buffer, max, timeout_ms, &n) ? static_cast<int>(n) : -1;
	}

private:
	bool Io(bool read, void* data, size_t size, DWORD timeout_ms, DWORD* done)
	{
		OVERLAPPED ov = {};
		ov.hEvent = ev_;
		ResetEvent(ev_);
		const BOOL ok = read ? ReadFile(h_, data, static_cast<DWORD>(size), nullptr, &ov)
			: WriteFile(h_, data, static_cast<DWORD>(size), nullptr, &ov);
		if (!ok && GetLastError() != ERROR_IO_PENDING)
			return false;
		if (!ok && WaitForSingleObject(ev_, timeout_ms) == WAIT_TIMEOUT)
			CancelIoEx(h_, &ov); // nothing arrived in time: 0 bytes
		if (GetOverlappedResult(h_, &ov, done, TRUE))
			return true;
		return GetLastError() == ERROR_OPERATION_ABORTED;
	}

	HANDLE h_;
	HANDLE ev_;
};

class ComTransport : public KdTransport {
public:
	explicit ComTransport(HANDLE h) : h_(h) {}
	~ComTransport() override { CloseHandle(h_); }
	bool Write(const void* data, size_t size) override
	{
		DWORD n = 0;
		return WriteFile(h_, data, static_cast<DWORD>(size), &n, nullptr) && n == size;
	}
	int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) override
	{
		COMMTIMEOUTS t = {};
		t.ReadIntervalTimeout = MAXDWORD;
		t.ReadTotalTimeoutMultiplier = MAXDWORD;
		t.ReadTotalTimeoutConstant = timeout_ms ? timeout_ms : 1;
		SetCommTimeouts(h_, &t);
		DWORD n = 0;
		if (!ReadFile(h_, buffer, static_cast<DWORD>(max), &n, nullptr))
			return -1;
		return static_cast<int>(n);
	}

private:
	HANDLE h_;
};

class TcpTransport : public KdTransport {
public:
	explicit TcpTransport(SOCKET s) : s_(s) {}
	~TcpTransport() override { closesocket(s_); }
	bool Write(const void* data, size_t size) override
	{
		return send(s_, static_cast<const char*>(data), static_cast<int>(size), 0) == static_cast<int>(size);
	}
	int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) override
	{
		fd_set set;
		FD_ZERO(&set);
		FD_SET(s_, &set);
		timeval tv = { static_cast<long>(timeout_ms / 1000), static_cast<long>((timeout_ms % 1000) * 1000) };
		const int ready = select(0, &set, nullptr, nullptr, &tv);
		if (ready <= 0)
			return ready;
		const int n = recv(s_, reinterpret_cast<char*>(buffer), static_cast<int>(max), 0);
		return n > 0 ? n : -1;
	}

private:
	SOCKET s_;
};

// UDP to a stub that keeps the byte stream reliable with stop-and-wait:
// datagram = 'K' 'D' type seq16 payload; DATA is acknowledged by an ACK with
// the same seq, resent until it is, duplicates acknowledged and dropped.
class UdpTransport : public KdTransport {
public:
	explicit UdpTransport(SOCKET s) : s_(s) {}
	~UdpTransport() override { closesocket(s_); }

	bool Write(const void* data, size_t size) override
	{
		const auto* p = static_cast<const uint8_t*>(data);
		while (size) {
			const size_t n = size < 1400 ? size : 1400;
			if (!SendReliably(p, n))
				return false;
			p += n;
			size -= n;
		}
		return true;
	}

	int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) override
	{
		if (in_.empty())
			Receive(timeout_ms);
		const size_t n = in_.size() < max ? in_.size() : max;
		for (size_t i = 0; i < n; ++i)
			buffer[i] = in_[i];
		in_.erase(in_.begin(), in_.begin() + static_cast<std::ptrdiff_t>(n));
		return static_cast<int>(n);
	}

private:
	enum : uint8_t { kData = 1, kAck = 2 };

	void Segment(uint8_t type, uint16_t seq, const uint8_t* data, size_t n)
	{
		std::string d = "KD";
		d += static_cast<char>(type);
		d += static_cast<char>(seq & 0xFF);
		d += static_cast<char>(seq >> 8);
		d.append(reinterpret_cast<const char*>(data), n);
		send(s_, d.data(), static_cast<int>(d.size()), 0);
	}

	// One datagram within timeout_ms: DATA is acknowledged and queued, an ACK returned.
	int Receive(uint32_t timeout_ms)
	{
		fd_set set;
		FD_ZERO(&set);
		FD_SET(s_, &set);
		timeval tv = { static_cast<long>(timeout_ms / 1000), static_cast<long>((timeout_ms % 1000) * 1000) };
		if (select(0, &set, nullptr, nullptr, &tv) <= 0)
			return -1;
		char d[2048];
		const int n = recv(s_, d, sizeof(d), 0);
		if (n < 5 || d[0] != 'K' || d[1] != 'D')
			return -1;
		const uint16_t seq = static_cast<uint16_t>(static_cast<uint8_t>(d[3]) | (static_cast<uint8_t>(d[4]) << 8));
		if (d[2] == kAck)
			return seq;
		if (d[2] != kData)
			return -1;
		Segment(kAck, seq, nullptr, 0);
		if (!synced_) { // the stub's numbering continues across sessions
			synced_ = true;
			expect_ = seq;
		}
		if (seq == expect_) {
			++expect_;
			in_.insert(in_.end(), d + 5, d + n);
		}
		return -1;
	}

	bool SendReliably(const uint8_t* data, size_t n)
	{
		for (int attempt = 0; attempt < 40; ++attempt) {
			Segment(kData, seq_, data, n);
			const uint64_t end = NowMs() + 150;
			for (uint64_t now = NowMs(); now < end; now = NowMs())
				if (Receive(static_cast<uint32_t>(end - now)) == seq_) {
					++seq_;
					return true;
				}
		}
		return false;
	}

	SOCKET s_;
	uint16_t seq_ = 0;   // the stub restarts its expectation at 0
	uint16_t expect_ = 0;
	bool synced_ = false;
	std::vector<uint8_t> in_;
};

const char kHex[] = "0123456789abcdef";

} // namespace

std::unique_ptr<KdTransport> OpenKdTransport(const std::string& kind, const std::string& address, uint32_t baud,
	std::string* error)
{
	if (kind == "pipe" || kind == "com") {
		std::string path = address;
		if (kind == "com" && path.rfind("\\\\.\\", 0) != 0)
			path = "\\\\.\\" + path; // COM10 and up need the device prefix
		HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
			kind == "pipe" ? FILE_FLAG_OVERLAPPED : 0, nullptr);
		if (h == INVALID_HANDLE_VALUE) {
			*error = "open " + path + " failed: " + std::to_string(GetLastError()) +
				(GetLastError() == ERROR_PIPE_BUSY ? " (another client is connected)" : "");
			return nullptr;
		}
		if (kind == "pipe")
			return std::make_unique<PipeTransport>(h);
		DCB dcb = { sizeof(dcb) };
		GetCommState(h, &dcb);
		dcb.BaudRate = baud ? baud : 115200;
		dcb.ByteSize = 8;
		dcb.Parity = NOPARITY;
		dcb.StopBits = ONESTOPBIT;
		dcb.fBinary = TRUE;
		if (!SetCommState(h, &dcb)) {
			*error = "configure " + path + " failed: " + std::to_string(GetLastError());
			CloseHandle(h);
			return nullptr;
		}
		return std::make_unique<ComTransport>(h);
	}
	if (kind == "udp") {
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
		const size_t colon = address.rfind(':');
		if (colon == std::string::npos) {
			*error = "udp address must be ip:port";
			return nullptr;
		}
		sockaddr_in to = {};
		to.sin_family = AF_INET;
		to.sin_port = htons(static_cast<u_short>(std::stoi(address.substr(colon + 1))));
		if (inet_pton(AF_INET, address.substr(0, colon).c_str(), &to.sin_addr) != 1) {
			*error = "udp address must be ip:port (IPv4)";
			return nullptr;
		}
		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s == INVALID_SOCKET || connect(s, reinterpret_cast<sockaddr*>(&to), sizeof(to)) != 0) {
			*error = "udp socket failed: " + std::to_string(WSAGetLastError());
			if (s != INVALID_SOCKET)
				closesocket(s);
			return nullptr;
		}
		return std::make_unique<UdpTransport>(s);
	}
	if (kind == "tcp") {
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
		const size_t colon = address.rfind(':');
		if (colon == std::string::npos) {
			*error = "tcp address must be host:port";
			return nullptr;
		}
		addrinfo hints = {};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		addrinfo* found = nullptr;
		if (getaddrinfo(address.substr(0, colon).c_str(), address.substr(colon + 1).c_str(), &hints, &found) != 0 || !found) {
			*error = "resolve " + address + " failed";
			return nullptr;
		}
		SOCKET s = socket(found->ai_family, found->ai_socktype, found->ai_protocol);
		const bool ok = s != INVALID_SOCKET && connect(s, found->ai_addr, static_cast<int>(found->ai_addrlen)) == 0;
		freeaddrinfo(found);
		if (!ok) {
			*error = "connect " + address + " failed: " + std::to_string(WSAGetLastError());
			if (s != INVALID_SOCKET)
				closesocket(s);
			return nullptr;
		}
		const BOOL nodelay = TRUE;
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
		return std::make_unique<TcpTransport>(s);
	}
	*error = "transport must be pipe, com or tcp";
	return nullptr;
}

void KernelDebugClient::Trace(char dir, const char* data, size_t n)
{
	if (!n)
		return;
	trace_ += dir;
	for (size_t i = 0; i < n; ++i)
		trace_ += (data[i] >= 0x20 && data[i] < 0x7F) ? data[i] : '.';
	if (trace_.size() > 400)
		trace_.erase(0, trace_.size() - 400);
}

bool KernelDebugClient::Send(const std::string& payload)
{
	uint8_t sum = 0;
	for (char c : payload)
		sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(c));
	const std::string frame = "$" + payload + "#" + kHex[sum >> 4] + kHex[sum & 15];
	Trace('>', frame.data(), frame.size());
	return transport_->Write(frame.data(), frame.size());
}

bool KernelDebugClient::Receive(std::string* payload, uint32_t timeout_ms)
{
	const uint64_t end = NowMs() + timeout_ms;
	for (;;) {
		const size_t start = buffer_.find('$');
		if (start != std::string::npos) {
			const size_t hash = buffer_.find('#', start);
			if (hash != std::string::npos && buffer_.size() >= hash + 3) {
                const auto hex=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
                uint8_t sum=0;for(size_t i=start+1;i<hash;++i)sum=static_cast<uint8_t>(sum+static_cast<uint8_t>(buffer_[i]));
                const int hi=hex(buffer_[hash+1]),lo=hex(buffer_[hash+2]);
                const bool valid=hi>=0&&lo>=0&&sum==static_cast<uint8_t>(hi*16+lo);
                *payload = buffer_.substr(start + 1, hash - start - 1);
                buffer_.erase(0, hash + 3);
                if(!valid){
                    wait_diagnostic_="RSP checksum mismatch";
                    if(!ack_)return false; // no-ack peers cannot retransmit this reply
                    Trace('>',"-",1);if(!transport_->Write("-",1))return false;
                    continue;
                }
				// VirtualBox's stub ends every payload with a NUL byte.
				while (!payload->empty() && payload->back() == '\0')
					payload->pop_back();
				if (ack_)
					{ Trace('>', "+", 1); transport_->Write("+", 1); }
				return true;
			}
		}
		const uint64_t now = NowMs();
		if (now >= end)
			return false;
		uint8_t chunk[4096];
		const int n = transport_->Read(chunk, sizeof(chunk), static_cast<uint32_t>(end - now < 50 ? end - now : 50));
		if (n < 0)
			return false;
		Trace('<', reinterpret_cast<char*>(chunk), static_cast<size_t>(n));
		buffer_.append(reinterpret_cast<char*>(chunk), static_cast<size_t>(n));
	}
}

bool KernelDebugClient::Request(const std::string& packet, std::string* reply, uint32_t timeout_ms)
{
	const auto deadline = NowMs() + timeout_ms;
	if (!Send(packet) || !Receive(reply, timeout_ms))
		return false;
	// Live (VirtualBox DBGC): after a breakpoint stop the console prints the
	// event as O<hex> packets, which then preceded the next reply ('z0' was
	// answered "O30"). No reply of ours starts with 'O' except OK.
	const auto console = [](const std::string& r) {
		return r.size() > 1 && r[0] == 'O' && r != "OK" &&
			r.find_first_not_of("0123456789abcdefABCDEF", 1) == std::string::npos;
	};
	// A stop reply answers only '?' and resumes; another one here is a late
	// event (live: 'z0' after a breakpoint stop got "T05thread:01;").
	const bool asks_stop = packet == "?";
	const auto late_stop = [&](const std::string& r) {
		return !asks_stop && r.size() >= 3 && (r[0] == 'T' || r[0] == 'S') &&
			std::isxdigit(static_cast<unsigned char>(r[1])) && std::isxdigit(static_cast<unsigned char>(r[2]));
	};
	for (int skipped = 0; (console(*reply) || late_stop(*reply)) && skipped < 4096; ++skipped) {
		if (late_stop(*reply))
			last_stop_ = *reply;
		const auto now = NowMs();
		if (now >= deadline || !Receive(reply, static_cast<uint32_t>(deadline - now)))
			return false;
	}
	return !console(*reply) && !late_stop(*reply);
}

bool KernelDebugClient::Monitor(const std::string& hex_command, std::string* hex_output, uint32_t timeout_ms)
{
	hex_output->clear();
	const auto deadline = NowMs() + timeout_ms;
	if (!Send("qRcmd," + hex_command))
		return false;
	// Live (VirtualBox DBGC): O<hex> packets, then OK; reading only the first
	// left the rest in the stream and every later reply was a packet late.
	for (int packets = 0; packets < 4096; ++packets) {
		std::string reply;
		const auto now = NowMs();
		if (now >= deadline || !Receive(&reply, static_cast<uint32_t>(deadline - now)))
			return false;
		if (reply == "OK" || reply.empty())
			return true;
		if (reply[0] == 'E' && reply.size() == 3)
			return false;
		if (reply[0] == 'O') {
			hex_output->append(reply, 1, std::string::npos);
			continue;
		}
		hex_output->append(reply); // a stub answering with one hex packet
		return true;
	}
	return false;
}

bool KernelDebugClient::Handshake(std::string* stop, std::string* error)
{
	std::string reply;
	// The first packet halts a target that was running; give it time.
	if (!Request("qSupported:swbreak+;hwbreak+;xmlRegisters=i386", &reply, 15000)) {
		*error = "no answer to qSupported (is the stub enabled and the transport right?)";
		return false;
	}
	// A stub that halts on connect (VirtualBox's DBGC) sends its stop reply
	// unasked, ahead of the qSupported answer: keep it and read the answer.
	if (!reply.empty() && (reply[0] == 'T' || reply[0] == 'S') && !Receive(&reply, 5000)) {
		*error = "no answer to qSupported after the stub's stop reply";
		return false;
	}
	if (Request("QStartNoAckMode", &reply) && reply == "OK")
		ack_ = false;
	if (!Request("?", stop)) {
		*error = "no stop reason";
		return false;
	}
	last_stop_ = *stop;
	running_ = false;
	return true;
}

bool KernelDebugClient::Resume(const std::string& packet)
{
	if (!Send(packet))
		return false;
	running_ = true;
	return true;
}

bool KernelDebugClient::WaitStop(std::string* stop, uint32_t timeout_ms)
{
	if (!running_) {
		*stop = last_stop_;
		return true;
	}
	// Live (VirtualBox DBGC): the console announces the event as O<hex>
	// packets ("dbgf event: Breakpoint ...") before the stop reply; taking
	// one as the stop left the real T packet to answer the next request.
	const auto deadline = GetTickCount64() + timeout_ms;
	for (int skipped = 0; skipped < 4096; ++skipped) {
		const auto now = GetTickCount64();
		if (now >= deadline || !Receive(stop, static_cast<uint32_t>(deadline - now))) {
			char note[160];
			std::snprintf(note, sizeof(note), "no stop reply within %u ms (%d console packet(s) skipped, %zu byte(s) buffered%s%.40s)",
				timeout_ms, skipped, buffer_.size(), buffer_.empty() ? "" : ": ", buffer_.c_str());
			wait_diagnostic_ = std::string(note) + " trace: " + trace_;
			return false;
		}
		const bool console = stop->size() > 1 && (*stop)[0] == 'O' && *stop != "OK" &&
			stop->find_first_not_of("0123456789abcdefABCDEF", 1) == std::string::npos;
		// Acknowledgements/unsupported vCont replies are not evidence of a stop.
		const bool stopped = stop->size() >= 3 &&
			((*stop)[0] == 'T' || (*stop)[0] == 'S' || (*stop)[0] == 'W' || (*stop)[0] == 'X') &&
			std::isxdigit(static_cast<unsigned char>((*stop)[1])) &&
			std::isxdigit(static_cast<unsigned char>((*stop)[2]));
		if (!console && stop->size() == 3 && (*stop)[0] == 'E' &&
			std::isxdigit(static_cast<unsigned char>((*stop)[1])) && std::isxdigit(static_cast<unsigned char>((*stop)[2]))) {
			wait_diagnostic_ = "resume refused: " + *stop;
			return false; // QueryStop must still confirm the actual halted state.
		}
		if (!console && stopped) {
			running_ = false;
			last_stop_ = *stop;
			wait_diagnostic_.clear();
			return true;
		}
	}
	wait_diagnostic_ = "no valid stop reply (packet limit reached)";
	return false;
}

bool KernelDebugClient::QueryStop(std::string* stop, uint32_t timeout_ms)
{
	std::string reply;
	if (!Request("?", &reply, timeout_ms) || reply.size() < 3 || (reply[0] != 'T' && reply[0] != 'S'))
		return false;
	*stop = reply;
	last_stop_ = reply;
	running_ = false;
	return true;
}

bool KernelDebugClient::Interrupt(std::string* stop, uint32_t timeout_ms)
{
	if (!running_) {
		*stop = last_stop_;
		return true;
	}
	// Live (tools/kd_stub_probe.ps1 against VirtualBox's stub): the 0x03 byte
	// was ignored while the target ran (RIP kept moving); "vCont;t", which the
	// stub advertises (vContSupported+), halted it with a stop reply within
	// 30 ms. Other stubs get the interrupt byte after a second.
	// Live (kd_x64, run 224301; the stub's link trace): vCont;t sent a few ms
	// after 'c' was acknowledged and ignored. The stub checks "halted" before
	// halting and the resume had not taken effect yet, so it did nothing and
	// the target then ran. vCont;t is repeated each second (a halted stub
	// ignores it), alternating with the interrupt byte for other stubs.
	const auto deadline = GetTickCount64() + timeout_ms;
	for (unsigned attempt = 0;; ++attempt) {
		const bool sent = (attempt & 1) ? transport_->Write("\x03", 1) : Send("vCont;t");
		if (!sent)
			return false;
		const auto now = GetTickCount64();
		if (now >= deadline)
			return false;
		const auto slice = static_cast<uint32_t>(std::min<uint64_t>(deadline - now, attempt ? 1000 : 300));
		if (WaitStop(stop, slice))
			return true;
	}
}

} // namespace veh

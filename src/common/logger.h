#pragma once
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <mutex>
#include <string>

namespace veh {

enum class LogLevel { Debug, Info, Warning, Error };

class Logger {
public:
	static Logger& Instance() {
		static Logger instance;
		return instance;
	}

	void SetLevel(LogLevel level) { level_ = level; }

	void SetFile(const std::string& path) {
		std::lock_guard<std::mutex> lock(mutex_);
		if (file_ && file_ != stderr) {
			fclose(file_);
		}
		file_ = fopen(path.c_str(), "a");
		if (!file_) file_ = stderr;
	}

	void Log(LogLevel level, const char* fmt, ...) {
		if (level < level_) return;

		std::lock_guard<std::mutex> lock(mutex_);

		time_t now = time(nullptr);
		struct tm tm;
		localtime_s(&tm, &now);

		fprintf(file_, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			LevelStr(level));

		va_list args;
		va_start(args, fmt);
		vfprintf(file_, fmt, args);
		va_end(args);

		fprintf(file_, "\n");
		fflush(file_);
	}

private:
	Logger() : file_(stderr), level_(LogLevel::Info) {}
	~Logger() {
		if (file_ && file_ != stderr) fclose(file_);
	}

	const char* LevelStr(LogLevel level) {
		switch (level) {
		case LogLevel::Debug:   return "DBG";
		case LogLevel::Info:    return "INF";
		case LogLevel::Warning: return "WRN";
		case LogLevel::Error:   return "ERR";
		default:                return "???";
		}
	}

	FILE* file_;
	LogLevel level_;
	std::mutex mutex_;
};

#define LOG_DEBUG(fmt, ...) veh::Logger::Instance().Log(veh::LogLevel::Debug, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  veh::Logger::Instance().Log(veh::LogLevel::Info, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  veh::Logger::Instance().Log(veh::LogLevel::Warning, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) veh::Logger::Instance().Log(veh::LogLevel::Error, fmt, ##__VA_ARGS__)

} // namespace veh

#pragma once

#include <string>
#include <chrono>
#include <mutex>
#include <functional>

/**
* This class provides a caching mechanism for metric values that are expensive to retrieve, such as GPU information. 
* It stores the last retrieved value along with a timestamp, and only refreshes the value if a specified cache duration has elapsed. 
* This helps reduce overhead while still providing reasonably up-to-date information.
*/
template<typename T>
class MetricCache {
public:
	/** 
	 * @brief Constructs a MetricCache with a specified cache duration and retrieval function.
	 * @param ttl_seconds The time-to-live for the cache in seconds. After this duration, the cached value will be considered stale and will be refreshed on the next request.
	*/
	explicit MetricCache(int ttl_seconds)
		: ttl_(std::chrono::seconds(ttl_seconds))
		, lastUpdate_(std::chrono::steady_clock::time_point::min())
		, isValid_(false)
	{}

	/**
	 * @brief Get cached value or compute new one if expired
	 * @param computeFunc Function to call if cache is expired
	 * @return The Cached or freshly computed value
	*/
	T get(std::function<T()> computeFunc) {
		std::lock_guard<std::mutex> lock(mutex_);

		auto now = std::chrono::steady_clock::now();
		auto elapsed = now - lastUpdate_;

		if (!isValid_ || elapsed >= ttl_) {
			cachedValue_ = computeFunc();
			lastUpdate_ = now;
			isValid_ = true;
		}

		return cachedValue_;
	}

	/** 
	* @brief Force cache invalidation (next get() will recompute)
	*/
	void invalidate() {
		std::lock_guard<std::mutex> lock(mutex_);
		isValid_ = false;
	}

	/** 
	* @brief Check if cache currently holds valid data
	*/
	bool isValid() const {
		std::lock_guard<std::mutex> lock(mutex_);
		auto now = std::chrono::steady_clock::now();
		auto elapsed = now - lastUpdate_;
		return isValid_ && (elapsed < ttl_);
	}

	/**
	* @brief Get the current TTL setting
	*/
	int getTtlSeconds() const {
		return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(ttl_).count());
	}

	/**
	* @brief Change TTL (does not invalidate existing cache)
	*/
	void setTtl(int ttl_seconds) {
		std::lock_guard<std::mutex> lock(mutex_);
		ttl_ = std::chrono::seconds(ttl_seconds);
	}

private:
	T cachedValue_;
	std::chrono::steady_clock::time_point lastUpdate_;
	std::chrono::seconds ttl_;
	bool isValid_;
	mutable std::mutex mutex_;
};

/**
* @brief Cache duration constants for metric types
*/
namespace CacheDurations {
	// Frequently changing metrics
	constexpr int CPU_USAGE = 0;
	constexpr int RAM_USAGE = 0;
	constexpr int DISK_QUEUE = 0;
	constexpr int NET_RETRANS = 0;
	constexpr int SYSTEM_UPTIME = 0;
	constexpr int GPU_USAGE = 5;

	constexpr int FREE_DISK_SPACE = 60;
	constexpr int HIGH_RAM_PROCS = 30;

	constexpr int WINDOWS_UPDATE = 300;
	constexpr int GPU_DRIVER_INFO = 3600;
}
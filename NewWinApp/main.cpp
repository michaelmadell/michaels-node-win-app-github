#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <vector>
#include <memory>
#include <csignal>
#include <algorithm>
#include <atomic>
#include "SystemInfo.hpp"
#include "../NewWinAppTray/resource.h"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace boost::asio;

boost::asio::io_context* g_io_context = nullptr;

class ServiceApp {
	io_context& io_;
	serial_port serial_;
	steady_timer telemetry_timer_;
	streambuf read_buf_;
	std::unique_ptr<SystemMonitor> monitor_;

	const int UPDATE_INTERVAL_SEC = 5;

	// Last-sent state for change detection
	std::string last_username_;
	int last_session_state_ = INT_MIN;
	double last_cpu_ = -1.0;
	double last_ram_ = -1.0;
	std::vector<NetworkInterface> last_nets_;

	std::atomic_bool running_{ true };

public:
	ServiceApp(io_context& io, const std::string& port_name)
		: io_(io),
		serial_(io),
		telemetry_timer_(io)
	{
		monitor_ = SystemMonitor::Create();

		try {
			serial_.open(port_name);
			serial_.set_option(serial_port_base::baud_rate(115200));
			serial_.set_option(serial_port_base::character_size(8));
			serial_.set_option(serial_port_base::parity(serial_port_base::parity::none));
			serial_.set_option(serial_port_base::stop_bits(serial_port_base::stop_bits::one));
			serial_.set_option(serial_port_base::flow_control(serial_port_base::flow_control::none));

			std::cout << "Serial port " << port_name << " opened." << std::endl;

			start_receive();

			send_startup_info();

			start_telemetry_loop();
		}
		catch (boost::system::system_error& e) {
			std::cerr << "Error opening serial port: " << e.what() << std::endl;
		}
	}

	void stop() {
		if (!running_.exchange(false)) return;
		boost::system::error_code ec;
		telemetry_timer_.cancel();
		serial_.close(ec);
		io_.stop();
	}

private:

	void start_receive() {
		async_read_until(serial_, read_buf_, "\n",
			boost::bind(&ServiceApp::handle_receive, this, placeholders::error, placeholders::bytes_transferred));
	}

	void handle_receive(const boost::system::error_code& error, size_t bytes_transferred) {
		if (!error) {
			std::istream is(&read_buf_);
			std::string line;
			std::getline(is, line);

			// Trim trailing CR if present (serial lines often end CRLF)
			if (!line.empty() && line.back() == '\r') line.pop_back();

			// Debug: always log the raw line
			std::cout << "[DEBUG] Serial Raw Line (" << bytes_transferred << " bytes): \"" << line << "\"" << std::endl;

			// Send entire line to tray application (previously only "c2a" commands were forwarded).
			// This ensures TrayApp receives all serial data lines.
			if (!line.empty()) {
				notify_agent(line);
			}

			// Existing command parsing retained for local handling/logging
			size_t idx = line.find("c2a, ");
			if (idx != std::string::npos) {
				std::string msg = line.substr(idx + 3);
				msg.erase(msg.find_last_not_of(" \n\r\t") + 1);
				std::cout << "[DEBUG] Command parsed: " << msg << std::endl;
				// Note: we already forwarded the full line above; if you want to forward only the parsed
				// command as well, uncomment the following line:
				// notify_agent(msg);
			}

			read_buf_.consume(bytes_transferred);
			start_receive();
		}
		else {
			std::cerr << "Receive error: " << error.message() << std::endl;
		}
	}

	void notify_agent(const std::string& msg) {
		try {
			ip::tcp::socket sock(io_);
			ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), 65432);

			// Debug: report IPC attempt
			std::cout << "[DEBUG] IPC: connecting to " << ep.address().to_string() << ":" << ep.port()
				<< " - payload=\"" << msg << "\"" << std::endl;

			sock.connect(ep);

			std::cout << "[DEBUG] IPC: connected, sending..." << std::endl;

			std::size_t bytes = boost::asio::write(sock, boost::asio::buffer(msg));
			std::cout << "[DEBUG] IPC: sent " << bytes << " bytes" << std::endl;

			boost::system::error_code ec;
			sock.shutdown(ip::tcp::socket::shutdown_both, ec);
			sock.close(ec);
		}
		catch (const std::exception& e) {
			std::cerr << "IPC Error: " << e.what() << std::endl;
		}
	}

	void send_startup_info() {
		std::ostringstream ss;
		ss << std::fixed << std::setprecision(1);

		ss << "hostname, " << monitor_->getHostname() << "\r\n";
		ss << "os, " << monitor_->getOsName() << "\r\n";

		std::string payload = ss.str();

		// Debug: log startup payload
		std::cout << "[DEBUG] Sending startup payload:\n" << payload << std::endl;

		// When sending to serial, also forward the same payload to the Tray app.
		async_send_payload(serial_, std::move(payload));
	}

	void start_telemetry_loop() {
		telemetry_timer_.expires_after(std::chrono::seconds(UPDATE_INTERVAL_SEC));
		telemetry_timer_.async_wait(boost::bind(&ServiceApp::handle_telemetry_timer, this, placeholders::error));
	}

	void handle_telemetry_timer(const boost::system::error_code& e) {
		if (e != error::operation_aborted) {
			send_periodic_changes();
			start_telemetry_loop();
		}
	}

	// Compose and send only changed dynamic telemetry lines
	void send_periodic_changes() {
		// Gather current values
		std::string username = monitor_->getCurrentUser();
		int session = monitor_->getSessionState();
		double cpu = monitor_->getCpuUsage();
		double ram = monitor_->getRamUsage();
		auto nets = monitor_->getFilteredInterfaces({ "00-17", "00-13" });

		// Build payload only for items that changed
		std::ostringstream ss;
		bool any = false;
		const double EPS = 0.5; // percent threshold for cpu/ram to be considered "changed"

		if (username != last_username_) {
			ss << "username, " << username << "\r\n";
			last_username_ = username;
			any = true;
		}

		if (session != last_session_state_) {
			ss << "sessionState, " << session << "\r\n";
			last_session_state_ = session;
			any = true;
		}

		if (cpu) {
			ss << "cpu, " << cpu << "\r\n";
			any = true;
		}

		if (ram) {
			ss << "ram, " << ram << "\r\n";
			any = true;
		}

		if (!nets_equal(nets, last_nets_)) {
			int count = 1;
			for (const auto& iface : nets) {
				ss << "net" << count++ << ", "
					<< iface.mac_address << ", "
					<< iface.ip_address << ", "
					<< (iface.dhcp_enabled ? "DHCP" : "STATIC") << ", "
					<< iface.speed_mbps << ", "
					<< (iface.is_up ? "UP" : "DOWN") << "\r\n";
			}
			last_nets_ = std::move(nets);
			any = true;
		}

		if (any) {
			std::string payload = ss.str();

			// Debug: log telemetry payload before sending
			std::cout << "[DEBUG] Sending telemetry payload:\n" << payload << std::endl;

			// When sending telemetry to serial, also forward same payload to Tray app.
			async_send_payload(serial_, std::move(payload));
		}
	}

	// Helper: compare network interface lists deterministically
	static bool nets_equal(std::vector<NetworkInterface> a, std::vector<NetworkInterface> b) {
		auto key = [](const NetworkInterface& n) { return n.mac_address + "|" + n.ip_address; };
		std::sort(a.begin(), a.end(), [&](auto& x, auto& y) { return key(x) < key(y); });
		std::sort(b.begin(), b.end(), [&](auto& x, auto& y) { return key(x) < key(y); });
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i) {
			if (a[i].mac_address != b[i].mac_address) return false;
			if (a[i].ip_address != b[i].ip_address) return false;
			if (a[i].is_up != b[i].is_up) return false;
			if (a[i].dhcp_enabled != b[i].dhcp_enabled) return false;
			if (a[i].speed_mbps != b[i].speed_mbps) return false;
		}
		return true;
	}

	// Overload for serial_port: forward payload to Tray app, then send to serial.
	void async_send_payload(serial_port& stream, std::string payload) {
		// Forward the same payload to the Tray application via IPC.
		// Use notify_agent which connects synchronously for reliability here.
		try {
			notify_agent(payload);
		}
		catch (...) {
			// ignore notify failure; continue with serial send
		}

		// Proceed to write to serial as before.
		auto data = std::make_shared<std::string>(std::move(payload));
		auto buf = boost::asio::buffer(*data);

		// Debug: log scheduling async write (for serial)
		std::cout << "[DEBUG] Scheduling async write (serial), bytes=" << data->size() << std::endl;

		boost::asio::async_write(stream, buf,
			[data](const boost::system::error_code& ec, std::size_t bytes_transferred)
			{
				if (ec) {
					std::cerr << "Failed to write: " << ec.message() << std::endl;
				}
				else {
					std::cout << "[DEBUG] Async write complete, bytes_transferred=" << bytes_transferred << std::endl;
				}
			});
	}

	// Generic async send with shared_ptr capture to extend payload lifetime.
	template <typename AsyncWriteStream>
	void async_send_payload(AsyncWriteStream& stream, std::string payload) {
		auto data = std::make_shared<std::string>(std::move(payload));
		auto buf = boost::asio::buffer(*data);

		// Debug: log scheduling async write
		std::cout << "[DEBUG] Scheduling async write, bytes=" << data->size() << std::endl;

		boost::asio::async_write(stream, buf,
			[data](const boost::system::error_code& ec, std::size_t bytes_transferred)
			{
				if (ec) {
					std::cerr << "Failed to write: " << ec.message() << std::endl;
				}
				else {
					std::cout << "[DEBUG] Async write complete, bytes_transferred=" << bytes_transferred << std::endl;
				}
			});
	}
};

#ifdef _WIN32
// Minimal Windows Service support: on SERVICE_CONTROL_STOP we stop the io_context.
// This is a lightweight integration - if you want a full service wrapper, we can add it.
SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
ServiceApp* g_serviceApp = nullptr;

void ReportServiceStatus(DWORD currentState, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
	if (!g_serviceStatusHandle) return;
	SERVICE_STATUS status = {};
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwCurrentState = currentState;
	status.dwWin32ExitCode = win32ExitCode;
	status.dwWaitHint = waitHint;
	SetServiceStatus(g_serviceStatusHandle, &status);
}

DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD /*eventType*/, LPVOID /*eventData*/, LPVOID /*context*/) {
	switch (control) {
	case SERVICE_CONTROL_STOP:
		if (g_serviceApp) g_serviceApp->stop();
		ReportServiceStatus(SERVICE_STOPPED);
		return NO_ERROR;
	default:
		return NO_ERROR;
	}
}
#endif

int main(int argc, char* argv[]) {
	try {
		io_context io;
		g_io_context = &io;

		std::string port = "COM3";
#ifndef _WIN32
		port = "/dev/ttyS2";
#endif
		if (argc > 1) port = argv[1];

		// Ctrl+C handler (console)
		std::signal(SIGINT, [](int) {
			if (g_io_context) g_io_context->stop();
			});

#ifdef _WIN32
		// Optionally run as service if started by SCM - minimal handling:
		// Full service installation/registration is outside this snippet.
		// If you want the app to run as a service, expand this block with a proper ServiceMain/dispatcher.
#endif

		std::cout << "Starting STSB Core on " << port << "..." << std::endl;

		ServiceApp app(io, port);

#ifdef _WIN32
		// Provide pointer for possible service stop handling above (if used)
		g_serviceApp = &app;
#endif

		io.run();
	}
	catch (std::exception& e) {
		std::cerr << "Fatal Error: " << e.what() << "\n";
		return 1;
	}
	return 0;
}
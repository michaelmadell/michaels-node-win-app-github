#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <shellapi.h>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <boost/asio.hpp>
#include "resource.h"

using boost::asio::ip::tcp;

static const unsigned short IPC_PORT = 65432;
static const UINT WM_APP_UPDATE_TOOLTIP = WM_APP + 1;

static inline std::string trim_copy(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

class TrayServer {
public:
	TrayServer(HWND hWnd)
		: hwnd_(hWnd),
		ioc_(),
		acceptor_(ioc_),
		running_(true)
	{
		start_accept();
		worker_ = std::thread([this]() {ioc_.run(); });
	}

	~TrayServer() {
		shutdown();
	}

	void shutdown() {
		if (!running_.exchange(false)) return;
		boost::system::error_code ec;
		acceptor_.close(ec);
		ioc_.stop();
		if (worker_.joinable()) worker_.join();
	}

	void set_latest_message(std::string msg) {
		{
			std::lock_guard<std::mutex> lock(mtx_);
			merge_messages_nolock(msg);
		}
		PostMessage(hwnd_, WM_APP_UPDATE_TOOLTIP, 0, 0);
	}

	std::string take_latest_message() {
		std::lock_guard<std::mutex> lock(mtx_);
		return latest_;
	}

private:
	// Parse text with lines like "key, value" and merge into latest_ (caller must hold mtx_).
	void merge_messages_nolock(const std::string& msg) {
		// Parse existing state into ordered keys + map
		std::vector<std::string> order;
		std::unordered_map<std::string, std::string> map;

		auto parse_into = [&](const std::string& text) {
			std::istringstream iss(text);
			std::string line;
			while (std::getline(iss, line)) {
				// remove trailing CR
				if (!line.empty() && line.back() == '\r') line.pop_back();
				auto comma = line.find(',');
				if (comma == std::string::npos) {
					// treat whole line as key with empty value
					std::string key = trim_copy(line);
					if (key.empty()) continue;
					if (map.find(key) == map.end()) order.push_back(key);
					map[key] = "";
				}
				else {
					std::string key = trim_copy(line.substr(0, comma));
					std::string val = trim_copy(line.substr(comma + 1));
					if (key.empty()) continue;
					if (map.find(key) == map.end()) order.push_back(key);
					map[key] = val;
				}
			}
		};

		// start from existing latest_ if present
		if (!latest_.empty()) parse_into(latest_);
		// merge new incoming message (new values replace existing keys or append)
		parse_into(msg);

		// Rebuild latest_ preserving original order for existing keys, then any new keys
		std::ostringstream out;
		for (size_t i = 0; i < order.size(); ++i) {
			const std::string& key = order[i];
			out << key;
			if (!map[key].empty()) out << ", " << map[key];
			if (i + 1 < order.size()) out << "\r\n";
		}
		latest_ = out.str();
	}

private:
	void start_accept() {
		try {
			tcp::endpoint ep(boost::asio::ip::address_v4::loopback(), IPC_PORT);
			acceptor_.open(ep.protocol());
			acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
			acceptor_.bind(ep);
			acceptor_.listen();
			do_accept();
		}
		catch (const std::exception& e) {
			std::string err = "Failed to start IPC server: ";
			err += e.what();
			set_latest_message(err);
		}
	}

	void do_accept() {
		auto sock = std::make_shared<tcp::socket>(ioc_);
		acceptor_.async_accept(*sock, [this, sock](const boost::system::error_code& ec) {
			if (!ec) {
				handle_session(sock);
			}
			if (running_) {
				do_accept();
			}
			});
	}

	void handle_session(std::shared_ptr<tcp::socket> sock) {
		auto buf = std::make_shared<std::vector<char>>(1024);
		auto acc = std::make_shared<std::string>();

		// Use a shared_ptr to the function so it stays alive for recursive async callbacks.
		auto handler = std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();

		*handler = [this, sock, buf, acc, handler](const boost::system::error_code& ec, std::size_t n) {
			if (!ec) {
				acc->append(buf->data(), buf->data() + n);
				sock->async_read_some(boost::asio::buffer(*buf), *handler);
			}
			else {
				if (!acc->empty()) {
					// trim trailing EOLs
					while (!acc->empty() && (acc->back() == '\n' || acc->back() == '\r')) {
						acc->pop_back();
					}
					// Merge incoming text lines into the stored state (preserve startup keys)
					set_latest_message(*acc);
				}
				boost::system::error_code ignored;
				sock->shutdown(tcp::socket::shutdown_both, ignored);
				sock->close(ignored);
			}
		};

		// start the first async read
		sock->async_read_some(boost::asio::buffer(*buf), *handler);
	}

private:
	HWND hwnd_;
	boost::asio::io_context ioc_;
	tcp::acceptor acceptor_;
	std::thread worker_;
	std::mutex mtx_;
	std::string latest_;
	std::atomic<bool> running_;
};

static std::wstring Utf8ToW(const std::string& s) {
	if (s.empty()) return std::wstring();
	int sz = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
	std::wstring out(sz, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], sz);
	return out;
}

static void UpdateTrayTooltip(HWND hwnd, const std::wstring& text) {
	NOTIFYICONDATAW nid = {};
	nid.cbSize = sizeof(nid);
	nid.hWnd = hwnd;
	nid.uID = 1;
	nid.uFlags = NIF_TIP;
	// Tooltip length historically limited; ensure termination and reasonable truncation.
	const size_t MAX_TIP = 127;
	std::wstring tip = text;
	if (tip.size() > MAX_TIP) tip.resize(MAX_TIP);
	wcsncpy_s(nid.szTip, tip.c_str(), _TRUNCATE);
	Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void ShowContextMenu(HWND hwnd) {
	POINT pt;
	GetCursorPos(&pt);
	HMENU menu = CreatePopupMenu();
	if (!menu) return;
	InsertMenu(menu, -1, MF_BYPOSITION, 1001, L"Exit");
	// set foreground and track
	SetForegroundWindow(hwnd);
	TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
	DestroyMenu(menu);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

static TrayServer* g_server = nullptr;

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, int lpCmdShow) {
	const wchar_t CLASS_NAME[] = L"TrayAppClass";
	WNDCLASS wc = {};
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = CLASS_NAME;
	RegisterClass(&wc);

	HWND hwnd = CreateWindowEx(
		0,
		CLASS_NAME,
		L"TrayApp",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL,
		NULL,
		hInstance,
		NULL
	);
	if (hwnd == NULL) {
		return 0;
	}
	if (!hwnd) {
		return 0;
	}

	NOTIFYICONDATAW nid = {};
	nid.cbSize = sizeof(nid);
	nid.hWnd = hwnd;
	nid.uID = 1;
	nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
	nid.uCallbackMessage = WM_APP;
	
	HICON appIcon = static_cast<HICON>(
		LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR | LR_DEFAULTSIZE));
	if (appIcon == nullptr) {
		nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	}
	else {
		nid.hIcon = appIcon;
	}

	wcsncpy_s(nid.szTip, L"TrayApp Running", _TRUNCATE);
	Shell_NotifyIconW(NIM_ADD, &nid);

	TrayServer server(hwnd);
	g_server = &server;

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	server.shutdown();
	Shell_NotifyIconW(NIM_DELETE, &nid);
	return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	switch (msg) {
	case WM_APP: {
		if (lParam == WM_RBUTTONUP) {
			ShowContextMenu(hwnd);
		}
		else if (lParam == WM_LBUTTONDBLCLK) {
			if (g_server) {
				std::string s = g_server->take_latest_message();
				std::wstring w = Utf8ToW(s.empty() ? "<no data>" : s);
				MessageBoxW(hwnd, w.c_str(), L"Latest IPC Message", MB_OK);
			}
		}
		break;
	}

	case WM_COMMAND: {
		switch (LOWORD(wParam)) {
		case 1001:
			PostQuitMessage(0);
			break;
		}
		break;
	}

	case WM_APP_UPDATE_TOOLTIP: {
		if (g_server) {
			std::string latest = g_server->take_latest_message();
			if (latest.empty()) break;
			std::string summary;
			summary.reserve(latest.size());
			for (char c : latest) {
				if (c == '\n' || c == '\r') {
					if (!summary.empty() && summary.back() != ' ') summary += ' ';
					summary += '|';
					summary += ' ';
				}
				else summary += c;
			}

			std::wstring w = Utf8ToW(summary);
			UpdateTrayTooltip(hwnd, w);
		}
		break;
	}
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

int main() {
	return wWinMain(GetModuleHandle(NULL), nullptr, GetCommandLineW(), SW_SHOWDEFAULT);
}
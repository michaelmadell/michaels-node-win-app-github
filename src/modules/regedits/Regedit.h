#pragma once

#include <string>
#include <functional>
#include <WinSock2.h>

class WindowsPlatform;

class Regedit {
	public:
	explicit Regedit(WindowsPlatform* platform);
	~Regedit();
	bool Read(std::string path, std::string value);
	bool Write(std::string path, std::string value, DWORD type);
	bool Create(std::string path, std::string value, DWORD type);
	bool Delete(std::string path);

private:
	WindowsPlatform* platform_ = nullptr;
};
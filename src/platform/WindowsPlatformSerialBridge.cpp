// Named-pipe serial bridge glue: lets an external app forward bytes to the
// serial port via SerialBridgePipe (see modules/serialpipe).
#ifdef _WIN32
#include <windows.h>
#include "WindowsPlatform.h"
#include <string>

#ifdef ENABLE_SERIAL_BRIDGE_PIPE
#include "../modules/serialpipe/SerialBridgePipe.h"
#endif

void WindowsPlatform::startSerialBridgePipe() {
#ifdef ENABLE_SERIAL_BRIDGE_PIPE
    if (!serial_bridge_pipe_) {
        serial_bridge_pipe_ = std::make_unique<SerialBridgePipe>(this);
        serial_bridge_pipe_->Start();
    }
#endif
}

void WindowsPlatform::stopSerialBridgePipe() {
#ifdef ENABLE_SERIAL_BRIDGE_PIPE
    if (serial_bridge_pipe_) {
        serial_bridge_pipe_->Stop();
        serial_bridge_pipe_.reset();
    }
#endif
}

void WindowsPlatform::setSerialBridgeHandler(SerialBridgeHandler handler) {
    serial_bridge_handler_ = std::move(handler);
}

bool WindowsPlatform::forwardSerialBridgeMessage(const std::string& data) {
    if (serial_bridge_handler_) {
        return serial_bridge_handler_(data);
    }
    return false;
}

#endif // _WIN32

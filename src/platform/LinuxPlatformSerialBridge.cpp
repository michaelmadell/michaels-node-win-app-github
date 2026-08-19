// Unix domain socket serial bridge glue: lets an external app forward bytes
// to the serial port via SerialBridgeSocket (see modules/serialpipe) --
// the Linux counterpart of WindowsPlatformSerialBridge.cpp.
#ifdef __linux__
#include "LinuxPlatform.h"

#ifdef ENABLE_SERIAL_BRIDGE_PIPE
#include "../modules/serialpipe/SerialBridgeSocket.h"
#endif

void LinuxPlatform::setSerialBridgeHandler(SerialBridgeHandler handler) {
    serial_bridge_handler_ = std::move(handler);
}

bool LinuxPlatform::forwardSerialBridgeMessage(const std::string& data) {
    if (serial_bridge_handler_) {
        return serial_bridge_handler_(data);
    }
    return false;
}

#ifdef ENABLE_SERIAL_BRIDGE_PIPE
void LinuxPlatform::startSerialBridgeSocket() {
    if (!serial_bridge_socket_) {
        serial_bridge_socket_ = std::make_unique<SerialBridgeSocket>(this);
        if (!serial_bridge_socket_->Start()) {
            logMessage("[LinuxPlatform] FATAL: serial bridge socket failed to start");
            serial_bridge_socket_.reset();
        }
    }
}

void LinuxPlatform::stopSerialBridgeSocket() {
    if (serial_bridge_socket_) {
        serial_bridge_socket_->Stop();
        serial_bridge_socket_.reset();
    }
}
#endif  // ENABLE_SERIAL_BRIDGE_PIPE

#endif  // __linux__

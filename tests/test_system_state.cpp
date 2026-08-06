#include <gtest/gtest.h>
#include "core/SystemState.h"

TEST(NetworkInterfaceTest, EqualWhenAllFieldsMatch) {
    NetworkInterface a{"eth0", "192.168.1.1", "::1", "dhcp", "up", "AA:BB:CC:DD:EE:FF"};
    NetworkInterface b{"eth0", "192.168.1.1", "::1", "dhcp", "up", "AA:BB:CC:DD:EE:FF"};

    EXPECT_TRUE(a == b);
    EXPECT_FALSE(a != b);
}

TEST(NetworkInterfaceTest, NotEqualWhenLinkStatusDiffers) {
    NetworkInterface a{"eth0", "192.168.1.1", "::1", "dhcp", "up", "AA:BB:CC:DD:EE:FF"};
    NetworkInterface b = a;
    b.linkStatus = "down";

    EXPECT_TRUE(a != b);
    EXPECT_FALSE(a == b);
}

TEST(NetworkInterfaceTest, NotEqualWhenMacAddressDiffers) {
    NetworkInterface a{"eth0", "192.168.1.1", "::1", "dhcp", "up", "AA:BB:CC:DD:EE:FF"};
    NetworkInterface b = a;
    b.macAddress = "00:11:22:33:44:55";

    EXPECT_TRUE(a != b);
}

TEST(SystemStateTest, DefaultConstructedStatesAreEqual) {
    SystemState a;
    SystemState b;

    EXPECT_FALSE(a != b);
}

TEST(SystemStateTest, NotEqualWhenHostnameDiffers) {
    SystemState a;
    SystemState b;
    a.hostname = "host-a";
    b.hostname = "host-b";

    EXPECT_TRUE(a != b);
}

TEST(SystemStateTest, NotEqualWhenNetworkInterfacesDiffer) {
    SystemState a;
    SystemState b;

    a.networkInterfaces.push_back(NetworkInterface{"eth0", "", "", "", "", ""});

    EXPECT_TRUE(a != b);
}

#include <gtest/gtest.h>
#include "../network/MdnsResponder.h"
#include "../../shared/protocol/ProtocolTypes.h"

using namespace MobileUnlock::Network;
using namespace MobileUnlock::Protocol;

TEST(MdnsTest, PayloadSerializationAndDeserialization) {
    DiscoveryAnnouncement original;
    original.HostName = "DEV-WORKSTATION-X";
    original.Port = 8443;
    original.State = PcState::LOCKED;
    original.ServiceType = "_mobileunlock._tcp.local.";

    auto payload = MdnsResponder::BuildDiscoveryResponsePayload(original);
    EXPECT_GT(payload.size(), static_cast<size_t>(0));

    DiscoveryAnnouncement parsed{};
    bool success = MdnsResponder::ParseDiscoveryResponsePayload(payload.data(), payload.size(), parsed);
    EXPECT_TRUE(success);
    EXPECT_EQ(parsed.HostName, "DEV-WORKSTATION-X");
    EXPECT_EQ(parsed.Port, static_cast<uint16_t>(8443));
    EXPECT_EQ(parsed.State, PcState::LOCKED);
    EXPECT_EQ(parsed.ServiceType, "_mobileunlock._tcp.local.");
}

TEST(MdnsTest, MalformedPayloadRejection) {
    DiscoveryAnnouncement parsed{};
    // Null data
    EXPECT_FALSE(MdnsResponder::ParseDiscoveryResponsePayload(nullptr, 0, parsed));

    // Incomplete/malformed JSON
    std::string badJson = "{\"host\":\"Incomplete\"";
    EXPECT_FALSE(MdnsResponder::ParseDiscoveryResponsePayload(reinterpret_cast<const uint8_t*>(badJson.data()), badJson.size(), parsed));

    // Invalid port string
    std::string invalidPortJson = "{\"host\":\"PC\",\"port\":-1,\"state\":2,\"service\":\"_mobileunlock._tcp.local.\"}";
    EXPECT_FALSE(MdnsResponder::ParseDiscoveryResponsePayload(reinterpret_cast<const uint8_t*>(invalidPortJson.data()), invalidPortJson.size(), parsed));
}

TEST(MdnsTest, ResponderLifecycle) {
    MdnsResponder responder(8449, 8443);
    EXPECT_FALSE(responder.IsRunning());
    EXPECT_EQ(responder.GetUdpPort(), static_cast<uint16_t>(8449));

    bool started = responder.Start(PcState::ONLINE);
    EXPECT_TRUE(started);
    EXPECT_TRUE(responder.IsRunning());

    responder.SetState(PcState::LOCKED);
    responder.Stop();
    EXPECT_FALSE(responder.IsRunning());
}

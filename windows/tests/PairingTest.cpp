#include <gtest/gtest.h>
#include "../pairing/DeviceIdentity.h"
#include "../pairing/SasPin.h"
#include "../pairing/DeviceRegistry.h"
#include "../pairing/PairingManager.h"
#include <cstring>
#include <thread>
#include <chrono>

using namespace MobileUnlock::Pairing;
using namespace MobileUnlock::Protocol;

// ---------------------------------------------------------------------------
// DeviceIdentity Tests
// ---------------------------------------------------------------------------
TEST(DeviceIdentityTest, GenerateIsNotEmpty) {
    DeviceId id = GenerateDeviceId();
    EXPECT_FALSE(DeviceIdIsEmpty(id));
}

TEST(DeviceIdentityTest, GenerateIsUnique) {
    DeviceId a = GenerateDeviceId();
    DeviceId b = GenerateDeviceId();
    EXPECT_FALSE(DeviceIdEqual(a, b));
}

TEST(DeviceIdentityTest, ToStringLength36) {
    DeviceId id = GenerateDeviceId();
    std::string s = DeviceIdToString(id);
    EXPECT_EQ(s.size(), static_cast<size_t>(36));
    EXPECT_EQ(s[8],  '-');
    EXPECT_EQ(s[13], '-');
    EXPECT_EQ(s[18], '-');
    EXPECT_EQ(s[23], '-');
}

TEST(DeviceIdentityTest, RoundTripStringToBinary) {
    DeviceId original = GenerateDeviceId();
    std::string str = DeviceIdToString(original);
    DeviceId parsed{};
    EXPECT_TRUE(DeviceIdFromString(str, parsed));
    EXPECT_TRUE(DeviceIdEqual(original, parsed));
}

TEST(DeviceIdentityTest, FromStringRejectsMalformed) {
    DeviceId out{};
    EXPECT_FALSE(DeviceIdFromString("not-a-uuid", out));
    EXPECT_FALSE(DeviceIdFromString("", out));
    EXPECT_FALSE(DeviceIdFromString("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", out));
    EXPECT_FALSE(DeviceIdFromString("123e4567-e89b-12d3-a456-42661417400", out)); // 35 chars
}

TEST(DeviceIdentityTest, EmptyIdIsAllZeros) {
    DeviceId empty{};
    EXPECT_TRUE(DeviceIdIsEmpty(empty));
}

// ---------------------------------------------------------------------------
// SasPin Tests
// ---------------------------------------------------------------------------
TEST(SasPinTest, GeneratedPinIs6Digits) {
    std::string pin = GenerateSasPin();
    EXPECT_FALSE(pin.empty());
    EXPECT_EQ(pin.size(), static_cast<size_t>(6));
    for (char c : pin) {
        EXPECT_GE(c, '0');
        EXPECT_LE(c, '9');
    }
}

TEST(SasPinTest, GeneratedPinsAreUnique) {
    // Run 10 generations; expect at least 1 difference
    std::string first = GenerateSasPin();
    bool foundDifferent = false;
    for (int i = 0; i < 10; ++i) {
        if (GenerateSasPin() != first) { foundDifferent = true; break; }
    }
    EXPECT_TRUE(foundDifferent);
}

TEST(SasPinTest, ValidatePinCorrectAccepted) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    std::string pin = GenerateSasPin();
    EXPECT_TRUE(ValidateSasPin(pin, pin, now, 0));
}

TEST(SasPinTest, ValidatePinWrongRejected) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    std::string pin = GenerateSasPin();
    EXPECT_FALSE(ValidateSasPin("000000", pin, now, 0));
}

TEST(SasPinTest, ValidatePinMaxAttemptsRejected) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    std::string pin = GenerateSasPin();
    // At SAS_MAX_ATTEMPTS, validation must fail regardless of correct PIN
    EXPECT_FALSE(ValidateSasPin(pin, pin, now, SAS_MAX_ATTEMPTS));
}

TEST(SasPinTest, ExpiredPinRejected) {
    // Build a FILETIME 120 seconds in the past to simulate expiry
    FILETIME old;
    GetSystemTimeAsFileTime(&old);
    uint64_t u64 = (static_cast<uint64_t>(old.dwHighDateTime) << 32) | old.dwLowDateTime;
    u64 -= 120ULL * 10000000ULL; // subtract 120 seconds
    old.dwHighDateTime = static_cast<DWORD>(u64 >> 32);
    old.dwLowDateTime  = static_cast<DWORD>(u64 & 0xFFFFFFFF);

    std::string pin = "123456";
    EXPECT_TRUE(SasPinExpired(old));
    EXPECT_FALSE(ValidateSasPin(pin, pin, old, 0)); // Expired — must fail
}

TEST(SasPinTest, InvalidFormatRejected) {
    EXPECT_FALSE(IsValidPinFormat("12345"));      // 5 digits
    EXPECT_FALSE(IsValidPinFormat("1234567"));    // 7 digits
    EXPECT_FALSE(IsValidPinFormat("abcdef"));     // non-digits
    EXPECT_FALSE(IsValidPinFormat("12 345"));     // space
    EXPECT_TRUE(IsValidPinFormat("000000"));
    EXPECT_TRUE(IsValidPinFormat("999999"));
}

// ---------------------------------------------------------------------------
// PairingManager — State Machine Tests
// ---------------------------------------------------------------------------

static std::vector<uint8_t> MakePairRequestPayload(const std::string& deviceId, const std::string& deviceName) {
    std::string json = "{\"deviceId\":\"" + deviceId + "\",\"deviceName\":\"" + deviceName + "\",\"publicKey\":\"\"}";
    return std::vector<uint8_t>(json.begin(), json.end());
}

static std::vector<uint8_t> MakePairConfirmPayload(const std::string& deviceId, const std::string& sasPin) {
    std::string json = "{\"deviceId\":\"" + deviceId + "\",\"sasPin\":\"" + sasPin + "\"}";
    return std::vector<uint8_t>(json.begin(), json.end());
}

static std::vector<uint8_t> MakeUnpairPayload(const std::string& deviceId) {
    std::string json = "{\"deviceId\":\"" + deviceId + "\"}";
    return std::vector<uint8_t>(json.begin(), json.end());
}

TEST(PairingManagerTest, MalformedPairRequestRejected) {
    PairingManager mgr;
    MessageType responseType = MessageType::UNKNOWN;
    auto resp = mgr.HandlePairRequest(1, "127.0.0.1",
                                      std::vector<uint8_t>{0x7B, 0x7D}, // "{}"
                                      responseType);
    EXPECT_EQ(responseType, MessageType::PROTO_ERROR);
    EXPECT_FALSE(resp.empty());
}

TEST(PairingManagerTest, ValidPairRequestProducesPairResponse) {
    PairingManager mgr;
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    // Capture SAS pin from callback
    std::string capturedPin;
    mgr.SetSasPinDisplayCallback([&](const std::string& pin, const std::string&) {
        capturedPin = pin;
    });

    MessageType responseType = MessageType::UNKNOWN;
    auto payload = MakePairRequestPayload(idStr, "TestPhone");
    auto resp = mgr.HandlePairRequest(42, "192.168.1.50", payload, responseType);

    EXPECT_EQ(responseType, MessageType::PAIR_RESPONSE);
    EXPECT_FALSE(resp.empty());
    EXPECT_TRUE(mgr.HasActivePairingSession(42));
    EXPECT_EQ(mgr.GetSessionState(42), PairingState::WAITING_FOR_SAS);
    EXPECT_EQ(capturedPin.size(), static_cast<size_t>(6));
}

TEST(PairingManagerTest, CorrectSasCompletesPairing) {
    SetRegistryRootForTesting(HKEY_CURRENT_USER);
    PairingManager mgr;
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    std::string capturedPin;
    mgr.SetSasPinDisplayCallback([&](const std::string& pin, const std::string&) {
        capturedPin = pin;
    });

    bool successCalled = false;
    mgr.SetPairingSuccessCallback([&](const DeviceId&, const std::string&, const std::string&) {
        successCalled = true;
    });

    MessageType rt = MessageType::UNKNOWN;
    auto req = MakePairRequestPayload(idStr, "TestPhone");
    mgr.HandlePairRequest(42, "127.0.0.1", req, rt);
    EXPECT_EQ(rt, MessageType::PAIR_RESPONSE);

    // Confirm with correct SAS
    auto conf = MakePairConfirmPayload(idStr, capturedPin);
    auto resp = mgr.HandlePairConfirm(42, conf, rt);

    EXPECT_EQ(rt, MessageType::PAIR_COMPLETE);
    EXPECT_FALSE(mgr.HasActivePairingSession(42));
    EXPECT_TRUE(successCalled);

    // Cleanup registry
    DeleteDeviceRecord(idStr);
}

TEST(PairingManagerTest, WrongSasRejectedWithAttemptCount) {
    PairingManager mgr;
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    std::string capturedPin;
    mgr.SetSasPinDisplayCallback([&](const std::string& pin, const std::string&) {
        capturedPin = pin;
    });

    MessageType rt = MessageType::UNKNOWN;
    auto req = MakePairRequestPayload(idStr, "TestPhone");
    mgr.HandlePairRequest(42, "127.0.0.1", req, rt);

    // Wrong PIN 1
    auto bad1 = MakePairConfirmPayload(idStr, "000000");
    mgr.HandlePairConfirm(42, bad1, rt);
    EXPECT_EQ(rt, MessageType::PROTO_ERROR);
    EXPECT_TRUE(mgr.HasActivePairingSession(42));

    // Wrong PIN 2
    auto bad2 = MakePairConfirmPayload(idStr, "111111");
    mgr.HandlePairConfirm(42, bad2, rt);
    EXPECT_EQ(rt, MessageType::PROTO_ERROR);

    // Wrong PIN 3 — max attempts reached, session terminated
    auto bad3 = MakePairConfirmPayload(idStr, "222222");
    mgr.HandlePairConfirm(42, bad3, rt);
    EXPECT_EQ(rt, MessageType::PROTO_ERROR);
    EXPECT_FALSE(mgr.HasActivePairingSession(42));
}

TEST(PairingManagerTest, CancelPairingSessionClearsState) {
    PairingManager mgr;
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    MessageType rt = MessageType::UNKNOWN;
    auto req = MakePairRequestPayload(idStr, "TestPhone");
    mgr.HandlePairRequest(77, "127.0.0.1", req, rt);
    EXPECT_TRUE(mgr.HasActivePairingSession(77));

    mgr.CancelPairingSession(77);
    EXPECT_FALSE(mgr.HasActivePairingSession(77));
}

TEST(PairingManagerTest, DuplicatePairRequestRejected) {
    SetRegistryRootForTesting(HKEY_CURRENT_USER);
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    DeviceRecord rec{};
    rec.deviceId = id;
    rec.deviceName = "AlreadyPaired";
    rec.accountSid = "S-1-5-21-fake";
    rec.pairStatus = kStatusActive;
    GetSystemTimeAsFileTime(&rec.pairedTime);
    rec.lastSeen = rec.pairedTime;

    LONG writeErr = WriteDeviceRecord(rec);
    ASSERT_EQ(writeErr, ERROR_SUCCESS);

    PairingManager mgr;
    MessageType rt = MessageType::UNKNOWN;
    auto req = MakePairRequestPayload(idStr, "TestPhone");
    auto resp = mgr.HandlePairRequest(99, "127.0.0.1", req, rt);
    EXPECT_EQ(rt, MessageType::PROTO_ERROR);

    DeleteDeviceRecord(idStr);
}

TEST(PairingManagerTest, UnpairRequestRemovesDevice) {
    SetRegistryRootForTesting(HKEY_CURRENT_USER);
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    DeviceRecord rec{};
    rec.deviceId = id;
    rec.deviceName = "ToRemove";
    rec.accountSid = "S-1-5-21-fake";
    rec.pairStatus = kStatusActive;
    GetSystemTimeAsFileTime(&rec.pairedTime);
    rec.lastSeen = rec.pairedTime;

    LONG writeErr = WriteDeviceRecord(rec);
    ASSERT_EQ(writeErr, ERROR_SUCCESS);

    EXPECT_TRUE(IsDeviceActive(idStr));

    PairingManager mgr;
    MessageType rt = MessageType::UNKNOWN;
    auto unpairPayload = MakeUnpairPayload(idStr);
    mgr.HandleUnpairRequest(1, unpairPayload, rt);
    EXPECT_EQ(rt, MessageType::UNPAIR_RESPONSE);
    EXPECT_FALSE(IsDeviceActive(idStr));
}

TEST(PairingManagerTest, MalformedPayloadCannotCrashService) {
    PairingManager mgr;
    MessageType rt = MessageType::UNKNOWN;
    // Garbage bytes
    std::vector<uint8_t> garbage = { 0xFF, 0xFE, 0x00, 0x01, 0xAA, 0xBB };
    auto resp = mgr.HandlePairRequest(1, "127.0.0.1", garbage, rt);
    EXPECT_EQ(rt, MessageType::PROTO_ERROR);
    EXPECT_FALSE(resp.empty());

    // Empty payload
    resp = mgr.HandlePairConfirm(1, {}, rt);
    EXPECT_EQ(rt, MessageType::PROTO_ERROR);
}

TEST(PairingManagerTest, ExpireStaleSessionsRemovesExpired) {
    PairingManager mgr;
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    std::string capturedPin;
    mgr.SetSasPinDisplayCallback([&](const std::string& p, const std::string&) { capturedPin = p; });

    MessageType rt = MessageType::UNKNOWN;
    mgr.HandlePairRequest(55, "127.0.0.1", MakePairRequestPayload(idStr, "Phone"), rt);
    EXPECT_TRUE(mgr.HasActivePairingSession(55));

    // ExpireStaleSessions should NOT remove a fresh session
    mgr.ExpireStaleSessions();
    EXPECT_TRUE(mgr.HasActivePairingSession(55));

    mgr.CancelPairingSession(55);
}

// ---------------------------------------------------------------------------
// DeviceRegistry Tests
// ---------------------------------------------------------------------------
TEST(DeviceRegistryTest, WriteReadRoundTrip) {
    SetRegistryRootForTesting(HKEY_CURRENT_USER);
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    DeviceRecord record{};
    record.deviceId    = id;
    record.deviceName  = "TestPhone";
    record.accountSid  = "S-1-5-21-test";
    record.pairStatus  = kStatusActive;
    GetSystemTimeAsFileTime(&record.pairedTime);
    record.lastSeen    = record.pairedTime;

    LONG writeErr = WriteDeviceRecord(record);
    ASSERT_EQ(writeErr, ERROR_SUCCESS);

    DeviceRecord readBack{};
    EXPECT_EQ(ReadDeviceRecord(idStr, readBack), ERROR_SUCCESS);
    EXPECT_EQ(readBack.deviceName, "TestPhone");
    EXPECT_EQ(readBack.accountSid, "S-1-5-21-test");
    EXPECT_EQ(readBack.pairStatus, kStatusActive);

    DeleteDeviceRecord(idStr);
}

TEST(DeviceRegistryTest, SetStatusToRevoked) {
    SetRegistryRootForTesting(HKEY_CURRENT_USER);
    DeviceId id = GenerateDeviceId();
    std::string idStr = DeviceIdToString(id);

    DeviceRecord record{};
    record.deviceId   = id;
    record.deviceName = "ToRevoke";
    record.accountSid = "S-1-5-21-test";
    record.pairStatus = kStatusActive;
    GetSystemTimeAsFileTime(&record.pairedTime);
    record.lastSeen = record.pairedTime;

    ASSERT_EQ(WriteDeviceRecord(record), ERROR_SUCCESS);

    EXPECT_TRUE(IsDeviceActive(idStr));
    SetDeviceStatus(idStr, kStatusRevoked);
    EXPECT_FALSE(IsDeviceActive(idStr));

    DeleteDeviceRecord(idStr);
}

TEST(DeviceRegistryTest, DeleteNonExistentDeviceIsNotError) {
    SetRegistryRootForTesting(HKEY_CURRENT_USER);
    std::string fakeId = "00000000-0000-4000-8000-000000000001";
    LONG err = DeleteDeviceRecord(fakeId);
    EXPECT_TRUE(err == ERROR_SUCCESS || err == ERROR_FILE_NOT_FOUND);
}

TEST(DeviceRegistryTest, ReadNonExistentDeviceReturnsFileNotFound) {
    SetRegistryRootForTesting(HKEY_CURRENT_USER);
    DeviceRecord rec{};
    LONG err = ReadDeviceRecord("00000000-0000-4000-8000-000000000099", rec);
    EXPECT_EQ(err, static_cast<LONG>(ERROR_FILE_NOT_FOUND));
}

import 'dart:typed_data';
import 'dart:convert';

const int PROTOCOL_MAGIC = 0x4D55;
const int PROTOCOL_MAJOR_VERSION = 1;
const int PROTOCOL_MINOR_VERSION = 0;
const int FRAME_HEADER_SIZE = 16;

const int OPCODE_LOCK_REQUEST  = 0x0030;
const int OPCODE_LOCK_RESPONSE = 0x0031;

Uint8List serializeFrameHeader({
  required int messageType,
  required int messageId,
  required int sequenceNumber,
  required int payloadLength,
}) {
  final bd = ByteData(FRAME_HEADER_SIZE);
  bd.setUint16(0, PROTOCOL_MAGIC, Endian.big);
  bd.setUint8(2, PROTOCOL_MAJOR_VERSION);
  bd.setUint8(3, PROTOCOL_MINOR_VERSION);
  bd.setUint16(4, messageType, Endian.big);
  bd.setUint16(6, 0, Endian.big); // Reserved
  bd.setUint32(8, messageId, Endian.big);
  bd.setUint32(12, sequenceNumber, Endian.big);
  return bd.buffer.asUint8List();
}

class LockResponse {
  final bool success;
  final String? reason;

  LockResponse({required this.success, this.reason});

  factory LockResponse.fromJson(Map<String, dynamic> json) {
    final status = json['status'] as String?;
    return LockResponse(
      success: status == 'SUCCESS',
      reason: json['reason'] as String?,
    );
  }
}

void main() {
  print('=== Running Phase 6 Remote PC Lock Protocol Tests ===');

  // Test 1: Serialize LOCK_REQUEST frame
  final lockPayload = utf8.encode('{"deviceId":"123e4567-e89b-12d3-a456-426614174000"}');
  final header = serializeFrameHeader(
    messageType: OPCODE_LOCK_REQUEST,
    messageId: 2001,
    sequenceNumber: 1,
    payloadLength: lockPayload.length,
  );

  assert(header.length == 16);
  final bd = ByteData.sublistView(header);
  assert(bd.getUint16(0, Endian.big) == PROTOCOL_MAGIC);
  assert(bd.getUint16(4, Endian.big) == OPCODE_LOCK_REQUEST);
  assert(bd.getUint32(8, Endian.big) == 2001);
  assert(bd.getUint32(12, Endian.big) == 1);
  print('Test 1: LOCK_REQUEST Frame Serialization PASSED');

  // Test 2: Parse LOCK_RESPONSE SUCCESS
  final successJson = jsonDecode('{"status":"SUCCESS"}') as Map<String, dynamic>;
  final respSuccess = LockResponse.fromJson(successJson);
  assert(respSuccess.success == true);
  assert(respSuccess.reason == null);
  print('Test 2: LOCK_RESPONSE SUCCESS Parsing PASSED');

  // Test 3: Parse LOCK_RESPONSE FAILURE
  final failureJson = jsonDecode('{"status":"FAILURE","reason":"DEVICE_UNAUTHORIZED"}') as Map<String, dynamic>;
  final respFailure = LockResponse.fromJson(failureJson);
  assert(respFailure.success == false);
  assert(respFailure.reason == 'DEVICE_UNAUTHORIZED');
  print('Test 3: LOCK_RESPONSE FAILURE Parsing PASSED');

  print('=== ALL PHASE 6 DART ASSERTIONS PASSED ===');
}

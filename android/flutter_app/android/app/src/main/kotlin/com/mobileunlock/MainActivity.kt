package com.mobileunlock

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.mobileunlock.security/biometrics"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "signCanonicalMessage" -> {
                    val payload = call.argument<ByteArray>("payload")
                    if (payload != null && payload.size == 88) {
                        // Phase 1 Foundation Placeholder (Returns 64-byte zero buffer for platform channel testing)
                        val dummySignature = ByteArray(64)
                        result.success(dummySignature)
                    } else {
                        result.error("INVALID_PAYLOAD", "Canonical payload must be exactly 88 bytes", null)
                    }
                }
                else -> result.notImplemented()
            }
        }
    }
}

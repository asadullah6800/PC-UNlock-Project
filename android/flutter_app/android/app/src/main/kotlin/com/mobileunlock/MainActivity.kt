package com.mobileunlock

import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterFragmentActivity() {
    private val CHANNEL = "com.mobileunlock.security/biometrics"

    private lateinit var keystoreManager: AndroidKeystoreManager
    private lateinit var biometricManager: BiometricManager

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        keystoreManager = AndroidKeystoreManager(this)
        biometricManager = BiometricManager(this)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "signCanonicalMessage" -> {
                    val payload = call.argument<ByteArray>("payload")
                    if (payload == null || payload.size != 88) {
                        result.error("INVALID_PAYLOAD", "Canonical payload must be exactly 88 bytes", null)
                        return@setMethodCallHandler
                    }

                    val title = call.argument<String>("title") ?: "Authorize Workstation Unlock"
                    val subtitle = call.argument<String>("subtitle") ?: "Scan your fingerprint to sign unlock challenge"

                    biometricManager.authenticateAndSign(
                        activity = this,
                        canonicalPayload = payload,
                        title = title,
                        subtitle = subtitle,
                        onSuccess = { signatureBytes ->
                            result.success(signatureBytes)
                        },
                        onError = { errorCode, errorMessage ->
                            result.error(errorCode, errorMessage, null)
                        }
                    )
                }

                "isBiometricAvailable" -> {
                    val available = biometricManager.canAuthenticate()
                    val status = biometricManager.getBiometricStatus()
                    result.success(mapOf(
                        "available" to available,
                        "status" to status
                    ))
                }

                "isStrongBoxSupported" -> {
                    result.success(keystoreManager.isStrongBoxSupported())
                }

                "getKeyStatus" -> {
                    val exists = keystoreManager.keyExists()
                    val securityLevel = keystoreManager.getKeySecurityLevel()
                    val isInvalidated = keystoreManager.isKeyInvalidated()
                    result.success(mapOf(
                        "exists" to exists,
                        "securityLevel" to securityLevel,
                        "isInvalidated" to isInvalidated
                    ))
                }

                "ensureKeyReady" -> {
                    try {
                        val status = keystoreManager.ensureKeyReady()
                        result.success(mapOf(
                            "exists" to status.exists,
                            "securityLevel" to status.securityLevel,
                            "isInvalidated" to status.isInvalidated
                        ))
                    } catch (e: Exception) {
                        result.error("KEY_GENERATION_FAILED", "Failed to ensure Keystore key: ${e.message}", null)
                    }
                }

                "getPublicKey" -> {
                    val pubKey = keystoreManager.getPublicKeyEncoded()
                    if (pubKey != null) {
                        result.success(pubKey)
                    } else {
                        result.error("KEY_NOT_FOUND", "No public key found in Keystore", null)
                    }
                }

                else -> result.notImplemented()
            }
        }
    }
}

package com.mobileunlock

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager as AndroidXBiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.SignatureException

/**
 * Manages AndroidX BiometricPrompt authentication and CryptoObject binding for cryptographic signing.
 */
class BiometricManager(private val context: Context) {

    private val keystoreManager = AndroidKeystoreManager(context)

    companion object {
        const val CANONICAL_PAYLOAD_SIZE = 88
        const val IEEE_P1363_SIGNATURE_SIZE = 64
    }

    /**
     * Checks if strong biometric authentication (BIOMETRIC_STRONG) is currently available on the device.
     */
    fun canAuthenticate(): Boolean {
        val biometricManager = AndroidXBiometricManager.from(context)
        return biometricManager.canAuthenticate(AndroidXBiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                AndroidXBiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Queries detailed strong biometric availability status string.
     */
    fun getBiometricStatus(): String {
        val biometricManager = AndroidXBiometricManager.from(context)
        return when (biometricManager.canAuthenticate(AndroidXBiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            AndroidXBiometricManager.BIOMETRIC_SUCCESS -> "SUCCESS"
            AndroidXBiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "NO_HARDWARE"
            AndroidXBiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "HW_UNAVAILABLE"
            AndroidXBiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "NONE_ENROLLED"
            AndroidXBiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "SECURITY_UPDATE_REQUIRED"
            AndroidXBiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "UNSUPPORTED"
            AndroidXBiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "UNKNOWN"
            else -> "UNAVAILABLE"
        }
    }

    /**
     * Authorizes signing of an 88-byte canonical message via BiometricPrompt with CryptoObject.
     *
     * @param activity The FragmentActivity hosting the prompt.
     * @param canonicalPayload Exactly 88-byte canonical SignedMessage payload.
     * @param onSuccess Callback invoked on successful signing with exactly 64-byte IEEE P1363 signature.
     * @param onError Callback invoked on error with structured error code and message.
     */
    fun authenticateAndSign(
        activity: FragmentActivity,
        canonicalPayload: ByteArray?,
        title: String = "Authorize Workstation Unlock",
        subtitle: String = "Scan your fingerprint to sign unlock challenge",
        onSuccess: (ByteArray) -> Unit,
        onError: (errorCode: String, errorMessage: String) -> Unit
    ) {
        // 1. Validate payload length strictly
        if (canonicalPayload == null || canonicalPayload.size != CANONICAL_PAYLOAD_SIZE) {
            onError("INVALID_PAYLOAD", "Canonical payload must be exactly $CANONICAL_PAYLOAD_SIZE bytes (got ${canonicalPayload?.size ?: 0})")
            return
        }

        // 2. Check biometric hardware availability
        if (!canAuthenticate()) {
            val status = getBiometricStatus()
            if (status == "NONE_ENROLLED") {
                onError("BIOMETRIC_NOT_ENROLLED", "No biometric enrollments registered on device")
            } else {
                onError("BIOMETRIC_UNAVAILABLE", "Strong biometric authentication is not available ($status)")
            }
            return
        }

        // 3. Ensure key exists and initialize Signature object
        val signature = try {
            keystoreManager.initSignatureForSigning()
        } catch (e: KeyPermanentlyInvalidatedException) {
            onError("KEY_INVALIDATED", "Keystore private key permanently invalidated by biometric changes")
            return
        } catch (e: IllegalStateException) {
            onError("KEY_NOT_FOUND", e.message ?: "Keystore key not found")
            return
        } catch (e: Exception) {
            onError("KEY_INITIALIZATION_FAILED", "Failed to initialize cryptographic signature: ${e.javaClass.simpleName}")
            return
        }

        // 4. Build CryptoObject & BiometricPrompt
        val cryptoObject = BiometricPrompt.CryptoObject(signature)
        val executor = ContextCompat.getMainExecutor(activity)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(AndroidXBiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val authenticatedSignature = result.cryptoObject?.signature
                if (authenticatedSignature == null) {
                    onError("SIGNATURE_FAILED", "CryptoObject did not contain an authenticated Signature instance")
                    return
                }

                try {
                    authenticatedSignature.update(canonicalPayload)
                    val derSignature = authenticatedSignature.sign()

                    val p1363Signature = DerToP1363Converter.derToP1363(derSignature)
                    if (p1363Signature.size != IEEE_P1363_SIGNATURE_SIZE) {
                        onError("INVALID_SIGNATURE_FORMAT", "Converted signature size is ${p1363Signature.size}, expected $IEEE_P1363_SIGNATURE_SIZE")
                        return
                    }

                    onSuccess(p1363Signature)
                } catch (e: SignatureException) {
                    onError("SIGNATURE_FAILED", "Failed to compute ECDSA signature")
                } catch (e: IllegalArgumentException) {
                    onError("INVALID_SIGNATURE_FORMAT", "Failed to convert DER signature to IEEE P1363: ${e.message}")
                } catch (e: Exception) {
                    onError("SIGNATURE_FAILED", "Unexpected signing error: ${e.javaClass.simpleName}")
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                val code = when (errorCode) {
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED -> "BIOMETRIC_CANCELLED"
                    BiometricPrompt.ERROR_NO_BIOMETRICS -> "BIOMETRIC_NOT_ENROLLED"
                    BiometricPrompt.ERROR_HW_UNAVAILABLE,
                    BiometricPrompt.ERROR_HW_NOT_PRESENT -> "BIOMETRIC_UNAVAILABLE"
                    BiometricPrompt.ERROR_LOCKOUT,
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> "BIOMETRIC_LOCKOUT"
                    else -> "BIOMETRIC_FAILED"
                }
                onError(code, errString.toString())
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // Called when an un-enrolled finger is scanned, BiometricPrompt remains open
            }
        })

        // 5. Display prompt
        try {
            biometricPrompt.authenticate(promptInfo, cryptoObject)
        } catch (e: Exception) {
            onError("BIOMETRIC_PROMPT_FAILED", "Failed to launch BiometricPrompt: ${e.javaClass.simpleName}")
        }
    }
}

package com.mobileunlock

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Manages the Android Keystore hardware-backed ECDSA P-256 private key for device authentication.
 *
 * Enforces AUTH_BIOMETRIC_STRONG, auth-per-use, biometric invalidation, and StrongBox preference.
 * Private key material is never exported, serialized, or exposed.
 */
class AndroidKeystoreManager(private val context: Context) {

    companion object {
        const val KEY_ALIAS = "MobileUnlockDeviceIdentityKey"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGN_ALGORITHM = "SHA256withECDSA"
        private const val EC_CURVE_P256 = "secp256r1"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    /**
     * Checks if the physical device hardware supports StrongBox Keymaster.
     */
    fun isStrongBoxSupported(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            false
        }
    }

    /**
     * Checks whether the device identity key currently exists in Android Keystore.
     */
    fun keyExists(): Boolean {
        return try {
            keyStore.containsAlias(KEY_ALIAS)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Ensures the device authentication key is generated and ready in Android Keystore.
     * Does NOT overwrite an existing valid key.
     *
     * @return Status map indicating whether key was created or already existed.
     */
    @Synchronized
    fun ensureKeyReady(): KeyStatusResult {
        if (keyExists()) {
            return KeyStatusResult(
                exists = true,
                securityLevel = getKeySecurityLevel(),
                isInvalidated = isKeyInvalidated()
            )
        }

        generateKeyPairInternal()
        return KeyStatusResult(
            exists = true,
            securityLevel = getKeySecurityLevel(),
            isInvalidated = false
        )
    }

    /**
     * Internal key pair generator. Prefers StrongBox if available; falls back to TEE.
     */
    private fun generateKeyPairInternal() {
        val useStrongBox = isStrongBoxSupported()

        try {
            generateWithParams(useStrongBox = useStrongBox)
        } catch (e: Exception) {
            if (useStrongBox && (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException)) {
                // StrongBox requested but failed; fallback to standard Keystore TEE
                generateWithParams(useStrongBox = false)
            } else {
                throw e
            }
        }
    }

    private fun generateWithParams(useStrongBox: Boolean) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE_P256))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    /**
     * Initializes a Signature object with the Keystore private key for biometric-authorized signing.
     * The private key is NEVER exposed directly; it remains securely bound to the Signature instance.
     *
     * @return Initialized Signature instance (unauthenticated state, ready for BiometricPrompt.CryptoObject).
     * @throws KeyPermanentlyInvalidatedException if biometric enrollment changed.
     * @throws IllegalStateException if key is missing or not accessible.
     */
    @Throws(KeyPermanentlyInvalidatedException::class, Exception::class)
    internal fun initSignatureForSigning(): Signature {
        if (!keyExists()) {
            throw IllegalStateException("KEY_NOT_FOUND: Device identity key does not exist in Keystore")
        }

        val privateKey = keyStore.getKey(KEY_ALIAS, null)
            ?: throw IllegalStateException("KEY_NOT_FOUND: Failed to retrieve private key entry")

        val signature = Signature.getInstance(SIGN_ALGORITHM)
        signature.initSign(privateKey as java.security.PrivateKey)
        return signature
    }

    /**
     * Retrieves the X.509 public key associated with the device identity key.
     */
    fun getPublicKey(): PublicKey? {
        return keyStore.getCertificate(KEY_ALIAS)?.publicKey
    }

    /**
     * Retrieves the raw X.509 encoded bytes of the public key.
     */
    fun getPublicKeyEncoded(): ByteArray? {
        return getPublicKey()?.encoded
    }

    /**
     * Checks if the key has been invalidated by a new biometric enrollment.
     */
    fun isKeyInvalidated(): Boolean {
        if (!keyExists()) return false
        return try {
            val privateKey = keyStore.getKey(KEY_ALIAS, null) ?: return false
            val sig = Signature.getInstance(SIGN_ALGORITHM)
            sig.initSign(privateKey as java.security.PrivateKey)
            false
        } catch (e: KeyPermanentlyInvalidatedException) {
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Inspects the actual hardware security level backing the key.
     * Returns: "STRONGBOX", "TEE", "SOFTWARE", or "UNKNOWN"
     */
    fun getKeySecurityLevel(): String {
        if (!keyExists()) return "NONE"

        return try {
            val privateKey = keyStore.getKey(KEY_ALIAS, null) ?: return "NONE"
            val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                    else -> "UNKNOWN"
                }
            } else {
                if (keyInfo.isInsideSecureHardware) "TEE" else "SOFTWARE"
            }
        } catch (e: Exception) {
            "UNKNOWN"
        }
    }

    /**
     * Deletes the key alias from Android Keystore.
     * Used only for explicit revocation or testing.
     */
    @Synchronized
    fun deleteKey() {
        if (keyExists()) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    data class KeyStatusResult(
        val exists: Boolean,
        val securityLevel: String,
        val isInvalidated: Boolean
    )
}

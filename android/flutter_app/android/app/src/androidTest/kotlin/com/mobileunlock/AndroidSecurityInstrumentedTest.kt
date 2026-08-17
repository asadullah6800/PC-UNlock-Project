package com.mobileunlock

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidSecurityInstrumentedTest {

    @Test
    fun testKeystoreKeyGenerationAndInspection() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val keystoreManager = AndroidKeystoreManager(appContext)

        // Ensure key is created
        val status = keystoreManager.ensureKeyReady()
        assertTrue(status.exists)
        assertTrue(status.securityLevel == "TEE" || status.securityLevel == "STRONGBOX" || status.securityLevel == "SOFTWARE")

        // Inspect public key
        val pubKey = keystoreManager.getPublicKey()
        assertNotNull("Public key must not be null", pubKey)
        assertEquals("EC", pubKey?.algorithm)

        // Verify key exists check
        assertTrue(keystoreManager.keyExists())
    }

    @Test
    fun testBiometricCapabilityInspection() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val biometricManager = BiometricManager(appContext)

        val status = biometricManager.getBiometricStatus()
        assertNotNull(status)
        assertTrue(listOf("SUCCESS", "NONE_ENROLLED", "NO_HARDWARE", "HW_UNAVAILABLE", "UNSUPPORTED", "UNKNOWN").contains(status))
    }
}

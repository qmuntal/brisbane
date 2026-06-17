/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software (each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at
 * a minimum a reference to the UPL must be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.oracle.jipher.internal.openssl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static com.oracle.jipher.internal.openssl.RandUtil.runAdaptiveProportionTest;
import static com.oracle.jipher.internal.openssl.RandUtil.runRepetitionCountTest;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class OsslLibTest {

    static final int STRENGTH = 256;

    static final String OPENSSL_CONFIG_PREFIX = """
        openssl_conf = openssl_init

        [openssl_init]
        alg_section = algorithm_sect
        """;
    static final String OPENSSL_CONFIG_FIPS_DISABLED = OPENSSL_CONFIG_PREFIX +
        """
        [algorithm_sect]
        default_properties = fips=no
        """;
    static final String OPENSSL_CONFIG_FIPS_ENABLED = OPENSSL_CONFIG_PREFIX +
        """
        [algorithm_sect]
        default_properties = fips=yes
        """;

    static final String OPENSSL_CONFIG_SEMANTIC_ERROR = OPENSSL_CONFIG_PREFIX;
    static final String OPENSSL_CONFIG_SYNTAX_ERROR = """
        openssl_conf = openssl_init

        [openssl nonsense % 1....
        """;

    OpenSsl openSsl;
    OSSL_LIB_CTX libCtx;
    OsslArena testArena;

    @Before
    public void setUp() throws Exception {
        openSsl = OpenSsl.getInstance();
        libCtx = LibCtx.getInstance();
        testArena = OsslArena.ofConfined();
    }

    @After
    public void tearDown() throws Exception {
        testArena.close();
    }

    @Test
    public void setConfig() {
        // Perform actions in a temporary library context to isolate the default library context from any side effects
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            OSSL_LIB_CTX ctx = openSsl.newOsslLibCtx(confinedArena);

            ctx.setConfig(OPENSSL_CONFIG_FIPS_DISABLED);
            assertFalse(ctx.isFipsEnabled());

            ctx.setConfig(OPENSSL_CONFIG_FIPS_ENABLED);
            assertTrue(ctx.isFipsEnabled());
        }
    }

    @Test
    public void loadConfig() throws IOException {
        // Perform actions in a temporary library context to isolate the default library context from any side effects
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            OSSL_LIB_CTX ctx = openSsl.newOsslLibCtx(confinedArena);

            File tempFile = File.createTempFile("openssl", ".cfg");
            tempFile.deleteOnExit();

            try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                outputStream.write(OPENSSL_CONFIG_FIPS_DISABLED.getBytes());
            }
            ctx.loadConfig(tempFile.getAbsolutePath());
            assertFalse(ctx.isFipsEnabled());

            try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                outputStream.write(OPENSSL_CONFIG_FIPS_ENABLED.getBytes());
            }
            ctx.loadConfig(tempFile.getAbsolutePath());
            assertTrue(ctx.isFipsEnabled());
        }
    }

    @Test
    public void randBytes() {
        byte[] randomBytes = new byte[1000];
        libCtx.randBytes(randomBytes, STRENGTH);

        // Perform a sanity check on the random bytes.
        // Note this sanity check has a low but non-zero false positive probability.
        assertTrue(runRepetitionCountTest(randomBytes));
        assertTrue(runAdaptiveProportionTest(randomBytes));
    }

    @Test
    public void randPrivBytes() {
        byte[] randomBytes = new byte[1000];
        libCtx.randPrivBytes(randomBytes, STRENGTH);

        // Perform a sanity check on the random bytes.
        // Note this sanity check has a low but non-zero false positive probability.
        assertTrue(runRepetitionCountTest(randomBytes));
        assertTrue(runAdaptiveProportionTest(randomBytes));
    }

    @Test
    public void setDefaultProperties() {
        // Perform action in temporary library context to isolate default library context from any side effect
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            OSSL_LIB_CTX ctx = openSsl.newOsslLibCtx(confinedArena);

            ctx.setDefaultProperties("fips=no");
            assertFalse(ctx.isFipsEnabled());
            ctx.setDefaultProperties("fips=yes");
            assertTrue(ctx.isFipsEnabled());
        }
    }

    @Test
    public void enableFips() {
        // Perform action in temporary library context to isolate default library context from any side effect
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            OSSL_LIB_CTX ctx = openSsl.newOsslLibCtx(confinedArena);

            ctx.enableFips(false);
            assertFalse(ctx.isFipsEnabled());
            ctx.enableFips(true);
            assertTrue(ctx.isFipsEnabled());
        }
    }

    @Test
    public void forEachCipher() {
        int[] count = new int[]{0};
        libCtx.forEachCipher(cipher -> count[0]++);
        assertTrue(count[0] > 0);
    }

    @Test
    public void forEachKdf() {
        int[] count = new int[]{0};
        libCtx.forEachKdf(kdf-> count[0]++);
        assertTrue(count[0] > 0);
    }

    @Test
    public void forEachMac() {
        int[] count = new int[]{0};
        libCtx.forEachMac(mac -> count[0]++);
        assertTrue(count[0] > 0);
    }

    @Test
    public void forEachMd() {
        int[] count = new int[]{0};
        libCtx.forEachMd(md -> count[0]++);
        assertTrue(count[0] > 0);
    }

    @Test
    public void forEachRand() {
        int[] count= new int[]{0};
        libCtx.forEachRand(rand-> count[0]++);
        assertTrue(count[0] > 0);
    }

    // Negative tests

    @Test
    public void setConfigSemanticErrorNeg() {
        try {
            libCtx.setConfig(OPENSSL_CONFIG_SEMANTIC_ERROR);
            fail("Failed to throw exception OpenSslException:module=alg_section");
        } catch (OpenSslException e) {
            assertTrue(e.getMessage().contains("module=alg_section"));
        }
    }

    @Test
    public void loadConfigSemanticErrorNeg() throws Exception {
        try {
            File tempFile = File.createTempFile("openssl", ".cfg");
            tempFile.deleteOnExit();

            try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                outputStream.write(OPENSSL_CONFIG_SEMANTIC_ERROR.getBytes());
            }
            libCtx.loadConfig(tempFile.getAbsolutePath());
            fail("Failed to throw exception OpenSslException:module=alg_section");
        } catch (OpenSslException e) {
            assertTrue(e.getMessage().contains("module=alg_section"));
        }
    }

    @Test
    public void setConfigSyntaxErrorNeg() {
        try {
            libCtx.setConfig(OPENSSL_CONFIG_SYNTAX_ERROR);
            fail("Failed to throw exception OpenSslException:Error on line 3 of config:missing close square bracket");
        } catch (OpenSslException e) {
            assertEquals("Error on line 3 of config", e.getMessage());
            assertTrue(e.getCause().getMessage().contains("missing close square bracket"));
        }
    }

    @Test
    public void loadConfigSyntaxErrorNeg() throws Exception {
        try {
            File tempFile = File.createTempFile("openssl", ".cfg");
            tempFile.deleteOnExit();

            try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
                outputStream.write(OPENSSL_CONFIG_SYNTAX_ERROR.getBytes());
            }
            libCtx.loadConfig(tempFile.getAbsolutePath());
            fail("Failed to throw exception OpenSslException:Error on line 3 of config:missing close square bracket");
        } catch (OpenSslException e) {
            assertTrue(e.getMessage().contains("line 3"));
            assertTrue(e.getMessage().contains("missing close square bracket"));
        }
    }

    @Test
    public void getDefaultInstance() {
        assertNotNull(OSSL_LIB_CTX.getDefaultInstance());
    }

    // The EvpRandTest calls libCtx.newEvpRandCtx with the test arena
    // This test tests calling libCtx.newEvpRandCtx without specifying an arena and thus defaulting to an ofAuto arena
    @Test
    public void newRandCtxOfAuto() {
        EVP_RAND rand = libCtx.fetchRand(getSupportedRandName(), null, testArena);
        assertNotNull(libCtx.newEvpRandCtxWithPrimaryAsParent(rand));
    }

    // Other tests suites call libCtx.fetch<Service>() specifying the test arena
    // The following tests call libCtx.fetch<Service>() methods that default to using an ofAuto arena

    @Test
    public void fetchCipherOfAuto() {
        String name = "AES-256-GCM";
        EVP_CIPHER cipher = libCtx.fetchCipher(name, null);
        assertNotNull(cipher);
        assertEquals(name, cipher.name());
    }

    @Test
    public void fetchKdfOfAuto() {
        String name = EVP_KDF.KDF_NAME_PBKDF2;
        EVP_KDF kdf = libCtx.fetchKdf(name, null);
        assertNotNull(kdf);
        assertEquals(name, kdf.name());
    }

    @Test
    public void fetchMacOfAuto() {
        String name = EVP_MAC.MAC_NAME_HMAC;
        EVP_MAC mac = libCtx.fetchMac(name, null);
        assertNotNull(mac);
        assertEquals(name, mac.name());
    }

    @Test
    public void fetchMdOfAuto() {
        String name = EVP_MD.DIGEST_NAME_SHA2_256;
        EVP_MD md = libCtx.fetchMd(name, null);
        assertNotNull(md);
        assertEquals(name, md.name());
    }

    @Test
    public void fetchRandOfAuto() {
        String name = getSupportedRandName();
        EVP_RAND rand = libCtx.fetchRand(name, null);
        assertNotNull(rand);
        assertEquals(name, rand.name());
    }

    String getSupportedRandName() {
        for (String name : new String[] {EVP_RAND.RAND_NAME_HASH_DRBG, EVP_RAND.RAND_NAME_CTR_DRBG}) {
            try {
                EVP_RAND rand = libCtx.fetchRand(name, null, testArena);
                if (rand.providerName().equals(LibCtx.getFipsProviderName())) {
                    return name;
                }
            } catch (OpenSslException e) {
                // Try the next RAND.
            }
        }
        throw new AssertionError("No supported RAND found");
    }

    // Negative tests

    @Test(expected = NullPointerException.class)
    public void setConfigNullNeg() {
        libCtx.setConfig(null);
    }

    @Test(expected = OpenSslException.class)
    public void fetchNonExistentCipherNeg() {
        libCtx.fetchCipher("non-existent", null, this.testArena);
    }

    @Test(expected = OpenSslException.class)
    public void fetchNonExistentKdfNeg() {
        libCtx.fetchKdf("non-existent", null, this.testArena);
    }

    @Test(expected = OpenSslException.class)
    public void fetchNonExistentMacNeg() {
        libCtx.fetchMac("non-existent", null, this.testArena);
    }

    @Test(expected = OpenSslException.class)
    public void fetchNonExistentMdNeg() {
        libCtx.fetchMd("non-existent", null, this.testArena);
    }

    @Test(expected = OpenSslException.class)
    public void fetchNonExistentRandNeg() {
        libCtx.fetchRand("non-existent", null, this.testArena);
    }
}

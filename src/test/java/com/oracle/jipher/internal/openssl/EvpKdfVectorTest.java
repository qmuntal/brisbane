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

import java.nio.ByteBuffer;
import java.util.Collection;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jipher.internal.common.Util;
import com.oracle.jiphertest.testdata.PbkdfTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test EVP_KDF_derive using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpKdfVectorTest extends EvpTest {

    static final long MAX_UNSIGNED_LONG = -1;
    static final long MAX_SIZE = MAX_UNSIGNED_LONG;

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(PbkdfTestVector.class);
    }

    final protected String kdfAlg;
    final protected String mdAlg;
    private final char[] password;
    private final byte[] salt;
    private final int iterationCount;
    private final byte[] derivedKey;

    EVP_KDF kdf;
    EVP_KDF_CTX kdfCtx;
    OsslParamBuffer kdfParams;

    static String getOpenSslKdfAlg(String kdfName) {
        if (kdfName.toUpperCase().startsWith("PBKDF2WITHHMAC")) {
            return EVP_KDF.KDF_NAME_PBKDF2;
        }
        throw new AssertionError();
    }

    static String getOpenSslMdAlg(String kdfName) {
        if (kdfName.toUpperCase().startsWith("PBKDF2WITHHMAC") || kdfName.toUpperCase().startsWith("PKCS12KDF")) {
            int beginIndex = kdfName.toUpperCase().indexOf("SHA");
            switch (kdfName.substring(beginIndex).toUpperCase()) {
                case "SHA1"   : return EVP_MD.DIGEST_NAME_SHA1;
                case "SHA224" : return EVP_MD.DIGEST_NAME_SHA2_224;
                case "SHA256" : return EVP_MD.DIGEST_NAME_SHA2_256;
                case "SHA384" : return EVP_MD.DIGEST_NAME_SHA2_384;
                case "SHA512" : return EVP_MD.DIGEST_NAME_SHA2_512;
            }
        }
        throw new AssertionError();
    }

    public EvpKdfVectorTest(String description, PbkdfTestVector tv) throws Exception {
        super();
        this.kdfAlg = getOpenSslKdfAlg(tv.getAlg());
        this.mdAlg = getOpenSslMdAlg(tv.getAlg());
        this.password = tv.getPasswordChars();
        this.salt = tv.getSalt();
        this.iterationCount = tv.getIterationCount();
        this.derivedKey = tv.getDk();

        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= this.password.length);
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.kdf = this.libCtx.fetchKdf(this.kdfAlg, null, testArena);
        this.kdfCtx = this.openSsl.newEvpKdfCtx(kdf);

        // Setup KDF parameters
        OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, this.salt);
        OSSL_PARAM iterParam = OSSL_PARAM.ofUnsigned(EVP_KDF.KDF_PARAM_ITER, this.iterationCount);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, this.mdAlg);
        OSSL_PARAM passParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PASSWORD, Util.utf8Encode(this.password));
        if (this.kdfAlg.equals(EVP_KDF.KDF_NAME_PBKDF2)) {
            OSSL_PARAM pkcs5Param = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PKCS5, 0);
            this.kdfParams = this.openSsl.dataParamBuffer(this.testArena, passParam, saltParam, iterParam, dgstParam, pkcs5Param);
        } else {
            this.kdfParams = this.openSsl.dataParamBuffer(this.testArena, passParam, saltParam, iterParam, dgstParam);
        }
    }

    @Test
    public void evpKdfState() {
        assertTrue(kdf.isA(kdfAlg));
        assertEquals(kdfAlg, kdf.name());
        if (!this.kdfAlg.equals(EVP_KDF.KDF_NAME_PKCS12)) {
            assertEquals(LibCtx.getFipsProviderName(), kdf.providerName());
        }
    }

    @Test
    public void evpKdfCtxState() {
        assertEquals(MAX_SIZE, kdfCtx.kdfSize());
    }

    @Test
    public void derive() throws Exception {
        byte[] output = new byte[this.derivedKey.length];

        kdfCtx.derive(output, this.kdfParams);

        assertArrayEquals(this.derivedKey, output);
    }

    @Test
    public void deriveByteBuffer() throws Exception {
        deriveByteBuffer(false);
    }

    @Test
    public void deriveByteBufferDirect() throws Exception {
        deriveByteBuffer(true);
    }

    public void deriveByteBuffer(boolean direct) throws Exception {
        int outLen = this.derivedKey.length;
        ByteBuffer output = direct ? ByteBuffer.allocateDirect(outLen) : ByteBuffer.allocate(outLen);

        kdfCtx.derive(output, this.kdfParams);
        assertFalse(output.hasRemaining());

        byte[] derivedKeyBytes = new byte[output.position()];
        output.flip().get(derivedKeyBytes);
        assertArrayEquals(this.derivedKey, derivedKeyBytes);
    }
}

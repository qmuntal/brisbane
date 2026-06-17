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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.MacTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test EVP_MAC and EVP_MAC_CTX using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpMacVectorTest extends EvpTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(MacTestVector.class);
    }

    final protected String mdAlg;
    private final byte[] key;
    final protected byte[] data;
    final protected byte[] expectedMac;

    protected EVP_MAC mac;
    protected EVP_MAC_CTX macCtx;

    static String getOpenSslMdAlg(String macName) {
        if (macName.toUpperCase().startsWith("HMAC")) {
            switch (macName.substring(4).toUpperCase()) {
                case "SHA1"   : return EVP_MD.DIGEST_NAME_SHA1;
                case "SHA224" : return EVP_MD.DIGEST_NAME_SHA2_224;
                case "SHA256" : return EVP_MD.DIGEST_NAME_SHA2_256;
                case "SHA384" : return EVP_MD.DIGEST_NAME_SHA2_384;
                case "SHA512" : return EVP_MD.DIGEST_NAME_SHA2_512;
            }
        }
        throw new AssertionError();
    }

    static long getBlockSize(String mdName) {
        return switch (mdName.toUpperCase()) {
            case EVP_MD.DIGEST_NAME_SHA1, EVP_MD.DIGEST_NAME_SHA2_224, EVP_MD.DIGEST_NAME_SHA2_256 -> 64;
            case EVP_MD.DIGEST_NAME_SHA2_384, EVP_MD.DIGEST_NAME_SHA2_512 -> 128;
            default -> throw new AssertionError();
        };
    }

    public EvpMacVectorTest(String description, MacTestVector tv) throws Exception {
        super();
        this.mdAlg = getOpenSslMdAlg(tv.getAlg());
        this.key = tv.getKey();
        this.data = tv.getData();
        this.expectedMac = tv.getMac();
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        mac = libCtx.fetchMac(EVP_MAC.MAC_NAME_HMAC, null, testArena);
        macCtx = openSsl.newEvpMacCtx(mac, testArena);
        OSSL_PARAM params = OSSL_PARAM.of(OSSL_PARAM.ALG_PARAM_DIGEST, mdAlg);
        macCtx.init(key, params);
    }

    @Test
    public void evpMacState() {
        assertTrue(mac.isA(EVP_MAC.MAC_NAME_HMAC));
        assertEquals(EVP_MAC.MAC_NAME_HMAC, mac.name());
        assertEquals(LibCtx.getFipsProviderName(), mac.providerName());
    }

    @Test
    public void evpMacCtxState() {
        assertEquals(getBlockSize(mdAlg), macCtx.blockSize());
        assertEquals(expectedMac.length, macCtx.macSize());
    }

    @Test
    public void macByteArray() throws Exception {
        byte[] observedMac = new byte[expectedMac.length];
        macCtx.update(data, 0, data.length);
        macCtx.doFinal(observedMac, 0);
        assertArrayEquals(this.expectedMac, observedMac);
    }

    @Test
    public void macByteBuffer() throws Exception {
        macByteBuffer(false);
    }

    @Test
    public void macByteBufferDirect() throws Exception {
        macByteBuffer(true);
    }

    void macByteBuffer(boolean direct) throws Exception {
        ByteBuffer dataBB = direct ? ByteBuffer.wrap(data) : copyDirect(data);
        byte[] observedMac = new byte[expectedMac.length];
        macCtx.update(dataBB);
        assertFalse(dataBB.hasRemaining());
        macCtx.doFinal(observedMac, 0);
        assertArrayEquals(this.expectedMac, observedMac);
    }

    ByteBuffer copyDirect(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf.clear();
    }
}

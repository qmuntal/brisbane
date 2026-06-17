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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.testdata.DigestTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static org.junit.Assert.assertFalse;

/**
 * Test EVP_MD and EVP_MD_CTX using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpMdVectorTest extends EvpTest {

    @Parameters(name="{0}:{index}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(DigestTestVector.class);
    }

    private final String jcaAlg;
    private final String alg;
    private final byte[] data;
    private final byte[] digest;

    private EVP_MD md;
    private EVP_MD_CTX mdCtx;

    public EvpMdVectorTest(String description, DigestTestVector tv) {
        jcaAlg = tv.getAlg();
        alg = getOpenSslName(jcaAlg);
        data = tv.getData();
        digest = tv.getDigest();
    }

    static String getOpenSslName(String jcaName) {
        if ("SHA-1".equalsIgnoreCase(jcaName)) {
            return EVP_MD.DIGEST_NAME_SHA1;
        }
        if ("SHA-224".equalsIgnoreCase(jcaName)) {
            return EVP_MD.DIGEST_NAME_SHA2_224;
        }
        if ("SHA-256".equalsIgnoreCase(jcaName)) {
            return EVP_MD.DIGEST_NAME_SHA2_256;
        }
        if ("SHA-384".equalsIgnoreCase(jcaName)) {
            return EVP_MD.DIGEST_NAME_SHA2_384;
        }
        if ("SHA-512".equalsIgnoreCase(jcaName)) {
            return EVP_MD.DIGEST_NAME_SHA2_512;
        }
        return jcaName;
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        md = libCtx.fetchMd(alg, null, testArena);
        mdCtx = openSsl.newEvpMdCtx(testArena);
        mdCtx.init(md);
    }

    @Test
    public void isA() {
        Assert.assertTrue(md.isA(alg));
        Assert.assertTrue(md.isA(jcaAlg)); // This will match one of the supported aliases.
    }

    @Test
    public void name() {
        Assert.assertEquals(alg, md.name());
    }

    @Test
    public void description() {
        String expectedDesc = (jcaAlg.startsWith("SHA3-") ? jcaAlg : jcaAlg.replaceAll("-", "")).toLowerCase();
        Assert.assertEquals(expectedDesc, md.description());
    }

    @Test
    public void providerName() {
        Assert.assertEquals(LibCtx.getFipsProviderName(), md.providerName());
    }

    @Test
    public void digest() {
        mdCtx.update(data, 0, data.length);
        byte[] out = new byte[digest.length];
        int outLen = mdCtx.digestFinal(out, 0);
        Assert.assertEquals(digest.length, outLen);
        Assert.assertArrayEquals(digest, out);
    }

    @Test
    public void digestByteBuffer() throws Exception {
        digestByteBuffer(false);
    }

    @Test
    public void digestByteBufferDirect() throws Exception {
        digestByteBuffer(true);
    }

    void digestByteBuffer(boolean direct) throws Exception {
        ByteBuffer dataBB = direct ? ByteBuffer.wrap(data) : copyDirect(data);
        mdCtx.update(dataBB);
        assertFalse(dataBB.hasRemaining());
        byte[] out = new byte[digest.length];
        int outLen = mdCtx.digestFinal(out, 0);
        Assert.assertEquals(digest.length, outLen);
        Assert.assertArrayEquals(digest, out);
    }

    ByteBuffer copyDirect(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf.clear();
    }

    @Test
    public void size() {
        Assert.assertTrue(digest.length <= EVP_MD.MAX_MD_SIZE);
        Assert.assertEquals(digest.length, md.size());
        Assert.assertEquals(digest.length, mdCtx.size());
    }

    @Test
    public void blockSize() {
        Assert.assertEquals(md.blockSize(), mdCtx.blockSize());
    }

}

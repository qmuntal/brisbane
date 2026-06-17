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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import com.oracle.jiphertest.testdata.DataSize;
import com.oracle.jiphertest.testdata.DigestTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class EvpMdTest extends EvpTest {

    static final Set<String> EMPTY_SET = Collections.<String>emptySet();

    static final String SHA_256_MD_DESCRIPTION = "sha256";

    // The following are the PARAM_KEYS in OpenSSL version 3.0.0. Later versions may support additional parameters
    static final Set<String> SHA_256_MD_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "blocksize", "size", "algid-absent", "xof"));

    static final Set<String> SHA_256_MD_NAMES = new HashSet<>(Arrays.asList(
            "SHA-256", "SHA256", "SHA2-256", "2.16.840.1.101.3.4.2.1"));
    static final int SHA_256_MD_SIZE = 32;
    static final int SHA_256_MD_BLOCK_SIZE = 64;

    private String jcaAlg;
    private String alg;
    private byte[] data;
    private byte[] dataDigest;
    private byte[] emptyDigest;

    private EVP_MD md;
    private EVP_MD_CTX mdCtx;
    private EVP_MD_CTX uninitialisedMdCtx;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        jcaAlg = "SHA-256";
        alg = EVP_MD.DIGEST_NAME_SHA2_256;
        DigestTestVector tv = TestData.getFirst(DigestTestVector.class, alg(jcaAlg).dataSize(DataSize.BASIC));
        DigestTestVector tvEmpty = TestData.getFirst(DigestTestVector.class, alg(jcaAlg).dataSize(DataSize.EMPTY));
        data = tv.getData();
        dataDigest = tv.getDigest();
        emptyDigest = tvEmpty.getDigest();

        md = libCtx.fetchMd(alg, null, testArena);
        mdCtx = openSsl.newEvpMdCtx(testArena);
        mdCtx.init(md);

        uninitialisedMdCtx = openSsl.newEvpMdCtx(testArena);
    }

    @Test
    public void isA() {
        assertTrue(md.isA(alg));
        assertTrue(md.isA(jcaAlg)); // This will match one of the supported aliases.
    }

    @Test
    public void name() {
        assertEquals(alg, md.name());
    }

    @Test
    public void forEachName() throws Exception {
        md.forEachName(name -> assertTrue(SHA_256_MD_NAMES.contains(name)));
    }

    @Test
    public void description() {
        assertEquals(SHA_256_MD_DESCRIPTION, md.description());
    }

    @Test
    public void providerName() {
        assertEquals(LibCtx.getFipsProviderName(), md.providerName());
    }

    @Test
    public void gettableParams() throws Exception {
        OsslParamBuffer params = md.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(SHA_256_MD_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void getParams() throws Exception {
        OsslParamBuffer blocksizeParam = this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("blocksize", OSSL_PARAM.Type.INTEGER));
        md.getParams(blocksizeParam);
        assertTrue(blocksizeParam.locate("blocksize").isPresent());
        int blocksize = (blocksizeParam.locate("blocksize").get().intValue());
        assertEquals(SHA_256_MD_BLOCK_SIZE, blocksize);
    }

    @Test
    public void getEmptyParams() throws Exception {
        // This test increases code coverage
        md.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void gettableCtxParams() throws Exception {
        OsslParamBuffer params = md.gettableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = FipsProviderInfoUtil.isSymCryptProvider() ?
            Set.of("state") : EMPTY_SET;
        assertEquals(expectedParamKeys, paramKeys);
    }

    @Test
    public void settableCtxParams() throws Exception {
        OsslParamBuffer params = md.settableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = FipsProviderInfoUtil.isSymCryptProvider() ?
            Set.of("recompute_checksum", "state") : EMPTY_SET;
        assertEquals(expectedParamKeys, paramKeys);
    }

    @Test
    public void upRef() throws Exception {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            md.upRef(confinedArena);
        }
        // Confirm md is still live
        assertEquals(alg, md.name());
    }

    @Test
    public void testObjectPool() throws Exception {
        int maxMainStackDepth = 10; // This is the ObjectPool MAX_STACK_DEPTH.
        int nrCtxObjects = 100;

        EVP_MD_CTX[] ctxObjects = new EVP_MD_CTX[nrCtxObjects];
        for (int i = 0; i < nrCtxObjects; ++i) {
            // Pooling is only used if no Arena is specified.
            // Get a new unique EVP_MD_CTX.
            ctxObjects[i] = openSsl.newEvpMdCtx();
            assertFalse(ctxObjects[i].isInitialized());

            // Verify that the instance is unique.
            for (int j = 0; j < i; ++j) {
                assertNotSame(ctxObjects[i], ctxObjects[j]);
            }
        }

        // Release all EVP_MD_CTXs and then verify that calls to newEvpMdCtx()
        // will get the same instances back in the expected order.
        for (int i = 0; i < nrCtxObjects; ++i) {
            ctxObjects[i].release();
        }

        // Verify the order of objects retrieved from the pool are in the expected order.

        // The first 10 released ctx objects will remain on the main stack and will be the
        // first 10 returned by newEvpMdCtx(), but in reverse order.
        for (int i = maxMainStackDepth - 1; i >= 0; --i) {
            EVP_MD_CTX ctx = openSsl.newEvpMdCtx();
            assertFalse(ctxObjects[i].isInitialized());
            assertSame(ctxObjects[i], ctx);
        }

        // The remaining ctx objects will come from the overflow stack, in reverse order.
        for (int i = nrCtxObjects - 1; i >= maxMainStackDepth; --i) {
            EVP_MD_CTX ctx = openSsl.newEvpMdCtx();
            assertFalse(ctxObjects[i].isInitialized());
            assertSame(ctxObjects[i], ctx);
        }
    }

    @Test
    public void testObjectPoolDup() throws Exception {
        int maxMainStackDepth = 10; // This is the ObjectPool MAX_STACK_DEPTH.
        int nrCtxObjects = 100;

        EVP_MD_CTX[] ctxObjects = new EVP_MD_CTX[nrCtxObjects];
        for (int i = 0; i < nrCtxObjects; ++i) {
            // Pooling is only used if no Arena is specified.
            // Get a new unique EVP_MD_CTX.
            ctxObjects[i] = mdCtx.dup();
            assertTrue(ctxObjects[i].isInitialized());

            // Verify that the instance is unique.
            for (int j = 0; j < i; ++j) {
                assertNotSame(ctxObjects[i], ctxObjects[j]);
            }
        }

        // Release all EVP_MD_CTXs and then verify that calls to dup()
        // will get the same instances back in the expected order.
        for (int i = 0; i < nrCtxObjects; ++i) {
            ctxObjects[i].release();
        }

        // Verify the order of objects retrieved from the pool are in the expected order.

        // The first 10 released ctx objects will remain on the main stack and will be the
        // first 10 returned by dup(), but in reverse order.
        for (int i = maxMainStackDepth - 1; i >= 0; --i) {
            EVP_MD_CTX ctx = mdCtx.dup();
            assertTrue(ctxObjects[i].isInitialized());
            assertSame(ctxObjects[i], ctx);
        }

        // The remaining ctx objects will come from the overflow stack, in reverse order.
        for (int i = nrCtxObjects - 1; i >= maxMainStackDepth; --i) {
            EVP_MD_CTX ctx = mdCtx.dup();
            assertTrue(ctxObjects[i].isInitialized());
            assertSame(ctxObjects[i], ctx);
        }
    }

    @Test
    public void ctxGettableParams() throws Exception {
        OsslParamBuffer params = mdCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = FipsProviderInfoUtil.isSymCryptProvider() ?
                Set.of("state") : EMPTY_SET;
        assertEquals(expectedParamKeys, paramKeys);
    }

    @Test
    public void ctxSettableParams() throws Exception {
        OsslParamBuffer params = mdCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = FipsProviderInfoUtil.isSymCryptProvider() ?
                Set.of("recompute_checksum", "state") : EMPTY_SET;
        assertEquals(expectedParamKeys, paramKeys);
    }

    @Test
    public void uninitializedCtxGettableParams() throws Exception {
        assertEquals(this.openSsl.emptyParamBuffer(), uninitialisedMdCtx.gettableParams());
    }

    @Test
    public void uninitializedCtxSettableParams() throws Exception {
        assertEquals(this.openSsl.emptyParamBuffer(), uninitialisedMdCtx.settableParams());
    }

    @Test
    public void size() throws Exception {
        assertEquals(SHA_256_MD_SIZE, md.size());
        assertEquals(SHA_256_MD_SIZE, mdCtx.size());
    }

    @Test
    public void blockSize() {
        assertEquals(SHA_256_MD_BLOCK_SIZE, md.blockSize());
        assertEquals(SHA_256_MD_BLOCK_SIZE, mdCtx.blockSize());
    }

    @Test
    public void uninitializedCtxSize() throws Exception {
        assertEquals(0, uninitialisedMdCtx.size());
    }

    @Test
    public void uninitializedCtxBlockSize() throws Exception {
        assertEquals(0, uninitialisedMdCtx.blockSize());
    }

    @Test
    public void isInitialized() {
        assertFalse(uninitialisedMdCtx.isInitialized());
        assertTrue(mdCtx.isInitialized());
    }

    @Test
    public void digest() {
        mdCtx.update(data, 0, data.length);
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
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
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
    }

    ByteBuffer copyDirect(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf.clear();
    }

    @Test
    public void digestFinalWithOffset() {
        mdCtx.update(data, 0, data.length);
        byte[] array = new byte[dataDigest.length + 10];
        int resultLen = mdCtx.digestFinal(array, 5);
        assertEquals(dataDigest.length, resultLen);
        byte[] result = Arrays.copyOfRange(array, 5, 5 + dataDigest.length);
        assertArrayEquals(dataDigest, result);
    }

    @Test
    public void updateWithOffset() {
        byte[] array = new byte[data.length + 10];
        System.arraycopy(data, 0, array, 5, data.length);
        mdCtx.update(array, 5, data.length);
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
    }

    @Test
    public void empty() throws Exception {
        byte[] result = new byte[emptyDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(emptyDigest.length, resultLen);
        assertArrayEquals(emptyDigest, result);
    }

    @Test
    public void updateEmpty() {
        mdCtx.update(data, 0, 0);
        byte[] result = new byte[emptyDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(emptyDigest.length, resultLen);
        assertArrayEquals(emptyDigest, result);
    }

    @Test
    public void updateEmptyZeroLengthArray() {
        mdCtx.update(new byte[0], 0, 0);
        byte[] result = new byte[emptyDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(emptyDigest.length, resultLen);
        assertArrayEquals(emptyDigest, result);
    }

    @Test
    public void updateOneByteAtATime() {
        byte[] buf = new byte[1];
        for (byte b : data) {
            buf[0] = b;
            mdCtx.update(buf, 0, 1);
        }
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
    }

    @Test
    public void updateParts() {
        mdCtx.update(data, 0, 3);
        mdCtx.update(data, 3, 3);
        byte[] finalData = Arrays.copyOfRange(data, 6, data.length);
        mdCtx.update(finalData, 0, finalData.length);
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
    }

    @Test
    public void reuse() {
        mdCtx.update(data, 0, data.length);
        byte[] result1 = new byte[dataDigest.length];
        int result1Len = mdCtx.digestFinal(result1, 0);
        assertEquals(dataDigest.length, result1Len);

        mdCtx.init(null);

        byte[] result2 = new byte[dataDigest.length];
        int result2Len = mdCtx.digestFinal(result2, 0);
        assertEquals(dataDigest.length, result2Len);

        mdCtx.init(null);

        mdCtx.update(data, 0, data.length);
        byte[] result3 = new byte[dataDigest.length];
        int result3Len = mdCtx.digestFinal(result3, 0);
        assertEquals(dataDigest.length, result3Len);

        assertArrayEquals(dataDigest, result1);
        assertArrayEquals(emptyDigest, result2);
        assertArrayEquals(dataDigest, result3);
    }

    @Test
    public void updateDupUpdate() {
        mdCtx.update(data, 0, 6);
        EVP_MD_CTX dupCtx = mdCtx.dup(testArena);

        byte[] finalData = Arrays.copyOfRange(data, 6, data.length);
        mdCtx.update(finalData, 0, finalData.length);
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);

        finalData = Arrays.copyOfRange(data, 6, data.length);
        dupCtx.update(finalData, 0, finalData.length);
        result = new byte[dataDigest.length];
        resultLen = dupCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
    }

    @Test
    public void updateDupResetUpdate() {
        mdCtx.update(data, 0, 6);
        EVP_MD_CTX dupCtx = mdCtx.dup(testArena);

        mdCtx.reset();
        mdCtx.init(md);
        mdCtx.update(data, 0, data.length);
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);

        byte[] finalData = Arrays.copyOfRange(data, 6, data.length);
        dupCtx.update(finalData, 0, finalData.length);
        result = new byte[dataDigest.length];
        resultLen = dupCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
    }

    @Test
    public void uninitializedCtxDup() throws Exception {
        // OpenSSL commit 11a044af6ed36f833e15b30ce742842318bc20cc added support copying uninitialized digest contexts.
        // This first appeared in 3.0.1
        assumeTrue(openSsl.versionMajor() > 3 || openSsl.versionMinor() > 0 || openSsl.versionPatch() > 0);
        assertFalse(uninitialisedMdCtx.dup(testArena).isInitialized());
    }

    @Test
    public void reset() {
        assertTrue(mdCtx.isInitialized());
        mdCtx.reset();
        assertFalse(mdCtx.isInitialized());
        mdCtx.init(md);
        assertTrue(mdCtx.isInitialized());
    }

    @Test
    public void ctxGetParams() throws Exception {
        // OpenSSL commit 5fbf6dd009fe23fcbd040eed058dd6b5f4d2e717 fixed null pointer verification in
        // EVP_MD_CTX_get_params.  Calling EVP_MD_CTX_get_params on an initialised EVP_MD_CTX in
        // OpenSSL 3.0.x versions < 3.0.9 and OpenSSL 3.1.x versions < 3.1.1 can trigger a null pointer
        // dereference that crashes the JVM.
        // Jipher must ensure that EVP_MD_CTX_get_params is not called in these circumstances.
        try {
            mdCtx.getParams(this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", OSSL_PARAM.Type.INTEGER)));
        } catch (OpenSslException e) {
            assertEquals("EVP_MD_CTX_get_params failed", e.getMessage());
        }
    }

    @Test
    public void ctxSetParams() throws Exception {
        // This test increases code coverage
        try {
            mdCtx.setParams(this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", 3)));
        } catch (OpenSslException e) {
            // The SHA-256 MD CTX does not have any gettable parameters
            assertEquals("EVP_MD_CTX_set_params failed", e.getMessage());
        }
    }

    @Test
    public void ctxGetEmptyParams() throws Exception {
        // This test increases code coverage
        mdCtx.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void ctxSetEmptyParams() throws Exception {
        // This test increases code coverage
        mdCtx.setParams(this.openSsl.emptyParamBuffer());
    }

    // Negative tests

    @Test(expected = RuntimeException.class)
    public void forEachNameThrowsRuntimeExceptionNeg() {
        md.forEachName(name -> {
            throw new RuntimeException("forEachConsumerFailed");
        });
    }

    @Test(expected = AssertionError.class)
    public void forEachNameThrowsExceptionNeg() {
        md.forEachName(name -> EvpMdTest.throwAsUnchecked(new Exception("forEachConsumerFailed")));
    }

    @Test(expected = Error.class)
    public void forEachNameThrowsErrorNeg() {
        md.forEachName(name -> {
            throw new Error("forEachConsumerFailed");
        });
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxGetParamsNeg() throws Exception {
        uninitialisedMdCtx.getParams(
                this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", OSSL_PARAM.Type.INTEGER)));
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxSetParamsNeg() throws Exception {
        uninitialisedMdCtx.setParams(
                this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", 3)));
    }

    @Test (expected = IllegalStateException.class)
    public void uninitializedCtxUpdateNeg() throws Exception {
        uninitialisedMdCtx.update(data, 0, data.length);
    }

    @Test (expected = IllegalStateException.class)
    public void uninitializedCtxDigestFinalNeg() throws Exception {
        byte[] output = new byte[dataDigest.length];
        uninitialisedMdCtx.digestFinal(output, 0);
    }

    @Test (expected = IllegalStateException.class)
    public void uninitializedCtxUpdateByteBufferNeg() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(data);
        uninitialisedMdCtx.update(input);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void insufficientOutputSpaceNeg() {
        mdCtx.update(data, 0, data.length);
        byte[] result = new byte[dataDigest.length - 1];
        int resultLen = mdCtx.digestFinal(result, 0);
        assertEquals(dataDigest.length, resultLen);
        assertArrayEquals(dataDigest, result);
    }

    // The type parameter (to EVP_DigestInit_ex2) can be NULL (only) if ctx has been already initialized
    @Test(expected = IllegalStateException.class)
    public void initNullAfterResetNeg() {
        mdCtx.reset();
        mdCtx.init(null);
    }

    // The type parameter (to EVP_DigestInit_ex2) can be NULL (only) if ctx has been already initialized
    @Test(expected = IllegalStateException.class)
    public void initNullAfterConstructNeg() {
        mdCtx = openSsl.newEvpMdCtx(testArena);
        mdCtx.init(null);
    }

    @Test(expected = IllegalStateException.class)
    public void updateAfterResetNeg() {
        mdCtx.reset();
        mdCtx.update(data, 0, data.length);
    }

    @Test(expected = IllegalStateException.class)
    public void digestFinalAfterResetNeg() {
        mdCtx.reset();
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
    }

    @Test(expected = IllegalStateException.class)
    public void updateAfterConstructNeg() {
        mdCtx = openSsl.newEvpMdCtx(testArena);
        mdCtx.update(data, 0, data.length);
    }

    @Test(expected = IllegalStateException.class)
    public void digestFinalAfterConstructNeg() {
        mdCtx = openSsl.newEvpMdCtx(testArena);
        byte[] result = new byte[dataDigest.length];
        int resultLen = mdCtx.digestFinal(result, 0);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateNegOffsetNeg() {
        mdCtx.update(data, -1, 3);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateNegLenNeg() {
        mdCtx.update(data, 0, -1);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateBadLenNeg() {
        mdCtx.update(data, 0, data.length + 1);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateBadOffsetNeg() {
        mdCtx.update(data, data.length + 1, 0);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateBadRemainingLenNeg() {
        mdCtx.update(data, 3, data.length - 1);
    }
}

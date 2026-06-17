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
import com.oracle.jiphertest.testdata.MacTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class EvpMacTest extends EvpTest {

    static final Set<String> EMPTY_SET = Collections.<String>emptySet();

    static final String MAC_NAME = EVP_MAC.MAC_NAME_HMAC;
    static final String MAC_DESCRIPTION = null;

    // The following are the PARAM_KEYS in OpenSSL version 3.0.0, excluding parameters that should not have been present
    // and were thus removed in https://github.com/openssl/openssl/pull/28142, specifically in
    // https://github.com/openssl/openssl/pull/28142/commits/62d2056b573dfae64802d8a553dc3b30fcfe6cc9
    // which first appeared in version 3.6.0. Later versions may support additional parameters
    static final Set<String> HMAC_GETTABLE_PARAM_KEYS = EMPTY_SET;
    static final Set<String> HMAC_CTX_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList("block-size", "size"));
    static final Set<String> HMAC_CTX_SETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "key", "digest", "tls-data-size", "properties"));

    static final long HMAC_SHA_256_MAC_SIZE = 32;
    static final long HMAC_SHA_256_MAC_BLOCK_SIZE = 64;

    private Version fipsProviderVersion;

    private String alg;
    private String mdAlg;
    private byte[] data;
    private byte[] dataMac;
    private byte[] emptyMac;

    private EVP_MAC mac;
    private EVP_MAC_CTX macCtx;
    private EVP_MAC_CTX macCtxEmpty;
    private EVP_MAC_CTX uninitialisedMacCtx;

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

    @Override
    public void setUp() throws Exception {
        super.setUp();

        fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        alg = MAC_NAME;
        MacTestVector tv = TestData.getFirst(MacTestVector.class, alg("HmacSHA256").dataSize(DataSize.BASIC));
        MacTestVector tvEmpty = TestData.getFirst(MacTestVector.class, alg("HmacSHA256").dataSize(DataSize.EMPTY));
        mdAlg = getOpenSslMdAlg(tv.getAlg());
        data = tv.getData();
        dataMac = tv.getMac();
        emptyMac = tvEmpty.getMac();

        mac = libCtx.fetchMac(alg, null, testArena);
        macCtx = openSsl.newEvpMacCtx(mac, testArena);

        OSSL_PARAM params = OSSL_PARAM.of(OSSL_PARAM.ALG_PARAM_DIGEST, mdAlg);
        macCtx.init(tv.getKey(), params);

        macCtxEmpty = openSsl.newEvpMacCtx(mac, testArena);
        macCtxEmpty.init(tvEmpty.getKey(), params);

        uninitialisedMacCtx = openSsl.newEvpMacCtx(mac, testArena);
    }

    @Test
    public void isA() {
        assertTrue(mac.isA(alg));
    }

    @Test
    public void name() {
        assertEquals(alg, mac.name());
    }

    @Test
    public void forEachName() throws Exception {
        mac.forEachName(name -> assertEquals(MAC_NAME, name));
    }

    @Test
    public void description() {
        assertEquals(MAC_DESCRIPTION, mac.description());
    }

    @Test
    public void providerName() {
        assertEquals(LibCtx.getFipsProviderName(), mac.providerName());
    }

    @Test
    public void gettableParams() throws Exception {
        OsslParamBuffer params = mac.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertEquals(HMAC_GETTABLE_PARAM_KEYS, paramKeys);
    }

    @Test
    public void getParams() throws Exception {
        // This test increases code coverage
        mac.getParams(this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", OSSL_PARAM.Type.INTEGER)));
    }

    @Test
    public void getEmptyParams() throws Exception {
        // This test increases code coverage
        mac.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void gettableCtxParams() throws Exception {
        OsslParamBuffer params = mac.gettableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(HMAC_CTX_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void settableCtxParams() throws Exception {
        OsslParamBuffer params = mac.settableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = new HashSet<>(HMAC_CTX_SETTABLE_PARAM_KEYS);
        if (FipsProviderInfoUtil.isSymCryptProvider()) {
            expectedParamKeys.remove("tls-data-size");
        }
        assertTrue(paramKeys.containsAll(expectedParamKeys));
    }

    @Test
    public void upRef() throws Exception {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            mac.upRef(confinedArena);
        }
        // Confirm mac is still live
        assertEquals(alg, mac.name());
    }

    @Test
    public void testObjectPool() throws Exception {
        int maxMainStackDepth = 10; // This is the ObjectPool MAX_STACK_DEPTH.
        int nrCtxObjects = 100;

        EVP_MAC_CTX[] ctxObjects = new EVP_MAC_CTX[nrCtxObjects];
        for (int i = 0; i < nrCtxObjects; ++i) {
            // Pooling is only used if no Arena is specified.
            // Get a new unique EVP_MAC_CTX.
            ctxObjects[i] = openSsl.newEvpMacCtx(mac);
            assertFalse(ctxObjects[i].isInitialized());

            // Verify that the instance is unique.
            for (int j = 0; j < i; ++j) {
                assertNotSame(ctxObjects[i], ctxObjects[j]);
            }
        }

        // Release all EVP_MAC_CTXs and then verify that calls to newEvpMacCtx()
        // will get the same instances back in the expected order.
        for (int i = 0; i < nrCtxObjects; ++i) {
            ctxObjects[i].release();
        }

        // Verify the order of objects retrieved from the pool are in the expected order.

        // The first 10 released ctx objects will remain on the main stack and will be the
        // first 10 returned by newEvpMacCtx(), but in reverse order.
        for (int i = maxMainStackDepth - 1; i >= 0; --i) {
            EVP_MAC_CTX ctx = openSsl.newEvpMacCtx(mac);
            assertFalse(ctxObjects[i].isInitialized());
            assertSame(ctxObjects[i], ctx);
        }

        // The remaining ctx objects will come from the overflow stack, in reverse order.
        for (int i = nrCtxObjects - 1; i >= maxMainStackDepth; --i) {
            EVP_MAC_CTX ctx = openSsl.newEvpMacCtx(mac);
            assertFalse(ctxObjects[i].isInitialized());
            assertSame(ctxObjects[i], ctx);
        }
    }

    @Test
    public void testObjectPoolDup() throws Exception {
        int maxMainStackDepth = 10; // This is the ObjectPool MAX_STACK_DEPTH.

        // Drain the main stack.
        EVP_MAC_CTX[] ctxObjects = new EVP_MAC_CTX[maxMainStackDepth];
        for (int i = 0; i < maxMainStackDepth; ++i) {
            ctxObjects[i] = openSsl.newEvpMacCtx(mac);
            assertFalse(ctxObjects[i].isInitialized());
        }
        EVP_MAC_CTX ctxObject = openSsl.newEvpMacCtx(mac);
        ctxObject.release();

        EVP_MAC_CTX dupCtxObject1 = macCtx.dup();
        assertTrue(dupCtxObject1.isInitialized());
        assertNotSame(dupCtxObject1, ctxObject);
        EVP_MAC_CTX dupCtxObject2 = macCtx.dup();
        assertTrue(dupCtxObject2.isInitialized());
        assertNotSame(dupCtxObject1, dupCtxObject2);

        // EVP_MAC_CTX objects returned by dup() are not from the HMAC EVP_MAC_CTX pool,
        // and are never released to the pool.
        dupCtxObject1.release();
        dupCtxObject2.release();
        ctxObject = openSsl.newEvpMacCtx(mac);
        assertNotSame(dupCtxObject1, ctxObject);
        assertNotSame(dupCtxObject2, ctxObject);
        ctxObject = openSsl.newEvpMacCtx(mac);
        assertNotSame(dupCtxObject1, ctxObject);
        assertNotSame(dupCtxObject2, ctxObject);
    }

    @Test
    public void ctxGettableParams() throws Exception {
        OsslParamBuffer params = macCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(HMAC_CTX_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void ctxSettableParams() throws Exception {
        OsslParamBuffer params = macCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = new HashSet<>(HMAC_CTX_SETTABLE_PARAM_KEYS);
        if (FipsProviderInfoUtil.isSymCryptProvider()) {
            expectedParamKeys.remove("tls-data-size");
        }
        assertTrue(paramKeys.containsAll(expectedParamKeys));
    }

    @Test
    public void uninitializedCtxGettableParams() throws Exception {
        OsslParamBuffer params = uninitialisedMacCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(HMAC_CTX_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void uninitializedCtxSettableParams() throws Exception {
        OsslParamBuffer params = uninitialisedMacCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = new HashSet<>(HMAC_CTX_SETTABLE_PARAM_KEYS);
        if (FipsProviderInfoUtil.isSymCryptProvider()) {
            expectedParamKeys.remove("tls-data-size");
        }
        assertTrue(paramKeys.containsAll(expectedParamKeys));
    }

    @Test
    public void macSize() throws Exception {
       assertEquals(HMAC_SHA_256_MAC_SIZE, macCtx.macSize());
    }

    @Test
    public void blockSize() {
        assertEquals(HMAC_SHA_256_MAC_BLOCK_SIZE, macCtx.blockSize());
    }

    @Test
    public void uninitializedCtxMacSize() throws Exception {
        assertEquals(0, uninitialisedMacCtx.macSize());

        // EVP_MAC_CTX_get_mac_size will leave a EVP_R_MESSAGE_DIGEST_IS_NULL error on the error queue.
        // 00F0476B01000000:error:0300009F:digital envelope routines:EVP_MD_get_size:message digest is null:crypto/evp/evp_lib.c:806:
        openSsl.clearErrorQueue();
    }

    @Test
    public void uninitializedCtxBlockSize() {
        assertEquals(0, uninitialisedMacCtx.blockSize());
    }

    @Test
    public void doFinalNullByteArray() {
        // If EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize) is called,
        // with 'out' being NULL and 'outl' pointing at a valid location, then '*outl' is set to the mac length.
        // This enables the caller to determine how large to allocate 'out' to be.
        // Similarly, macCtx.doFinal(null) (should) return the mac length.
        assertEquals(this.dataMac.length, macCtx.doFinal(null, 0));
    }

    @Test
    public void mac() {
        macCtx.update(data, 0, data.length);
        byte[] result = new byte[dataMac.length];
        int resultLen = macCtx.doFinal(result, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, result);
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
        byte[] observedMac = new byte[dataMac.length];
        macCtx.update(dataBB);
        assertFalse(dataBB.hasRemaining());
        int resultLen = macCtx.doFinal(observedMac, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, observedMac);
    }

    ByteBuffer copyDirect(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf.clear();
    }

    @Test
    public void doFinalWithOffset() {
        macCtx.update(data, 0, data.length);
        byte[] array = new byte[dataMac.length + 10];
        int resultLen = macCtx.doFinal(array, 5);
        assertEquals(dataMac.length, resultLen);
        byte[] result = Arrays.copyOfRange(array, 5, 5 + dataMac.length);
        assertArrayEquals(dataMac, result);
    }

    @Test
    public void updateWithOffset() {
        byte[] array = new byte[data.length + 10];
        System.arraycopy(data, 0, array, 5, data.length);
        macCtx.update(array, 5, data.length);
        byte[] result = new byte[dataMac.length];
        int resultLen = macCtx.doFinal(result, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, result);
    }

    @Test
    public void empty() throws Exception {
        byte[] result = new byte[emptyMac.length];
        int resultLen = macCtxEmpty.doFinal(result, 0);
        assertEquals(emptyMac.length, resultLen);
        assertArrayEquals(emptyMac, result);
    }

    @Test
    public void updateEmpty() {
        macCtxEmpty.update(data, 0, 0);
        byte[] result = new byte[emptyMac.length];
        int resultLen = macCtxEmpty.doFinal(result, 0);
        assertEquals(emptyMac.length, resultLen);
        assertArrayEquals(emptyMac, result);
    }

    @Test
    public void updateEmptyZeroLengthArray() {
        macCtxEmpty.update(new byte[0], 0, 0);
        byte[] result = new byte[emptyMac.length];
        int resultLen = macCtxEmpty.doFinal(result, 0);
        assertEquals(emptyMac.length, resultLen);
        assertArrayEquals(emptyMac, result);
    }

    @Test
    public void updateOneByteAtATime() {
        byte[] buf = new byte[1];
        for (byte b : data) {
            buf[0] = b;
            macCtx.update(buf, 0, 1);
        }
        byte[] result = new byte[dataMac.length];
        int resultLen = macCtx.doFinal(result, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, result);
    }

    @Test
    public void updateParts() {
        macCtx.update(data, 0, 3);
        macCtx.update(data, 3, 3);
        byte[] finalData = Arrays.copyOfRange(data, 6, data.length);
        macCtx.update(finalData, 0, finalData.length);
        byte[] result = new byte[dataMac.length];
        int resultLen = macCtx.doFinal(result, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, result);
    }

    @Test
    public void reuse() {
        // OpenSSL commit 4f675d8c600bfde652aff28cb10c2d16be11fa65 fixed a bug in EVP_MAC reinitialization
        assumeTrue("EVP_MAC reinitialization bug fix first appeared in 3.0.3",
                fipsProviderVersion.compareTo(Version.of("3.0.3")) >= 0);
        macCtx.update(data, 0, data.length);
        byte[] result1 = new byte[dataMac.length];
        int result1Len = macCtx.doFinal(result1, 0);
        assertEquals(dataMac.length, result1Len);

        macCtx.init(null);
        macCtx.update(data, 0, data.length);
        byte[] result2 = new byte[dataMac.length];
        int result2Len = macCtx.doFinal(result2, 0);
        assertEquals(dataMac.length, result2Len);

        assertArrayEquals(dataMac, result1);
        assertArrayEquals(dataMac, result2);
    }

    @Test
    public void updateDupUpdate() {
        macCtx.update(data, 0, 6);
        EVP_MAC_CTX dupCtx = macCtx.dup(testArena);

        byte[] finalData = Arrays.copyOfRange(data, 6, data.length);
        macCtx.update(finalData, 0, finalData.length);
        byte[] result = new byte[dataMac.length];
        int resultLen = macCtx.doFinal(result, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, result);

        finalData = Arrays.copyOfRange(data, 6, data.length);
        dupCtx.update(finalData, 0, finalData.length);
        result = new byte[dataMac.length];
        resultLen = dupCtx.doFinal(result, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, result);
    }

    @Test
    public void uninitializedCtxDup() throws Exception {
        assumeTrue(fipsProviderVersion.compareTo(Version.of("3.0.0")) > 0);
        uninitialisedMacCtx.dup();
    }

    @Test
    public void ctxGetParams() throws Exception {
        OsslParamBuffer sizeParam = this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("size", OSSL_PARAM.Type.INTEGER));
        macCtx.getParams(sizeParam);
        assertTrue(sizeParam.locate("size").isPresent());
        assertEquals(HMAC_SHA_256_MAC_SIZE, sizeParam.locate("size").get().intValue());
    }

    @Test
    public void ctxSetParams() throws Exception {
        OsslParamBuffer digestParam = this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("digest", mdAlg));
        macCtx.setParams(digestParam);
    }

    @Test
    public void uninitializedCtxGetParamsNeg() throws Exception {
        uninitialisedMacCtx.getParams(
                this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("size", OSSL_PARAM.Type.INTEGER)));

        // EVP_MAC_CTX_get_params will leave a EVP_R_MESSAGE_DIGEST_IS_NULL error on the error queue.
        // 00F0476B01000000:error:0300009F:digital envelope routines:EVP_MD_get_size:message digest is null:crypto/evp/evp_lib.c:806:
        openSsl.clearErrorQueue();
    }

    @Test
    public void uninitializedCtxSetParamsNeg() throws Exception {
        uninitialisedMacCtx.setParams(
                this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("digest", mdAlg)));
    }

    @Test
    public void ctxGetEmptyParams() throws Exception {
        // This test increases code coverage
        macCtx.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void ctxSetEmptyParams() throws Exception {
        // This test increases code coverage
        macCtx.setParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void shortKey() throws Exception {
        try {
            byte[] key = new byte[112 / 8 - 1];
            byte[] data = new byte[1];
            byte[] mac = new byte[]{102, 32, -77, 31, 41, 36, -72, -64, 21, 71, 116, 95, 65, -126, 93, 50, 35, 54, -8, 62, -69, 19, -41, 35, 103, -121, -119, -43, 84, -40, -93, -17};
            macCtx.init(key, OSSL_PARAM.of(OSSL_PARAM.ALG_PARAM_DIGEST, EVP_MD.DIGEST_NAME_SHA2_256));
            macCtx.update(data, 0, data.length);
            byte[] output = new byte[dataMac.length];
            macCtx.doFinal(output, 0);
            assertArrayEquals(mac, output);
        } catch (OpenSslException e) {
            // hmac-key-check was added in 3.4.0
            assumeTrue("From version 3.4.0, the OpenSSL FIPS provider disallows keys with a security strength < 112 bits when hmac-key-check=1",
                    fipsProviderVersion.compareTo(Version.of("3.4.0")) >= 0);
            assumeTrue(e.getMessage().contains("EVP_MAC_init failed"));
            assumeTrue(e.getMessage().contains("invalid key length"));
        }
    }

    @Test
    public void longKey() throws Exception {
        byte[] key = new byte[128];
        byte[] data = new byte[1];
        byte[] mac = new byte[]{92, -41, 117, 66, 88, -25, 123, -42, -56, 115, 3, 7, 48, -111, 24, -122, 60, -31, -97, -119, 16, 89, 98, -109, 9, -48, 47, -68, -19, -9, 39, -59};
        macCtx.init(key, OSSL_PARAM.of(OSSL_PARAM.ALG_PARAM_DIGEST, EVP_MD.DIGEST_NAME_SHA2_256));
        macCtx.update(data, 0, data.length);
        byte[] output = new byte[dataMac.length];
        macCtx.doFinal(output, 0);
        assertArrayEquals(mac, output);
    }

    // Negative tests

    @Test(expected = IllegalStateException.class)
    public void uninitializedCtxUpdateNeg() throws Exception {
        assertFalse(uninitialisedMacCtx.isInitialized());
       uninitialisedMacCtx.update(data, 0, data.length);
    }

    @Test(expected = IllegalStateException.class)
    public void uninitializedCtxDoFinaNeg() throws Exception {
        byte[] output = new byte[dataMac.length];
        uninitialisedMacCtx.doFinal(output, 0);
    }

    @Test(expected = IllegalStateException.class)
    public void uninitializedCtxUpdateByteBufferNeg() throws Exception {
        uninitialisedMacCtx.update(ByteBuffer.wrap(data));
    }

    @Test(expected = RuntimeException.class)
    public void forEachNameThrowsRuntimeExceptionNeg() {
        mac.forEachName(name -> {
            throw new RuntimeException("forEachConsumerFailed");
        });
    }

    @Test(expected = IllegalStateException.class)
    public void uninitializedCtxDoFinalNullByteArrayNeg() {
        assertEquals(0, uninitialisedMacCtx.doFinal(null, 0));
    }

    @Test(expected = AssertionError.class)
    public void forEachNameThrowsExceptionNeg() {
        mac.forEachName(name -> EvpMacTest.throwAsUnchecked(new Exception("forEachConsumerFailed")));
    }

    @Test(expected = Error.class)
    public void forEachNameThrowsErrorNeg() {
        mac.forEachName(name -> {
            throw new Error("forEachConsumerFailed");
        });
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    @Test(expected = IllegalArgumentException.class)
    public void ctxGetReadOnlyParams() throws Exception {
        OsslParamBuffer readOnlyParams = macCtx.gettableParams();
        try {
            macCtx.getParams(readOnlyParams);
        } catch (IllegalArgumentException e) {
            assertEquals("Read-only OsslParamBuffer supplied", e.getMessage());
            throw e;
        }
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void insufficientOutputSpaceNeg() {
        macCtx.update(data, 0, data.length);
        byte[] result = new byte[dataMac.length - 1];
        int resultLen = macCtx.doFinal(result, 0);
        assertEquals(dataMac.length, resultLen);
        assertArrayEquals(dataMac, result);
    }

    @Test(expected = OpenSslException.class)
    public void initNullAfterConstructNeg() {
        // OpenSSL commit 4f675d8c600bfde652aff28cb10c2d16be11fa65 fixed a bug in EVP_MAC reinitialization
        // The bug fix was first release in version 3.0.3
        assumeTrue("EVP_MAC reinitialization bug fix first appeared in 3.0.3",
                fipsProviderVersion.compareTo(Version.of("3.0.3")) >= 0);

        macCtx = openSsl.newEvpMacCtx(mac, testArena);
        macCtx.init(null);
    }

    @Test(expected = IllegalStateException.class)
    public void updateAfterConstructNeg() {
        macCtx = openSsl.newEvpMacCtx(mac, testArena);
        macCtx.update(data, 0, data.length);
    }

    @Test(expected = IllegalStateException.class)
    public void digestFinalAfterConstructNeg() {
        macCtx = openSsl.newEvpMacCtx(mac, testArena);
        byte[] result = new byte[dataMac.length];
        int resultLen = macCtx.doFinal(result, 0);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateNegOffsetNeg() {
        macCtx.update(data, -1, 3);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateNegLenNeg() {
        macCtx.update(data, 0, -1);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateBadLenNeg() {
        macCtx.update(data, 0, data.length + 1);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateBadOffsetNeg() {
        macCtx.update(data, data.length + 1, 0);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void updateBadRemainingLenNeg() {
        macCtx.update(data, 3, data.length - 1);
    }
}

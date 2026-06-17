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
import java.nio.ReadOnlyBufferException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.ShortBufferException;

import org.junit.Assert;
import org.junit.Test;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.DECRYPTION;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.ENCRYPTION;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class EvpCipherTest extends EvpTest {

    static final Set<String> AES_256_GCM_CIPHER_NAMES = new HashSet<>(Arrays.asList(
            "aes-256-gcm", "id-aes256-GCM", "2.16.840.1.101.3.4.1.46"));
    static final String AES_256_GCM_CIPHER_DESCRIPTION = "aes-256-gcm";

    // The following are the PARAM_KEYS in OpenSSL version 3.0.0. Later versions may support additional parameters.
    static final Set<String> AES_256_GCM_CIPHER_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "mode", "blocksize", "keylen", "ivlen", "aead",
            "cts", "custom-iv", "tls-multi", "has-randkey"));
    static final Set<String> AES_256_GCM_CIPHER_CTX_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "keylen", "ivlen", "taglen", "iv", "tag",
            "updated-iv", "tlsaadpad", "tlsivgen"));
    static final Set<String> AES_256_GCM_CIPHER_CTX_SETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "ivlen", "tag", "tlsaad", "tlsivfixed", "tlsivinv"));

    static final int AES_256_GCM_CIPHER_BLOCK_SIZE = 1;

    private Version fipsProviderVersion;

    private String alg;
    private byte[] key;
    private byte[] iv;
    private int tagLen;
    private byte[] aad;
    private byte[] plaintext;
    private byte[] ciphertext;

    private EVP_CIPHER cipher;
    private EVP_CIPHER_CTX cipherCtx;
    private EVP_CIPHER_CTX uninitialisedCipherCtx;
    private OsslParamBuffer params;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        alg = "AES-256-GCM";
        SymCipherTestVector tv = TestData.getFirst(SymCipherTestVector.class, DataMatchers.symMatcher().alg("AES/GCM/NoPadding").keySize(32));
        key = tv.getKey();
        plaintext = tv.getData();
        ciphertext = tv.getCiphertext();
        aad = tv.getAad();
        cipher = libCtx.fetchCipher(alg, null, testArena);

        SymCipherTestVector.CipherParams cipherParams = tv.getCiphParams();
        iv = cipherParams.getIv();
        tagLen = cipherParams.getTagLen();

        params = openSsl.dataParamBuffer(
                OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_IVLEN, iv.length),
                OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_AEAD_TAGLEN, tagLen / 8));

        cipherCtx = openSsl.newEvpCipherCtx(testArena);
        cipherCtx.init(cipher, key, iv, ENCRYPTION, params);

        uninitialisedCipherCtx = openSsl.newEvpCipherCtx(testArena);
    }

    @Test
    public void isA() {
        assertTrue(cipher.isA(alg));
    }

    @Test
    public void name() {
        assertEquals(alg, cipher.name());
    }

    @Test
    public void forEachName() {
        cipher.forEachName(name -> assertTrue(AES_256_GCM_CIPHER_NAMES.contains(name)));
    }

    @Test
    public void description() {
        assertEquals(AES_256_GCM_CIPHER_DESCRIPTION, cipher.description());
    }

    @Test
    public void providerName() {
        assertEquals(LibCtx.getFipsProviderName(), cipher.providerName());
    }

    @Test
    public void gettableParams() throws Exception {
        OsslParamBuffer params = cipher.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(AES_256_GCM_CIPHER_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void getParams() throws Exception {
        OsslParamBuffer blocksizeParam = this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("blocksize", OSSL_PARAM.Type.INTEGER));
        cipher.getParams(blocksizeParam);
        assertTrue(blocksizeParam.locate("blocksize").isPresent());
        assertEquals(AES_256_GCM_CIPHER_BLOCK_SIZE, blocksizeParam.locate("blocksize").get().intValue());
    }

    @Test
    public void getEmptyParams() {
        // This test increases code coverage
        cipher.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void gettableCtxParams() {
        OsslParamBuffer params = cipher.gettableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(AES_256_GCM_CIPHER_CTX_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void settableCtxParams() {
        OsslParamBuffer params = cipher.settableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = new HashSet<>(AES_256_GCM_CIPHER_CTX_SETTABLE_PARAM_KEYS);
        if (FipsProviderInfoUtil.isSymCryptProvider()) {
            expectedParamKeys.remove("ivlen");
        }
        assertTrue(paramKeys.containsAll(expectedParamKeys));
    }

    @Test
    public void upRef() {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            cipher.upRef(confinedArena);
        }
        // Confirm cipher is still live
        assertEquals(alg, cipher.name());
    }

    @Test
    public void testObjectPool() {
        int maxMainStackDepth = 10; // This is the ObjectPool MAX_STACK_DEPTH.
        int nrCtxObjects = 100;

        EVP_CIPHER_CTX[] ctxObjects = new EVP_CIPHER_CTX[nrCtxObjects];
        for (int i = 0; i < nrCtxObjects; ++i) {
            // Pooling is only used if no Arena is specified.
            // Get a new unique EVP_CIPHER_CTX.
            ctxObjects[i] = openSsl.newEvpCipherCtx();

            // Verify that the instance is unique.
            for (int j = 0; j < i; ++j) {
                assertNotSame(ctxObjects[i], ctxObjects[j]);
            }
        }

        // Release all EVP_CIPHER_CTXs and then verify that calls to newEvpCipherCtx()
        // will get the same instances back in the expected order.
        for (int i = 0; i < nrCtxObjects; ++i) {
            ctxObjects[i].release();
        }

        // Verify the order of objects retrieved from the pool are in the expected order.

        // The first 10 released ctx objects will remain on the main stack and will be the
        // first 10 returned by newEvpCipherCtx(), but in reverse order.
        for (int i = maxMainStackDepth - 1; i >= 0; --i) {
            EVP_CIPHER_CTX ctx = openSsl.newEvpCipherCtx();
            assertSame(ctxObjects[i], ctx);
        }

        // The remaining ctx objects will come from the overflow stack, in reverse order.
        for (int i = nrCtxObjects - 1; i >= maxMainStackDepth; --i) {
            EVP_CIPHER_CTX ctx = openSsl.newEvpCipherCtx();
            assertSame(ctxObjects[i], ctx);
        }
    }

    @Test
    public void testObjectPoolDup() {
        int maxMainStackDepth = 10; // This is the ObjectPool MAX_STACK_DEPTH.
        int nrCtxObjects = 100;

        // Create an EVP_CIPHER_CTX that can be duplicated.
        EVP_CIPHER cbcCipher = libCtx.fetchCipher("aes-128-cbc", null, testArena);
        EVP_CIPHER_CTX cbcCipherCtx = openSsl.newEvpCipherCtx(testArena);
        cbcCipherCtx.init(cbcCipher, new byte[16], new byte[16], ENCRYPTION);

        EVP_CIPHER_CTX[] ctxObjects = new EVP_CIPHER_CTX[nrCtxObjects];
        for (int i = 0; i < nrCtxObjects; ++i) {
            // Pooling is only used if no Arena is specified.
            // Get a new unique EVP_CIPHER_CTX.
            ctxObjects[i] = cbcCipherCtx.dup();

            // Verify that the instance is unique.
            for (int j = 0; j < i; ++j) {
                assertNotSame(ctxObjects[i], ctxObjects[j]);
            }
        }

        // Release all EVP_CIPHER_CTXs and then verify that calls to dup()
        // will get the same instances back in the expected order.
        for (int i = 0; i < nrCtxObjects; ++i) {
            ctxObjects[i].release();
        }

        // Verify the order of objects retrieved from the pool are in the expected order.

        // The first 10 released ctx objects will remain on the main stack and will be the
        // first 10 returned by dup(), but in reverse order.
        for (int i = maxMainStackDepth - 1; i >= 0; --i) {
            EVP_CIPHER_CTX ctx = cbcCipherCtx.dup();
            assertSame(ctxObjects[i], ctx);
        }

        // The remaining ctx objects will come from the overflow stack, in reverse order.
        for (int i = nrCtxObjects - 1; i >= maxMainStackDepth; --i) {
            EVP_CIPHER_CTX ctx = cbcCipherCtx.dup();
            assertSame(ctxObjects[i], ctx);
        }
    }

    @Test
    public void ctxGettableParams() {
        OsslParamBuffer params = cipherCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(AES_256_GCM_CIPHER_CTX_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void ctxSettableParams() {
        OsslParamBuffer params = cipherCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = new HashSet<>(AES_256_GCM_CIPHER_CTX_SETTABLE_PARAM_KEYS);
        if (FipsProviderInfoUtil.isSymCryptProvider()) {
            expectedParamKeys.remove("ivlen");
        }
        assertTrue(paramKeys.containsAll(expectedParamKeys));
    }

    @Test
    public void uninitializedCtxGettableParams() {
        // Calling EVP_CIPHER_CTX_gettable_params on an uninitialised EVP_CIPHER_CTX causes a null pointer to be
        // dereferenced. The Java layer must thus protect against this potential for crashing the JVM.
        assertEquals(this.openSsl.emptyParamBuffer(), uninitialisedCipherCtx.gettableParams());
    }

    @Test
    public void uninitializedCtxSettableParams() {
        // Calling EVP_CIPHER_CTX_settable_params on an uninitialised EVP_CIPHER_CTX causes a null pointer to be
        // dereferenced. The Java layer must thus protect against this potential for crashing the JVM.
        assertEquals(this.openSsl.emptyParamBuffer(), uninitialisedCipherCtx.settableParams());
    }

    @Test
    public void blockSize() {
        assertEquals(AES_256_GCM_CIPHER_BLOCK_SIZE, cipher.blockSize());
        assertEquals(AES_256_GCM_CIPHER_BLOCK_SIZE, cipherCtx.blockSize());
    }

    @Test
    public void keyLength() {
        assertEquals(this.key.length, cipher.keyLength());
        assertEquals(this.key.length, cipherCtx.keyLength());
    }

    @Test
    public void ivLength() {
        assertEquals(this.iv.length, cipher.ivLength());
        assertEquals(this.iv.length, cipherCtx.ivLength());
    }

    @Test
    public void tagLength() {
        assertEquals(this.tagLen / 8, cipherCtx.tagLength());
    }

    @Test
    public void uninitializedCtxBlockSize() {
        assertEquals(0, uninitialisedCipherCtx.blockSize());
    }

    @Test
    public void uninitializedCtxKeyLength() {
        assertEquals(0, uninitialisedCipherCtx.keyLength());
    }

    @Test
    public void uninitializedCtxIvLength() {
        assertEquals(0, uninitialisedCipherCtx.ivLength());
    }

    @Test
    public void uninitializedCtxTagLength() {
        assertEquals(0, uninitialisedCipherCtx.tagLength());
    }

    @Test
    public void flags() {
        long flags = EVP_CIPHER.CIPH_CUSTOM_IV | EVP_CIPHER.CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPHER.CIPH_FLAG_AEAD_CIPHER |
                EVP_CIPHER.Mode.GCM.num();
        assertEquals(flags, cipher.flags());
    }

    @Test
    public void mode() {
        assertEquals(EVP_CIPHER.Mode.GCM, cipher.mode());
    }

    @Test
    public void isInitialized() {
        assertFalse(uninitialisedCipherCtx.isInitialized());
        assertTrue(cipherCtx.isInitialized());
    }

    @Test
    public void isEncrypting() {
        assertFalse(uninitialisedCipherCtx.isEncrypting());
        assertTrue(cipherCtx.isEncrypting());
    }

    @Test
    public void updateDupUpdate() throws ShortBufferException {
        assumeTrue(isDupSupported());

        if (aad != null) {
            cipherCtx.update(aad, 0, aad.length, null, 0);
        }

        // Encrypt half the plaintext
        byte[] output = new byte[ciphertext.length];
        int offset = cipherCtx.update(plaintext, 0, plaintext.length / 2, output, 0);

        // Duplicate the cipher context and the ciphertext created thus far
        EVP_CIPHER_CTX dupCtx = cipherCtx.dup(testArena);
        byte[] dupOutput = Arrays.copyOf(output, output.length);
        int dupOffset = offset;

        // Encrypt the remaining plaintext and add that tag
        offset += cipherCtx.update(plaintext, plaintext.length / 2, plaintext.length - (plaintext.length / 2), output, offset);
        offset += cipherCtx.doFinal(output, offset);
        if (tagLen > 0) {
            int tagLenInBytes = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenInBytes);
            OSSL_PARAM[] params = cipherCtx.getParams(template);
            System.arraycopy(params[0].byteArrayValue(), 0, output, offset, tagLenInBytes);
        }
        assertArrayEquals(this.ciphertext, output);

        // Use the duplicated cipher context to encrypt the remaining plaintext and add that tag
        dupOffset += dupCtx.update(plaintext, plaintext.length / 2, plaintext.length - (plaintext.length / 2), dupOutput, dupOffset);
        dupOffset += dupCtx.doFinal(dupOutput, dupOffset);
        if (tagLen > 0) {
            int tagLenInBytes = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenInBytes);
            OSSL_PARAM[] params = dupCtx.getParams(template);
            System.arraycopy(params[0].byteArrayValue(), 0, dupOutput, dupOffset, tagLenInBytes);
        }
        assertArrayEquals(this.ciphertext, dupOutput);
    }

    @Test
    public void updateDupResetUpdate() throws ShortBufferException {
        assumeTrue(isDupSupported());

        if (aad != null) {
            cipherCtx.update(aad, 0, aad.length, null, 0);
        }

        // Encrypt half the plaintext
        byte[] output = new byte[ciphertext.length];
        int offset = cipherCtx.update(plaintext, 0, plaintext.length / 2, output, 0);

        // Duplicate the cipher context and the ciphertext created thus far
        EVP_CIPHER_CTX dupCtx = cipherCtx.dup(testArena);
        byte[] dupOutput = Arrays.copyOf(output, output.length);
        int dupOffset = offset;

        // Reset the (original) cipher context
        cipherCtx.reset();
        cipherCtx.init(cipher, key, iv, ENCRYPTION, params);

        // (Re)encrypt the plaintext and add the tag
        offset = cipherCtx.update(plaintext, 0, plaintext.length, output, 0);
        offset += cipherCtx.doFinal(output, offset);
        if (tagLen > 0) {
            int tagLenInBytes = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenInBytes);
            OSSL_PARAM[] params = cipherCtx.getParams(template);
            System.arraycopy(params[0].byteArrayValue(), 0, output, offset, tagLenInBytes);
        }
        assertArrayEquals(this.ciphertext, output);

        // Use the duplicated cipher context to encrypt the remaining plaintext and add the tag
        dupOffset += dupCtx.update(plaintext, plaintext.length / 2, plaintext.length - (plaintext.length / 2), dupOutput, dupOffset);
        dupOffset += dupCtx.doFinal(dupOutput, dupOffset);
        if (tagLen > 0) {
            int tagLenInBytes = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenInBytes);
            OSSL_PARAM[] params = dupCtx.getParams(template);
            System.arraycopy(params[0].byteArrayValue(), 0, dupOutput, dupOffset, tagLenInBytes);
        }
        assertArrayEquals(this.ciphertext, dupOutput);
    }

    @Test
    public void reinitialize() throws ShortBufferException {
        if (aad != null) {
            cipherCtx.update(aad, 0, aad.length, null, 0);
        }

        byte[] output = new byte[ciphertext.length];
        // Encrypt the plaintext
        int offset = cipherCtx.update(plaintext, 0, plaintext.length, output, 0);
        offset += cipherCtx.doFinal(output, offset);
        if (tagLen > 0) {
            int tagLenInBytes = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenInBytes);
            OSSL_PARAM[] params = cipherCtx.getParams(template);
            System.arraycopy(params[0].byteArrayValue(), 0, output, offset, tagLenInBytes);
        }
        assertArrayEquals(this.ciphertext, output);

        // (Re)initialise the cipher with the same key (implicit) and iv (explicit)
        cipherCtx.init(null, null, iv, ENCRYPTION, params);

        // ((Re) Encrypt the plaintext
        offset = cipherCtx.update(plaintext, 0, plaintext.length, output, 0);
        offset += cipherCtx.doFinal(output, offset);
        if (tagLen > 0) {
            int tagLenInBytes = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenInBytes);
            OSSL_PARAM[] params = cipherCtx.getParams(template);
            System.arraycopy(params[0].byteArrayValue(), 0, output, offset, tagLenInBytes);
        }
        assertArrayEquals(this.ciphertext, output);
    }

    @Test
    public void ctxGetParams() {
        OsslParamBuffer keylenParam = this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("keylen", OSSL_PARAM.Type.INTEGER));
        cipherCtx.getParams(keylenParam);
        assertTrue(keylenParam.locate("keylen").isPresent());
        assertEquals(this.key.length, keylenParam.locate("keylen").get().intValue());
    }

    @Test
    public void ctxSetParams() {
        int newIvLen = this.iv.length / 2;
        OsslParamBuffer ivlenParam = this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("ivlen", newIvLen));
        cipherCtx.setParams(ivlenParam);

        // Confirm new IV length was set
        ivlenParam = this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("ivlen", OSSL_PARAM.Type.INTEGER));
        cipherCtx.getParams(ivlenParam);
        assertTrue(ivlenParam.locate("ivlen").isPresent());
        assertEquals(newIvLen, ivlenParam.locate("ivlen").get().intValue());
    }

    @Test
    public void ctxGetEmptyParams() {
        // This test increases code coverage
        cipherCtx.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void ctxSetEmptyParams() {
        // This test increases code coverage
        cipherCtx.setParams(this.openSsl.emptyParamBuffer());
    }

    // Negative tests

    @Test(expected = RuntimeException.class)
    public void forEachNameThrowsRuntimeExceptionNeg() {
        cipher.forEachName(name -> {
            throw new RuntimeException("forEachConsumerFailed");
        });
    }

    @Test(expected = AssertionError.class)
    public void forEachNameThrowsExceptionNeg() {
        cipher.forEachName(name -> EvpCipherTest.throwAsUnchecked(new Exception("forEachConsumerFailed")));
    }

    @Test(expected = Error.class)
    public void forEachNameThrowsErrorNeg() {
        cipher.forEachName(name -> {
            throw new Error("forEachConsumerFailed");
        });
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    @Test (expected = IllegalArgumentException.class)
    public void initialiseWithoutTypeNeg() {
        EVP_CIPHER_CTX ctx = openSsl.newEvpCipherCtx(testArena);
        ctx.init(null, key, iv, ENCRYPTION, params);
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxGetParamsNeg() {
        uninitialisedCipherCtx.getParams(
                this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("keylen", OSSL_PARAM.Type.INTEGER)));
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxSetParamsNeg() {
        uninitialisedCipherCtx.setParams(
                this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("ivlen", iv.length)));
    }

    @Test (expected = IllegalStateException.class)
    public void uninitializedCtxUpdateNeg() throws Exception {
        byte[] output = new byte[ciphertext.length];
        uninitialisedCipherCtx.update(plaintext, 0, plaintext.length, output, 0);
    }

    @Test (expected = IllegalStateException.class)
    public void uninitializedCtxDoFinalNeg() throws Exception {
        byte[] output = new byte[ciphertext.length];
        uninitialisedCipherCtx.doFinal(output, 0);
    }

    @Test (expected = IllegalStateException.class)
    public void uninitializedCtxUpdateByteBufferNeg() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(plaintext);
        ByteBuffer output = ByteBuffer.allocate(ciphertext.length);
        uninitialisedCipherCtx.update(input, output);
    }

    @Test (expected = IllegalStateException.class)
    public void uninitializedCtxDoFinalByteBufferNeg() throws Exception {
        ByteBuffer output = ByteBuffer.allocate(ciphertext.length);
        uninitialisedCipherCtx.doFinal(output);
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxDupNeg() {
        uninitialisedCipherCtx.dup();
    }

    @Test (expected = IllegalArgumentException.class)
    public void ctxGetReadOnlyParams() {
        OsslParamBuffer readOnlyParams = cipherCtx.gettableParams();
        try {
            cipherCtx.getParams(readOnlyParams);
        } catch (IllegalArgumentException e) {
            assertEquals("Read-only OsslParamBuffer supplied", e.getMessage());
            throw e;
        }
    }

    @Test(expected = ReadOnlyBufferException.class)
    public void updateReadOnlyOutputByteBufferNeg() throws ShortBufferException {
        updateReadOnlyOutputByteBuffer(false);
    }

    @Test(expected = ReadOnlyBufferException.class)
    public void updateReadOnlyOutputDirectByteBufferNeg() throws ShortBufferException {
        updateReadOnlyOutputByteBuffer(true);
    }

    @Test(expected = ReadOnlyBufferException.class)
    public void doFinalReadOnlyOutputDirectByteNeg() throws ShortBufferException {
        doFinalReadOnlyOutputByteBuffer(false);
    }

    @Test(expected = ReadOnlyBufferException.class)
    public void doFinalReadOnlyOutputDirectByteBufferNeg() throws ShortBufferException {
        doFinalReadOnlyOutputByteBuffer(true);
    }

    void updateReadOnlyOutputByteBuffer(boolean direct) throws ShortBufferException {
        if (aad != null) {
            cipherCtx.update(aad, 0, aad.length, null, 0);
        }
        ByteBuffer input = ByteBuffer.wrap(plaintext);
        ByteBuffer output = allocateReadOnlyByteBuffer(ciphertext.length, direct);
        cipherCtx.update(input, output);
    }

    void doFinalReadOnlyOutputByteBuffer(boolean direct) throws ShortBufferException {
        if (aad != null) {
            cipherCtx.update(aad, 0, aad.length, null, 0);
        }
        ByteBuffer input = ByteBuffer.wrap(plaintext);
        ByteBuffer output = ByteBuffer.allocate(ciphertext.length);
        cipherCtx.update(input, output);
        output = allocateReadOnlyByteBuffer(ciphertext.length - output.position(), direct);
        cipherCtx.doFinal(output);
    }

    @Test(expected = ShortBufferException.class)
    public void paddedEncryptInsufficientOutputBuffer() throws Exception {
        final int AES_ECB_BLOCK_SIZE = 16;

        byte[] input = new byte[AES_ECB_BLOCK_SIZE - 1];
        byte[] output = new byte[input.length]; // This buffer is intentionally of insufficient capacity

        // Create an AES ECB Cipher
        EVP_CIPHER cipher = LibCtx.getInstance().fetchCipher("aes-256-ecb", null, OsslArena.ofConfined());
        EVP_CIPHER_CTX cipherCtx = OpenSsl.getInstance().newEvpCipherCtx(OsslArena.ofConfined());

        // Initialise the cipher context for encryption with padding enabled
        cipherCtx.init(cipher, key, null, ENCRYPTION);
        cipherCtx.setParams(OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, 1));

        // Encrypt the input into an output buffer that is insufficient capacity to accommodate the padding bytes
        int offset = cipherCtx.update(input, 0, input.length, output, 0);
        cipherCtx.doFinal(output, offset);
    }

    @Test(expected = ShortBufferException.class)
    public void paddedDecryptInsufficientOutputBuffer() throws Exception {
        final int AES_ECB_BLOCK_SIZE = 16;

        byte[] plainText = new byte[1];
        byte[] cipherText = new byte[AES_ECB_BLOCK_SIZE];

        // The following buffer is intentionally of insufficient capacity to accommodate
        // the worst case padding block decrypt (BLOCK_SIZE - 1 bytes).
        byte[] recoveredText = new byte[(AES_ECB_BLOCK_SIZE - 1) - 1];

        // Create an AES ECB Cipher
        EVP_CIPHER cipher = LibCtx.getInstance().fetchCipher("aes-256-ecb", null, OsslArena.ofConfined());
        EVP_CIPHER_CTX cipherCtx = OpenSsl.getInstance().newEvpCipherCtx(OsslArena.ofConfined());

        // Initialise the cipher context for encryption with padding enabled
        cipherCtx.init(cipher, key, null, ENCRYPTION);
        cipherCtx.setParams(OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, 1));

        // Encrypt the plaintext into the ciphertext
        int offset = cipherCtx.update(plainText, 0, plainText.length, cipherText, 0);
        cipherCtx.doFinal(cipherText, offset);

        // Initialise the cipher context for decryption with padding enabled
        cipherCtx.init(cipher, key, null, DECRYPTION);
        cipherCtx.setParams(OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, 1));

        // Decrypt the ciphertext into an output buffer that has insufficient capacity to accommodate
        // the worst case padding block decrypt (BLOCK_SIZE - 1 bytes).
        offset = cipherCtx.update(cipherText, 0, cipherText.length, recoveredText, 0);
        cipherCtx.doFinal(recoveredText, offset);
    }

    @Test(expected = IllegalArgumentException.class)
    public void wrapTooMuchData() throws Exception {
        final int SIXTEEN_KILOBYTES = 16384;

        // The 32-bit default ICV for KWP
        final byte[] icv2   = new byte[]{(byte) 0xA6, (byte) 0x59, (byte) 0x59, (byte) 0xA6};
        final int AES_WRAP_PAD_BLOCK_SIZE = 8;

        byte[] input = new byte[SIXTEEN_KILOBYTES + 1];
        byte[] output = new byte[SIXTEEN_KILOBYTES + AES_WRAP_PAD_BLOCK_SIZE * 2];

        // Create an AES Wrap Pad cipher context
        EVP_CIPHER wrapCipher = getCipher("id-aes256-wrap-pad");
        assumeTrue("AES-KWP with padding is not supported", wrapCipher != null);
        EVP_CIPHER_CTX wrapCipherCtx = openSsl.newEvpCipherCtx(testArena);
        wrapCipherCtx.init(wrapCipher, key, icv2, ENCRYPTION);

        // Use it to wrap 16Kb + 1 byte.
        int offset = wrapCipherCtx.update(input, 0, input.length, output, 0);
        wrapCipherCtx.doFinal(output, offset);
    }

    static ByteBuffer allocateReadOnlyByteBuffer(int capacity, boolean direct) {
        return (direct ? ByteBuffer.allocateDirect(capacity) : ByteBuffer.allocate(capacity)).asReadOnlyBuffer();
    }

    boolean isDupSupported() {
        // Support for EVP_CIPHER_CTX_copy was first added in 3.0.13 & 3.1.5
        return switch (fipsProviderVersion.getParts()[1]) {
            case 0 -> fipsProviderVersion.compareTo(Version.of("3.0.13")) >= 0;
            case 1 -> fipsProviderVersion.compareTo(Version.of("3.1.5")) >= 0;
            default -> true;
        };
    }

    // Confirms that the padding state of cipher contexts
    // initialised with a cipher that supports padding
    // can be predicted.
    @Test
    public void testPadding() {
        final Set<String> SUPPORTED_PADDING_CIPHERS = new HashSet<>(Arrays.asList(
                "aes-128-ecb", "aes-192-ecb", "aes-256-ecb",
                "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            SUPPORTED_PADDING_CIPHERS.addAll(Arrays.asList("des-ede3-cbc", "des-ede3-ecb"));
        }

        EVP_CIPHER _cipher;
        EVP_CIPHER_CTX _cipherCtx;

        byte[] key, iv;

        final int paddingDisabled = 0;
        final int paddingEnabled = 1;
        int observed;

        final OSSL_PARAM disablePadding = OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, paddingDisabled);
        final OSSL_PARAM enablePadding = OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, paddingEnabled);
        final OSSL_PARAM queryPadding = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_PADDING, OSSL_PARAM.Type.UNSIGNED_INTEGER);

        int testedCipherCount = 0;
        for (String cipherName : SUPPORTED_PADDING_CIPHERS) {
            _cipher = getCipher(cipherName);
            if (_cipher == null) {
                continue;
            }
            // Some providers can set padding but do not advertise CIPHER_PARAM_PADDING as gettable.
            // This test validates padding state readback, so only exercise ciphers that can report it.
            if (!_cipher.gettableCtxParams().hasKey(EVP_CIPHER.CIPHER_PARAM_PADDING)) {
                continue;
            }
            testedCipherCount++;

            key = cipherName.contains("des") ? new byte[24] : new byte[Integer.parseInt(cipherName.substring(4, 7)) / 8];
            iv = cipherName.contains("ecb")  ? null : cipherName.contains("des") ? new byte[8] : new byte[16];


            // Test 1st time initialization
            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingEnabled, observed);

            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, disablePadding);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingDisabled, observed);

            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, enablePadding);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingEnabled, observed);


            // Test reinitialization with cipher
            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, disablePadding);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingEnabled, observed);

            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, enablePadding);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, disablePadding);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingDisabled, observed);

            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, disablePadding);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, enablePadding);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingEnabled, observed);


            // Test reinitialization without cipher (restore to state when last initialised)
            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, disablePadding);
            _cipherCtx.init(null, key, iv, DECRYPTION);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingDisabled, observed);

            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION, enablePadding);
            _cipherCtx.init(null, key, iv, DECRYPTION);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingEnabled, observed);


            // Test setParams
            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION);
            _cipherCtx.setParams(disablePadding);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingDisabled, observed);

            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION);
            _cipherCtx.setParams(enablePadding);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingEnabled, observed);


            // Test reinitialization without cipher (restore to state when last initialised) with setParams
            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION);
            _cipherCtx.setParams(disablePadding);
            _cipherCtx.init(null, key, iv, DECRYPTION);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingDisabled, observed);

            _cipherCtx = openSsl.newEvpCipherCtx(testArena);
            _cipherCtx.init(_cipher, key, iv, DECRYPTION);
            _cipherCtx.setParams(enablePadding);
            _cipherCtx.init(null, key, iv, DECRYPTION);
            observed = _cipherCtx.getParams(queryPadding)[0].intValue();
            Assert.assertEquals(paddingEnabled, observed);
        }
        assumeTrue("No padding-capable ciphers support padding state queries", testedCipherCount > 0);
    }

    EVP_CIPHER getCipher(String cipherName)  {
        EVP_CIPHER[] cipher = new EVP_CIPHER[1];
        libCtx.forEachCipher((confinedScopeCipher) -> {
            if (confinedScopeCipher.providerName().equals(LibCtx.getFipsProviderName())) {
                // The OpenSSL FIPS provider includes a few non-approved algorithms that are allowed for legacy usage.
                // E.g. Triple DES ECB & CBC. These algorithms, provided by the OpenSSL FIPS provider,
                // would not be returned by an algorithm fetch with a "fips=yes" property query.
                // See https://github.com/openssl/openssl/commit/d65b52ab5751c0c041d0acff2f09e1c30de16daa
                confinedScopeCipher.forEachName(name -> {
                    if (name.equalsIgnoreCase(cipherName)) {
                        cipher[0] = confinedScopeCipher.upRef(testArena);
                    }
                });
            }
        });
        return cipher[0];
    }
}

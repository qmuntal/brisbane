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
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Assume;
import org.junit.Test;

import com.oracle.jiphertest.testdata.AsymCipherTestVector;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static com.oracle.jiphertest.testdata.DataMatchers.keyId;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class EvpPkeyCipherTest extends EvpTest {

    // The following are the PARAM_KEYS in OpenSSL version 3.0.0. Later versions may support additional parameters
    static final Set<String> RSA_ECB_OAEP_CIPHER_CTX_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "pad-mode", "digest", "mgf1-digest", "oaep-label",
            "tls-client-version", "tls-negotiated-version"));
    static final Set<String> RSA_ECB_OAEP_CIPHER_CTX_SETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "pad-mode", "digest", "mgf1-digest", "oaep-label",
            "mgf1-properties", "tls-client-version", "tls-negotiated-version"));

    private  byte[] plaintext;
    private  byte[] ciphertext;

    private EVP_PKEY_CTX encryptorCtx;
    private EVP_PKEY_CTX decryptorCtx;

    private EVP_PKEY_CTX uninitialisedCtx;

    static String getOpenSslMdAlg(String alg) {
        String digest = alg.replace("SHA-", "SHA").replace("SHA", "SHA-");
        return switch (digest) {
            case "SHA-1" -> EVP_MD.DIGEST_NAME_SHA1;
            case "SHA-224" -> EVP_MD.DIGEST_NAME_SHA2_224;
            case "SHA-256" -> EVP_MD.DIGEST_NAME_SHA2_256;
            case "SHA-384" -> EVP_MD.DIGEST_NAME_SHA2_384;
            case "SHA-512" -> EVP_MD.DIGEST_NAME_SHA2_512;
            default -> throw new AssertionError();
        };
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();

        AsymCipherTestVector tv = TestData.getFirst(AsymCipherTestVector.class, alg("RSA/ECB/OAEPPadding"));
        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        KeySpec privateKeySpec = KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        KeySpec publicKeySpec = KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.plaintext = tv.getData();
        this.ciphertext = tv.getCiphertext();

        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PAD_MODE, EVP_PKEY.PKEY_RSA_PAD_MODE_OAEP));
        params.add(OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_DIGEST, EVP_MD.DIGEST_NAME_SHA1));
        if (tv.getParams() != null) {
            AsymCipherTestVector.AsymParams asymParams = tv.getParams();
            params.add(OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_MGF1_DIGEST, getOpenSslMdAlg(asymParams.mgfAlg())));
            params.add(OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_OAEP_LABEL, asymParams.psourceVal()));
        } else {
            // Defaults
            params.add(OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_MGF1_DIGEST, EVP_MD.DIGEST_NAME_SHA1));
            params.add(OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_OAEP_LABEL, new byte[0]));
        }
        OsslParamBuffer asymCipherParams = this.openSsl.dataParamBuffer(this.testArena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));

        EVP_PKEY publicKey = KeyUtil.loadPublic(publicKeySpec, this.libCtx, this.testArena);
        encryptorCtx = libCtx.newPkeyCtx(publicKey,null, this.testArena);
        encryptorCtx.encryptInit();
        encryptorCtx.setParams(asymCipherParams);

        EVP_PKEY privateKey = KeyUtil.loadPrivate(privateKeySpec, this.libCtx, this.testArena);
        decryptorCtx = libCtx.newPkeyCtx(privateKey, null, this.testArena);
        decryptorCtx.decryptInit();
        decryptorCtx.setParams(asymCipherParams);

        uninitialisedCtx = libCtx.newPkeyCtx(publicKey, null, this.testArena);
    }

    @Test
    public void isA() {
        assertTrue(encryptorCtx.isA("RSA"));
    }

    @Test
    public void ctxGettableParams() throws Exception {
        OsslParamBuffer params = encryptorCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = new HashSet<>(RSA_ECB_OAEP_CIPHER_CTX_GETTABLE_PARAM_KEYS);
        if (FipsProviderInfoUtil.isSymCryptProvider()) {
            expectedParamKeys.remove("tls-client-version");
            expectedParamKeys.remove("tls-negotiated-version");
        }
        assertTrue(paramKeys.containsAll(expectedParamKeys));
    }

    @Test
    public void ctxSettableParams() throws Exception {
        OsslParamBuffer params = encryptorCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = new HashSet<>(RSA_ECB_OAEP_CIPHER_CTX_SETTABLE_PARAM_KEYS);
        if (FipsProviderInfoUtil.isSymCryptProvider()) {
            expectedParamKeys.remove("tls-client-version");
            expectedParamKeys.remove("tls-negotiated-version");
            expectedParamKeys.add("digest-props");
        }
        assertTrue(paramKeys.containsAll(expectedParamKeys));
    }

    @Test
    public void uninitializedCtxGettableParams() throws Exception {
        assertEquals(this.openSsl.emptyParamBuffer(), uninitialisedCtx.gettableParams());
    }

    @Test
    public void uninitializedCtxSettableParams() throws Exception {
        assertEquals(this.openSsl.emptyParamBuffer(), uninitialisedCtx.settableParams());
    }

    @Test
    public void ctxGetParams() throws Exception {
        String digest = EVP_MD.DIGEST_NAME_SHA1;
        OsslParamBuffer digestParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("digest", OSSL_PARAM.Type.UTF8_STRING, digest.getBytes(StandardCharsets.UTF_8).length + 1));
        encryptorCtx.getParams(digestParam);
        assertTrue(digestParam.locate("digest").isPresent());
        assertEquals(digest, digestParam.locate("digest").get().stringValue());
    }

    @Test
    public void ctxSetParams() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isRsaOaepMgf1DigestAllowedToDifferFromDigest());
        String expectedDigest = EVP_MD.DIGEST_NAME_SHA2_256;
        String digest = FipsProviderInfoUtil.getDigestName(expectedDigest);
        OsslParamBuffer digestParam = this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("digest", digest));
        encryptorCtx.setParams(digestParam);

        // Confirm new digest was set
        digestParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("digest", OSSL_PARAM.Type.UTF8_STRING, digest.getBytes(StandardCharsets.UTF_8).length + 1));
        encryptorCtx.getParams(digestParam);
        assertTrue(digestParam.locate("digest").isPresent());
        assertEquals(expectedDigest, digestParam.locate("digest").get().stringValue());
    }

    @Test
    public void ctxGetEmptyParams() throws Exception {
        // This test increases code coverage
        encryptorCtx.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void ctxSetEmptyParams() throws Exception {
        // This test increases code coverage
        encryptorCtx.setParams(this.openSsl.emptyParamBuffer());
    }

    // Negative tests

    @Test (expected = OpenSslException.class)
    public void uninitialisedCtxGetParamsNeg() throws Exception {
        String digest = EVP_MD.DIGEST_NAME_SHA1;
        OsslParamBuffer digestParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("digest", OSSL_PARAM.Type.UTF8_STRING, digest.getBytes(StandardCharsets.UTF_8).length + 1));
        uninitialisedCtx.getParams(digestParam);
    }

    @Test (expected = OpenSslException.class)
    public void uninitialisedCtxSetParamsNeg() throws Exception {
        String digest = EVP_MD.DIGEST_NAME_SHA2_256;
        OsslParamBuffer digestParam = this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("digest", digest));
        uninitialisedCtx.setParams(digestParam);
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxEncryptNeg() throws Exception {
        byte[] input = plaintext;
        byte[] output = new byte[ciphertext.length];
        uninitialisedCtx.encrypt(input, 0, input.length, output, 0);
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxDecryptNeg() throws Exception {
        byte[] input = ciphertext;
        byte[] output = new byte[plaintext.length];
        uninitialisedCtx.decrypt(input, 0, input.length, output, 0);
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxEncryptByteBufferNeg() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(this.plaintext);
        ByteBuffer output = ByteBuffer.allocate(this.ciphertext.length);
        uninitialisedCtx.encrypt(input,output);
    }

    @Test (expected = OpenSslException.class)
    public void uninitializedCtxDecryptByteBufferNeg() throws Exception {
        ByteBuffer input = ByteBuffer.wrap(this.ciphertext);
        ByteBuffer output = ByteBuffer.allocate(this.plaintext.length);
        uninitialisedCtx.decrypt(input, output);
    }

    @Test (expected = IllegalArgumentException.class)
    public void ctxGetReadOnlyParamsNeg() throws Exception {
        OsslParamBuffer readOnlyParams = encryptorCtx.gettableParams();
        try {
            encryptorCtx.getParams(readOnlyParams);
        } catch (IllegalArgumentException e) {
            assertEquals("Read-only OsslParamBuffer supplied", e.getMessage());
            throw e;
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void encryptReadOnlyOutputByteBufferNeg() {
        encryptReadOnlyOutputByteBuffer(false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encryptReadOnlyOutputDirectByteBufferNeg() {
        encryptReadOnlyOutputByteBuffer(true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void signFinalReadOnlyOutputByteBufferNeg() {
        signFinalReadOnlyOutputByteBuffer(false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void signFinalReadOnlyOutputDirectByteBufferNeg() {
        signFinalReadOnlyOutputByteBuffer(true);
    }

    void encryptReadOnlyOutputByteBuffer(boolean direct) {
        ByteBuffer input = ByteBuffer.wrap(this.plaintext);
        int outLen = encryptorCtx.encrypt(input, null);
        ByteBuffer output = allocateReadOnlyByteBuffer(outLen, direct);
        encryptorCtx.encrypt(input, output);
    }

    void signFinalReadOnlyOutputByteBuffer(boolean direct) {
        ByteBuffer input = ByteBuffer.wrap(this.ciphertext);
        int outLen = decryptorCtx.decrypt(input, null);
        ByteBuffer output = allocateReadOnlyByteBuffer(outLen, direct);
        decryptorCtx.decrypt(input, output);
    }

    static ByteBuffer allocateReadOnlyByteBuffer(int capacity, boolean direct) {
        return (direct ? ByteBuffer.allocateDirect(capacity) : ByteBuffer.allocate(capacity)).asReadOnlyBuffer();
    }
}

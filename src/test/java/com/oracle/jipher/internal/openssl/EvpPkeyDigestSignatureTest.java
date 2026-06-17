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

import java.security.SignatureException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.SignatureTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static com.oracle.jiphertest.testdata.DataMatchers.keyId;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class EvpPkeyDigestSignatureTest extends EvpTest {

    static final Set<String> EMPTY_SET = Collections.<String>emptySet();

    private byte[] data;
    private byte[] signature;
    private EVP_MD_CTX signCtx;
    private EVP_MD_CTX verifyCtx;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        SignatureTestVector tv = TestData.getFirst(SignatureTestVector.class, alg("SHA256withECDSA"));
        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        KeySpec privateKeySpec = KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        KeySpec publicKeySpec = KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.data = tv.getData();
        this.signature = tv.getSignature();

        this.signCtx = openSsl.newEvpMdCtx(testArena);
        EVP_PKEY privateKey = KeyUtil.loadPrivate(privateKeySpec, this.libCtx, this.testArena);
        this.signCtx.signInit(null, EVP_MD.DIGEST_NAME_SHA2_256, this.libCtx, null, privateKey);

        this.verifyCtx = openSsl.newEvpMdCtx(testArena);
        EVP_PKEY publicKey = KeyUtil.loadPublic(publicKeySpec, this.libCtx, this.testArena);
        this.verifyCtx.verifyInit(null, EVP_MD.DIGEST_NAME_SHA2_256, this.libCtx, null, publicKey);
    }

    @Test
    public void ctxGettableParams() throws Exception {
        OsslParamBuffer params = signCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = FipsProviderInfoUtil.isSymCryptProvider() ?
                Set.of("state") : EMPTY_SET;
        assertEquals(expectedParamKeys, paramKeys);
    }

    @Test
    public void ctxSettableParams() throws Exception {
        OsslParamBuffer params = signCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        Set<String> expectedParamKeys = FipsProviderInfoUtil.isSymCryptProvider() ?
                Set.of("recompute_checksum", "state") : EMPTY_SET;
        assertEquals(expectedParamKeys, paramKeys);
    }

    @Test
    public void verifyIncorrectSignature() throws Exception {
        byte[] incorrectSignature = getIncorrectSignature();
        assertFalse(verifyCtx.verify(this.data, 0, this.data.length,
                incorrectSignature, 0, incorrectSignature.length));
    }

    @Test
    public void verifyUpdateFinalIncorrectSignature() throws Exception {
        byte[] incorrectSignature = getIncorrectSignature();
        verifyCtx.verifyUpdate(this.data, 0, this.data.length);
        assertFalse(verifyCtx.verifyFinal(incorrectSignature, 0, incorrectSignature.length));
    }

    // Negative tests

    @Test(expected = SignatureException.class)
    public void verifySignatureWithInvalidEncoding() throws Exception {
        byte[] signatureWithInvalidEncoding = getSignatureWithInvalidEncoding();
        verifyCtx.verify(this.data, 0, this.data.length,
                signatureWithInvalidEncoding, 0, signatureWithInvalidEncoding.length);
    }

    @Test(expected = SignatureException.class)
    public void verifyUpdateFinalSignatureWithInvalidEncoding() throws Exception {
        byte[] signatureWithInvalidEncoding = getSignatureWithInvalidEncoding();
        verifyCtx.verifyUpdate(this.data, 0, this.data.length);
        verifyCtx.verifyFinal(signatureWithInvalidEncoding, 0, signatureWithInvalidEncoding.length);
    }

    @Test(expected = SignatureException.class)
    public void verifyZeroExtendedSignature() throws Exception {
        byte[] zeroExtendedSignature = Arrays.copyOf(this.signature, signature.length + 1);
        verifyCtx.verify(this.data, 0, this.data.length,
                    zeroExtendedSignature, 0, zeroExtendedSignature.length);
    }

    @Test(expected = SignatureException.class)
    public void verifyUpdateFinalZeroExtendedSignature() throws Exception {
        byte[] zeroExtendedSignature = Arrays.copyOf(this.signature, signature.length + 1);
        verifyCtx.verifyUpdate(this.data, 0, this.data.length);
        verifyCtx.verifyFinal(zeroExtendedSignature, 0, zeroExtendedSignature.length);
    }

    byte[] getIncorrectSignature() {
        // RFC 5480 defines and ECDSA signature DER encoding as SEQUENCE {r  INTEGER, s  INTEGER }
        // An INTEGER is encoded as 0x02, LENGTH, BYTES...
        int rLengthIndex = 2 /*SEQUENCE*/ + 1 /* INTEGER type */;
        int rLength = this.signature[rLengthIndex];
        int rTamperIndex = rLengthIndex + 1 /* LENGTH */ + (rLength / 2);

        // Change a single bit in r to invalidate the signature
        byte[] tampered = Arrays.copyOf(this.signature, this.signature.length);
        tampered[rTamperIndex] = (byte) (tampered[rTamperIndex] ^ 0x01);
        return tampered;
    }

    private byte[] getSignatureWithInvalidEncoding() {
        // RFC 5480 defines and ECDSA signature DER encoding as SEQUENCE {r  INTEGER, s  INTEGER }
        // An INTEGER is encoded as 0x02, LENGTH, BYTES...
        int rLengthIndex = 2 /*SEQUENCE*/ + 1 /* INTEGER type */;
        int rLength = this.signature[rLengthIndex];
        int sTypeIndex = rLengthIndex + 1 /* LENGTH */ + rLength;

        // Change the type of S to boolean (0x01)
        byte[] tampered = Arrays.copyOf(this.signature, this.signature.length);
        tampered[sTypeIndex] = 0x01;
        return tampered;
    }
}

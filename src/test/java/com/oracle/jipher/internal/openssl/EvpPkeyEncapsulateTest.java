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

import java.security.spec.KeySpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;

public class EvpPkeyEncapsulateTest extends EvpTest {
    static final private OSSL_PARAM RSASVE = OSSL_PARAM.of("operation", "RSASVE");

    private EVP_PKEY privateKey;
    private EVP_PKEY publicKey;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("RSA").secParam(Integer.toString(2048)));
        KeySpec privateKeySpec = KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        KeySpec publicKeySpec = KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());

        this.privateKey = KeyUtil.loadPrivate(privateKeySpec, this.libCtx, this.testArena);
        this.publicKey = KeyUtil.loadPublic(publicKeySpec, this.libCtx, this.testArena);
    }

    @Test
    public void encapsulateDecapsulate() throws Exception {
        EVP_PKEY_CTX encapCtx = libCtx.newPkeyCtx(this.publicKey, null, this.testArena);
        try {
            encapCtx.encapsulateInit(RSASVE);
        } catch (OpenSslException e) {
            Assume.assumeNoException("RSASVE encapsulation is not supported", e);
        }

        // Determine wrapped and unwrapped key buffer lengths
        int[] sizes = encapCtx.encapsulate(null, 0, null, 0);
        byte[] wrappedKey = new byte[sizes[0]];
        byte[] genKey = new byte[sizes[1]];
        // Generate wrapped and unwrapped keys
        encapCtx.encapsulate(wrappedKey, 0, genKey, 0);

        EVP_PKEY_CTX decapCtx = libCtx.newPkeyCtx(this.privateKey, null, this.testArena);
        try {
            decapCtx.decapsulateInit(RSASVE);
        } catch (OpenSslException e) {
            Assume.assumeNoException("RSASVE decapsulation is not supported", e);
        }

        // Determine unwrapped key buffer lengths
        int unwrappedLen = decapCtx.decapsulate(wrappedKey, 0,  wrappedKey.length, null, 0);
        byte[] unwrappedKey = new byte[unwrappedLen];
        decapCtx.decapsulate(wrappedKey, 0,  wrappedKey.length, unwrappedKey, 0);

        Assert.assertArrayEquals(genKey, unwrappedKey);
    }
}

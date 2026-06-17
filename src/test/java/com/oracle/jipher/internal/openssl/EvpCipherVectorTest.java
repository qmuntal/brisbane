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
import java.util.Collection;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.TestUtil;

import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.DECRYPTION;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.ENCRYPTION;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test EVP_CIPHER and EVP_CIPHER_CTX using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpCipherVectorTest extends EvpTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(SymCipherTestVector.class);
    }

    private Version fipsProviderVersion;

    private final String cipherName;
    private final String mode;
    private final boolean padding;
    private final String alg;
    private final byte[] key;
    private final byte[] plaintext;
    private final byte[] ciphertext;
    private final byte[] aad;
    private final byte[] iv;
    private final byte[] tag;
    private final int tagLen;

    private EVP_CIPHER cipher;
    private EVP_CIPHER_CTX encryptorCtx;
    private EVP_CIPHER_CTX decryptorCtx;

    public EvpCipherVectorTest(String jcaAlg, SymCipherTestVector tv) throws Exception {
        String[] transformation = jcaAlg.split("/");
        this.cipherName = transformation[0].toUpperCase();
        this.mode = transformation[1].toUpperCase();
        this.padding = !transformation[2].equalsIgnoreCase("NoPadding");
        this.alg = getOpenSslName(cipherName, mode, tv);
        this.key = tv.getKey();
        this.plaintext = tv.getData();
        this.ciphertext = tv.getCiphertext();
        this.aad = tv.getAad();
        SymCipherTestVector.CipherParams params = tv.getCiphParams();
        if (params != null) {
            this.iv = params.getIv();
            if (mode.equals("GCM")) {
                this.tag = tv.getAuthTag();
                this.tagLen = params.getTagLen();
            } else {
                this.tag = null;
                this.tagLen = 0;
            }
        } else {
            this.iv = null;
            this.tag = null;
            this.tagLen = 0;
        }

        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !this.cipherName.contains("DESEDE"));
        Assume.assumeTrue(isCipherSupported(this.alg));
    }

    static String getOpenSslName(String cipherName, String mode, SymCipherTestVector tv) {
        if (cipherName.equals("AES")) {
            return "AES-" + (tv.getKey().length * 8) + '-' + mode.toUpperCase();
        } else if (cipherName.equals("DESEDE")) {
            return "DES-EDE3-" + mode.toUpperCase();
        }
        throw new AssertionError();
    }

    public static boolean isLegacy(String algorithm) {
        return algorithm.toUpperCase().contains("DES-EDE3");
    }

    static boolean isCipherSupported(String algorithm) {
        boolean[] supported = new boolean[1];
        LibCtx.forEachCipher(cipher -> {
            if (cipher.providerName().equals(LibCtx.getFipsProviderName())) {
                cipher.forEachName(name -> {
                    if (name.equalsIgnoreCase(algorithm)) {
                        supported[0] = true;
                    }
                });
            }
        });
        return supported[0];
    }

    // The OpenSSL FIPS provider includes a few algorithms that are allowed by FIPS for legacy use ONLY.
    // E.g. Triple DES ECB & CBC. These algorithms, provided by the OpenSSL FIPS provider, are not returned
    // by an algorithm fetch with a (default) "fips=yes" property query.
    // See https://github.com/openssl/openssl/commit/d65b52ab5751c0c041d0acff2f09e1c30de16daa
    void setUpCipher() {
        if (isLegacy(alg)) {
            // Fetch a FIPS legacy algorithm (from the OpenSSL FIPS provider).
            cipher = libCtx.fetchCipher(alg, "provider=fips,-fips", testArena);
        } else {
            // Fetch a FIPS approved algorithm (from the OpenSSL FIPS provider).
            cipher = libCtx.fetchCipher(alg, null, testArena);
        }
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();

        fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        setUpCipher();
        OSSL_PARAM[] params = {};
        if ((mode.equals("ECB") || mode.equals("CBC")) && !padding) {
            params = new OSSL_PARAM[] {OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, 0)};
        } else if (mode.equals("GCM")) {
            params = new OSSL_PARAM[] {
                    OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_IVLEN, iv.length)
            };
        }

        if (cipherName.equals("DESEDE") && fipsProviderVersion.compareTo(Version.of("3.4.0")) >= 0) {
            // From version 3.4.0, the OpenSSL FIPS provider disallows DESEDE for encryption when tdes-encrypt-disabled=1
            encryptorCtx = null;
        } else {
            encryptorCtx = openSsl.newEvpCipherCtx(testArena);
            encryptorCtx.init(cipher, key, iv, ENCRYPTION, params);
        }
        decryptorCtx = openSsl.newEvpCipherCtx(testArena);
        decryptorCtx.init(cipher, key, iv, DECRYPTION, params);
        if (mode.equals("GCM")) {
            // Set in setUp() to facilitate testing decryptorCtx.tagLength() == tagLen / 8 in evpCipherCtxState()
            decryptorCtx.setParams(OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, this.tag));
        }
    }

    int getEvpCipherIvLength() {
        if (mode.equals("ECB")) {
            // OpenSSL versions less than 3.0.2 contain a bug causing them to report
            // the iv length for 'DESede/ECB/...' Ciphers to be the block size (8)
            if (!cipherName.equals("DESEDE") || fipsProviderVersion.compareTo(Version.of("3.0.2")) >= 0) {
                return 0;
            }
        } else if (mode.equals("GCM")) {
            return 12;
        }
        return cipherName.equals("AES") ? 16 : 8;
    }

    int getEvpCipherCtxIvLength() {
        if (mode.equals("ECB")) {
            if (FipsProviderInfoUtil.isSymCryptProvider() && cipherName.equals("AES")) {
                // SymCrypt reports the AES block size as the context IV length for ECB,
                // even though ECB does not use an IV.
                // See https://github.com/microsoft/SymCrypt-OpenSSL/issues/170.
                return 16;
            }
            // OpenSSL versions less than 3.0.2 contain a bug causing them to report
            // the iv length for 'DESede/ECB/...' Ciphers to be the block size (8)
            if (cipherName.equals("DESEDE") && fipsProviderVersion.compareTo(Version.of("3.0.2")) < 0) {
                return 8;
            }
            return 0;
        }
        return iv.length;
    }

    @Test
    public void evpCipherState() {
        assertTrue(cipher.isA(alg));
        assertEquals(alg, cipher.name());
        assertEquals(LibCtx.getFipsProviderName(), cipher.providerName());
        int cipherBlockSize = cipherName.equals("AES") ? 16 : 8;
        int blockSize = (mode.equals("ECB") || mode.equals("CBC")) ? cipherBlockSize : 1;
        assertEquals(blockSize, cipher.blockSize());
        assertEquals(key.length, cipher.keyLength());
        assertEquals(getEvpCipherIvLength(), cipher.ivLength());
        assertEquals(cipher.mode().num(), cipher.flags() & EVP_CIPHER.CIPH_MODE);
        assertEquals(mode, cipher.mode().name());
    }

    @Test
    public void evpCipherCtxState() {
        if (encryptorCtx != null) {
            assertTrue(encryptorCtx.isInitialized());
            assertTrue(encryptorCtx.isEncrypting());
        }
        assertTrue(decryptorCtx.isInitialized());
        assertFalse(decryptorCtx.isEncrypting());
        int cipherBlockSize = cipherName.equals("AES") ? 16 : 8;
        int blockSize = (mode.equals("ECB") || mode.equals("CBC")) ? cipherBlockSize : 1;
        if (encryptorCtx != null) {
            assertEquals(blockSize, encryptorCtx.blockSize());
            assertEquals(key.length, encryptorCtx.keyLength());
            assertEquals(getEvpCipherCtxIvLength(), encryptorCtx.ivLength());
            // A GCM cipher context's settable parameter keys do not include 'taglen'
            // hence it is not possible to set a non-default (16-byte) tag len for encrypt.
            if (tagLen == 128) {
                assertEquals(tagLen / 8, encryptorCtx.tagLength());
            }
            assertEquals(mode.equals("GCM") ? 16 : 0, encryptorCtx.tagLength());
        }
        assertEquals(blockSize, decryptorCtx.blockSize());
        assertEquals(key.length, decryptorCtx.keyLength());
        assertEquals(getEvpCipherCtxIvLength(), decryptorCtx.ivLength());
        assertEquals(tagLen / 8, decryptorCtx.tagLength());
    }

    @Test
    public void encryptDecrypt() throws Exception {
        Assume.assumeNotNull(this.encryptorCtx);
        if (aad != null) {
            encryptorCtx.update(aad, 0, aad.length, null, 0);
        }
        byte[] ctext = new byte[ciphertext.length];
        int offset = encryptorCtx.update(plaintext, 0, plaintext.length, ctext, 0);
        offset += encryptorCtx.doFinal(ctext, offset);

        if (tagLen > 0) {
            int tagLenB = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenB);
            OSSL_PARAM[] params = encryptorCtx.getParams(template);
            System.arraycopy(params[0].byteArrayValue(), 0, ctext, offset, tagLenB);
            offset += tagLenB;
        }

        assertEquals(ciphertext.length, offset);
        doDecrypt(ctext);
    }

    void doDecrypt(byte[] cTextComputed) throws Exception {
        if (aad != null) {
            decryptorCtx.update(aad, 0, aad.length, null, 0);
        }
        byte[] decrypted = new byte[plaintext.length];
        int tagLenB = tagLen / 8;
        int offset = decryptorCtx.update(cTextComputed, 0, cTextComputed.length - tagLenB, decrypted, 0);

        if (tagLenB > 0) {
            byte[] tag = Arrays.copyOfRange(cTextComputed, cTextComputed.length - tagLenB, cTextComputed.length);
            OSSL_PARAM param = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, tag);
            decryptorCtx.setParams(param);
        }

        byte[] finalBuf = new byte[cipher.blockSize()];
        int finalLen = decryptorCtx.doFinal(finalBuf, 0);
        System.arraycopy(finalBuf, 0, decrypted, offset, finalLen);
        offset += finalLen;
        assertEquals(plaintext.length, offset);

        if (!Arrays.equals(decrypted, this.plaintext)) {
            System.out.println("was:      " + TestUtil.bytesToHex(decrypted));
            System.out.println("expected: " + TestUtil.bytesToHex(this.plaintext));
        }
        assertArrayEquals(this.plaintext, decrypted);
    }

    @Test
    public void encryptDecryptByteBuffer() throws Exception {
        encryptDecryptByteBuffer(false);
    }

    @Test
    public void encryptDecryptByteBufferDirect() throws Exception {
        encryptDecryptByteBuffer(true);
    }

    void encryptDecryptByteBuffer(boolean direct) throws Exception {
        Assume.assumeNotNull(this.encryptorCtx);
        if (aad != null) {
            encryptorCtx.update(direct ? ByteBuffer.wrap(aad) : copyDirect(aad), null);
        }
        ByteBuffer ctext = direct ? ByteBuffer.allocateDirect(ciphertext.length) : ByteBuffer.allocate(ciphertext.length);
        int offset = encryptorCtx.update(direct ? ByteBuffer.wrap(plaintext) : copyDirect(plaintext), ctext);
        assertEquals(ctext.position(), offset);
        offset += encryptorCtx.doFinal(ctext);
        assertEquals(ctext.position(), offset);

        if (tagLen > 0) {
            int tagLenB = tagLen / 8;
            OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, tagLenB);
            OSSL_PARAM[] params = encryptorCtx.getParams(template);
            ctext.put(params[0].byteArrayValue());
        }

        assertFalse(ctext.hasRemaining());
        doDecrypt(ctext.rewind(), direct);
    }

    void doDecrypt(ByteBuffer cTextComputed, boolean direct) throws Exception {
        if (aad != null) {
            decryptorCtx.update(direct ? ByteBuffer.wrap(aad) : copyDirect(aad), null);
        }
        ByteBuffer decrypted = direct ? ByteBuffer.allocateDirect(plaintext.length) : ByteBuffer.allocate(plaintext.length);
        int tagLenB = tagLen / 8;
        cTextComputed.limit(cTextComputed.capacity() - tagLenB);
        int offset = decryptorCtx.update(cTextComputed, decrypted);
        assertEquals(decrypted.position(), offset);

        if (tagLenB > 0) {
            cTextComputed.limit(cTextComputed.capacity());
            byte[] tag = new byte[tagLenB];
            cTextComputed.get(tag);
            OSSL_PARAM param = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, tag);
            decryptorCtx.setParams(param);
        }

        ByteBuffer finalBuf = direct ? ByteBuffer.allocateDirect(cipher.blockSize()) : ByteBuffer.allocate(cipher.blockSize());
        offset = decryptorCtx.doFinal(finalBuf);
        assertEquals(finalBuf.position(), offset);
        decrypted.put(finalBuf.flip());
        assertFalse(decrypted.hasRemaining());

        byte[] decryptedBytes = new byte[plaintext.length];
        decrypted.flip().get(decryptedBytes);
        if (!Arrays.equals(decryptedBytes, this.plaintext)) {
            System.out.println("was:      " + TestUtil.bytesToHex(decryptedBytes));
            System.out.println("expected: " + TestUtil.bytesToHex(this.plaintext));
        }
        assertArrayEquals(this.plaintext, decryptedBytes);
    }

    ByteBuffer copyDirect(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf.clear();
    }

}

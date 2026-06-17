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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import static com.oracle.jipher.internal.openssl.EVP_CIPHER.GCM_IV_MAX_SIZE;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.DECRYPTION;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.ENCRYPTION;

/**
 * Cipher context object for performing symmetric cipher operations.
 */
public final class CipherCtx {
    static final private Map<String, EVP_CIPHER> PREFETCHED_CIPHERS;
    static {
        Map<String, EVP_CIPHER> ciphers = new HashMap<>();
        LibCtx.forEachCipher((confinedScopeCipher) -> {
            if (confinedScopeCipher.providerName().equals(LibCtx.getFipsProviderName())) {
                // The OpenSSL FIPS provider includes a few non-approved algorithms that are allowed for legacy usage.
                // E.g. Triple DES ECB & CBC. These algorithms, provided by the OpenSSL FIPS provider,
                // would not be returned by an algorithm fetch with a "fips=yes" property query.
                // See https://github.com/openssl/openssl/commit/d65b52ab5751c0c041d0acff2f09e1c30de16daa
                EVP_CIPHER cipher = confinedScopeCipher.upRef(OsslArena.global());
                cipher.forEachName(name -> ciphers.put(name.toLowerCase(), cipher));
            }
        });
        PREFETCHED_CIPHERS = Collections.unmodifiableMap(ciphers);
    }

    private final EVP_CIPHER_CTX evpCipherCtx;
    private boolean encrypting;

    public CipherCtx() {
        this.evpCipherCtx = OpenSsl.getInstance().newEvpCipherCtx();
    }

    private CipherCtx(EVP_CIPHER_CTX ctx, boolean encrypting) {
        this.evpCipherCtx = ctx;
        this.encrypting = encrypting;
    }

    /**
     * Release the EVP_CIPHER_CTX object to the EVP_CIPHER_CTX object pool.
     * The caller must cease using this CipherCtx object after calling this method.
     */
    public void release() {
        this.evpCipherCtx.release();
    }

    /**
     * Returns a duplicate of the cipher ctx.
     *
     * @return the duplicate
     * @throws ProviderException if duplicating the cipher ctx fails
     */
    public CipherCtx dup() {
        return new CipherCtx(this.evpCipherCtx.dup(), this.encrypting);
    }

    /**
     * Initialize cipher.
     *
     * @param cipherAlg the cipher algorithm
     * @param padding whether to perform padding
     * @param encrypt whether operation is encryption (true) or decryption (false)
     * @param key the key bytes
     * @param iv the iv bytes
     * @throws InvalidAlgorithmParameterException error initializing cipher with the parameters
     */
    public void init(String cipherAlg, boolean padding, boolean encrypt, byte[] key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException {
        EVP_CIPHER type = PREFETCHED_CIPHERS.get(cipherAlg);
        OSSL_PARAM param = null;

        if (type.mode() == EVP_CIPHER.Mode.ECB || type.mode() == EVP_CIPHER.Mode.CBC) {
            param = OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, padding ? 1 : 0);
        }

        if (key != null) {
            if (key.length != type.keyLength()) {
                // Jipher does not currently support any cipher algorithms that support variable length keys.
                throw new InvalidKeyException("Provided key length (" + key.length +
                        ") does not match cipher algorithm key length (" + type.keyLength() + ")");
            }
        }

        if (iv != null) {
            if (iv.length != type.ivLength()) {
                // GCM is the only cipher mode Jipher supports that supports a variable length IV
                if (type.mode() == EVP_CIPHER.Mode.GCM) {
                    if (encrypt) {
                        // FIPS 140-3 requires the GCM nonce (IV) to be generated within the FIPS boundary when
                        // encrypting. See SP 800-38D section 9.1 'Design considerations' & FIPS 140-3
                        // implementation guidance section C.H 'Key/IV Pair Uniqueness Requirements from SP 800-38D'.
                        //
                        // The OpenSSL FIPS module's security policy document states:
                        // "The Module also supports importing of GCM IVs when an IV is not generated within the
                        //  Module. In the approved mode, an IV must not be imported for encryption from outside the
                        //  cryptographic boundary of the Module as this will result in a non-conformance."
                        //
                        // The SunJSSE provider:
                        // 1) Supplies a 96-bit IV, constructed according to (D)TLS protocol, versions 1.2 & 1.3
                        //    (See FIPS-140-3 IG C.H scenario 1), when encrypting TLS record content with GCM.
                        // 2) Supplies a 128-bit IV, constructed in accordance with SP800-38D section 8.2.2
                        //    RBG-based Construction with a random field of 128-bits and an empty free field
                        //    (See FIPS-140-3 IG C.H scenario 2), when generating a session ticket using GCM.
                        //    When the SecureRandom used to generate the IV is provided by Jipher the
                        //    IV bytes are generated within the cryptographic boundary of the FIPS Module.
                        //
                        // To facilitate providing the cryptography required by the SunJSSE, Jipher does not
                        // enforce that an IV must not be 'imported' for GCM encryption. Instead, the Jipher
                        // documentation documents that the Java Cryptography API should not be used to import
                        // an IV for GCM encryption.  Jipher does enforce that the IV length be at least the
                        // default length (96-bits) as this does not impact the SunJSSE and this is the
                        // minimum length allowed for the 'RBG-based Construction' in SP 800-38D section 8.2.2.
                        if (iv.length < type.ivLength()) {
                            throw new InvalidAlgorithmParameterException(
                                    "Provided IV length (" + iv.length + ") is not supported for GCM encryption");
                        }
                    }
                    if (iv.length > GCM_IV_MAX_SIZE) {
                        throw new InvalidAlgorithmParameterException(
                                "Provided IV length (" + iv.length + ") is longer than maximum length (" + GCM_IV_MAX_SIZE + ") supported by OpenSSL");
                    }
                    param = OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_IVLEN, iv.length);
                } else {
                    throw new InvalidAlgorithmParameterException("Provided IV length (" + iv.length +
                            ") does not match cipher algorithm IV length (" + type.ivLength() + ")");
                }
            }
        }

        this.evpCipherCtx.init(type, key, iv, encrypt ? ENCRYPTION : DECRYPTION, param);
        this.encrypting = encrypt;
    }

    /**
     * Re-initialize the cipher to the state it was in when it was previously
     * initialized, using the previously provided key and IV. It is only intended
     * to be used to implement the documented javax.crypto.Cipher auto-reset
     * semantics, and only for:
     *  - encryption for ECB and CBC modes only.
     *  - decryption for all modes except CTR and GCM.
     *
     * @throws IllegalStateException if the cipher has not already been initialized
     */
    public void reInit() {
        reInit(null);
    }

    /**
     * Re-initialize the cipher context to the existing key and specified IV or, if the
     * <em>iv</em> parameter is <code>null</code>, the state the context was in after
     * it was previously initialized, using the previously provided key and IV.
     *
     * @param iv the new IV or <code>null</code> when no IV is specified
     * @throws IllegalStateException if the cipher has not already been initialized
     */
    public void reInit(byte[] iv) {
        try {
            this.evpCipherCtx.init(null, null, iv, this.encrypting ? ENCRYPTION : DECRYPTION);
        } catch (Exception e) {
            throw new IllegalStateException("Not initialized", e);
        }
    }

    /**
     * Get the IV from the cipher context.
     *
     * @return the IV
     * @throws IllegalStateException if the IV is not available
     */
    public byte[] getIv() {
        int len = this.evpCipherCtx.ivLength();
        OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_IV, OSSL_PARAM.Type.OCTET_STRING, len).sensitive();
        OSSL_PARAM[] params = this.evpCipherCtx.getParams(template);
        return params[0].data;
    }

    /**
     * Update the cipher with the given input, placing output in given array.
     *
     * @param in the input byte array
     * @param inOff the offset into input to begin update
     * @param inLen the number of bytes of input to update
     * @param out the array to place any output
     * @param outOff the offset into out array to place output bytes
     * @return the number of bytes of output written
     */
    public int update(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws ShortBufferException {
        return this.evpCipherCtx.update(in, inOff, inLen, out, outOff);
    }

    /**
     * Update the cipher with the given additional authenticated data.
     *
     * @param in the input aad byte array
     * @param inOff the offset into input to begin update
     * @param inLen the number of bytes of aad input to update
     */
    public void updateAad(byte[] in, int inOff, int inLen) {
        try {
            this.evpCipherCtx.update(in, inOff, inLen, null, 0);
        } catch (ShortBufferException e) {
            throw new AssertionError("Internal error: Unexpected ShortBufferException", e);
        }
    }

    /**
     * Complete the cipher operation, placing output in given array.
     *
     * @param out an array to place any output
     * @param offset the offset into out array to place output bytes
     * @return the number of bytes of output written
     */
    public int doFinal(byte[] out, int offset) throws BadPaddingException, IllegalBlockSizeException, ShortBufferException {
        try {
            return this.evpCipherCtx.doFinal(out, offset);
        } catch (OpenSslException e) {
            if (this.evpCipherCtx.isEncrypting()) {
                IllegalBlockSizeException ibse = new IllegalBlockSizeException(e.getMessage());
                ibse.initCause(e);
                throw ibse;
            } else {
                BadPaddingException bpe = new BadPaddingException(e.getMessage());
                bpe.initCause(e);
                throw bpe;
            }
        }
    }

    /**
     * Set the authentication tag for this decryption.
     *
     * @param tag the tag bytes
     * @param offset the offset into tag bytes
     * @param len the number of tag bytes
     */
    public void setAuthTag(byte[] tag, int offset, int len) {
        byte[] _tag = (offset == 0 && tag.length == len) ? tag: Arrays.copyOfRange(tag, offset, offset + len);
        OSSL_PARAM param = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, _tag);
        this.evpCipherCtx.setParams(param);
    }

    /**
     * Write the authentication tag resulting from this encryption to the given buffer.
     *
     * @param out the output array
     * @param offset the offset into tag bytes
     * @param len the number of tag bytes
     */
    public void getAuthTag(byte[] out, int offset, int len) {
        OSSL_PARAM template = OSSL_PARAM.of(EVP_CIPHER.CIPHER_PARAM_AEAD_TAG, OSSL_PARAM.Type.OCTET_STRING, len);
        OSSL_PARAM[] params = this.evpCipherCtx.getParams(template);
        System.arraycopy(params[0].data, 0, out, offset, len);
    }

}

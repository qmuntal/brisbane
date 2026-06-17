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

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

import org.junit.Assume;
import org.junit.Test;

import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.DECRYPTION;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.ENCRYPTION;

public class MaliciousCipherCtxTest {
    static final int BLOCK_SIZE = 16;
    static final byte[] KEY = new byte[BLOCK_SIZE * 2];
    static final byte[] IV = new byte[BLOCK_SIZE];
    static final String AES_256_WRAP_PAD = "id-aes256-wrap-pad";

    @Test(expected = ShortBufferException.class)
    public void primeBlockSizeMinus1Update1() throws Exception {
        int inLen;
        byte[] in;
        byte[] out;

        // Create an AES CBC cipher context for encrypting with PKCS5Padding
        com.oracle.jipher.internal.openssl.CipherCtx cipherCtx = new com.oracle.jipher.internal.openssl.CipherCtx();
        cipherCtx.init("aes-256-cbc", true, true, KEY, IV);

        // Load 'block size - 1' bytes into the EVP_CIPHER_CTX's internal buffer
        inLen = BLOCK_SIZE - 1;
        in = new byte[inLen];
        out = new byte[inLen];
        cipherCtx.update(in, 0, inLen, out, 0);

        // Perform a 1-byte update with a 1-byte output buffer that will trigger OpenSSL to write a whole block
        inLen = 1;
        in = new byte[inLen];
        out = new byte[inLen];
        cipherCtx.update(in, 0, inLen, out, 0);
    }

    @Test (expected = ShortBufferException.class)
    public void updateDoFinalUpdateUpdate() throws Exception {
        int inLen;
        byte[] in;
        byte[] out;

        // Create an AES CBC cipher context for encrypting with PKCS5Padding
        com.oracle.jipher.internal.openssl.CipherCtx cipherCtx = new com.oracle.jipher.internal.openssl.CipherCtx();
        cipherCtx.init("aes-256-cbc", true, true, KEY, IV);

        // Load 'block size / 2' bytes into the EVP_CIPHER_CTX's internal buffer
        inLen = BLOCK_SIZE >> 1;
        in = new byte[inLen];
        out = new byte[BLOCK_SIZE];
        cipherCtx.update(in, 0, inLen, out, 0);

        // Finish the ciphering operation by calling doFinal
        // The aim here is to leave the record of the number of bytes currently internally buffered by the cipher
        // context at (block size / 2) while the actual number of bytes internally buffered has been reset to 0.
        out = new byte[BLOCK_SIZE];
        cipherCtx.doFinal(out, 0);

        // Perform a 'block size - 1'-byte update
        // The aim here is to set the number of bytes internally buffered by the cipher context to 'block size - 1'
        // while the (mistaken) record of the number of bytes currently internally buffered by the cipher is updated
        // to (block size / 2) - 1
        inLen = BLOCK_SIZE - 1;
        in = new byte[inLen];
        out = new byte[BLOCK_SIZE*2];
        cipherCtx.update(in, 0, inLen, out, 0);

        // Perform a 1-byte update with a '1-byte' output buffer
        // The aim here is to trigger the cipher context to output a block when the (mistaken) record of the number
        // of bytes currently internally buffered by the cipher does not expect any bytes to be output.
        inLen = 1;
        in = new byte[inLen];
        out = new byte[inLen];
        cipherCtx.update(in, 0, inLen, out, 0);
    }

    @Test (expected = IllegalStateException.class)
    public void updateDoFinalBadPaddingExceptionUpdate() throws Exception {
        int inLen;
        byte[] in;
        byte[] out;

        // Create an AES CBC cipher context for decrypting with PKCS5Padding
        com.oracle.jipher.internal.openssl.CipherCtx cipherCtx = new com.oracle.jipher.internal.openssl.CipherCtx();
        cipherCtx.init("aes-256-cbc", true, false, KEY, IV);

        // Perform a 'block size - 1'-byte update
        // The aim here is to set the number of bytes internally buffered by the cipher context to 'block size - 1'
        inLen = BLOCK_SIZE - 1;
        in = new byte[inLen];
        out = new byte[BLOCK_SIZE*2];
        cipherCtx.update(in, 0, inLen, out, 0);

        // Deliberately trigger an error (in this case due to bad padding on a doFinal decrypt).
        // The aim here is to cause the record of the number of bytes currently internally buffered by the cipher
        // to deviate from the actual number of bytes internally buffered by the cipher context in the event of
        // an error.
        try {
            out = new byte[BLOCK_SIZE];
            cipherCtx.doFinal(out, 0);
        } catch (BadPaddingException e) {
            // Expected exception - swallow.
        }

        // Perform a 2-byte update with a '2-byte' output buffer.
        // The aim here is to trigger the cipher context to output a block (block size - 1 + 2 bytes have been input)
        // when the record of the number of bytes currently internally buffered by the cipher could mistakenly
        // be 0 (if the accounting logic does not account for the fact that an error was triggered).
        inLen = 2;
        in = new byte[inLen];
        out = new byte[inLen];
        cipherCtx.update(in, 0, inLen, out, 0);
    }

    // This test case allocates 2 2Gb byte arrays so requires jvmargs of at least '-Xms4200m -Xmx4200m' to run
    // @Test (expected = IllegalArgumentException.class)
    public void encryptMaxIntPlusOneBytes() throws Exception {
        int inLen;
        byte[] in;
        byte[] out;

        // Create an AES CBC cipher context for encrypting with PKCS5Padding
        com.oracle.jipher.internal.openssl.CipherCtx cipherCtx = new com.oracle.jipher.internal.openssl.CipherCtx();
        cipherCtx.init("aes-256-cbc", true, true, KEY, IV);

        // Load 'BLOCK_SIZE - 1' bytes into the EVP_CIPHER_CTX's internal buffer
        inLen = BLOCK_SIZE - 1;
        in = new byte[inLen];
        out = new byte[inLen];
        cipherCtx.update(in, 0, inLen, out, 0);

        // Perform a 'MAX_VALUE - BLOCK_SIZE + 2'-byte update
        // The aim here is to trigger integer overflow
        inLen = Integer.MAX_VALUE - BLOCK_SIZE + 2;
        in = new byte[inLen];
        out = new byte[inLen];
        cipherCtx.update(in, 0, inLen, out, 0);
    }

    @Test(expected = ShortBufferException.class)
    public void unwrapBlockSizeMinus1() throws Exception {
        Assume.assumeTrue("AES-KWP with padding is not supported", isCipherSupported(AES_256_WRAP_PAD));
        // The 32-bit default ICV for KWP
        final byte[] icv2   = new byte[]{(byte) 0xA6, (byte) 0x59, (byte) 0x59, (byte) 0xA6};
        final int blkSz = 8;  // blkSz is 8 for AES Key Wrap

        byte[] plaintText = new byte[blkSz - 1];
        byte[] cipherText = new byte[blkSz * 2];
        byte[] recoveredText = new byte[plaintText.length];

        // Create an AES Wrap Pad cipher context
        com.oracle.jipher.internal.openssl.CipherCtx cipherCtx = new com.oracle.jipher.internal.openssl.CipherCtx();
        cipherCtx.init(AES_256_WRAP_PAD, true, true, KEY, icv2);

        // Use it to wrap blkSz - 1 bytes of plaintext.
        int offset = cipherCtx.update(plaintText, 0, plaintText.length, cipherText, 0);
        cipherCtx.doFinal(cipherText, offset);

        // Now, attempt to unwrap the ciphertext into a buffer the same size as the plaintext.
        // OpenSSL first unwraps the ciphertext into a multiple of blkSz bytes and THEN strips the padding byte(s).
        // The provided buffer (which can only accommodate up to blkSz - 1 bytes) is too small to accommodate
        // the intermediate result output by OpenSSL (that includes the padding bytes).
        // Consequently, the update() call should fail.
        cipherCtx.init(AES_256_WRAP_PAD, true, false, KEY, icv2);
        offset = cipherCtx.update(cipherText, 0, cipherText.length, recoveredText, 0);
        cipherCtx.doFinal(recoveredText, offset);
    }

    private static boolean isCipherSupported(String cipherName) {
        boolean[] supported = new boolean[1];
        LibCtx.forEachCipher(cipher -> {
            if (cipher.providerName().equals(LibCtx.getFipsProviderName())) {
                cipher.forEachName(name -> {
                    if (name.equalsIgnoreCase(cipherName)) {
                        supported[0] = true;
                    }
                });
            }
        });
        return supported[0];
    }

    @Test(expected = ShortBufferException.class)
    public void decryptTogglePadding() throws Exception {
        byte[] plainText = new byte[BLOCK_SIZE * 2];
        byte[] cipherText = new byte[BLOCK_SIZE * 2];
        byte[] recoveredText = new byte[BLOCK_SIZE];

        // Create an AES ECB Cipher
        EVP_CIPHER cipher = LibCtx.getInstance().fetchCipher("aes-256-ecb", null, OsslArena.ofConfined());
        EVP_CIPHER_CTX cipherCtx = OpenSsl.getInstance().newEvpCipherCtx(OsslArena.ofConfined());

        // Initialise the cipher context for encryption with padding disabled
        cipherCtx.init(cipher, KEY, null, ENCRYPTION);
        cipherCtx.setParams(OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, 0));

        // Encrypt the 2 blocks of plaintext into 2 blocks of ciphertext
        int offset = cipherCtx.update(plainText, 0, plainText.length, cipherText, 0);
        cipherCtx.doFinal(cipherText, offset);

        // Initialise the cipher context for decryption with padding ENABLED
        cipherCtx.init(cipher, KEY, null, DECRYPTION);
        cipherCtx.setParams(OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, 1));

        // Decrypt the 2 blocks of ciphertext
        // The OpenSSL engine will buffer the last block of cipher text because it may be a padding block
        offset = cipherCtx.update(cipherText, 0, cipherText.length, recoveredText, 0);

        // Disable Padding
        cipherCtx.setParams(OSSL_PARAM.ofUnsigned(EVP_CIPHER.CIPHER_PARAM_PADDING, 0));

        cipherCtx.doFinal(recoveredText, offset);
    }
}

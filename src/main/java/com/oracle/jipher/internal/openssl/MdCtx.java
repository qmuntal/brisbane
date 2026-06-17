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

import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * MdCtx object for performing digest and digest-signature operations.
 */
public abstract class MdCtx {
    static final private Map<String, EVP_MD> PREFETCHED_MDS;
    static {
        Map<String, EVP_MD> mds = new HashMap<>();
        LibCtx.forEachMd((confinedScopeMd) -> {
            if (confinedScopeMd.providerName().equals(LibCtx.getFipsProviderName())) {
                EVP_MD md = confinedScopeMd.upRef(OsslArena.global());
                md.forEachName(name -> mds.put(name.toUpperCase(), md));
            }
        });
        PREFETCHED_MDS = Collections.unmodifiableMap(mds);
    }

    final EVP_MD_CTX evpMdCtx;

    // Copy constructor
    private MdCtx(MdCtx other) {
        this.evpMdCtx = other.evpMdCtx.dup();
    }

    private MdCtx() {
        this(OpenSsl.getInstance().newEvpMdCtx());
    }

    private MdCtx(EVP_MD_CTX evpMdCtx) {
        this.evpMdCtx = evpMdCtx;
    }

    /**
     * Release the EVP_MD_CTX object to the EVP_MD_CTX object pool.
     * The caller must cease using this MdCtx object after calling this method.
     */
    public void release() {
        this.evpMdCtx.release();
    }

    /**
     * MdCtx Digest class provides operations for performing digests.
     */
    public static final class Digest extends MdCtx {

        // Copy constructor
        public Digest(Digest other) {
            super(other);
        }

        public Digest() {
            super();
        }

        /**
         * Initialize the digest for the specified algorithm type.
         * @param mdAlg the digest algorithm type
         * @throws ProviderException if an error occurs unexpectedly
         */
        public void init(MdAlg mdAlg) {
            try {
                EVP_MD type = PREFETCHED_MDS.get(mdAlg.getAlg());
                this.evpMdCtx.init(type);
            } catch (OpenSslException e) {
                throw new ProviderException("Failed to initialize digest", e);
            }
        }

        /**
         * Update the digest object with the specified data.
         * @param in the input data array
         * @param off the offset into input data
         * @param len the length of data bytes to update
         * @throws ProviderException if an error occurs unexpectedly
         */
        public void update(byte[] in, int off, int len) {
            try {
                this.evpMdCtx.update(in, off, len);
            } catch (OpenSslException e) {
                throw new ProviderException("Failed to update digest", e);
            }
        }

        /**
         * Complete the digest operation, placing the digest in
         * the specified output array.
         * @param out the output array
         * @param off the offset into output array to place output
         * @throws ProviderException if an error occurs unexpectedly
         */
        public void digest(byte[] out, int off) {
            try {
                this.evpMdCtx.digestFinal(out, off);
            } catch (OpenSslException e) {
                throw new ProviderException("Failed to complete digest operation", e);
            }
        }
    }

    /**
     * Provides operations for performing digest-based signing and verifying.
     */
    public static final class Signature extends MdCtx {

        public Signature() {
            super();
        }

        /**
         * Initialize the object for signing.
         * @param alg the algorithm to initialize with
         * @param key the key to initialize with
         * @throws InvalidKeyException if an error occurred while initializing with the specified key
         */
        public void signInit(MdAlg alg, Pkey key, Params params) throws InvalidKeyException {
            try {
                String mdName = alg.getAlg();
                this.evpMdCtx.signInit(params, mdName, LibCtx.getInstance(), LibCtx.PROPERTY_QUERY_FIPS, key.getEvpPkey());
            } catch (OpenSslException e) {
                throw new InvalidKeyException("Failed to initialize Signature object for signing", e);
            }
        }

        /**
         * Initialize the object for verification.
         * @param alg the algorithm to initialize with
         * @param key the key to initialize with
         * @throws InvalidKeyException if an error occurred while initializing with the specified key
         */
        public void verifyInit(MdAlg alg, Pkey key, Params params) throws InvalidKeyException {
            try {
                String mdName = alg.getAlg();
                this.evpMdCtx.verifyInit(params, mdName, LibCtx.getInstance(), LibCtx.PROPERTY_QUERY_FIPS, key.getEvpPkey());
            } catch (OpenSslException e) {
                throw new InvalidKeyException("Failed to initialize Signature object for verification", e);
            }
        }

        /**
         * Update the signature with the specified input data.
         * @param input the input data
         * @param offset the offset into input to start update
         * @param len the length of input to update
         * @throws SignatureException if an error occurred during update
         */
        public void signUpdate(byte[] input, int offset, int len) throws SignatureException {
            try {
                this.evpMdCtx.signUpdate(input, offset, len);
            } catch (OpenSslException e) {
                throw new SignatureException("Failed to update Signature object", e);
            }
        }

        /**
         * Update the verification with the specified input data.
         * @param input the input data
         * @param offset the offset into input to start update
         * @param len the length of input to update
         * @throws SignatureException if an error occurred during update
         */
        public void verifyUpdate(byte[] input, int offset, int len) throws SignatureException {
            try {
                this.evpMdCtx.verifyUpdate(input, offset, len);
            } catch (OpenSslException e) {
                throw new SignatureException("Failed to update Signature object in verify mode", e);
            }
        }

        /**
         * Complete the signature operation.
         * @return the signature bytes
         * @throws SignatureException if an error occurred during update
         */
        public byte[] signFinal() throws SignatureException {
            try {
                int expectedSigLen = this.evpMdCtx.signFinal(null, 0);
                byte[] sig = new byte[expectedSigLen];
                int sigLen = this.evpMdCtx.signFinal(sig, 0);
                if (sigLen < expectedSigLen) {
                    return Arrays.copyOf(sig, sigLen);
                }
                return sig;
            } catch (OpenSslException e) {
                throw new SignatureException("Failed to complete signing operation", e);
            }
        }

        /**
         * Verify the signature is valid for the updated data.
         * @param signature the signature bytes
         * @param offset the offset into signature where signature begins
         * @param len the length of signature in bytes
         * @return {@code true} if the signature verified successfully, {@code false} otherwise
         * @throws SignatureException if an error occurred while verifying the signature
         */
        public boolean verifyFinal(byte[] signature, int offset, int len) throws SignatureException {
            try {
                return this.evpMdCtx.verifyFinal(signature, offset, len);
            } catch (OpenSslException e) {
                throw new SignatureException("Failed to verify signature", e);
            }
        }

        public abstract static class Params implements Consumer<EVP_PKEY_CTX> {}

        public static class PssParams extends Params {
            final int saltLen;

            public PssParams(int saltLen) {
                this.saltLen = saltLen;
            }

            public void accept(EVP_PKEY_CTX evpPkeyCtx) {
                evpPkeyCtx.setParams(
                        OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PAD_MODE, EVP_PKEY.PKEY_RSA_PAD_MODE_PSS),
                        OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_RSA_PSS_SALTLEN, saltLen));
            }
        }
    }

}

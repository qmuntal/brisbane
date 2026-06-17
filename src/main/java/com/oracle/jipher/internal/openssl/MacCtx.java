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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * MacCtx object for performing Message Authentication Code operations.
 */
public abstract class MacCtx {
    static final private Map<String, EVP_MAC> PREFETCHED_MACS;
    static {
        Map<String, EVP_MAC> macs = new HashMap<>();
        LibCtx.forEachMac((confinedScopeMac) -> {
            if (confinedScopeMac.providerName().equals(LibCtx.getFipsProviderName())) {
                EVP_MAC mac = confinedScopeMac.upRef(OsslArena.global());
                mac.forEachName(name -> macs.put(name.toUpperCase(), mac));
            }
        });
        PREFETCHED_MACS = Collections.unmodifiableMap(macs);
    }

    private final EVP_MAC_CTX evpMacCtx;

    // Copy constructor
    private MacCtx(MacCtx other) {
        this.evpMacCtx = other.evpMacCtx.dup();
    }

    private MacCtx(EVP_MAC evpMac, MdAlg md) {
        this.evpMacCtx = OpenSsl.getInstance().newEvpMacCtx(evpMac);
        OSSL_PARAM params = OSSL_PARAM.of(OSSL_PARAM.ALG_PARAM_DIGEST, md.getAlg());
        this.evpMacCtx.setParams(params);
    }

    /**
     * Initialize the Mac with the given key bytes.
     * @param key the MAC key
     * @throws InvalidKeyException if an error occurs unexpectedly
     */
    public void init(byte[] key) throws InvalidKeyException {
        try {
            this.evpMacCtx.init(key);
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to initialize Mac", e);
        }
    }

    /**
     * Release the EVP_MAC_CTX object to the appropriate EVP_MAC_CTX object pool.
     * The caller must cease using this MacCtx object after calling this method.
     */
    public void release() {
        this.evpMacCtx.release();
    }

    /**
     * Update the mac object with the specified data.
     * @param in the input data array
     * @param off the offset into input data
     * @param len the length of data bytes to update
     */
    public void update(byte[] in, int off, int len) {
        this.evpMacCtx.update(in, off, len);
    }

    /**
     * Complete the mac operation, placing the MAC in
     * the specified output array.
     * @param out the output array
     * @param off the offset into output array to place output
     */
    public int mac(byte[] out, int off) {
        return this.evpMacCtx.doFinal(out, off);
    }

    /**
     * MacCtx Hmac class provides operations for performing HMAC mac.
     */
    public static final class Hmac extends MacCtx {

        // Copy constructor
        public Hmac(Hmac other) {
            super(other);
        }

        public Hmac(MdAlg md) {
            super(getHmac(), md);
        }

        static EVP_MAC getHmac() {
            return PREFETCHED_MACS.get(EVP_MAC.MAC_NAME_HMAC);
        }
    }
}

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
import java.security.InvalidParameterException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.oracle.jipher.internal.common.ToolkitProperties;

/**
 * EVP_KDF.
 */
public final class Kdf {

    static final private Map<String, EVP_KDF> PREFETCHED_KDFS;
    static {
        Map<String, EVP_KDF> kdfs = new HashMap<>();
        LibCtx.forEachKdf(confinedScopeKdf -> {
            if (confinedScopeKdf.providerName().equals(LibCtx.getFipsProviderName())) {
                EVP_KDF kdf = confinedScopeKdf.upRef(OsslArena.global());
                kdf.forEachName(name -> kdfs.put(name.toUpperCase(), kdf));
            }
        });
        PREFETCHED_KDFS = Collections.unmodifiableMap(kdfs);
    }

    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    public static byte[] pbkdf2Derive(byte[] pass, byte[] salt, int iter, MdAlg md, int keyLen) throws InvalidAlgorithmParameterException {
        if (iter > ToolkitProperties.getJipherPbkdf2MaximumIterationCountValue()) {
            throw new InvalidAlgorithmParameterException("iterationCount (" + iter + ") exceeds upper bound (" +
                    ToolkitProperties.getJipherPbkdf2MaximumIterationCountValue() + ") applied for PBKDF2");
        }

        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_KDF type = PREFETCHED_KDFS.get(EVP_KDF.KDF_NAME_PBKDF2);

            EVP_KDF_CTX kdfCtx = OpenSsl.getInstance().newEvpKdfCtx(type, confinedArena);

            byte[] key = new byte[keyLen];

            OSSL_PARAM passParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PASSWORD, pass).sensitive();
            OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, salt);
            OSSL_PARAM iterParam = OSSL_PARAM.ofUnsigned(EVP_KDF.KDF_PARAM_ITER, iter);
            OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, md.getAlg());
            // OpenSSL's FIPS provider defaults PBKDF2 pkcs5 mode to 0, which applies SP800-132 lower-bound checks.
            // Set it explicitly so providers with a different default enforce the same FIPS policy.
            OSSL_PARAM pkcs5Param = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PKCS5, 0);

            kdfCtx.derive(key, passParam, saltParam, iterParam, dgstParam, pkcs5Param);
            return key;
        } catch (OpenSslException e) {
            throw new InvalidAlgorithmParameterException("Failed to derive key using PBKDF2", e);
        }
    }

    public static byte[] tls1PrfDerive(byte[] secret, byte[] label, byte[] seed1, byte[] seed2, MdAlg md, int outLen) throws InvalidParameterException {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_KDF type = PREFETCHED_KDFS.get(EVP_KDF.KDF_NAME_TLS1_PRF);
            EVP_KDF_CTX kdfCtx = OpenSsl.getInstance().newEvpKdfCtx(type, confinedArena);

            byte[] out = new byte[outLen];

            byte[] seed = new byte[label.length + seed1.length + (seed2 == null ? 0 : seed2.length)];
            System.arraycopy(label, 0, seed, 0, label.length);
            System.arraycopy(seed1, 0, seed, label.length, seed1.length);
            if (seed2 != null) {
                System.arraycopy(seed2, 0, seed, label.length + seed1.length, seed2.length);
            }

            if (secret == null) {
                secret = EMPTY_BYTE_ARRAY;
            }

            OSSL_PARAM scrtParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SECRET, secret).sensitive();
            OSSL_PARAM seedParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SEED, seed);
            OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, md.getAlg());

            kdfCtx.derive(out, scrtParam, seedParam, dgstParam);

            return out;
        } catch (OpenSslException e) {
            throw new InvalidParameterException("Failed to derive key using TLS1-PRF", e);
        }
    }

    public static byte[] hkdfExtract(MdAlg md, byte[] key, byte[] salt, int outLen) throws InvalidAlgorithmParameterException {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_KDF type = PREFETCHED_KDFS.get(EVP_KDF.KDF_NAME_HKDF);
            EVP_KDF_CTX kdfCtx = OpenSsl.getInstance().newEvpKdfCtx(type, confinedArena);

            byte[] out = new byte[outLen];

            OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, md.getAlg());
            OSSL_PARAM keyParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_KEY, key).sensitive();
            OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, salt);
            OSSL_PARAM modeParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_MODE, "EXTRACT_ONLY");

            kdfCtx.derive(out, dgstParam, keyParam, saltParam, modeParam);
            return out;
        } catch (OpenSslException e) {
            throw new InvalidAlgorithmParameterException("Failed to derive key using HKDF Extract", e);
        }
    }

    public static byte[] hkdfExpand(MdAlg md, byte[] key, byte[] info,  int outLen) throws InvalidAlgorithmParameterException {

        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_KDF type = PREFETCHED_KDFS.get(EVP_KDF.KDF_NAME_HKDF);
            EVP_KDF_CTX kdfCtx = OpenSsl.getInstance().newEvpKdfCtx(type, confinedArena);

            byte[] out = new byte[outLen];

            OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, md.getAlg());
            OSSL_PARAM keyParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_KEY, key).sensitive();
            OSSL_PARAM infoParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_INFO, info);
            OSSL_PARAM modeParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_MODE, "EXPAND_ONLY");

            kdfCtx.derive(out, dgstParam, keyParam, infoParam, modeParam);

            return out;
        } catch (OpenSslException e) {
            throw new InvalidAlgorithmParameterException("Failed to derive key using HKDF Expand", e);
        }
    }

    public static byte[] hkdfExtractThenExpand(MdAlg md, byte[] key, byte[] salt, byte[] info,  int outLen) throws InvalidAlgorithmParameterException {

        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_KDF type = PREFETCHED_KDFS.get(EVP_KDF.KDF_NAME_HKDF);
            EVP_KDF_CTX kdfCtx = OpenSsl.getInstance().newEvpKdfCtx(type, confinedArena);

            byte[] out = new byte[outLen];

            OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, md.getAlg());
            OSSL_PARAM keyParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_KEY, key).sensitive();
            OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, salt);
            OSSL_PARAM infoParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_INFO, info);

            kdfCtx.derive(out, dgstParam, keyParam, saltParam, infoParam);

            return out;
        } catch (OpenSslException e) {
            throw new InvalidAlgorithmParameterException("Failed to derive key using HKDF Extract-and-Expand", e);
        }
    }

}

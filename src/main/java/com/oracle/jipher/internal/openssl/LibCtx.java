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

import java.security.ProviderException;
import java.util.function.Consumer;

import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.platform.OsslLocator;

// Jipher uses a non-default OpenSSL library context because:
//  *  It is possible for application code other than Jipher to call methods in the instance of the
//     OpenSSL libcryto shared library loaded by Jipher and configure the default library context
//     in ways that make it unsuitable for Jipher.
//         * This also means that there is little point in Jipher configuring the default library context
//           to only have the null provider.
//  *  Different class loaders may load and initialise multiple copies of the Jipher classes. We want to
//     avoid race conditions where a shared OpenSSL library context is configured multiple times from
//     different threads.
//         * Some OpenSSL library context configuration methods, such as EVP_default_properties_enable_fips
//           are not thread safe.

public final class LibCtx {
    private static final OSSL_LIB_CTX LIB_CTX_INSTANCE;
    private static final Exception INIT_EXCEPTION;

    static final String PROPERTY_QUERY_FIPS = "fips=yes";
    static final String PROPERTY_QUERY_NON_FIPS = "-fips";

    static final private String FIPS_PROVIDER_NAME = OsslLocator.getFipsProviderName();
    static final private String FIPS_PROVIDER_NAME_STRING;
    static final private String FIPS_PROVIDER_VERSION_STRING;

    static final private String A_FIPS_MD_ALG = "SHA-256";
    static final private String A_NON_FIPS_MD_ALG = "MD5";

    static {
        OSSL_LIB_CTX libCtx;
        Exception exception = null;
        String fipsProviderName = null;
        String fipsProviderVersion = null;

        try {
            // Create a (non-default) library context and configure it to load the OpenSSL FIPS provider.
            // The global arena is used to avoid OpenSSL issue [16778](https://github.com/openssl/openssl/issues/16778)
            libCtx = OpenSsl.getInstance().newOsslLibCtx(OsslArena.global());
            configure(libCtx);

            // Verify that the library context provides access to FIPS approved algorithms from the FIPS provider
            // by default and cannot be used to access a non-FIPS allowed algorithm.
            if (!isFips(libCtx)) {
                throw new ProviderException(
                        "Failed to configure OpenSSL to only provide FIPS allowed algorithms from the FIPS provider");
            }

            fipsProviderName = libCtx.forProvider(FIPS_PROVIDER_NAME, provider-> {
                OSSL_PARAM query = OSSL_PARAM.of(OSSL_PROVIDER.PROV_PARAM_NAME, OSSL_PARAM.Type.UTF8_PTR);
                OSSL_PARAM[] params = provider.getParams(query);
                return params[0].stringValue();
            }).orElse(null);

            // Retrieve OpenSSL FIPS provider version string
            fipsProviderVersion = libCtx.forProvider(FIPS_PROVIDER_NAME, provider-> {
                OSSL_PARAM query = OSSL_PARAM.of(OSSL_PROVIDER.PROV_PARAM_VERSION, OSSL_PARAM.Type.UTF8_PTR);
                OSSL_PARAM[] params = provider.getParams(query);
                return params[0].stringValue();
            }).orElse(null);

            if (!VersionSanctioner.FipsProvider.accept(fipsProviderVersion)) {
                throw new ProviderException(String.format(
                        "OpenSSL FIPS provider version '%s' is not a sanctioned version '%s'",
                        fipsProviderVersion, VersionSanctioner.FipsProvider.getSanctionedVersions()));
            }
        } catch (Exception e) {
            libCtx = null;
            exception = e;
        }

        FIPS_PROVIDER_NAME_STRING = fipsProviderName;
        FIPS_PROVIDER_VERSION_STRING = fipsProviderVersion;
        LIB_CTX_INSTANCE = libCtx;
        INIT_EXCEPTION = exception;
    }

    private static void configure(OSSL_LIB_CTX libCtx) {
        // Configure the (default) search path to use to locate the FIPS provider
        libCtx.setDefaultProviderSearchPath(OsslLocator.getProviderSearchPath().toString());

        String mac = OsslLocator.getFipsModuleMac();
        libCtx.setConfig(String.format("""
                openssl_conf = openssl_init

                [openssl_init]
                providers = provider_sect

                [provider_sect]
                %3$s = fips_sect

                [fips_sect]
                activate = 1
                conditional-errors = 1
                security-checks = 1
                tls1-prf-ems-check = 1
                no-short-mac = 1
                drbg-no-trunc-md = 1
                signature-digest-check = 1
                dsa-sign-disabled = 1
                hkdf-digest-check = 1
                tls13-kdf-digest-check = 1
                tls1-prf-digest-check = 1
                sshkdf-digest-check = 1
                sskdf-digest-check = 1
                x963kdf-digest-check = 1
                tdes-encrypt-disabled = 1
                rsa-pkcs15-pad-disabled = 1
                rsa-pss-saltlen-check = 1
                rsa-sign-x931-pad-disabled = 1
                hkdf-key-check = 1
                kbkdf-key-check = 1
                tls13-kdf-key-check = 1
                tls1-prf-key-check = 1
                sshkdf-key-check = 1
                sskdf-key-check = 1
                x963kdf-key-check = 1
                x942kdf-key-check = 1
                pbkdf2-lower-bound-check = 1
                ecdh-cofactor-check = 1
                kmac-key-check = 1
                hmac-key-check = %1$d
                %2$s
                """,

                // hmac-key-check = %1$d
                //
                // HMAC verification is allowed for keys with a security strength < 112 bits for "Legacy use" -
                // See SP800 131A Rev 2 section 10. Consequently, the OpenSSL FIPS provider is configured to support
                // it when Jipher is not configured in FIPS_STRICT mode which disallows "Legacy use"
                ToolkitProperties.getFipsEnforcementValue() == Fips.EnforcementPolicy.FIPS_STRICT ? 1 : 0,

                // %2$s
                mac != null ? "module-mac = " + mac : "",

                // %3$s
                FIPS_PROVIDER_NAME
        ));

        if (!libCtx.isProviderAvailable(FIPS_PROVIDER_NAME)) {
            throw new OpenSslException("FIPS provider is not available");
        }

        // Set 'fips=yes' to be a default property query for the library context
        libCtx.enableFips(true);
    }

    // Checks that a library context provides access to FIPS approved algorithms from the FIPS provider by default
    // and cannot be used to access a non-FIPS allowed algorithm.
    private static boolean isFips(OSSL_LIB_CTX libCtx) {
        // Checks that the 'fips' provider is available for use by the library context
        if (!libCtx.isProviderAvailable(FIPS_PROVIDER_NAME)) {
            return false;
        }

        // Check that 'fips=yes' is a default property for the library context.
        if (!libCtx.isFipsEnabled()) {
            return false;
        }

        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            if ("fips".equals(FIPS_PROVIDER_NAME)) {
                // Verify that the library context doesn't provide a non-FIPS algorithm with a NULL property query string
                try {
                    libCtx.fetchMd(A_NON_FIPS_MD_ALG, null, confinedArena);
                    return false;
                } catch (OpenSslException e) {
                    // Expected failure - Do nothing.
                }

                // Verify that the library context doesn't provide a non-FIPS algorithm with a '-fips' property query string
                try {
                    libCtx.fetchMd(A_NON_FIPS_MD_ALG, PROPERTY_QUERY_NON_FIPS, confinedArena);
                    return false;
                } catch (OpenSslException e) {
                    // Expected failure - Do nothing.
                }
            }

            // Verify that the library context will provide a FIPS algorithm from the FIPS provider even with a NULL
            // property query string (due to the default property query string being 'fips=yes')
            EVP_MD md = libCtx.fetchMd(A_FIPS_MD_ALG, null, confinedArena);
            if (!md.providerName().equals((FIPS_PROVIDER_NAME))) {
                // Unexpected provider
                return false;
            }
        }

        return true;
    }

    private LibCtx() {}

    static OSSL_LIB_CTX getInstance() {
        if (LIB_CTX_INSTANCE != null) {
            return LIB_CTX_INSTANCE;
        }
        throw newProviderException();
    }

    /**
     * Validates that the OpenSSL library context is available as it has been successfully
     * created and configured, which means that the OpenSSL <code>libcrypto</code> and
     * <code>fips</code> libraries have also been loaded successfully.
     *
     * @return <code>true</code> if available, <code>false</code> otherwise
     */
    public static boolean isAvailable() {
        return LIB_CTX_INSTANCE != null;
    }

    /**
     * Returns the exception that occurred at initialization time.
     *
     * @return The exception that prevented the OpenSSL library context from being created
     * and configured successfully, in the form of a <code>ProviderException</code>.
     */
    public static ProviderException getInitException() {
        return INIT_EXCEPTION == null ? null : newProviderException();
    }

    private static ProviderException newProviderException() {
        return new ProviderException("Failed to create and configure OSSL_LIB_CTX", INIT_EXCEPTION);
    }

    public static String getFipsProviderNameString() {
        return FIPS_PROVIDER_NAME_STRING;
    }

    static String getFipsProviderName() {
        return FIPS_PROVIDER_NAME;
    }

    public static String getFipsProviderVersionString() {
        return FIPS_PROVIDER_VERSION_STRING;
    }

    static void forEachCipher(Consumer<EVP_CIPHER> consumer) {
        getInstance().forEachCipher(consumer);
    }
    static void forEachKdf(Consumer<EVP_KDF> consumer) {
        getInstance().forEachKdf(consumer);
    }
    static void forEachMac(Consumer<EVP_MAC> consumer) {
        getInstance().forEachMac(consumer);
    }
    static void forEachMd(Consumer<EVP_MD> consumer) {
        getInstance().forEachMd(consumer);
    }

    static void forEachRand(Consumer<EVP_RAND> consumer) {
        getInstance().forEachRand(consumer);
    }

    public static EVP_PKEY_CTX newPkeyCtx(String name, OsslArena arena) {
        return getInstance().newPkeyCtx(name, PROPERTY_QUERY_FIPS, arena);
    }

    public static EVP_PKEY_CTX newPkeyCtx(EVP_PKEY pkey, OsslArena arena) {
        // IllegalStateException("No longer active") is expected to be thrown when the application attempts
        // to use a pkey that the application has already de-activated by destroying the encompassing key object.
        return getInstance().newPkeyCtx(pkey, PROPERTY_QUERY_FIPS, arena);
    }

    public static void randBytes(byte[] bytes, int strength) {
        getInstance().randBytes(bytes, strength);
    }

    public static void randPrivBytes(byte[] bytes, int strength) {
        getInstance().randPrivBytes(bytes, strength);
    }
}

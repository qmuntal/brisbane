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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OsslProviderTest {
        static final Set<String> FIPS_PROVIDER_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "name", "version", "status"));

    OpenSsl openSsl;
    OSSL_LIB_CTX libCtx;
    OsslArena testArena;

    @Before
    public void setUp() throws Exception {
        openSsl = OpenSsl.getInstance();
        libCtx = LibCtx.getInstance();
        testArena = OsslArena.ofConfined();
    }

    @After
    public void tearDown() throws Exception {
        testArena.close();
    }

    @Test
    public void name() {
        libCtx.forProvider(LibCtx.getFipsProviderName(), provider -> {
            assertEquals(LibCtx.getFipsProviderName(), provider.name());
            return true;
        });
    }

    @Test
    public void gettableParams() {
        libCtx.forProvider(LibCtx.getFipsProviderName(), provider -> {
            OsslParamBuffer params = provider.gettableParams();
            Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
            Set<String> paramKeys = stringStream.collect(Collectors.toSet());
            assertTrue(paramKeys.containsAll(FIPS_PROVIDER_GETTABLE_PARAM_KEYS));
            return true;
        });
    }

    @Test
    public void getParams() {
        libCtx.forProvider(LibCtx.getFipsProviderName(), provider -> {
            OsslParamBuffer statusParam = this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("status", OSSL_PARAM.Type.INTEGER));
            provider.getParams(statusParam);
            assertTrue(statusParam.locate("status").isPresent());
            assertEquals(1, statusParam.locate("status").get().intValue());
            return true;
        });
    }

    @Test
    public void getEmptyParams() {
        // This test increases code coverage
        libCtx.forProvider(LibCtx.getFipsProviderName(), provider -> {
            provider.getParams(this.openSsl.emptyParamBuffer());
            return true;
        });
    }

    @Test
    public void forProviderNonExistent() {
        Optional<Boolean> result = libCtx.forProvider("Does not Exist", provider -> true);
        assertFalse(result.isPresent());
    }
}

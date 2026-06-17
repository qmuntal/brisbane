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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import static com.oracle.jipher.internal.openssl.RandUtil.runAdaptiveProportionTest;
import static com.oracle.jipher.internal.openssl.RandUtil.runRepetitionCountTest;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class EvpRandTest extends EvpTest {
    static final String RAND_DESCRIPTION = null;

    // Prefer HASH-DRBG because, unlike CTR-DRBG, it supports reseeding by using the entropy as additional input
    // in the seeding process. Some providers only expose CTR-DRBG, and exercising the shared EVP_RAND paths is
    // still valuable in that case.
    static final String HASH_DRBG_DIGEST_ALGORITHM = EVP_MD.DIGEST_NAME_SHA2_256;
    static final Set<String> EMPTY_SET = Collections.<String>emptySet();

    // The following are the PARAM_KEYS in OpenSSL version 3.0.0. Later versions may support additional parameters
    static final Set<String> HASH_DRBG_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList("digest",
            "state", "strength", "min_entropylen", "max_entropylen", "min_noncelen", "max_noncelen",
            "max_perslen", "max_adinlen", "max_request",
            "reseed_counter",  "reseed_requests", "reseed_time", "reseed_time_interval"));
    static final Set<String> HASH_DRBG_SETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList("digest",
            "properties", "reseed_requests", "reseed_time_interval"));
    static final Set<String> CTR_DRBG_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
        "state", "strength", "max_request"));
    static final Set<String> CTR_DRBG_SETTABLE_PARAM_KEYS = EMPTY_SET;

    static final int STRENGTH = 256;
    static final boolean PREDICTION_RESISTANCE = false;
    static final byte[] PERSONALISATION_STRING = new byte[16];
    static final byte[] ADDITIONAL_INPUT = new byte[16];// Length must be less than max_adinlen
    static final byte[] ENTROPY = new byte[32]; // Length must be in range [min_entropylen, max_entropylen]

    private String alg;

    private EVP_RAND rand;
    private EVP_RAND_CTX randCtx;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        alg = getSupportedRandName();
        rand = libCtx.fetchRand(alg, null, testArena);
        randCtx = openSsl.newEvpRandCtx(rand, null, testArena);

        if (isHashDrbg()) {
            OSSL_PARAM digestParam = OSSL_PARAM.of(EVP_RAND.DRBG_PARAM_DIGEST, HASH_DRBG_DIGEST_ALGORITHM);
            OsslParamBuffer params = this.openSsl.dataParamBuffer(this.testArena, digestParam);
            randCtx.setParams(params);
        }
    }


    @Test
    public void isA() {
        assertTrue(rand.isA(alg));
    }

    @Test
    public void name() {
        assertEquals(alg, rand.name());
    }

    @Test
    public void forEachName() throws Exception {
        rand.forEachName(name -> assertEquals(alg, name));
    }

    @Test
    public void description() {
        assertEquals(RAND_DESCRIPTION, rand.description());
    }

    @Test
    public void providerName() {
        assertEquals(LibCtx.getFipsProviderName(), rand.providerName());
    }

    @Test
    public void gettableParams() throws Exception {
        OsslParamBuffer params = rand.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertEquals(EMPTY_SET, paramKeys);
    }

    @Test
    public void getParams() throws Exception {
        // This test increases code coverage
        rand.getParams(this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", OSSL_PARAM.Type.INTEGER)));
    }

    @Test
    public void getEmptyParams() throws Exception {
        // This test increases code coverage
        rand.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void gettableCtxParams() throws Exception {
        OsslParamBuffer params = rand.gettableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(getExpectedGettableCtxParamKeys()));
    }

    @Test
    public void settableCtxParams() throws Exception {
        OsslParamBuffer params = rand.settableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(getExpectedSettableCtxParamKeys()));
    }

    @Test
    public void upRef() throws Exception {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            rand.upRef(confinedArena);
        }
        // Confirm rand is still live
        assertEquals(alg, rand.name());
    }

    @Test
    public void newRandCtx() {
        assertNotNull(libCtx.newEvpRandCtxWithPrimaryAsParent(rand, this.testArena));
    }

    @Test
    public void ctxGettableParams() throws Exception {
        OsslParamBuffer params = randCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(getExpectedGettableCtxParamKeys()));
    }

    @Test
    public void ctxSettableParams() throws Exception {
        OsslParamBuffer params = randCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(getExpectedSettableCtxParamKeys()));
    }

    @Test
    public void getAlgorithmSpecificParam() {
        OSSL_PARAM param = isHashDrbg()
                ? OSSL_PARAM.of(EVP_RAND.DRBG_PARAM_DIGEST, OSSL_PARAM.Type.UTF8_STRING, HASH_DRBG_DIGEST_ALGORITHM.getBytes(StandardCharsets.UTF_8).length + 1)
                : OSSL_PARAM.of(EVP_RAND.RAND_PARAM_STATE, OSSL_PARAM.Type.INTEGER);
        OsslParamBuffer paramValues = this.openSsl.templateParamBuffer(this.testArena, param);

        randCtx.getParams(paramValues);
        if (isHashDrbg()) {
            assertEquals(HASH_DRBG_DIGEST_ALGORITHM, paramValues.asArray()[0].stringValue());
        } else {
            assertEquals(randCtx.state().ordinal(), paramValues.asArray()[0].intValue());
        }
    }

    @Test
    public void enableLocking() {
        // This test is included to raise code coverage (rather than validate an OpenSSL state change)
        randCtx.enableLocking();
    }

    @Test
    public void initialState() {
        assertEquals(getExpectedInitialState(), randCtx.state());
    }

    @Test
    public void instantiate() {
        doInstantiate();
        assertEquals(EVP_RAND_CTX.State.READY, randCtx.state());
    }

    @Test
    public void instantiateUninstantiate() {
        randCtx.instantiate(STRENGTH, PREDICTION_RESISTANCE, PERSONALISATION_STRING);
        randCtx.uninstantiate();
        assertEquals(getExpectedInitialState(), randCtx.state());
    }

    void doInstantiate() {
        randCtx.instantiate(STRENGTH, PREDICTION_RESISTANCE, PERSONALISATION_STRING);
    }

    boolean isHashDrbg() {
        return EVP_RAND.RAND_NAME_HASH_DRBG.equals(alg);
    }

    static String getSupportedRandName() {
        for (String name : new String[] {EVP_RAND.RAND_NAME_HASH_DRBG, EVP_RAND.RAND_NAME_CTR_DRBG}) {
            try {
                EVP_RAND rand = LibCtx.getInstance().fetchRand(name, null);
                if (rand.providerName().equals(LibCtx.getFipsProviderName())) {
                    return name;
                }
            } catch (OpenSslException e) {
                // Try the next RAND.
            }
        }
        throw new AssertionError("No supported RAND found");
    }

    Set<String> getExpectedGettableCtxParamKeys() {
        return isHashDrbg() ? HASH_DRBG_GETTABLE_PARAM_KEYS : CTR_DRBG_GETTABLE_PARAM_KEYS;
    }

    Set<String> getExpectedSettableCtxParamKeys() {
        return isHashDrbg() ? HASH_DRBG_SETTABLE_PARAM_KEYS : CTR_DRBG_SETTABLE_PARAM_KEYS;
    }

    EVP_RAND_CTX.State getExpectedInitialState() {
        return isHashDrbg() ? EVP_RAND_CTX.State.UNINITIALISED : EVP_RAND_CTX.State.READY;
    }

    @Test
    public void strength() throws Exception {
        doInstantiate();
        assertEquals(STRENGTH, randCtx.strength());
    }

    @Test
    public void generate() {
        byte[] out = new byte[16];

        doInstantiate();
        randCtx.generate(out, STRENGTH, PREDICTION_RESISTANCE, ADDITIONAL_INPUT);
        assertEquals(EVP_RAND_CTX.State.READY, randCtx.state());
    }

    @Test
    public void generateNoAdditionalInput() {
        byte[] randomBytes = new byte[1000];

        doInstantiate();
        randCtx.generate(randomBytes, STRENGTH, PREDICTION_RESISTANCE, null);
        assertEquals(EVP_RAND_CTX.State.READY, randCtx.state());

        // Perform a sanity check on the random bytes.
        // Note this sanity check has a low but non-zero false positive probability.
        assertTrue(runRepetitionCountTest(randomBytes));
        assertTrue(runAdaptiveProportionTest(randomBytes));
    }

    @Test
    public void generateFromInitialState() {
        assertEquals(getExpectedInitialState(), randCtx.state());

        byte[] randomBytes = new byte[1000];
        randCtx.generate(randomBytes, STRENGTH, PREDICTION_RESISTANCE, ADDITIONAL_INPUT);
        assertEquals(EVP_RAND_CTX.State.READY, randCtx.state());

        // Perform a sanity check on the random bytes.
        // Note this sanity check has a low but non-zero false positive probability.
        assertTrue(runRepetitionCountTest(randomBytes));
        assertTrue(runAdaptiveProportionTest(randomBytes));
    }

    @Test
    public void reseed() throws Exception {
        doInstantiate();
        randCtx.reseed(PREDICTION_RESISTANCE, ENTROPY, ADDITIONAL_INPUT);
        assertEquals(EVP_RAND_CTX.State.READY, randCtx.state());
    }

    @Test
    public void reseedNoEntropyOrAdditionalInput() throws Exception {
        doInstantiate();
        randCtx.reseed(PREDICTION_RESISTANCE, null, null);
        assertEquals(EVP_RAND_CTX.State.READY, randCtx.state());
    }

    @Test
    public void ctxGetEmptyParams() throws Exception {
        // This test increases code coverage
        randCtx.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void ctxSetEmptyParams() throws Exception {
        // This test increases code coverage
        randCtx.setParams(this.openSsl.emptyParamBuffer());
    }

    // Negative tests

    @Test(expected = RuntimeException.class)
    public void forEachNameThrowsRuntimeExceptionNeg() {
        rand.forEachName(name -> {
            throw new RuntimeException("forEachConsumerFailed");
        });
    }

    @Test(expected = AssertionError.class)
    public void forEachNameThrowsExceptionNeg() {
        rand.forEachName(name -> EvpRandTest.throwAsUnchecked(new Exception("forEachConsumerFailed")));
    }

    @Test(expected = Error.class)
    public void forEachNameThrowsErrorNeg() {
        rand.forEachName(name -> {
            throw new Error("forEachConsumerFailed");
        });
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    @Test (expected = IllegalArgumentException.class)
    public void ctxGetReadOnlyParams() throws Exception {
        OsslParamBuffer readOnlyParams = randCtx.gettableParams();
        try {
            randCtx.getParams(readOnlyParams);
        } catch (IllegalArgumentException e) {
            assertEquals("Read-only OsslParamBuffer supplied", e.getMessage());
            throw e;
        }
    }

    static ByteBuffer allocateReadOnlyByteBuffer(int capacity, boolean direct) {
        return (direct ? ByteBuffer.allocateDirect(capacity) : ByteBuffer.allocate(capacity)).asReadOnlyBuffer();
    }
}

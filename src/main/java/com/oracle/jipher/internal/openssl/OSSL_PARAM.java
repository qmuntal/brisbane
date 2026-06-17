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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import javax.security.auth.Destroyable;

public final class OSSL_PARAM implements Destroyable {

    /* The following are OpenSSL API constants defined in core_names.h */

    /* Algorithm parameters */
    public static final String ALG_PARAM_ALGORITHM_ID = "algorithm-id"; /* octet_string */
    public static final String ALG_PARAM_ALGORITHM_ID_PARAMS = "algorithm-id-params"; /* octet_string */
    public static final String ALG_PARAM_CIPHER       = "cipher";     /* utf8_string */
    public static final String ALG_PARAM_DIGEST       = "digest";     /* utf8_string */
    public static final String ALG_PARAM_FIPS_APPROVED_INDICATOR = "fips-indicator"; /* int, 0 or 1 */
    public static final String ALG_PARAM_MAC          = "mac";        /* utf8_string */
    public static final String ALG_PARAM_PROPERTIES   = "properties"; /* utf8_string */

    /* OpenSSL API constant defined in params.h */
    /* The return_size field of an OSSL_PARAM is initialized to PARAM_UNMODIFIED prior to getting a param. */
    public static final long PARAM_UNMODIFIED = -1L;

    public static final OSSL_PARAM[] EMPTY_ARRAY = new OSSL_PARAM[0];

    static final BigInteger MASK64 = BigInteger.ZERO.setBit(64).subtract(BigInteger.ONE);
    static final long MASK32 = 0xffffffffL;

    /* OpenSSL API constants defined in core.h */
    public enum Type {
        NONE,                // 0
        INTEGER,             // 1
        UNSIGNED_INTEGER,    // 2
        REAL,                // 3
        UTF8_STRING,         // 4
        OCTET_STRING,        // 5
        UTF8_PTR,            // 6
        OCTET_PTR            // 7
    }

    public final String key;
    public final Type dataType;
    public final byte[] data;
    public final long dataSize;
    public final long returnSize;
    public final boolean sensitive;

    OSSL_PARAM(String key, Type dataType, long dataSize) {
        this(key, dataType, null, dataSize, PARAM_UNMODIFIED, false);
    }

    OSSL_PARAM(String key, Type dataType, byte[] data) {
        this(key, dataType, data, data.length, PARAM_UNMODIFIED, false);
    }

    // Intended to be invoked by decoders.
    public OSSL_PARAM(String key, Type dataType, byte[] data, long dataSize, long returnSize, boolean sensitive) {
        this.key = Objects.requireNonNull(key, "key parameter must not be null");
        this.dataType = Objects.requireNonNull(dataType, "dataType parameter must not be null");
        this.data = data;
        this.dataSize = dataSize;
        this.returnSize = returnSize;
        this.sensitive = sensitive;
    }

    public static OSSL_PARAM of(String key, int data) {
        byte[] bytes = ByteBuffer.allocate(Integer.BYTES).putInt(data).array();
        return new OSSL_PARAM(key, Type.INTEGER, bytes);
    }
    public static OSSL_PARAM of(String key, long data) {
        byte[] bytes = ByteBuffer.allocate(Long.BYTES).putLong(data).array();
        return new OSSL_PARAM(key, Type.INTEGER, bytes);
    }
    public static OSSL_PARAM ofIntegerBytes(String key, byte[] data) {
        return new OSSL_PARAM(key, Type.INTEGER, Objects.requireNonNull(data, "data parameter must not be null"));
    }
    public static OSSL_PARAM of(String key, BigInteger data) {
        byte[] bytes = data.toByteArray();
        return new OSSL_PARAM(key, Type.INTEGER, bytes);
    }

    public static OSSL_PARAM ofUnsigned(String key, int data) {
        byte[] bytes = ByteBuffer.allocate(Integer.BYTES).putInt(data).array();
        return new OSSL_PARAM(key, Type.UNSIGNED_INTEGER, bytes);
    }
    public static OSSL_PARAM ofUnsigned(String key, long data) {
        byte[] bytes = ByteBuffer.allocate(Long.BYTES).putLong(data).array();
        return new OSSL_PARAM(key, Type.UNSIGNED_INTEGER, bytes);
    }
    public static OSSL_PARAM ofUnsignedIntegerBytes(String key, byte[] data) {
        return new OSSL_PARAM(key, Type.UNSIGNED_INTEGER, stripRedundantLeadingZeroBytes(
                Objects.requireNonNull(data, "data must not be null")));
    }
    public static OSSL_PARAM ofUnsigned(String key, BigInteger data) {
        if (data.signum() == -1) {
            throw new IllegalArgumentException("data parameter must not be negative");
        }
        byte[] bytes = stripRedundantLeadingZeroBytes(data.toByteArray());
        return new OSSL_PARAM(key, Type.UNSIGNED_INTEGER, bytes);
    }

    /**
     * Removes sign-extension bytes from an unsigned integer encoding.
     * BigInteger.toByteArray() returns a two's-complement representation, so positive values with the high bit set
     * include a leading zero byte. OpenSSL treats UNSIGNED_INTEGER parameters as unsigned magnitudes, and some
     * providers use the OSSL_PARAM data size when importing key material, so keep the encoding canonical.
     */
    private static byte[] stripRedundantLeadingZeroBytes(byte[] data) {
        int index = 0;
        while (index < data.length - 1 && data[index] == 0) {
            index++;
        }
        return index == 0 ? data : Arrays.copyOfRange(data, index, data.length);
    }

    public static OSSL_PARAM of(String key, float data) {
        byte[] bytes = ByteBuffer.allocate(Float.BYTES).putFloat(data).array();
        return new OSSL_PARAM(key, Type.REAL, bytes);
    }
    public static OSSL_PARAM of(String key, double data) {
        byte[] bytes = ByteBuffer.allocate(Double.BYTES).putDouble(data).array();
        return new OSSL_PARAM(key, Type.REAL, bytes);
    }

    public static OSSL_PARAM of(String key, String data) {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        return new OSSL_PARAM(key, Type.UTF8_STRING, bytes);
    }

    public static OSSL_PARAM of(String key, byte[] data) {
        return new OSSL_PARAM(key, Type.OCTET_STRING, data);
    }

    public static OSSL_PARAM of(String key, Type dataType) {
        return of(key, dataType, 0L);
    }

    public static OSSL_PARAM of(String key, Type dataType, long dataSize) {
        if (dataSize < 0L) {
            throw new IllegalArgumentException("dataSize parameter must not be negative");
        }
        switch (dataType) {
            case NONE:
                throw new IllegalArgumentException("dataType NONE not supported");
            case INTEGER:
            case UNSIGNED_INTEGER:
                if (dataSize == 0L) {
                    dataSize = Integer.BYTES;
                }
                break;
            case REAL:
                if (dataSize == 0L) {
                    dataSize = Double.BYTES;
                } else if (dataSize != 4L && dataSize != 8L) {
                    throw new IllegalArgumentException("dataSize must be 4 or 8 for dataType REAL, was %d".formatted(dataSize));
                }
                break;
            case UTF8_STRING, OCTET_STRING:
                // Note that when requesting parameters for dataType UTF8_STRING, dataSize (the size of
                // the buffer to be populated) should accommodate enough space for a terminating NUL byte.
                // See the OpenSSL OSSL_PARAM documentation (https://docs.openssl.org/3.0/man3/OSSL_PARAM/#description).
                if (dataSize == 0L) {
                    throw new IllegalArgumentException("dataSize must be at least 1 for dataType %s, was %d".formatted(dataType, dataSize));
                }
                break;
            case UTF8_PTR, OCTET_PTR:
                break;
        }
        return new OSSL_PARAM(key, dataType, dataSize);
    }

    public OSSL_PARAM sensitive() {
        return new OSSL_PARAM(this.key, this.dataType, this.data, this.dataSize, this.returnSize, true);
    }

    public boolean hasData() {
        return this.data != null;
    }

    void checkHasData() {
        if (this.data == null) {
            throw new IllegalStateException("No data");
        }
    }

    public Number number() {
        checkHasData();
        if (this.dataType == Type.INTEGER || this.dataType == Type.UNSIGNED_INTEGER) {
            switch (this.data.length) {
                case Integer.BYTES:
                    int intValue = ByteBuffer.wrap(this.data).getInt();
                    if (intValue < 0 && this.dataType == Type.UNSIGNED_INTEGER) {
                        return ((long) intValue) & MASK32;
                    }
                    return intValue;
                case Long.BYTES:
                    long longValue = ByteBuffer.wrap(this.data).getLong();
                    if (longValue < 0 && this.dataType == Type.UNSIGNED_INTEGER) {
                        // Prevent sign-extension, since the value is unsigned
                        return BigInteger.valueOf(longValue).and(MASK64);
                    }
                    return longValue;
                default:
                    return this.dataType == Type.UNSIGNED_INTEGER ? new BigInteger(1, this.data) : new BigInteger(this.data);
            }
        } else if (this.dataType == Type.REAL) {
            return switch (this.data.length) {
                case Float.BYTES -> ByteBuffer.wrap(this.data).getFloat();
                case Double.BYTES -> ByteBuffer.wrap(this.data).getDouble();
                default ->
                        throw new IllegalStateException("return size must be 4 or 8 for dataType REAL, was %d".formatted(this.data.length));
            };
        }
        throw new IllegalStateException("Not REAL, INTEGER or UNSIGNED_INTEGER");
    }

    public int intValue() {
        return number().intValue();
    }

    public long longValue() {
        return number().longValue();
    }

    public int intValueExact() {
        Number n = number();
        if (n instanceof Integer) {
            return n.intValue();
        }
        if (n instanceof Long) {
            return Math.toIntExact(n.longValue());
        }
        if (n instanceof BigInteger) {
            return ((BigInteger) n).intValueExact();
        }
        throw new IllegalStateException("Not INTEGER or UNSIGNED_INTEGER");
    }

    public long longValueExact() {
        Number n = number();
        if (n instanceof Integer || n instanceof Long) {
            return n.longValue();
        }
        if (n instanceof BigInteger) {
            return ((BigInteger) n).longValueExact();
        }
        throw new IllegalStateException("Not INTEGER or UNSIGNED_INTEGER");
    }

    public BigInteger bigIntegerValue() {
        Number n = number();
        if (n instanceof BigInteger) {
            return (BigInteger) n;
        }
        return BigInteger.valueOf(n.longValue());
    }

    public float floatValue() {
        return number().floatValue();
    }

    public double doubleValue() {
        return number().doubleValue();
    }

    public String stringValue() {
        checkHasData();
        if (this.dataType != Type.UTF8_PTR && this.dataType != Type.UTF8_STRING) {
            throw new IllegalStateException("Not UTF8_PTR or UTF8_STRING");
        }
        return new String(this.data, StandardCharsets.UTF_8);
    }

    // Returns a copy of data.
    // To avoid the copy, access the data member directly.
    public byte[] byteArrayValue() {
        checkHasData();
        return this.data.clone();
    }

    public String printable() {
        if (this.data == null) {
            return "null";
        }
        return switch (this.dataType) {
            case INTEGER, UNSIGNED_INTEGER, REAL -> number().toString();
            case UTF8_STRING, UTF8_PTR -> "\"" + stringValue() + "\"";
            case OCTET_STRING, OCTET_PTR -> "[" + this.data.length + " bytes]";
            default -> throw new AssertionError();
        };
    }

    public static void destroy(OSSL_PARAM[] params) {
        if (params != null) {
            for (OSSL_PARAM param : params) {
                if (param != null) {
                    param.destroy();
                }
            }
        }
    }

    @Override
    public void destroy() {
        if (this.data != null) {
            Arrays.fill(this.data, (byte) 0);
        }
    }

    @Override
    public boolean isDestroyed() {
        if (this.data == null) {
            return true;
        }
        byte mask = (byte) 0;
        for (byte b : this.data) {
            mask |= b;
        }
        return mask == 0;
    }

    @Override
    public String toString() {
        return "key:%s data_type:%s data_size:%d data:%s return_size:%d".formatted(
                this.key, this.dataType, this.dataSize, printable(), this.returnSize);
    }
}

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

package com.oracle.jipher.internal.platform;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.oracle.jipher.internal.common.Debug;

public abstract class LinuxDistro {

    private static final Debug DEBUG = Debug.getInstance("jipher");

    private static final Path OS_RELEASE_PATH = Paths.get("/etc/os-release");

    // Read the value of the specified 'key' from the '/etc/os-release' file.
    private static String getValue(String key) {
        if (key != null) {
            String prefix = key + "=";
            if (Files.exists(OS_RELEASE_PATH) && !Files.isDirectory(OS_RELEASE_PATH)) {
                try (BufferedReader reader = Files.newBufferedReader(OS_RELEASE_PATH)) {
                    return reader.lines().filter(line -> line.startsWith(prefix)).findFirst()
                            .map(line -> line.substring(prefix.length()).replace("\"", ""))
                            .orElse(null);
                } catch (IOException e) {
                    // Log this exception for debug purposes but otherwise ignore it
                    // by returning null to indicate that the key value was not found.
                    DEBUG.println(() -> "IOException while reading OS release file: " + e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * Get the Linux distribution for the running environment.
     * @return The Linux distribution
     */
    static LinuxDistro getLinuxDistro() throws UnrecognisedLinuxDistroException {
        return getLinuxDistro(getValue("ID"), getValue("VERSION_ID"));
    }

    /**
     * Get the Linux distribution for the specified identifiers:
     * @param id         a lower case string identifying the operating system, excluding any version information.
     *                   See os-release man page for more information
     * @param versionId  a lower-case string identifying a specific variant or edition of the operating system.
     *                   See os-release man page for more information
     * @return the Linux distribution
     */
     static LinuxDistro getLinuxDistro(String id, String versionId) throws UnrecognisedLinuxDistroException {
        if ("ol".equals(id) && versionId != null && versionId.matches("[0-9]+\\.[0-9]+(\\..*)?")) {
            return new OracleLinux(versionId);
        }
        if ("azurelinux".equals(id) && versionId != null && versionId.matches("[0-9]+\\.[0-9]+(\\..*)?")) {
            return new AzureLinux(versionId);
        }
        throw new UnrecognisedLinuxDistroException("id=" + id + ", versionId=" + versionId);
     }

    private final String distroName;
    protected final String versionString;

    private LinuxDistro(String distroName, String versionString) {
        this.distroName = distroName;
        this.versionString = versionString;
    }

    public String toString() {
        return distroName + " " + versionString;
    }

    abstract boolean providesFipsModule();
    abstract Path getCryptoLibPath();
    abstract Path getProviderSearchPath();
    abstract String getFipsProviderName();
    abstract String getFipsModuleMac();

    // Fedora's modules are not submitted for FIPS validation, however several distributions downstream of Fedora
    // (including RHEL and Oracle Linux) perform their own FIPS validations.
    abstract static class FedoraLike extends LinuxDistro {

        FedoraLike(String distroName, String versionString) {
            super(distroName, versionString);
        }

        int getMajorVersion() {
            return Integer.parseInt(versionString.split("\\.")[0]);
        }

        @Override
        Path getCryptoLibPath() {
            return providesFipsModule() ? Paths.get("/usr/lib64/libcrypto.so.3") : null;
        }

        @Override
        Path getProviderSearchPath() {
            return providesFipsModule() ? Paths.get("/usr/lib64/ossl-modules") : null;
        }

        @Override
        String getFipsModuleMac() {
            // Distributions downstream of Fedora embed the module-mac as a data element in the FIPS module.
            // Consequently, the module-mac does not need to be specified, as part of the module configuration,
            // when loading the FIPS module.
            return null;
        }

        @Override
        String getFipsProviderName() {
            return "fips";
        }
    }

    static class OracleLinux extends FedoraLike {

        OracleLinux(String versionId) {
            super("Oracle Linux", versionId);
        }

        int getMinorVersion() {
            return Integer.parseInt(versionString.split("\\.")[1]);
        }

        @Override
        boolean providesFipsModule() {
            // A certified OpenSSL(3) FIPS module was first distributed in OL 9.4
            return (getMajorVersion() >= 10) || (getMajorVersion() == 9 && getMinorVersion() >= 4);
        }
    }

    static class AzureLinux extends FedoraLike {

        AzureLinux(String versionId) {
            super("Microsoft Azure Linux", versionId);
        }

        @Override
        boolean providesFipsModule() {
            return getMajorVersion() >= 3;
        }

        @Override
        String getFipsProviderName() {
            return "symcryptprovider";
        }
    }
}

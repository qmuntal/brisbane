# Building and Testing

Project Brisbane delivers its Java Security Provider in a Java module called `com.oracle.jipher`.
This document describes how to build and test this module.

## Before You Begin

Follow the steps in [prerequisites.md](prerequisites.md).

## Building the library

To build the library JAR invoke the `jar` gradle task:

```
sh gradlew jar
```

The resulting JARs are output to `./build/libs/`

| Binary (library) JAR       | Source JAR                         |
|----------------------------|------------------------------------|
| `jipher-jce-<version>.jar` | `jipher-jce-<version>-sources.jar` |

## Testing the library

At runtime Jipher loads the [OpenSSL](https://openssl-library.org/) cryptographic library, FIPS provider and
optionally (to access the FIPS module MAC) the OpenSSL configuration file from the filesystem.
Refer to the [OpenSSL](prerequisites.md#openssl) section in [prerequisites.md](prerequisites.md)
for information on providing the OpenSSL dependencies and configuring Jipher to locate them.

### Running the Jipher main class

The gradle task `runMainClass` runs the Jipher main class which outputs information about Jipher
and the OpenSSL cryptographic library & FIPS provider it loads at runtime.
It can thus be used to verify that Jipher has been properly configured to locate its run time dependencies.

```
sh gradlew runMainClass
```

If Jipher has been properly configured to locate its run time dependencies then
the `runMainClass` task should produce output similar to the following:

```
JipherJCE Provider <version>[OpenSSL <version> <date> with <FIPS provider name> version <version>] (implements <cryptographic algorithm list>)
```

Troubleshooting:
 * `OpenSSL crypto library path not found` indicates that Jipher failed to locate or load the OpenSSL cryptographic library.
 * `FIPS provider is not available` indicates that Jipher failed to locate, load or activate the OpenSSL FIPS provider.
    * Activation can fail if Jipher is unable to locate the FIPS module MAC in the OpenSSL configuration file.

Refer to the [OpenSSL](prerequisites.md#openssl) section in [prerequisites.md](prerequisites.md)
for information on providing the OpenSSL dependencies and configuring Jipher to locate them.

### Testing overview

The Brisbane project supports:
* Unit testing: Directly tests internal blocks of library code in isolation.
* Integration testing: Verifies the library's functionality through the Java Cryptography Architecture (JCA) API.
* Leak Testing: Ensures native objects are properly released and do not remain allocated beyond their intended lifetime.
* Deployment and configuration testing: Validates various deployment and configuration scenarios.

The tests in the project use a common set of utility and helper classes.
The `jipherTestJar` gradle task compiles and packages these classes into a modular JAR.

```
sh gradlew jipherTestJar
```

### General testing

The `sanity` gradle task builds the Jipher library, runs the main class, builds and runs the unit & integration tests
and verifies that the testing performed covers a sufficient proportion of the library code.

```
sh gradlew sanity
```

After running the `sanity` task:
 * open the HTML test report:
    * **macOS** : `open build/reports/allTests/index.html`
    * **Linux** : `xdg-open build/reports/allTests/index.html`
    * **Windows**: `start "" "build\reports\allTests\index.html"`
* open the HTML code coverage report with:
   * **macOS** : `open build/reports/jacoco/test/html/index.html`
   * **Linux** : `xdg-open build/reports/jacoco/test/html/index.html`
   * **Windows**: `start "" "build\reports\jacoco\test\html\index.html"`

### Unit testing

The unit tests directly test internal blocks of library code in isolation.

The `testClasses` gradle task assembles all unit test classes and resources required for execution.
```
sh gradlew testClasses
```

The `test` gradle task executes the unit tests and produces a test report.
```
sh gradlew test
```

Open the HTML unit test report with:
 * **macOS** : `open build/reports/tests/test/index.html`
 * **Linux** : `xdg-open build/reports/tests/test/index.html`
 * **Windows**: `start "" "build\reports\tests\test\index.html"`

### Integration testing:

The integration (API) tests verify the library's functionality through the Java Cryptography Architecture (JCA) API.

The `intTestClasses` gradle task assembles all integration test classes and resources required for execution.
```
sh gradlew intTestClasses
```

The `integrationTest` gradle task executes the integration tests and produces a test report.
```
sh gradlew integrationTest
```

Open the HTML integration (API) test report with:
* **macOS** : `open build/reports/tests/integrationTest/index.html`
* **Linux** : `xdg-open build/reports/tests/integrationTest/index.html`
* **Windows**: `start "" "build\reports\tests\integrationTest\index.html"`

### Leak testing

Jipher provides cryptographic services by creating, using, and freeing OpenSSL native objects.
Some native objects are ephemeral: they are allocated, used, and released entirely within a
single Java Cryptography API call. Others have a longer lifetime that is tied to the
Java object they support (for example, a key, context, or cipher instance).

To verify that native resources are released correctly, Jipher supports native object lifecycle tracking.
A lifecycle callback can be registered to receive OpenSSL allocation events (NEW, UP_REF, and FREE)
including the originating OpenSSL function name and the native pointer value.
These events can be forwarded to a lifecycle monitor, which can report at any time which native
objects have been created but not yet freed.

Leak testing uses this tracking to confirm that, after the JVM garbage collector has reclaimed
all Java objects associated with a given native object (and their cleanup logic has executed),
the corresponding OpenSSL native objects are freed.

The `leakTestClasses` gradle task assembles all leak test classes and resources required for execution.
```
sh gradlew leakTestClasses
```

The `leaktest` gradle task registers a native object lifecycle callback associated with a native object lifecycle monitor,
performs a wide range of cryptography, releases all Java objects, triggers garbage collection and finally queries the
native object lifecycle monitor to verify that no live native objects remain.

```
sh gradlew leakTest
```

*Note:* If a **very** large number of native memory usage errors occurs then the JVM may exit with a
`java.lang.OutOfMemoryError: Java heap space` error due to the error list and/or the map of tracked native memory
object allocations consuming all the available Java heap.


The `lifeCycleHookTest` gradle task verifies that the native object lifecycle hook functionality is itself
functioning correctly by running a series of known answer tests.

```
sh gradlew lifeCycleHookTest
```

### Deployment and configuration testing

This collection of gradle tasks test various deployment and configuration scenarios.

The `systemTestClasses` gradle task assembles all deployment and configuration test classes and resources required for execution.
```
sh gradlew systemTestClasses
```

The `systemTest` gradle task executes the deployment and configuration tests.
```
sh gradlew systemTest
```

#### Testing AEAD ciphering with streaming enabled

The `apiAeadCipherTest_(stream)` gradle task runs the `AeadCipher` and `AeadCipherStream` tests with
the Java system property `jipher.cipher.AEAD.stream` set to `true`.
For more information see [configuration.md](configuration.md).

```
sh gradlew 'apiAeadCipherTest_(stream)'
```

#### Testing provider registration

The `configTest_(<provider registration configuration>)_default` gradle tasks test Jipher with various provider
registration configurations:
 * `NoReg-INSTANCE`:
   * `JipherJCE` not registered (either statically or dynamically) with the JCA.
   * Service algorithm instances are acquired by calling `getInstance(String algorithm, java.security.Provider provider)` where `provider` is an instance of `com.oracle.jipher.provider.JipherJCE`.
 * `NoReg-DYNAMIC_FIRST`:
   * `JipherJCE` is not statically registered but is dynamically registered with the JCA as the most preferred (position 1) provider - `java.security.Security.insertProviderAt(new com.oracle.jipher.provider.JipherJCE(), 1)`
   * Service algorithm instances are acquired by calling `getInstance(String algorithm)` which lets the JCA select the most preferred registered provider that supports the algorithm.
 * `NoReg-DYNAMIC_STRING`:
   * `JipherJCE` is not statically registered but is dynamically registered with the JCA as the least preferred provider - `java.security.Security.addProvider(new com.oracle.jipher.provider.JipherJCE())`
   * Service algorithm instances are acquired by calling `getInstance(String algorithm, "JipherJCE")`
 * `PosN-STRING`:
   * JipherJCE is statically registered with the JCA as the least preferred provider using a `java.security` file.
   * Service algorithm instances are acquired by calling `getInstance(String algorithm, "JipherJCE")`
 * `Pos1-FIRST`:
   * JipherJCE is statically registered with the JCA as the most preferred (position 1) provider using a `java.security` file.
   * Service algorithm instances are acquired by calling `getInstance(String algorithm)` which lets the JCA select the most preferred registered provider that supports the algorithm.

For example:
```
sh gradlew 'configTest_(NoReg-DYNAMIC_FIRST)_default'
```

#### Testing FIPS enforcement policies

Jipher can perform enforcement of FIPS 140 algorithm usage and key sizes according to how the algorithm and key is being used.
You can specify a FIPS 140 enforcement policy with the `jipher.fips.enforcement` system property.
For more information see [configuration.md](configuration.md).

The `fipsTest_(<enforcement policy>)` gradle tasks test Jipher with various FIPS enforcement policies:
* `FIPS`: Approved algorithms and key lengths are permitted in accordance with how they are used. Legacy use is permitted.
* `FIPS_STRICT`: Only algorithms and key lengths with Acceptable approval status are permitted.
* `NONE`: No additional enforcement is performed; any enforcement implemented in OpenSSL is still applied.

For example:
```
sh gradlew 'fipsTest_(FIPS_STRICT)'
```

#### Testing TLS provider configurations

The `jsseTest_(<client-server-arrangement>)` gradle tasks run a TLS client-server test using the `SunJSSE` provider
to provide the TLS stack and the `JipherJCE` provider to provide the cryptography required by the `SunJSSE`
for one or both of the TLS peers.

When a TLS peer is configured to use `JipherJCE` to provide the cryptography required by the `SunJSSE`
only the following providers are registered with the JCA in the order listed:
1. `com.oracle.jipher.provider.JipherJCE` - required to provide cryptography.
2. `SUN` - required to provide `KeyStore` and `CertPathValidator` support.
3. `SunJSSE` - required to provide TLS stack.

Client-Server arrangements:
 * `jdkToJipherServer` - TLS client using JDK providers to provide cryptography to TLS server using `JipherJCE` provider to provide cryptography
 * `jipherToJdkServer` - TLS client using `JipherJCE` provider to provide cryptography to TLS server using the JDK providers to provide cryptography
 * `jipherToJipherServer` - TLS client using `JipherJCE` provider to provide cryptography to TLS server using `JipherJCE` provider to provide cryptography

For example:
```
sh gradlew 'jsseTest_(jipherToJipherServer)'
```

#### Testing loading JipherJCE with multiple class loaders

The `classloaderTest` gradle task tests loading two instances of Jipher into a single JVM using two class loaders.
Loading two instances of Jipher configured to use distinct instances of the OpenSSL run time dependencies is tested.

```
sh gradlew classloaderTest
```

#### Testing loading JipherJCE via the service loader

The `serviceloaderTest` gradle task tests loading the `JipherJCE` provider via the `ServiceLoader`.

```
sh gradlew serviceloaderTest
```

#### Testing sanctioning of OpenSSL versions.

The `sanctionedVersionsTest` gradle task tests that Jipher will refuse to load a version of the OpenSSL cryptography
library or a version of the OpenSSL FIPS module that has not been sanctioned.

```
sh gradlew sanctionedVersionsTest
```

### Running the full set of tests

The `testAll` gradle task can be called to execute all tests and output a test report.

```
sh gradlew testAll
```

Note that by default, this task assumes that the jipher library has been built and that all test classes
have been compiled. The task intentionally disables any other (e.g. compile/build) tasks.

For development purposes, it may be useful to re-enable these tasks. This can be done by specifying
the gradle property `enableBuild` with value of `true` (which will succeed in compiling any test changes).

```
sh gradlew testAll -PenableBuild=true
```

Open the full HTML test report with:
* **macOS** : `open build/reports/allTests/index.html`
* **Linux** : `xdg-open build/reports/allTests/index.html`
* **Windows**: `start "" "build\reports\allTests\index.html"`

## Optional steps

### Signing the library JAR File

This section applies to Oracle JDKs only.

The [JCA](https://docs.oracle.com/en/java/javase/25/security/java-cryptography-architecture-jca-reference-guide.html)
*in Oracle JDKs* authenticates
[cryptographic service providers](https://docs.oracle.com/en/java/javase/25/security/java-cryptography-architecture-jca-reference-guide.html#GUID-3E0744CE-6AC7-4A6D-A1F6-6C01199E6920)
that provide encryption algorithms through the
`Cipher`, `KDF`, `KEM`, `KeyAgreement`, `KeyGenerator`, `Mac`, or `SecretKeyFactory` classes.
If Jipher is to be run on an Oracle JDK then the JAR must be signed with a code signing certificate obtained from Oracle.
See [Step 7: Sign Your JAR File, If Necessary](https://docs.oracle.com/en/java/javase/25/security/howtoimplaprovider.html#GUID-2D4432F9-1C3C-4A91-8612-2B2840188B36).
This section documents how to configure the build scripts to sign the JAR with the code signing key.

Create a `~/.gradle/gradle.properties` file and configure the build with the location of a KeyStore that contains a
code signing key.
```
propertyJceKsFile=<path to jce signing keystore file>
propertyJceKsStorePass=<keystore store password>
propertyJceKsAlias=<alias of the signing key in the keystore>
```

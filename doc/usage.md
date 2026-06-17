# Usage

Project Brisbane delivers a Java Security Provider, named `JipherJCE`, in a Java module called `com.oracle.jipher`
in a modular JAR named `jipher-jce-<version>.jar`.
This document describes how to make the cryptographic services provided by `JipherJCE` available to a Java application.

## Listing the JAR on the class path or module path

Add the JAR file to the module path or class path.
When placed on the module path, it will be observable as the module `com.oracle.jipher`.

In the following examples the `-<version>` portion of the JAR file name is omitted for brevity.
For Windows use a `;` path separator.

Module path example:
```
java --module-path jipher-jce.jar:example-app.jar --module com.example.app
```

Class path example:
```
java -cp jipher-jce.jar:example-app.jar com.example.Main
```

## Enabling Native Access

Jipher uses the Java [Foreign Function and Memory (FFM) API](https://docs.oracle.com/en/java/javase/25/core/foreign-function-and-memory-api.html)
to communicate with OpenSSL native libraries.
It uses [restricted methods](https://docs.oracle.com/en/java/javase/25/core/restricted-methods.html) from the FFM API.

When running a Java application that lists Jipher on the module path
set the `--enable-native-access` option to enable native access for the `com.oracle.jipher` module:
```
java --enable-native-access=com.oracle.jipher --module-path jipher-jce.jar:example-app.jar --module com.example.app
```

When running a Java application that lists Jipher on the class path
set the `--enable-native-access` option to enable native access for all unnamed modules:
```
java --enable-native-access=ALL-UNNAMED -cp jipher-jce.jar:example-app.jar com.example.Main
```

Refer to the *Enabling Native Access* section of the
[Restricted Methods](https://docs.oracle.com/en/java/javase/25/core/restricted-methods.html) documentation for
alternative ways to specify the `--enable-native-access` option.

## OpenSSL dependencies

At runtime Jipher loads the [OpenSSL](https://openssl-library.org/) cryptographic library, FIPS provider and
optionally (to access the FIPS module MAC) the OpenSSL configuration file from the filesystem.

For information on providing the OpenSSL dependencies and configuring Jipher to locate them
refer to the [OpenSSL](./prerequisites.md#openssl) section in [./prerequisites.md](./prerequisites.md).

## Reporting version information

The `com.oracle.jipher` module main class reports version information for both Jipher and the OpenSSL native libraries
it loads at run time:

```
> java --enable-native-access=com.oracle.jipher --module-path <path to jipher JAR> -m com.oracle.jipher
JipherJCE Provider <version>[OpenSSL <version> <date> with <FIPS provider name> version <version>] (implements AES, DESede, Diffie-Hellman, DSA, ECDSA, ECDH, HMAC, PBKDF2, RSA, SHA-1, SHA-2, SHA-3)
```

## Provider Registration

To use a security provider that's not included in the JDK, such as `JipherJCE`, you must register it so that
the JCA can access its security services. You can register a provider statically or dynamically.

### Static registration

Static registration is implemented by specifying the provider in the list of registered providers in the `java.security` file.

The following example is an excerpt from the `java.security` file.
It registers `JipherJCE` as the highest priority provider (position 1) by specifying its provider class,
`com.oracle.jipher.provider.JipherJCE`.
It also registers the `SUN` provider in position 2, and `SunJSSE` in position 3:
```
security.provider.1=com.oracle.jipher.provider.JipherJCE
security.provider.2=SUN
security.provider.3=SunJSSE
# Other registered providers follow...
```

### Dynamic registration

Dynamic registration is implemented by calling either the `addProvider` or `insertProviderAt` method in the
`java.security.Security` class in your application code. For example:
````
java.security.Security.insertProviderAt(new com.oracle.jipher.provider.JipherJCE(), 1);
````

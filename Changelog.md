# Changelog #

## 3.2 ##
 * Add support for python 3.8.
 * Drop support for python 3.4.
 * Fix false positive redirect error in consumer verification.
 * Do not percent escape sub delimiters in path in URI normalization. Thanks Colin Watson for report.
 * Fix tests and static code checks. Thanks Colin Watson.

## 3.1 ##
 * Convert data values for extensions to text.
 * Fixes in Python 2/3 support.
 * Fix examples.
 * Add support for python 3.7
 * Fix static code checks
 * Use bumpversion

## 3.0 ##

 * Support Python3.
 * Change most of the API to the text strings. UTF-8 encoded byte string should be compatible.
 * Authentication methods based on SHA-256 are now preferred over SHA-1.
 * Use `cryptography` library for cryptography tasks.
 * Add new base64-based API for `DiffieHellman` class.
 * Refactor script to negotiate association with an OpenID server.
 * Decrease log levels on repetitive logs.
 * Default fetcher is picked from more options.
 * Remove `openid.consumer.html_parse` module.
 * Remove `hmacSha*`, `randomString`, `randrange` and `sha*` functions from `openid.cryptutil`.
 * A lot of refactoring and clean up.

### Deprecation ###
 * Binary strings are deprecated, unless explicitely allowed.
 * `hash_func` is deprecated in favor of `algorithm` in `DiffieHellmanSHA*ServerSession` and `DiffieHellmanSHA*ConsumerSession`.
 * `DiffieHellmanSHA*ServerSession.consumer_pubkey` is deprecated in favor of `consumer_public_key`.
 * Functions `longToBinary` and `binaryToLong` deprecated in favor of `int_to_bytes` and `bytes_to_int`, respectively.
 * Old `DiffieHellman` API is deprecated.

## 2.3.0 ##

 * Prevent timing attacks on signature comparison. Thanks to Carl Howells.
 * Prevent XXE attacks.
 * Fix unicode errors. Thanks to Kai Lautaportti.
 * Drop support for python versions < 2.7.
 * Use logging module. Thanks to Attila-Mihaly Balazs.
 * Allow signatory, encoder and decoder to be set for Server. Thanks to julio.
 * Fix URL limit to server responses. Thanks to Rodrigo Primo.
 * Fix several protocol errors.
 * Add utility method to AX store extension.
 * Fix curl detection. Thanks to Sergey Shepelev.
 * Use setuptools. Thanks to Tres Seaver.
 * Refactor `Message` class creation.
 * Add `RequestsFetcher`. Thanks to Lennonka.
 * Updated examples.
 * Add tox for testing. Thanks to Marc Abramowitz.
 * Refactor tests.
 * Clean code and add static checks.

### Deprecation ###
 * `Message.setOpenIDNamespace()` method.
 * `UndefinedOpenIDNamespace` exception.
 * `OpenIDRequest.namespace` attribute.
 * `openid.extensions.draft` packages, namely its `pape2` and `pape5` modules.

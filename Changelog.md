# Changelog #

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

 # `BCUtil` Broski Cryptography Utilities

> Utilities for cryptographic operations.

## About

`BCUtil`, or <em>Broski Cryptography Utilities</em>, is a set of utilities for performing cryptographic operations.

## BCUtil Contents

### BCUtil `Collections`

BCUtil `Collections` are designed to preserve integrity of their data while taking care of size. Most (if not all) Collections
implement the `Trimmable` interface, where they can **both** be shortened _and_ keep data integrity.

### BCUtil `References`

BCUtil `References` are re-implementations of Java's `javax.crypto.SealedObject` except that they
- Support generics *(if you don't want them just set the type to `SecureReference<Object>`)*
- [Use `Gson` serialization instead of native Java serialization](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data), just like
every other class that relies on deserialization.

### BCUtil `Digest`

BCUtil `Digest` is a package of utility classes performing non-I/O operations, such as
- salt generation
- POJO *(Plain Old Java Object)* hashing

### BCUtil `Authentication`

BCUtil `Authentication`, or `Auth` for short, is a set of classes related to authentication, i.e. credentials
and identity.

### BCUtil `IO`
BCUtil `IO` contains classes related to file encryption and checksums.


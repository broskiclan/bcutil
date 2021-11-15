/**
 * <h1>Broski Cryptography Utilities</h1>
 * <h2>About</h2>
 * Broski Cryptography Utilities (or {@code bcutil} for short)
 * is a set of utilities to perform cryptographic digest including - but
 * not limited to:
 * <ul>
 *     <li><b>Store</b> {@link java.io.Serializable serializable data} to be written to files.</li>
 *     <li><b>Secure</b> serializable Java objects using a {@link org.broskiclan.bcutil.ref.SecureReference}.</li>
 *     <li><b>Preserve</b> integrity of contents in a {@link org.broskiclan.bcutil.collections.HashChain HashChain}.</li>
 * </ul>
 */
module org.broskiclan.bcryptutils {

	exports org.broskiclan.bcutil.collections;
	exports org.broskiclan.bcutil.ref;
	exports org.broskiclan.bcutil.auth;
	exports org.broskiclan.bcutil.digest;

	requires static lombok;
	requires static java.desktop;
	requires org.jetbrains.annotations;
	requires org.apache.commons.codec;
	requires org.apache.commons.lang3;

}
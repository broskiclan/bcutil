/**
 * <h1>Broski Cryptography Utilities</h1>
 * <h2>About</h2>
 * Broski Cryptography Utilities (or {@code bcutil} for short)
 * is a set of utilities to perform cryptographic operations including - but
 * not limited to:
 * <ul>
 *     <li><b>Store</b> {@link java.io.Serializable serializable data} to be written to files.</li>
 *     <li><b>Preserve</b> integrity of contents in a {@link org.broskiclan.bcutil.collections.HashChain HashChain}.</li>
 * </ul>
 * <h2>Notes</h2>
 * <ul>
 *     <li><b>All</b> operations in this library involving bytes are (if necessary) done with
 *     the {@link java.nio.charset.StandardCharsets#ISO_8859_1 ISO-8859-1} charset, <b>excluding file operations</b>.</li>
 * </ul>
 */
open module org.broskiclan.bcryptutils {

	exports org.broskiclan.bcutil.collections;

	requires static lombok;
	requires org.jetbrains.annotations;
	requires org.apache.commons.codec;
	requires com.google.gson;
	requires org.apache.commons.lang3;
	requires org.apache.commons.io;

}
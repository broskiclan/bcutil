/**
 * Utilities for cryptographic operations.
 */
module org.broskiclan.bcryptutils {

	exports org.broskiclan.bcutil.collections;
	exports org.broskiclan.bcutil.ref;
	exports org.broskiclan.bcutil.auth;
	exports org.broskiclan.bcutil.digest;
	exports org.broskiclan.bcutil.io;

	exports org.broskiclan.bcutil.internal to com.google.gson;
	opens org.broskiclan.bcutil.auth to com.google.gson;
	opens org.broskiclan.bcutil.ref to com.google.gson;

	requires static lombok;
	requires static java.desktop;
	requires com.google.gson;
	requires org.jetbrains.annotations;
	requires org.apache.commons.codec;
	requires org.apache.commons.lang3;

}
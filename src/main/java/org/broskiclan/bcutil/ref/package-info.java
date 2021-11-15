/**
 * <h1>BCUtil {@link org.broskiclan.bcutil.ref.SecureReference References}</h1>
 * BCUtil {@link org.broskiclan.bcutil.ref.SecureReference References} are containers for {@link java.io.Serializable serializable objects} that
 * once {@link org.broskiclan.bcutil.ref.SecureReference#encrypt() encrypted}, its internal data cannot be
 * accessed without knowing the secret/private key. As constructors of {@code References} contain
 * a substantial amount of parameters <em>(5 to be exact)</em>, a {@link org.broskiclan.bcutil.ref.ReferenceFactory} can
 * be used to ease the instantiation of those {@code SecureReferences}.<br><br>
 * <b>WARNING</b> {@code References} are <em>not thread-safe</em>.
 */
package org.broskiclan.bcutil.ref;
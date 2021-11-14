package org.broskiclan.bcutil.net.auth;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.security.MessageDigest;

public final class Credentials {

	/**
	 * Creates a new instance of {@link Credentials}.
	 * @param digest The {@link MessageDigest} to use. In order to avoid <em>hash collisions</em>
	 *               (where two hashes of different data match),
	 *               it is best to use secure hashes. Examples include (but are not limited to)
	 *               {@code SHA-256}, {@code SHA-512}, {@code SHA3-512}.
	 * @param requester The requester to use.
	 * @param fields
	 */
	@Contract(pure = true)
	public Credentials(@NotNull MessageDigest digest, @NotNull String requester, Serializable @NotNull ... fields) {
		byte[] array = null;
		for(Serializable s : fields) {
			if(array != null) {
				array = ArrayUtils.addAll(array, SerializationUtils.serialize(s));
			} else {
				array = SerializationUtils.serialize(s);
			}
		}
	}

}

package org.broskiclan.bcutil.internal;

import lombok.SneakyThrows;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;

/**
 * Internal utilities for the secure
 * deserialization of objects. This class
 * is meant to try to mitigate unsafe
 * deserialization.
 */
public final class InternalSerializationUtils {

	/**
	 * Deserializes an object using a secure
	 * {@link org.apache.commons.io.serialization.ValidatingObjectInputStream ObjectInputStream}.
	 * @param bytes The bytes to deserialize from
	 * @return the deserialized object.
	 */
	@SuppressWarnings("unchecked")
	@SneakyThrows
	public static <T> T deserialize(byte @NotNull [] bytes, Class<?>... permittedClasses) {
		try(ValidatingObjectInputStream objectInputStream = new ValidatingObjectInputStream(
				new ByteArrayInputStream(bytes)
		)) {
			objectInputStream.accept(permittedClasses);
			return (T) objectInputStream.readObject();
		}
	}

	private InternalSerializationUtils() {}

}

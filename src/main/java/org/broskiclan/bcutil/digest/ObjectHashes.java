package org.broskiclan.bcutil.digest;

import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.util.HashSet;

public final class ObjectHashes {

	private final MessageDigest digest;

	/**
	 * Returns a new instance of {@link ObjectHashes}
	 * using the given digest.
	 * @param digest The {@link MessageDigest} to use when hashing objects.
	 * @return an instance of {@link ObjectHashes} that uses the given digest.
	 */
	@Contract("_ -> new")
	public static @NotNull ObjectHashes getInstance(@Nullable MessageDigest digest) {
		return new ObjectHashes(digest);
	}

	/**
	 * Returns a new instance of {@link ObjectHashes}
	 * using the {@code SHA3-256} digest.
	 * @return an instance of {@link ObjectHashes} that uses the {@code SHA3-256} digest.
	 */
	@Contract(" -> new")
	public static @NotNull ObjectHashes getInstance() {
		return new ObjectHashes(null);
	}

	/**
	 * Creates a hash of the given object's <em>{@linkplain Class identity}</em>.
	 * All properties of the given object are ignored, except the {@link Class}
	 * returned by its {@link Object#getClass() getClass()} method. This is in contrast
	 * with the methods {@link #ofSerializable(Serializable)}, which read the values of a field.
	 * @param object The object to get a hashed identity of.
	 * @param <T> The type of the object.
	 * @return an identity hash of the given object.
	 */
	@Contract(pure = true)
	public <T> byte[] ofIdentity(@NotNull T object) {
		var clazz = object.getClass();
		byte[] b = SerializationUtils.serialize(clazz);
		b = ArrayUtils.addAll(b, SerializationUtils.serialize(
				clazz.getName()
		));
		b = ArrayUtils.addAll(b, SerializationUtils.serialize(
				clazz.toString()
		));
		b = ArrayUtils.addAll(b, SerializationUtils.serialize(
				clazz.getName()
		));
		b = ArrayUtils.addAll(b, SerializationUtils.serialize(
				clazz.getModifiers()
		));
		return digest.digest(b);
	}

	/**
	 * Creates a hash of the given object from finding its
	 * <em>{@linkplain #ofIdentity(Object) identity}</em>
	 * and all serializable fields.
	 * @param object The object to hash.
	 * @param <T> The type of the object.
	 * @return A hash containing fields of the given object
	 * and its <em>{@linkplain #ofIdentity(Object) identity}</em>.
	 */
	@Contract(pure = true)
	public <T> byte[] ofObject(@NotNull T object) {
		byte[] identity = ofIdentity(object);
		byte[] hashCode = new byte[] {(byte) object.hashCode()};
		byte[] data = ArrayUtils.addAll(SerializationUtils.serialize(new SerializableWrapper<>(object).getSerializableObjects()), hashCode);
		return digest.digest(ArrayUtils.addAll(identity, data));
	}

	/**
	 * Creates a hash of the given {@link Serializable serializable} object.
	 * @param serializable The {@link Serializable object} to hash.
	 * @param <T> The type of the object.
	 * @return a hash of the given object.
	 */
	@Contract(pure = true)
	public <T extends Serializable> byte[] ofSerializable(@NotNull T serializable) {
		return digest.digest(
				SerializationUtils.serialize(serializable)
		);
	}

	/**
	 * Creates a {@link ObjectHashes} instance. Use the
	 * {@link #getInstance()} or {@link #getInstance(MessageDigest)}
	 * instead.
	 * @param digest A digest to use when hashing the objects.
	 */
	@SneakyThrows
	private ObjectHashes(@Nullable MessageDigest digest) {
		if(digest != null) this.digest = digest;
		else this.digest = MessageDigest.getInstance("SHA3-256");
	}

	/**
	 * A helper class that collects almost everything that is serializable
	 * and adds it to an internal array.
	 * @param <T> the object type.
	 */
	private static class SerializableWrapper<T> implements Serializable {

		@Serial private static final long serialVersionUID = 3392610324746774441L;
		@Getter private final HashSet<Serializable> serializableObjects;

		public SerializableWrapper(@NotNull T object) {
			var clazz = object.getClass();
			var fields = clazz.getDeclaredFields();
			this.serializableObjects = new HashSet<>(fields.length);
			for(Field field : fields) {
				var t = field.getType();
				if(!Serializable.class.isAssignableFrom(t)) continue;
				serializableObjects.add(t);
				serializableObjects.add(t.getName());
			}
		}

	}

}

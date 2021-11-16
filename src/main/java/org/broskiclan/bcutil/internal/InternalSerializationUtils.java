package org.broskiclan.bcutil.internal;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.SneakyThrows;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.lang.reflect.Type;

/**
 * Internal utilities for the secure
 * deserialization of objects. This class
 * is meant to try to mitigate unsafe
 * deserialization.
 */
public final class InternalSerializationUtils {

	private static final Gson gson = new GsonBuilder()
			.registerTypeHierarchyAdapter(byte[].class, new ByteArraySerializationAdapter())
			.generateNonExecutableJson()
			.create();

	/**
	 * Deserializes an object from JSON.
	 * @param s the string to deserialize from.
	 * @param clazz the class to deserialize into.
	 * @return the deserialized object.
	 */
	@SneakyThrows
	@Contract(pure = true)
	public static <T> T deserialize(@NotNull String s, Class<T> clazz) {
		return gson.fromJson(s, (Type) clazz);
	}

	/**
	 * Serializes an object into JSON.
	 * @param <T> the type of the object.
	 * @param t the object to serialize into JSON.
	 * @return a JSON string containing the object data.
	 */
	@SneakyThrows
	@Contract(pure = true)
	public static <T> String serialize(@NotNull T t) {
		return gson.toJson(t, t.getClass());
	}

	private InternalSerializationUtils() {}

}

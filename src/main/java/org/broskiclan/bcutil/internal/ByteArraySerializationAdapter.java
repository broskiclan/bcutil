package org.broskiclan.bcutil.internal;

import com.google.gson.*;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

public class ByteArraySerializationAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {

	private static final Hex hex = new Hex(StandardCharsets.ISO_8859_1);

	@Override
	public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
		return new JsonPrimitive(new String(hex.encode(src), StandardCharsets.ISO_8859_1));
	}

	@SneakyThrows
	public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		return hex.decode(json.getAsString().getBytes(StandardCharsets.ISO_8859_1));
	}

}

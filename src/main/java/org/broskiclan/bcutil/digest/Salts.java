package org.broskiclan.bcutil.digest;

import org.jetbrains.annotations.NotNull;

import java.awt.*;
import java.security.SecureRandom;

/**
 * A utility class for generating salts.
 */
public final class Salts {

	/**
	 * Generates a salt using {@link MouseInfo#getPointerInfo()} and returns
	 * it in a byte array of the specified length.<br>
	 * <b>To use this method one must explicitly declare a dependency on {@link java.awt}
	 * as it is a static dependency of this module.</b>
	 * @param length The length of the salt to generate.
	 * @throws HeadlessException if this method is invoked on a headless server.
	 * @return a salt of the specified length.
	 */
	public static byte @NotNull [] ofMousePosition(int length) {
		var info = MouseInfo.getPointerInfo().getLocation();
		byte[] bytes = new byte[length];
		int x = info.x;
		int y = info.y;
		var sec = new SecureRandom();
		sec.nextBytes(bytes);
		bytes[sec.nextInt(0, length)] = (byte) x;
		bytes[sec.nextInt(0, length)] = (byte) y;
		return bytes;
	}

	/**
	 * Generates a salt of the specified length using the given {@link SecureRandom}.
	 * @param random The {@code SecureRandom} to use when generating a salt.
	 * @param length The length of the salt to generate.
	 * @return the generated salt.
	 */
	public static byte @NotNull [] ofSecureRandom(@NotNull SecureRandom random, int length) {
		byte[] bytes = new byte[length];
		random.nextBytes(bytes);
		return bytes;
	}

	/**
	 * Generates a salt of the specified length.
	 * @param length The length of the salt to generate.
	 * @return the generated salt.
	 */
	public static byte @NotNull [] ofSecureRandom(int length) {
		byte[] bytes = new byte[length];
		new SecureRandom().nextBytes(bytes);
		return bytes;
	}

	private Salts() {}

}

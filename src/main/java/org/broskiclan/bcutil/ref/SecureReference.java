package org.broskiclan.bcutil.ref;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.Cipher;
import java.io.InvalidObjectException;
import java.io.Serializable;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

// leave to internal classes to implement
@SuppressWarnings({"unused", "RedundantThrows"})
public abstract class SecureReference<T extends Serializable> implements Serializable {

	/**
	 * Creates a new {@link SecureReference} of the given type {@link T}.
	 * @param data The data to encrypt.
	 * @param random a {@link SecureRandom} to use when initializing.
	 * @param spec a specification of cryptographic parameters.
	 * @param algorithm The algorithm to use during encryption.
	 * @param cipher The cipher to use in encryption and decryption.
	 * @param provider The provider name of the internally created key generator. If null,<br>
	 *                 {@code getInstance(...)}<br> will be used instead of <br>{@code getInstance(..., provider)}.
	 * @throws InvalidAlgorithmParameterException if the parameter {@code spec} is not null and is invalid for initialization.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 */
	public SecureReference(T data, @NotNull SecureRandom random, @Nullable AlgorithmParameterSpec spec, @Nullable String algorithm, @Nullable String provider, @NotNull Cipher cipher) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {}

	/**
	 * Creates a new {@link SecureReference} of the given type {@link T}.
	 * @param data The data to encrypt.
	 * @param random a {@link SecureRandom} to use when initializing.
	 * @param keySize The key size to use.
	 * @param algorithm The algorithm to use during encryption.
	 * @param cipher The cipher to use in encryption and decryption.
	 * @param provider The provider name of the internally created key generator. If null,<br>
	 *                 {@code getInstance(...)}<br> will be used instead of <br>{@code getInstance(..., provider)}.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 */
	public SecureReference(T data, @NotNull SecureRandom random, int keySize, @Nullable String algorithm, @Nullable String provider, @NotNull Cipher cipher) throws NoSuchAlgorithmException {}

	/**
	 * A constructor for subclasses to ease the problem of writing {@code super(...);}.
	 * No classes must call this constructor AT ALL.
	 */
	protected SecureReference() {
		if(StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE).getCallerClass() != getClass())
			throw new IllegalCallerException();
	}

	/**
	 * Decrypts the securely encapsulated object stored in this {@link SecureReference}.
	 * Note that to get the same object using this method, this method <b>must</b> be called again. Thus,
	 * <b>if possible</b>, there should <em>never</em> be a field directly referencing the object, like <br><br>
	 * {@code private T data; // UNSAFE: Reflection}<br><br>
	 * as this may raise security issues when accessed via {@link Class#getDeclaredField(String)}
	 * or any other reflective way. If the above is necessary, it is best to make the
	 * field {@code transient}.
	 * @param key The key to use when decrypting the object.
	 * @return the object in the reference.
	 * @throws InvalidObjectException if an object was unable to be found when decrypting.
	 * @throws IllegalStateException if the object has not yet been encrypted by {@link #encrypt()}
	 * @throws InvalidKeyException if the given key is faulty.
	 */
	public abstract T get(Key key) throws InvalidObjectException, InvalidKeyException;

	/**
	 * Encrypts the stored object and stores it in a byte array.
	 * @param cipherSpec a cipher {@link AlgorithmParameterSpec} for use with
	 *                   cipher initialization.
	 * @return A key that is able to decrypt the stored object.
	 * @throws IllegalStateException if the stored object has already been encrypted.
	 */
	public abstract Key encrypt(@Nullable AlgorithmParameterSpec cipherSpec);

	/**
	 * Encrypts the stored object and stores it in a byte array.
	 * @return A key that is able to decrypt the stored object.
	 * @throws IllegalStateException if the stored object has already been encrypted.
	 */
	public abstract Key encrypt();

	/**
	 * Returns whether the object in the {@link SecureReference} has
	 * been encrypted and is ready to accept {@link #get(Key)} invocations.
	 * @return whether the object has been encrypted.
	 */
	public abstract boolean isEncrypted();

	/**
	 * Gets the raw data (encrypted) of the
	 * stored object.
	 * @return the (encrypted) byte array of the stored object.
	 * @throws IllegalStateException if the object has not yet been encrypted by {@link #encrypt()}
	 */
	public abstract byte[] getRawData();

}

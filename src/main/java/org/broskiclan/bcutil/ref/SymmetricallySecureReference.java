package org.broskiclan.bcutil.ref;

import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.lang3.SerializationException;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import java.io.InvalidObjectException;
import java.io.Serializable;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * <b>SymmetricallySecureReference</b>
 * A container for a {@link Serializable serializable object} that
 * can encrypt its data for security.
 * @param <T> The type to secure.
 */
// ignore this complicated warning that I am too lazy to figure out
@SuppressWarnings("scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUseappropriatesecretkeygenerationalgorithmOtheralgorithms")
public final class SymmetricallySecureReference<T extends Serializable> extends SecureReference<T> implements Serializable {

	private transient final KeyGenerator keyGenerator;
	private transient final Cipher cipher;
	private transient T current; // do not serialize unsecure objects
	@ApiStatus.Internal
	private byte[] data; // encrypted, permit serialization
	@Getter private boolean isEncrypted = false;

	/**
	 * Creates a new {@link SymmetricallySecureReference} of the given type {@link T}.
	 * @param data The data to encrypt.
	 * @param random a {@link SecureRandom} to use when initializing.
	 * @param spec a specification of cryptographic parameters.
	 * @param algorithm The symmetric algorithm to use during encryption. See {@link javax.crypto.KeyGenerator#getInstance(String)}.
	 *                  If {@code null}, the {@code AES} algorithm will be used.
	 * @throws InvalidAlgorithmParameterException if the parameter {@code spec} is not null and is invalid for initialization.
	 * @see javax.crypto.KeyGenerator#getInstance(String)
	 */
	public SymmetricallySecureReference(T data, @NotNull SecureRandom random, @Nullable AlgorithmParameterSpec spec, @Nullable String algorithm, Cipher cipher)
	throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		this.keyGenerator = KeyGenerator.getInstance(algorithm == null ? "AES" : algorithm);
		this.cipher = cipher;
		this.current = data;
		if(spec != null) keyGenerator.init(spec, random); else keyGenerator.init(random);
	}

	/**
	 * Creates a new {@link SymmetricallySecureReference} of the given type {@link T}.
	 * @param data The data to encrypt.
	 * @param random a {@link SecureRandom} to use when initializing.
	 * @param keySize The key size to use.
	 * @param algorithm The algorithm to use during encryption.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 */
	public SymmetricallySecureReference(T data, @NotNull SecureRandom random, int keySize, @Nullable String algorithm, Cipher cipher) throws NoSuchAlgorithmException {
		this.keyGenerator = KeyGenerator.getInstance(algorithm == null ? "AES" : algorithm);
		this.cipher = cipher;
		this.current = data;
		keyGenerator.init(keySize, random);
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
	 */
	@Override
	public T get(@NotNull Key key) throws InvalidObjectException, InvalidKeyException {
		if(!isEncrypted) throw new IllegalStateException();
		try {
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] result = cipher.doFinal(data);
			return SerializationUtils.deserialize(result);
		} catch(SerializationException | IllegalBlockSizeException | BadPaddingException e) {
			var e1 = new InvalidObjectException("Unable to find object during decryption");
			e1.initCause(e);
			throw e1;
		}
	}

	/**
	 * Encrypts the stored object and stores it in a byte array.
	 *
	 * @param cipherSpec a cipher {@link AlgorithmParameterSpec} for use with
	 *                   cipher initialization.
	 * @return The key used to encrypt the encapsulated object.
	 * @throws IllegalStateException if the stored object has already been encrypted.
	 */
	@SneakyThrows
	@Override
	public Key encrypt(@Nullable AlgorithmParameterSpec cipherSpec) {
		if(current == null) throw new IllegalStateException();
		Key key = keyGenerator.generateKey();
		if(cipherSpec != null) cipher.init(Cipher.ENCRYPT_MODE, key, cipherSpec);
		else cipher.init(Cipher.ENCRYPT_MODE, key);
		data = cipher.doFinal(SerializationUtils.serialize(current));
		isEncrypted = true;
		return key;
	}

	/**
	 * Encrypts the stored object and stores it in a byte array.
	 * @return The key used to encrypt the encapsulated object.
	 * @throws IllegalStateException if the stored object has already been encrypted.
	 */
	@SneakyThrows
	@Override
	public Key encrypt() {
		if(current == null) throw new IllegalStateException();
		Key key = keyGenerator.generateKey();
		cipher.init(Cipher.ENCRYPT_MODE, key);
		data = cipher.doFinal(SerializationUtils.serialize(current));
		isEncrypted = true;
		return key;
	}

	/**
	 * Gets the raw data (encrypted) of the
	 * stored object.
	 *
	 * @return the (encrypted) byte array of the stored object.
	 * @throws IllegalStateException if the object has not yet been encrypted by {@link #encrypt()}
	 */
	@Override
	public byte[] getRawData() {
		return data.clone();
	}

}
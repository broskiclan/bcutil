package org.broskiclan.bcutil.ref;

import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.lang3.SerializationException;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.InvalidObjectException;
import java.io.Serializable;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * <b>SymmetricallySecureReference</b>
 * A container for a {@link Serializable serializable object} that
 * can encrypt its data for security.
 * @param <T> The type to secure.
 */
public class AsymmetricallySecureReference<T extends Serializable> extends SecureReference<T> {

	private transient T temp;
	private transient final Cipher cipher;
	private transient final KeyPairGenerator keyPairGenerator;
	@Getter private boolean isEncrypted = false;
	@Getter private byte[] rawData;

	/**
	 * Creates a new {@link AsymmetricallySecureReference} of the given type {@link T}.
	 *
	 * @param data      The data to encrypt.
	 * @param random    a {@link SecureRandom} to use when initializing.
	 * @param spec      a specification of cryptographic parameters. If null, a key-size of 256 bits is used.
	 * @param algorithm The algorithm to use during encryption. If null,
	 *                  the elliptic-curve algorithm is used.
	 * @param cipher The cipher to use in encryption and decryption.
	 * @throws InvalidAlgorithmParameterException if the parameter {@code spec} is not null and is invalid for initialization.
	 * @throws NoSuchAlgorithmException           if the given algorithm could not be found.
	 * @throws NoSuchProviderException if the provider is not null and cannot be found
	 */
	@SuppressWarnings("scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUsesufficientlylongkeysizeskeyPairGeneratorbadvalue")
	public AsymmetricallySecureReference(T data, @NotNull SecureRandom random, @Nullable AlgorithmParameterSpec spec, @Nullable String algorithm, @Nullable String provider, @NotNull Cipher cipher) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		this.temp = data;
		this.cipher = cipher;
		if(provider != null) this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm != null ? algorithm : "EC", provider);
		else this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm != null ? algorithm : "EC");
		if(spec == null) {
			// we're using EC (discrete logarithm problem is harder than scalar multiplication), so
			// we can set a smaller key-size (256 bits) instead of RSA's 2048 bits
			keyPairGenerator.initialize(256, random);
		} else keyPairGenerator.initialize(spec, random);
	}

	/**
	 * Creates a new {@link AsymmetricallySecureReference} of the given type {@link T}.
	 *
	 * @param data      The data to encrypt.
	 * @param random    a {@link SecureRandom} to use when initializing.
	 * @param keySize   The key size to use.
	 * @param algorithm The algorithm to use during encryption. If null,
	 *                  the elliptic-curve algorithm is used.
	 * @param cipher The cipher to use in encryption and decryption.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 * @throws NoSuchProviderException if the provider is not null and cannot be found
	 */
	public AsymmetricallySecureReference(T data, @NotNull SecureRandom random, int keySize, @Nullable String algorithm, @Nullable String provider, @NotNull Cipher cipher) throws NoSuchAlgorithmException, NoSuchProviderException {
		this.temp = data;
		this.cipher = cipher;
		if(provider != null) this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm != null ? algorithm : "EC", provider);
		else this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm != null ? algorithm : "EC");
		keyPairGenerator.initialize(keySize, random);
	}

	/**
	 * Decrypts the securely encapsulated object stored in this {@link SecureReference}.
	 * Note that to get the same object using this method, this method <b>must</b> be called again. Thus,
	 * <b>if possible</b>, there should <em>never</em> be a field directly referencing the object, like <br><br>
	 * {@code private T data; // UNSAFE: Reflection}<br><br>
	 * as this may raise security issues when accessed via {@link Class#getDeclaredField(String)}
	 * or any other reflective way. If the above is necessary, it is best to make the
	 * field {@code transient}.
	 *
	 * @param key The key to use when decrypting the object.
	 * @return the object in the reference.
	 * @throws InvalidObjectException if an object was unable to be found when decrypting.
	 * @throws IllegalStateException  if the object has not yet been encrypted by {@link #encrypt()}
	 * @throws InvalidKeyException    if the given key is faulty.
	 */
	@Override
	public T get(Key key) throws InvalidObjectException, InvalidKeyException {
		try {
			if(!(key instanceof PrivateKey)) throw new InvalidKeyException("The given key is not a private key.");
			if(!isEncrypted) throw new IllegalStateException();
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] b = cipher.doFinal(rawData);
			return SerializationUtils.deserialize(b);
		} catch(SerializationException | IllegalBlockSizeException | BadPaddingException e) {
			var e1 = new InvalidObjectException("Unable to find object");
			e1.initCause(e);
			throw e1;
		}
	}

	/**
	 * Encrypts the stored object and stores it in a byte array.
	 *
	 * @param cipherSpec a cipher {@link AlgorithmParameterSpec} for use with
	 *                   cipher initialization.
	 * @return A key that is able to decrypt the stored object.
	 * @throws IllegalStateException if the stored object has already been encrypted.
	 */
	@Override
	@SneakyThrows
	public Key encrypt(@Nullable AlgorithmParameterSpec cipherSpec) {
		KeyPair kp = keyPairGenerator.generateKeyPair();
		if(cipherSpec == null) cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
		else cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic(), cipherSpec);
		rawData = cipher.doFinal(SerializationUtils.serialize(temp));
		this.temp = null;
		isEncrypted = true;
		return kp.getPrivate();
	}

	/**
	 * Encrypts the stored object and stores it in a byte array.
	 *
	 * @return A key that is able to decrypt the stored object.
	 * @throws IllegalStateException if the stored object has already been encrypted.
	 */
	@Override
	@SneakyThrows
	public Key encrypt() {
		if(isEncrypted) throw new IllegalStateException();
		KeyPair kp = keyPairGenerator.generateKeyPair();
		cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
		rawData = cipher.doFinal(SerializationUtils.serialize(temp));
		this.temp = null;
		isEncrypted = true;
		return kp.getPrivate();
	}

}
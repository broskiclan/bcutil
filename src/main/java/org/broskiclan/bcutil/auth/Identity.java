package org.broskiclan.bcutil.auth;


import com.google.gson.JsonParseException;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.broskiclan.bcutil.internal.InternalSerializationUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * A hashable identity that is able to sign messages.
 * and get its messages verified. All methods except
 * {@link #regenerateKeys()} do not mutate an instance
 * of {@code Identity}.
 * <b>This class exposes {@linkplain #keyPair confidential data}
 * through getters and must be {@linkplain org.broskiclan.bcutil.ref safeguarded} and/or
 * {@linkplain Serializable stored locally}.</b>
 */
@SuppressWarnings("scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUsestrongsymmetriccryptographicalgorithm")
public class Identity implements Serializable {

	private transient final KeyPairGenerator keyPairGenerator;
	private transient final KeyGenerator keyGenerator;
	private final String algorithm; // asymmetric algorithm
	private final String algorithm2;
	private final String cipherAlgorithm;
	private final String provider;
	private transient final Cipher cipher;
	private transient final Cipher cipherB;
	private final Credentials credentials;
	@Getter private transient KeyPair keyPair;
	private boolean defaultCipher = false;

	/**
	 * Helper method for default mode GCM
	 */
	@VisibleForTesting
	public static GCMParameterSpec getSpec() {
		byte[] b = new byte[16];
		new SecureRandom().nextBytes(b);
		return new GCMParameterSpec(128, b);
	}

	/**
	 * Creates a new {@link Identity}.
	 * @param algorithm The asymmetric algorithm to use for key-pair creation.
	 * @param spec The {@link AlgorithmParameterSpec} to use.
	 * @param random The {@link SecureRandom} to use for key-pair creation.
	 * @param provider The provider to use. Can be null.
	 * @param cipher The cipher to use with the internally created {@link KeyPairGenerator}.
	 * @param credentials The {@link Credentials} to associate this {@link Identity} with.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 * @throws InvalidAlgorithmParameterException if the given {@link AlgorithmParameterSpec} is invalid for the given algorithm.
	 * @throws NoSuchProviderException if the given provider is not null and cannot be found.
	 */
	@SneakyThrows(NoSuchPaddingException.class)
	@Contract(pure = true)
	public Identity(String algorithm, AlgorithmParameterSpec spec, SecureRandom random, @Nullable String provider, @NotNull Cipher cipher, @NotNull Credentials credentials) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		this.algorithm = algorithm;
		this.algorithm2 = "AES";
		this.provider = provider;
		this.cipher = cipher;
		this.credentials = credentials;
		if(provider != null) this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
		else this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(spec, random);
		this.keyPair = keyPairGenerator.generateKeyPair();
		cipherAlgorithm = cipher.getAlgorithm();
		keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		cipherB = Cipher.getInstance("AES");
		defaultCipher = true;
	}

	/**
	 * Creates a new {@link Identity}.
	 * @param algorithm The asymmetric algorithm to use for key-pair creation.
	 * @param keySize The key-size to use for {@link KeyPairGenerator#initialize(int, SecureRandom)
	 * KeyPairGenerator initialization.}
	 * @param random The {@link SecureRandom} to use for key-pair creation.
	 * @param provider The provider to use. Can be null.
	 * @param cipher The cipher to use with the internally created {@link KeyPairGenerator}.
	 * @param credentials The {@link Credentials} to associate this {@link Identity} with.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 * @throws NoSuchProviderException if the given provider is not null and cannot be found.
	 */
	@Contract(pure = true)
	@SneakyThrows(NoSuchPaddingException.class)
	public Identity(String algorithm, int keySize, @NotNull SecureRandom random, @Nullable String provider, @NotNull Cipher cipher, @NotNull Credentials credentials) throws NoSuchAlgorithmException, NoSuchProviderException {
		this.algorithm = algorithm;
		this.algorithm2 = "AES";
		this.provider = provider;
		this.cipher = cipher;
		this.credentials = credentials;
		if(provider != null) this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
		else this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(keySize, random);
		this.keyPair = keyPairGenerator.generateKeyPair();
		cipherAlgorithm = cipher.getAlgorithm();
		keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		cipherB = Cipher.getInstance("AES");
		defaultCipher = true;
	}

	/**
	 * Creates a new {@link Identity}.
	 * @param aAlgorithm The asymmetric algorithm to use for key-pair creation.
	 * @param bAlgorithm The symmetric algorithm to use to encrypt a generated asymmetric key.
	 * @param spec The {@link AlgorithmParameterSpec} to use for the internally created {@link KeyPairGenerator}.
	 * @param bSpec The {@link AlgorithmParameterSpec} to use for the internally created {@link KeyGenerator}.
	 * @param random The {@link SecureRandom} to use for key-pair creation.
	 * @param provider The provider to use. Can be null.
	 * @param cipher The cipher to use with the internally created {@link KeyPairGenerator}.
	 * @param cipherB The cipher to use with the internally created {@link KeyGenerator}.
	 * @param credentials The {@link Credentials} to associate this {@link Identity} with.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 * @throws InvalidAlgorithmParameterException if the given {@link AlgorithmParameterSpec} is invalid for the given algorithm.
	 * @throws NoSuchProviderException if the given provider is not null and cannot be found.
	 */
	@Contract(pure = true)
	public Identity(

			String aAlgorithm,
			String bAlgorithm,
			AlgorithmParameterSpec spec,
			AlgorithmParameterSpec bSpec,
			SecureRandom random, @Nullable
			String provider,
			@NotNull Cipher cipher,
			@NotNull Cipher cipherB,
			@NotNull Credentials credentials

	) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		this.algorithm = aAlgorithm;
		this.algorithm2 = bAlgorithm;
		this.provider = provider;
		this.cipher = cipher;
		this.credentials = credentials;
		if(provider != null) this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
		else this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(spec, random);
		this.keyPair = keyPairGenerator.generateKeyPair();
		cipherAlgorithm = cipher.getAlgorithm();
		//noinspection scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUseappropriatesecretkeygenerationalgorithmOtheralgorithms
		keyGenerator = KeyGenerator.getInstance(bAlgorithm);
		keyGenerator.init(bSpec, random);
		this.cipherB = cipherB;
	}

	/**
	 * Creates a new {@link Identity}.
	 * @param aAlgorithm The asymmetric algorithm to use for key-pair creation.
	 * @param bAlgorithm The symmetric algorithm to use to encrypt a generated asymmetric key.
	 * @param keySize The key-size to use for {@link KeyPairGenerator#initialize(int, SecureRandom)
	 * KeyPairGenerator initialization.}
	 * @param bKeySize The key-size to use for {@link KeyGenerator} initialization.
	 * @param random The {@link SecureRandom} to use for key-pair creation.
	 * @param provider The provider to use. Can be null.
	 * @param cipher The cipher to use with the internally created {@link KeyPairGenerator}.
	 * @param cipherB The cipher to use with the internally created {@link KeyGenerator}.
	 * @param credentials The {@link Credentials} to associate this {@link Identity} with.
	 * @throws NoSuchAlgorithmException if the given algorithm could not be found.
	 * @throws NoSuchProviderException if the given provider is not null and cannot be found.
	 */
	@Contract(pure = true)
	@SneakyThrows(NoSuchPaddingException.class)
	public Identity(

			String aAlgorithm,
			String bAlgorithm,
			int keySize,
			int bKeySize,
			@NotNull SecureRandom random,
			@Nullable String provider,
			@NotNull Cipher cipher,
			@NotNull Cipher cipherB,
			@NotNull Credentials credentials

	) throws NoSuchAlgorithmException, NoSuchProviderException {
		this.algorithm = aAlgorithm;
		this.algorithm2 = bAlgorithm;
		this.provider = provider;
		this.cipher = cipher;
		this.credentials = credentials;
		if(provider != null) this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
		else this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(keySize, random);
		this.keyPair = keyPairGenerator.generateKeyPair();
		cipherAlgorithm = cipher.getAlgorithm();
		//noinspection scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUseappropriatesecretkeygenerationalgorithmOtheralgorithms
		keyGenerator = KeyGenerator.getInstance(bAlgorithm);
		keyGenerator.init(bKeySize, random); // force key size
		//noinspection scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUsestrongsymmetriccryptographicalgorithmUntrusted
		this.cipherB = Cipher.getInstance(bAlgorithm);
	}

	/**
	 * Signs a serializable object using this {@link Identity}'s
	 * {@link KeyPair#getPrivate() private key.}
	 * @param serializable The serializable object to sign.
	 * @return A byte array containing the signed data and the wrapped key used to sign it.
	 */
	@SneakyThrows
	@Contract(pure = true)
	public byte[] sign(Serializable serializable) {
		try(
				ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)
		) {
			// write identity for verification
			objectOutputStream.writeUTF(
					// java native serialization has a vulnerability
					InternalSerializationUtils.serialize(this)
			);
			objectOutputStream.writeObject(serializable);
			objectOutputStream.close();
			Key key = keyGenerator.generateKey();
			cipher.init(Cipher.WRAP_MODE, keyPair.getPrivate());
			cipherB.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipherB.doFinal(byteArrayOutputStream.toByteArray());
			byte[] wrappedKey = cipher.wrap(key);
			return SerializationUtils.serialize(ImmutablePair.of(result, wrappedKey));
		}
	}

	/**
	 * Signs a serializable object using this {@link Identity}'s
	 * {@link KeyPair#getPrivate() private key.}
	 * @param serializable The serializable object to sign.
	 * @param spec The {@link AlgorithmParameterSpec} to use with the asymmetric cipher.
	 * @return A byte array containing the signed data and the wrapped key used to sign it.
	 */
	@SneakyThrows
	@Contract(pure = true)
	public byte @NotNull [] sign(Serializable serializable, AlgorithmParameterSpec spec) {
		try(
				ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)
		) {
			// write identity for verification
			objectOutputStream.writeUTF(
					// java native serialization has a vulnerability
					InternalSerializationUtils.serialize(this)
			);
			objectOutputStream.writeObject(serializable);
			objectOutputStream.close();
			Key key = keyGenerator.generateKey();
			cipher.init(Cipher.WRAP_MODE, keyPair.getPrivate(), spec);
			cipherB.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipherB.doFinal(byteArrayOutputStream.toByteArray());
			byte[] wrappedKey = cipher.wrap(key);
			return SerializationUtils.serialize(ImmutablePair.of(result, wrappedKey));
		}
	}

	/**
	 * Regenerate the key-pair of this Identity.
	 */
	public void regenerateKeys() {
		keyPair = keyPairGenerator.generateKeyPair();
	}

	/**
	 * Returns whether a <em>message</em> given in the form of a
	 * byte array has been signed by the given {@link Identity}.
	 * @param message The <em>message</em> to verify signature of.
	 * @param identity The identity suspected to have signed the given <em>message</em>.
	 * @param cipher1Spec The {@link AlgorithmParameterSpec} to use with the {@link Cipher} in {@link Cipher#UNWRAP_MODE}.
	 * @param cipher2spec The {@link AlgorithmParameterSpec} to use with the {@link Cipher} in {@link Cipher#DECRYPT_MODE}.
	 * @return whether the suspected identity has signed the given <em>message</em>.
	 */
	@SuppressWarnings("unchecked")
	@Contract(pure = true)
	@SneakyThrows
	public static boolean verifyIdentity(byte @NotNull [] message, @NotNull Identity identity, @Nullable AlgorithmParameterSpec cipher1Spec, @Nullable AlgorithmParameterSpec cipher2spec) {
		var cipher = identity.cipher;
		cipher.init(Cipher.DECRYPT_MODE, identity.keyPair.getPublic());
		try(
				ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(message);
				ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream) {
					@Override
					protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
						Class<?> clazz = super.resolveClass(desc);
						if (
								clazz.isArray() ||
										clazz.equals(ImmutablePair.class) ||
										clazz.equals(Pair.class) ||
										clazz.equals(String.class) ||
										Number.class.isAssignableFrom(clazz)
						) return clazz;
						throw new SecurityException("Security violation: attempt to deserialize unauthorized class " + clazz);
					}
				}
		) {
			// left -> signed data
			// right -> wrapped key
			var obj = (ImmutablePair<byte[], byte[]>) objectInputStream.readObject();
			if(cipher1Spec != null) identity.cipher.init(Cipher.UNWRAP_MODE, identity.getKeyPair().getPublic(), cipher1Spec);
			else identity.cipher.init(Cipher.UNWRAP_MODE, identity.getKeyPair().getPublic());
			var cipherWrap = identity.cipher;
			SecretKey key = (SecretKey) cipherWrap.unwrap(obj.right, identity.algorithm2, Cipher.SECRET_KEY);
			var cipherCrypt = identity.cipherB;
			if(cipher2spec != null) cipherCrypt.init(Cipher.DECRYPT_MODE, key, cipher2spec);
			else cipherCrypt.init(Cipher.DECRYPT_MODE, key);
			byte[] b2 = cipherCrypt.doFinal(obj.left);
			try(ObjectInputStream inputStream = new ObjectInputStream(
					new ByteArrayInputStream(b2)
			)) {
				Identity identity1 = InternalSerializationUtils.deserialize(inputStream.readUTF(), Identity.class);
				return identity.equals(identity1);
			} catch(JsonParseException jsonParseException) {
				return false;
			}
		} catch(InvalidKeyException | BadPaddingException exception) {
			return false;
		}
	}

	@Override
	public boolean equals(Object o) {
		if(this == o) return true;
		if(o == null || getClass() != o.getClass()) return false;
		Identity identity = (Identity) o;
		return new EqualsBuilder()
				.append(algorithm, identity.algorithm)
				.append(cipherAlgorithm, identity.cipherAlgorithm)
				.append(credentials, identity.credentials)
				.isEquals();
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17, 37)
				.append(algorithm)
				.append(cipherAlgorithm)
				.append(credentials)
				.toHashCode();
	}
}
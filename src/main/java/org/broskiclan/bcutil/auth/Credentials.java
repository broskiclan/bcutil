package org.broskiclan.bcutil.auth;

import lombok.SneakyThrows;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import java.io.*;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.HashSet;

/**
 * An immutable and serializable class storing
 * hashable data. This class should NEVER directly be stored in
 * servers: it should be serialized in the form of bytes.
 */
public final class Credentials implements Serializable {

	@Serial
	private static final long serialVersionUID = 903697082214965067L;
	private final MessageDigest digest;
	private final KeyPairGenerator generator;
	private final Cipher cipher;
	private boolean isEncrypted = false;
	private byte[] encrypted;
	// ============ WARNING ============= //
	//  DO NOT WRITE TO AN OUTPUT STREAM  //
	//      CONTAINS SENSITIVE DATA       //
	// ================================== //
	// encrypt before serialization
	private/* transient */final HashSet<byte[]> bytes = new HashSet<>();
	// ============ WARNING ============= //
	//  DO NOT WRITE TO AN OUTPUT STREAM  //
	//      CONTAINS SENSITIVE DATA       //
	// ================================== //
	// malicious actors could brute force
	// until this hash is achieved
	private transient byte[] hashCache; // cache hashes

	/**
	 * Creates a new instance of {@link Credentials}.
	 * @param digest The {@link MessageDigest} to use. In order to avoid <em>hash collisions</em>
	 *               (where two digest of different data match),
	 *               it is best to use secure digest. Examples include (but are not limited to)
	 *               {@code SHA3-256}, {@code SHA-512}, {@code SHA3-512}.
	 * @param generator An initialized KeyPairGenerator.
	 * @param cipher The cipher to use for encryption. Initialization is not required.
	 * @param fields The fields to use.
	 */
	@Contract(pure = true)
	public Credentials(@NotNull MessageDigest digest, @NotNull KeyPairGenerator generator, @NotNull Cipher cipher, Serializable @NotNull ... fields) {
		this.digest = digest;
		this.generator = generator;
		this.cipher = cipher;
		for(Serializable s : fields) {
			bytes.add(SerializationUtils.serialize(s));
		}
	}

	/**
	 * Hashes the data stored.
	 * @return the stored data hashed by the given {@link Cipher} in the
	 * {@link #Credentials(MessageDigest, KeyPairGenerator, Cipher, Serializable...) constructor}.
	 */
	public byte @NotNull [] hash() {
		if(hashCache == null) {
			hashCache = digest.digest(SerializationUtils.serialize(bytes));
		}
		return hashCache;
	}

	/**
	 * Encrypts the data stored in {@link #bytes}.
	 */
	@SneakyThrows
	public void encrypt() {
		var k = generator.generateKeyPair();
		cipher.init(Cipher.ENCRYPT_MODE, k.getPublic());
		encrypted = cipher.doFinal();
		isEncrypted = true;
	}

	@Serial
	private void writeObject(@NotNull ObjectOutputStream o) throws IOException {
		if(isEncrypted) throw new IllegalStateException("Not encrypted");
		o.writeInt(encrypted.length);
		o.write(encrypted);
	}

	@Serial
	private void readObject(@NotNull ObjectInputStream o) throws IOException {
		int i = o.readInt();
		encrypted = o.readNBytes(i);
	}

}

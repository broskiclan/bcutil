package org.broskiclan.bcutil.collections;

import com.google.gson.Gson;
import lombok.Getter;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * This class represents a specialized {@link IBlock block} for a HashChain.
 */
public class HashChainBlock implements IBlock, Serializable {

	@Getter
	private final String hash;
	@Getter
	private final String prevHash;
	@Getter
	private final String prevHash2;
	@Getter
	protected final Object data;

	/**
	 * If a {@link HashChain} has no blocks yet, this class is to be used.
	 * @apiNote Trying to perform operations on this (null) block will throw an {@link
	 * IllegalAccessException}, as this block is intended to be unmodified.
	 */
	public static final class NullHashChainBlock extends HashChainBlock {

		private final String nHash;

		public NullHashChainBlock(MessageDigest digest) {
			super("", "", "", digest);
			nHash = this.calculateHash(digest);
		}

		@Override
		public String getHash() {
			return nHash;
		}
	}

	/**
	 * Returns whether the block is a {@link NullHashChainBlock}
	 * or if this block's hash <i>inherits</i> its previous hash.
	 * @return Whether the block <i>inherits</i> a {@link NullHashChainBlock}'s
	 * hash, or if it <i>is, itself,</i> one.
	 */
	public boolean inheritsHashFromNullBlock() {
		return Objects.equals(this.prevHash2, "");
	}

	/**
	 * Creates a new 'block' from the previous block.
	 * @param prevBlock The previous block.
	 */
	HashChainBlock(@NotNull HashChainBlock prevBlock, @NotNull Object data, MessageDigest digest) {
		this.data = data;
		this.prevHash = prevBlock.getHash();
		boolean v = File.class.isAssignableFrom(data.getClass());
		this.hash = calculateHash(digest);
		this.prevHash2 = prevBlock.prevHash;
	}

	private HashChainBlock(@NotNull String hash, @NotNull String prevHash, @NotNull String prevHash2, MessageDigest digest) {
		this.hash = hash;
		this.prevHash = prevHash;
		this.prevHash2 = prevHash2;
		this.data = null;
	}

	public String toJson() {
		return new Gson().toJson(this, HashChainBlock.class);
	}

	/**
	 * Calculates the hash of the block (in hexadecimal).
	 * @return the calculated hash in a hexadecimal string.
	 */
	@SneakyThrows
	@Contract("_ -> new")
	protected @NotNull String calculateHash(MessageDigest digest) {

		var p = this.prevHash.getBytes(StandardCharsets.ISO_8859_1);
		byte[] p2 = null;
		if(!(prevHash2 == null)) p2 = this.prevHash2.getBytes(StandardCharsets.ISO_8859_1);
		byte[] c, k;
		var i = Objects.hash(this, this.toJson(), this.data);
		c = DigestUtils.sha3_256(String.valueOf(i));

		byte[] allByteArray;
		if(p2 != null) allByteArray = new byte[p.length + c.length + p2.length]; else
			 allByteArray = new byte[p.length + c.length];
		ByteBuffer buff = ByteBuffer.wrap(allByteArray);
		buff.put(p);
		buff.put(c);
		if(p2 != null) buff.put(p2);
		k = buff.array();
		buff.clear();

		digest.update(k);
		var f = digest.digest();
		return new String(
				new Hex(StandardCharsets.ISO_8859_1).encode(f),
				StandardCharsets.ISO_8859_1
		);
	}

	@Contract("-> new")
	public final byte @NotNull [] asBytes() {
		return SerializationUtils.serialize(this);
	}

	public static HashChainBlock fromBytes(byte[] bytes) {
		return SerializationUtils.deserialize(bytes);
	}

}
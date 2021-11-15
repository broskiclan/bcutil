package org.broskiclan.bcutil.collections;

import lombok.Getter;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.Serial;
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
	@Serial
	private static final long serialVersionUID = 4258303698233042573L;
	/**
	 * If a {@link HashChain} has no blocks yet, this class is to be used.
	 * @apiNote Trying to perform digest on this (null) block will throw an {@link
	 * IllegalAccessException}, as this block is intended to be unmodified.
	 */
	public static final class NullHashChainBlock extends HashChainBlock {

		private final String nHash;

		public NullHashChainBlock(MessageDigest digest) {
			super("", "", "");
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
	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
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
		this.hash = calculateHash(digest);
		this.prevHash2 = prevBlock.prevHash;
	}

	private HashChainBlock(@NotNull String hash, @NotNull String prevHash, @NotNull String prevHash2) {
		this.hash = hash;
		this.prevHash = prevHash;
		this.prevHash2 = prevHash2;
		this.data = null;
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
		var i = Objects.hash(this, this.data);
		c = digest.digest(String.valueOf(i).getBytes(StandardCharsets.ISO_8859_1));

		byte[] allByteArray;
		if(p2 != null) allByteArray = new byte[p.length + c.length + p2.length]; else
			 allByteArray = new byte[p.length + c.length];
		ByteBuffer buff = ByteBuffer.wrap(allByteArray);
		buff.put(p);
		buff.put(c);
		if(p2 != null) buff.put(p2);
		k = buff.array();
		buff.clear();

		var f = digest.digest(k);
		return new String(
				new Hex(StandardCharsets.ISO_8859_1).encode(f),
				StandardCharsets.ISO_8859_1
		);
	}

}
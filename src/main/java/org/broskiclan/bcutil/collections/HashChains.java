package org.broskiclan.bcutil.collections;

import lombok.SneakyThrows;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

@SuppressWarnings("UnusedReturnValue")
public final class HashChains {

	/**
	 * Stores the HashChain in a file.
	 * @param hashChain The HashChain to store.
	 * @param file The file to store it in.
	 * @param checkValid Whether the chain should be validated. If it is not valid, <code>false</code>
	 *                   will be returned and the chain is not stored.
	 * @param <E> The HashChain type parameter.
	 * @return Whether the HashChain was stored.
	 * @throws IOException if an I/O error occurs.
	 */
	public static <E> boolean storeChain(@NotNull HashChain<E> hashChain, @NotNull File file, boolean checkValid) throws IOException {

		// the && operator short-circuits: hashChain.validate() MUST BE LAST
		if(checkValid && !hashChain.validate()) return false;
		var ba = hashChain.toBlockArray();
		if(!file.exists()) //noinspection ResultOfMethodCallIgnored
			file.createNewFile();

		try(var o = new ObjectOutputStream(
				Files.newOutputStream(file.toPath())
		)) {

			var p = new Properties();
			p.put("ChainArrayCapacity", String.valueOf(hashChain.getArrayCapacity()));
			p.put("ArrayIncrement", String.valueOf(hashChain.increment()));
			p.put("ChainElementCount", String.valueOf(hashChain.size()));
			p.put("StructuralModifications", String.valueOf(hashChain.getStructuralModificationCount()));
			p.put("DigestAlgorithm", hashChain.getDigest().getAlgorithm());
			o.writeObject(p);

			for(HashChainBlock hashChainBlock : hashChain.data) {
				o.writeObject(hashChainBlock);
			}

		}

		return true;

	}

	@SneakyThrows({ClassNotFoundException.class, NoSuchAlgorithmException.class})
	public static <E> @NotNull HashChain<E> readChain(@NotNull File file) throws IOException {

		ObjectInputStream objectInputStream = new ObjectInputStream(
				Files.newInputStream(file.toPath())
		);

		// read properties
		Properties p = (Properties) objectInputStream.readObject();
		var cac = Integer.parseInt((String) p.get("ChainArrayCapacity"));
		var ai = Integer.parseInt((String)  p.get("ArrayIncrement"));
		var cec = Integer.parseInt((String) p.get("ChainElementCount"));
		var sm = Integer.parseInt((String) p.get("StructuralModifications"));
		var dig = (String) p.get("DigestAlgorithm");

		var hc = new HashChain<E>(ai, cac, false, MessageDigest.getInstance(dig));

		for(int i = 0; i < cec; i++) {
			var hcb = (HashChainBlock) objectInputStream.readObject();
			hc.add(hcb, hc.data, hc.size());
		}

		hc.setModCount(sm);
		return hc;

	}

	private HashChains() {}

}

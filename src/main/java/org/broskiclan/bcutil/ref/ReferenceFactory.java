package org.broskiclan.bcutil.ref;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.Cipher;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * A parameterized factory for asymmetric and symmetric references.
 */
public final class ReferenceFactory {

	@NotNull private final SecureRandom secureRandom;
	@Nullable private final String provider;
	@NotNull private final Cipher cipher;
	private int keySize;
	private AlgorithmParameterSpec spec;

	@Contract(pure = true)
	public static @NotNull ReferenceFactory from(@NotNull SecureRandom secureRandom, @NotNull AlgorithmParameterSpec spec, @Nullable String provider, @NotNull Cipher cipher) {
		return new ReferenceFactory(secureRandom, spec, provider, cipher);
	}

	@Contract(pure = true)
	public static @NotNull ReferenceFactory from(@NotNull SecureRandom secureRandom, @NotNull AlgorithmParameterSpec spec, @NotNull Cipher cipher) {
		return new ReferenceFactory(secureRandom, spec, null, cipher);
	}

	@Contract(pure = true)
	public static @NotNull ReferenceFactory from(@NotNull SecureRandom secureRandom, int keySize, @Nullable String provider, @NotNull Cipher cipher) {
		return new ReferenceFactory(secureRandom, keySize, provider, cipher);
	}

	@Contract(pure = true)
	public static @NotNull ReferenceFactory from(SecureRandom secureRandom, int keySize, Cipher cipher) {
		return new ReferenceFactory(secureRandom, keySize, null, cipher);
	}

	@Contract(value = "_, _ -> new", pure = true)
	public <T extends Serializable> @NotNull SecureReference<T> ofSymmetric(T data, String algorithm) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		if(spec != null) {
			return new SymmetricallySecureReference<>(
					data,
					secureRandom,
					spec,
					algorithm,
					provider,
					cipher
			);
		} else {
			return new SymmetricallySecureReference<>(
					data,
					secureRandom,
					keySize,
					algorithm,
					provider,
					cipher
			);
		}
	}

	@Contract(value = "_, _ -> new", pure = true)
	public <T extends Serializable> @NotNull SecureReference<T> ofAsymmetric(T data, String algorithm) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		if(spec != null) {
			return new AsymmetricallySecureReference<>(
					data,
					secureRandom,
					spec,
					algorithm,
					provider,
					cipher
			);
		} else {
			return new AsymmetricallySecureReference<>(
					data,
					secureRandom,
					keySize,
					algorithm,
					provider,
					cipher
			);
		}
	}

	private ReferenceFactory(@NotNull SecureRandom secureRandom, int keySize, @Nullable String provider, @NotNull Cipher cipher) {
		this.secureRandom = secureRandom;
		this.keySize = keySize;
		this.provider = provider;
		this.cipher = cipher;
	}

	private ReferenceFactory(@NotNull SecureRandom secureRandom, @NotNull AlgorithmParameterSpec spec, @Nullable String provider, @NotNull Cipher cipher) {
		this.secureRandom = secureRandom;
		this.spec = spec;
		this.provider = provider;
		this.cipher = cipher;
	}

}

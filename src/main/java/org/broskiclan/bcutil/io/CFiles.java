package org.broskiclan.bcutil.io;

import lombok.SneakyThrows;
import org.apache.commons.lang3.ArrayUtils;
import org.broskiclan.bcutil.digest.ObjectHashes;
import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Cryptographic file operations for encryption, decryption,
 * checksums, etc. <b>All methods in this class
 * are thread-safe.</b>
 */
@SuppressWarnings("unused")
public class CFiles {

	private CFiles() {}

	/**
	 * Utility method for checking whether file is under 2 GB.
	 */
	private static boolean isFileUnder2GB(@NotNull Path path) throws IOException {
		if(path.toFile().isDirectory()) throw new FileSystemException("Given path is a directory");
		return Files.size(path) * 0.000000001D < 2000000000L;
	}

	/**
	 * Overwrites the given file represented by the {@link Path} object.
	 * @param path The path to overwrite the file contents of.
	 * @param key The key to encrypt the file with.
	 * @param cipher An initialized cipher to encrypt the file.
	 * @throws IOException if an I/O error occurs
	 * @throws FileNotFoundException if the file represented by the path does not exist
	 */
	@SneakyThrows({IllegalBlockSizeException.class, BadPaddingException.class})
	public static void encrypt(@NotNull Path path, @NotNull Key key, @NotNull Cipher cipher) throws IOException {
		if(path.toFile().isDirectory()) throw new FileSystemException("Given path is a directory");
		// do not cause an OutOfMemoryError //////////////
		//    file size     ||    to gb    ||    2gb
		byte[] raw;
		if(isFileUnder2GB(path)) {
			raw = Files.readAllBytes(path);
			if(raw.length <= 0) return;
			Files.write(path, cipher.doFinal(raw));
		} else {
			try(
					FileChannel rChannel = new FileInputStream(path.toFile()).getChannel();
					FileChannel wChannel = new FileOutputStream(path.toFile()).getChannel()
			) {
				byte[] toEncrypt = null;
				var bf = ByteBuffer.allocateDirect(1500); // allocate small amount first: reset later
				while(rChannel.read(bf) < 1) {
					if(!bf.hasArray()) throw new AssertionError();
					if(toEncrypt == null) toEncrypt = bf.array();
					else toEncrypt = ArrayUtils.addAll(toEncrypt, bf.array());
					bf.clear();
				}
				if(toEncrypt == null) return;
				wChannel.write(ByteBuffer.wrap(cipher.doFinal(toEncrypt)));
			}
		}
	}

	/**
	 * Decrypts the contents of the given file represented by the {@link Path} object.
	 * @param path The path to read from.
	 * @param key The key to decrypt the file with.
	 * @param cipher An initialized cipher to decrypt the file.
	 * @throws IOException if an I/O error occurs
	 * @throws FileNotFoundException if the file represented by the path does not exist
	 */
	public static byte[] decrypt(@NotNull Path path, @NotNull Key key, @NotNull Cipher cipher) throws IOException {
		return decrypt(path, key, cipher, false);
	}

	/**
	 * Decrypts the contents of the given file represented by the {@link Path} object.
	 * @param path The path to read from.
	 * @param key The key to decrypt the file with.
	 * @param cipher An initialized cipher to decrypt the file.
	 * @param rewriteFile whether the given file should be overwritten with the new contents.
	 * @throws IOException if an I/O error occurs
	 * @throws FileNotFoundException if the file represented by the path does not exist
	 */
	@SneakyThrows({IllegalBlockSizeException.class, BadPaddingException.class})
	public static byte[] decrypt(@NotNull Path path, @NotNull Key key, @NotNull Cipher cipher, boolean rewriteFile) throws IOException {
		if(path.toFile().isDirectory()) throw new FileSystemException("Given path is a directory");
		// do not cause an OutOfMemoryError //////////////
		//    file size     ||    to gb    ||    2gb
		byte[] raw;
		if(isFileUnder2GB(path)) {
			raw = Files.readAllBytes(path);
			if(raw.length <= 0) return null;
			var res = cipher.doFinal(raw);
			if(rewriteFile) Files.write(path, res);
			return res;
		} else {
			try(
					FileChannel rChannel = new FileInputStream(path.toFile()).getChannel();
					FileChannel wChannel = new FileOutputStream(path.toFile()).getChannel()
			) {
				raw = null;
				var bf = ByteBuffer.allocateDirect(1500); // allocate small amount first: reset later
				while(rChannel.read(bf) < 1) {
					if(!bf.hasArray()) throw new AssertionError();
					if(raw == null) raw = bf.array();
					else raw = ArrayUtils.addAll(raw, bf.array());
					bf.clear();
				}
				if(raw == null) return null;
				var res = cipher.doFinal(raw);
				if(rewriteFile) wChannel.write(ByteBuffer.wrap(res));
				return res;
			}
		}
	}

	/**
	 * Calculates the checksum of the given path.
	 * If the given path is a directory, the content calculation will be based on
	 * the files of the directory.
	 * @param path The path to calculate checksums from.
	 * @return the calculated checksum.
	 * @throws IOException if an I/O error occurs.
	 */
	@SneakyThrows(NoSuchAlgorithmException.class)
	public static byte[] getChecksum(@NotNull Path path) throws IOException {
		return getChecksum(path, MessageDigest.getInstance("SHA3-256"), ChecksumPolicy.CONTENTS);
	}

	/**
	 * Calculates the checksum of the given path based on the given {@link ChecksumPolicy}.
	 * If the given path is a directory, the content calculation will be based on
	 * the files of the directory.
	 * @param path The path to calculate checksums from.
	 * @param policy The policy on how checksums should be calculated.
	 * @return the calculated checksum.
	 * @throws IOException if an I/O error occurs.
	 */
	@SneakyThrows(NoSuchAlgorithmException.class)
	public static byte[] getChecksum(@NotNull Path path, @NotNull ChecksumPolicy policy) throws IOException {
		return getChecksum(path, MessageDigest.getInstance("SHA3-256"), policy);
	}

	/**
	 * Calculates the checksum of the given path.
	 * If the given path is a directory, the content calculation will be based on
	 * the files of the directory.
	 * @param path The path to calculate checksums from.
	 * @param algorithm The {@link MessageDigest} algorithm to use.
	 * @return the calculated checksum.
	 * @throws IOException if an I/O error occurs.
	 */
	public static byte[] getChecksum(@NotNull Path path, String algorithm) throws IOException, NoSuchAlgorithmException {
		return getChecksum(path, MessageDigest.getInstance(algorithm), ChecksumPolicy.CONTENTS);
	}

	/**
	 * Calculates the checksum of the given path based on the given {@link ChecksumPolicy}.
	 * If the given path is a directory, the content calculation will be based on
	 * the files of the directory.
	 * @param path The path to calculate checksums from.
	 * @param algorithm The {@link MessageDigest} algorithm to use.
	 * @param policy The policy on how checksums should be calculated.
	 * @return the calculated checksum.
	 * @throws IOException if an I/O error occurs.
	 */
	public static byte[] getChecksum(@NotNull Path path, String algorithm, @NotNull ChecksumPolicy policy) throws IOException, NoSuchAlgorithmException {
		return getChecksum(path, MessageDigest.getInstance(algorithm), policy);
	}

	/**
	 * Calculates the checksum of the given path.
	 * If the given path is a directory, the content calculation will be based on
	 * the files of the directory.
	 * @param path The path to calculate checksums from.
	 * @param digest The {@link MessageDigest} to use.
	 * @return the calculated checksum.
	 * @throws IOException if an I/O error occurs.
	 */
	public static byte[] getChecksum(@NotNull Path path, @NotNull MessageDigest digest) throws IOException {
		return getChecksum(path, digest, ChecksumPolicy.CONTENTS);
	}

	/**
	 * Calculates the checksum of the given path based on the given {@link ChecksumPolicy}.
	 * If the given path is a directory, the content calculation will be based on
	 * the files of the directory.
	 * @param path The path to calculate checksums from.
	 * @param digest The {@link MessageDigest} to use.
	 * @param policy The policy on how checksums should be calculated.
	 * @return the calculated checksum.
	 * @throws IOException if an I/O error occurs.
	 */
	public static byte[] getChecksum(@NotNull Path path, @NotNull MessageDigest digest, @NotNull ChecksumPolicy policy) throws IOException {
		return getChecksum(path, digest, policy, false);
	}

	/**
	 * Calculates the checksum of the given path based on the given {@link ChecksumPolicy}.
	 * If the given path is a directory, the content calculation will be based on
	 * the files of the directory.
	 * @param path The path to calculate checksums from.
	 * @param digest The {@link MessageDigest} to use.
	 * @param policy The policy on how checksums should be calculated.
	 * @param recursive whether the checksum should be recursively calculated. Applies only if
	 *                  the given path represents a directory.
	 * @return the calculated checksum.
	 * @throws IOException if an I/O error occurs.
	 */
	public static byte[] getChecksum(@NotNull Path path, @NotNull MessageDigest digest, @NotNull ChecksumPolicy policy, boolean recursive) throws IOException {
		byte[] internal = null;
		if(policy == ChecksumPolicy.LOCATION || policy ==  ChecksumPolicy.CONTENTS_AND_LOCATION) {
			internal = ObjectHashes.getInstance(digest).ofSerializable(path.toUri());
		}
		if((policy == ChecksumPolicy.CONTENTS || policy ==  ChecksumPolicy.CONTENTS_AND_LOCATION) && !path.toFile().isDirectory()) {
			byte[] raw;
			if(isFileUnder2GB(path)) {
				raw = Files.readAllBytes(path);
			} else {
				try(
						FileChannel rChannel = new FileInputStream(path.toFile()).getChannel()
				) {
					raw = null;
					var bf = ByteBuffer.allocateDirect(1500); // allocate small amount first: reset later
					while(rChannel.read(bf) < 1) {
						if(!bf.hasArray()) throw new AssertionError();
						if(raw == null) raw = bf.array();
						else raw = ArrayUtils.addAll(raw, bf.array());
						bf.clear();
					}
				}
			}
			if(raw != null) if(internal == null) internal = ObjectHashes.getInstance().ofSerializable(raw);
			else 								 internal = ArrayUtils.addAll(internal, ObjectHashes.getInstance().ofSerializable(raw));
		} else if(policy == ChecksumPolicy.CONTENTS || policy ==  ChecksumPolicy.CONTENTS_AND_LOCATION) {
			byte[] raw = null;
			var files = path.toFile().listFiles();
			assert files != null;
			for(File f : files) {
				if(recursive) {
					if(internal != null) internal = ArrayUtils.addAll(internal, getChecksum(f.toPath(), digest, policy, true));
					else internal = getChecksum(f.toPath(), digest, policy, true);
				} else {
					if(internal != null) internal = ArrayUtils.addAll(internal, f.toPath().toUri().toString().getBytes(StandardCharsets.ISO_8859_1));
					else internal = f.toPath().toUri().toString().getBytes(StandardCharsets.ISO_8859_1);
				}
			}
		}
		return digest.digest(internal);
	}

	/**
	 * What a checksum method in this file should return.
	 */
	public enum ChecksumPolicy {
		/**
		 * The checksums of both the location and
		 * contents should be returned.
		 */
		CONTENTS_AND_LOCATION,
		/**
		 * The checksums of only the
		 * contents should be returned.
		 */
		CONTENTS,
		/**
		 * The checksums of only the
		 * location should be returned.
		 */
		LOCATION
	}

}

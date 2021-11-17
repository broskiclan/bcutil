package tests.broskiclan.bcutil;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;
import org.broskiclan.bcutil.io.CFiles;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class IOTests {

	private File file;

	@Before
	@SneakyThrows
	public void setup() {
		this.file = new File("test.txt");
		Files.write(file.toPath(), Arrays.asList(
				"hello world. lorem ipsum uwu lol",
				"pls no ioException",
				"now some totally gibberish stuff here:",
				"0xfduewjdewjdoijaskifduei9239jdkojokjd0i23ujdi23joidjek",
				"32hsaijidu389quwsdjcdjsakjdkok03qu0isjdksnakowjdi9uwqd",
				"fh4ew9udjkdkwplksioewuauiojckjepokfopsaidoiufoiewjjaisydf",
				"ewihoijdeiowjdfioewjdioewjdiouewiofjuihfiudcsdhewuidehwiudh",
				"fhewiuhdijasghiueu7fdhjsncja9udeijdioweuiduojasijfeu3udfoih",
				"fhewiudxehfuwhdiuhweuifhewiojdewiuhduehwudgudviklpsxkjsakjd",
				"0xfduewjdewjdoijaskifduei9239jdkojokjd0i23ujdi23joidjek",
				"32hsaijidu389quwsdjcdjsakjdkok03qu0isjdksnakowjdi9uwqd",
				"fh4ew9udjkdkwplksioewuauiojckjepokfopsaidoiufoiewjjaisydf",
				"ewihoijdeiowjdfioewjdioewjdiouewiofjuihfiudcsdhewuidehwiudh",
				"fhewiuhdijasghiueu7fdhjsncja9udeijdioweuiduojasijfeu3udfoih",
				"fhewiudxehfuwhdiuhweuifhewiojdewiuhduehwudgudviklpsxkjsakjd",
				"0xfduewjdewjdoijaskifduei9239jdkojokjd0i23ujdi23joidjek",
				"32hsaijidu389quwsdjcdjsakjdkok03qu0isjdksnakowjdi9uwqd",
				"fh4ew9udjkdkwplksioewuauiojckjepokfopsaidoiufoiewjjaisydf",
				"ewihoijdeiowjdfioewjdioewjdiouewiofjuihfiudcsdhewuidehwiudh",
				"fhewiuhdijasghiueu7fdhjsncja9udeijdioweuiduojasijfeu3udfoih",
				"fhewiudxehfuwhdiuhweuifhewiojdewiuhduehwudgudviklpsxkjsakjd",
				"0xfduewjdewjdoijaskifduei9239jdkojokjd0i23ujdi23joidjek",
				"32hsaijidu389quwsdjcdjsakjdkok03qu0isjdksnakowjdi9uwqd",
				"fh4ew9udjkdkwplksioewuauiojckjepokfopsaidoiufoiewjjaisydf",
				"ewihoijdeiowjdfioewjdioewjdiouewiofjuihfiudcsdhewuidehwiudh",
				"fhewiuhdijasghiueu7fdhjsncja9udeijdioweuiduojasijfeu3udfoih",
				"fhewiudxehfuwhdiuhweuifhewiojdewiuhduehwudgudviklpsxkjsakjd"
		));
	}

	@Test
	@SneakyThrows
	public void file_encryption_and_decryption() {
		var k = KeyGenerator.getInstance("AES");
		k.init(256);
		SecretKey key = k.generateKey();
		var ci = Cipher.getInstance("AES/GCM/NoPadding");
		byte[] iv = new byte[64];
		new SecureRandom().nextBytes(iv);
		ci.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
		System.out.println("PRINTING FILE CONTENTS =========================================================================================================================================================================\n" +
				new String(Files.readAllBytes(file.toPath())) +
						   "================================================================================================================================================================================================");
		System.out.println("ENCRYPTING...");
		CFiles.encrypt(file.toPath(), key, ci);
		System.out.println("PRINTING FILE CONTENTS (HEX) (ISO-8859-1) ===========================================================================================================================================================================================================\n" +
				new String(new Hex(StandardCharsets.ISO_8859_1).encode(Files.readAllBytes(file.toPath())), StandardCharsets.ISO_8859_1) +
				"\n=============================================================================================================================================================================================================================================================");
		System.out.println("DECRYPTING...");
		ci.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
		byte[] bytes = CFiles.decrypt(file.toPath(), key, ci);
		System.out.println("PRINTING FILE CONTENTS =========================================================================================================================================================================\n" +
				new String(bytes) +
				"================================================================================================================================================================================================");
	}

	@Test
	@SneakyThrows
	public void file_checksums() {
		System.out.println("Finding checksum of test.txt...");
		System.out.println("CHECKSUM: " + new String(
				new Hex(StandardCharsets.ISO_8859_1).encode(CFiles.getChecksum(Paths.get("test.txt"))),
				StandardCharsets.ISO_8859_1
		));
		System.out.println("=================================================================================================");
		System.out.println("Finding checksum of ./target... (fixed)");
		System.out.println("CHECKSUM: " + new String(
				new Hex(StandardCharsets.ISO_8859_1).encode(CFiles.getChecksum(Paths.get("target/"), MessageDigest.getInstance("SHA3-512"), CFiles.ChecksumPolicy.CONTENTS_AND_LOCATION, false)),
				StandardCharsets.ISO_8859_1
		));
		System.out.println("=================================================================================================");
		System.out.println("Finding checksum of ./target... (recursive)");
		System.out.println("CHECKSUM: " + new String(
				new Hex(StandardCharsets.ISO_8859_1).encode(CFiles.getChecksum(Paths.get("target/"), MessageDigest.getInstance("SHA3-512"), CFiles.ChecksumPolicy.CONTENTS_AND_LOCATION, true)),
				StandardCharsets.ISO_8859_1
		));
	}

	@After
	@SneakyThrows
	public void cleanup() {
		Files.delete(Paths.get("test.txt"));
	}

}
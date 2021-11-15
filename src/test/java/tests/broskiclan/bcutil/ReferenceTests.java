package tests.broskiclan.bcutil;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.broskiclan.bcutil.ref.AsymmetricallySecureReference;
import org.broskiclan.bcutil.ref.SecureReference;
import org.broskiclan.bcutil.ref.SymmetricallySecureReference;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.InvalidObjectException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

public class ReferenceTests {

	//=================================================================
	// REGISTRATION OF BouncyCastle PROVIDER
	//=================================================================

	@Before
	public void setup() {
		Security.addProvider(new BouncyCastleProvider());
	}

	//=================================================================
	// SYMMETRIC REFERENCE TESTS | ALGORITHM -> AES
	//=================================================================

	@SneakyThrows
	@Test
	public void round_trip_symmetric_storage() {
		System.out.println("String to store: " + "\"testString\"");
		@SuppressWarnings("scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUsestrongsymmetriccryptographicalgorithm")
		SecureReference<String> secureReference = new SymmetricallySecureReference<>("testString", new SecureRandom(), 256, "AES", null, Cipher.getInstance("AES"));
		System.out.println("Created symmetric SecureReference with algorithm AES and cipher AES");
		var k = secureReference.encrypt();
		String kString = new String(new Hex(StandardCharsets.ISO_8859_1).encode(k.getEncoded()), StandardCharsets.ISO_8859_1);
		System.out.println("Encrypted symmetric SecureReference and got key " + kString + "\n");
		System.out.println("Printing hex-encoded bytes of encrypted object ====================================================");
		System.out.println("HEX: " + new String(new Hex(StandardCharsets.ISO_8859_1).encode(secureReference.getRawData()), StandardCharsets.ISO_8859_1));
		System.out.println("===================================================================================================");
		System.out.println("Decrypting using key " + kString);
		System.out.println("===================================================================================================");
		var ref = secureReference.get(k);
		System.out.println("RESULT: " + ref);
		System.out.println("MATCHES: " + ref.equals("testString"));
		System.out.println("===================================================================================================");
	}

	@SneakyThrows
	@Test
	public void round_trip_symmetric_storage_invalid_key() {
		System.out.println("String to store: " + "\"testString\"");
		@SuppressWarnings("scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUsestrongsymmetriccryptographicalgorithm")
		SecureReference<String> secureReference = new SymmetricallySecureReference<>("testString", new SecureRandom(), 256, "AES", null, Cipher.getInstance("AES"));
		System.out.println("Created symmetric SecureReference with algorithm AES and cipher AES");
		secureReference.encrypt();
		var gen = KeyGenerator.getInstance("AES");
		gen.init(256, new SecureRandom());
		var k = gen.generateKey();
		String kString = new String(new Hex(StandardCharsets.ISO_8859_1).encode(k.getEncoded()), StandardCharsets.ISO_8859_1);
		System.out.println("Encrypted symmetric SecureReference and got key " + kString + "\n");
		System.out.println("Printing hex-encoded bytes of encrypted object ====================================================");
		System.out.println("HEX: " + new String(new Hex(StandardCharsets.ISO_8859_1).encode(secureReference.getRawData()), StandardCharsets.ISO_8859_1));
		System.out.println("===================================================================================================");
		System.out.println("Decrypting using invalid key " + kString);
		System.out.println("===================================================================================================");
		try {
			var ref = secureReference.get(k);
			System.out.println("RESULT: " + ref);
			System.out.println("MATCHES: " + ref.equals("testString"));
		} catch(InvalidObjectException e) {
			System.out.println("Exception thrown of type InvalidObjectException\n" +
					"Expected exception thrown, test is fulfilled");
		}
		System.out.println("===================================================================================================");
	}

	//=================================================================
	// ASYMMETRIC REFERENCE TESTS | ALGORITHM -> EC
	//=================================================================

	@SneakyThrows
	@Test
	public void round_trip_asymmetric_storage() {
		System.out.println("String to store: " + "\"testString\"");
		SecureReference<String> secureReference = new AsymmetricallySecureReference<>("testString", new SecureRandom(), 2048, "RSA", null, Cipher.getInstance("RSA/ECB/OAEPWithSHA3-256AndMGF1Padding"));
		System.out.println("Created symmetric SecureReference with algorithm RSA and cipher RSA/ECB/OAEPWithSHA3-256AndMGF1Padding");
		var k = secureReference.encrypt();
		String kString = new String(new Hex(StandardCharsets.ISO_8859_1).encode(k.getEncoded()), StandardCharsets.ISO_8859_1);
		System.out.println("Encrypted symmetric SecureReference and got key " + kString + "\n");
		System.out.println("Printing hex-encoded bytes of encrypted object ====================================================");
		System.out.println("HEX: " + new String(new Hex(StandardCharsets.ISO_8859_1).encode(secureReference.getRawData()), StandardCharsets.ISO_8859_1));
		System.out.println("===================================================================================================");
		System.out.println("Decrypting using key " + kString);
		System.out.println("===================================================================================================");
		var ref = secureReference.get(k);
		System.out.println("RESULT: " + ref);
		System.out.println("MATCHES: " + ref.equals("testString"));
		System.out.println("===================================================================================================");
	}

	@SneakyThrows
	@Test
	public void round_trip_asymmetric_storage_invalid_key() {
		try {
			System.out.println("String to store: " + "\"testString\"");
			SecureReference<String> secureReference = new AsymmetricallySecureReference<>("testString", new SecureRandom(), 2048, "RSA", null, Cipher.getInstance("RSA/ECB/OAEPWithSHA3-256AndMGF1Padding"));
			System.out.println("Created symmetric SecureReference with algorithm RSA and cipher RSA/ECB/OAEPWithSHA3-256AndMGF1Padding");
			var k = secureReference.encrypt();
			String kString = new String(new Hex(StandardCharsets.ISO_8859_1).encode(k.getEncoded()), StandardCharsets.ISO_8859_1);
			System.out.println("Encrypted symmetric SecureReference and got key " + kString + "\n");
			System.out.println("Printing hex-encoded bytes of encrypted object ====================================================");
			System.out.println("HEX: " + new String(new Hex(StandardCharsets.ISO_8859_1).encode(secureReference.getRawData()), StandardCharsets.ISO_8859_1));
			KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
			instance.initialize(2048, new SecureRandom());
			k = instance.generateKeyPair().getPrivate();
			kString = new String(new Hex(StandardCharsets.ISO_8859_1).encode(k.getEncoded()), StandardCharsets.ISO_8859_1);
			System.out.println("===================================================================================================");
			System.out.println("Decrypting using key " + kString);
			System.out.println("===================================================================================================");
			var ref = secureReference.get(k);
			throw new AssertionError();
		} catch(InvalidObjectException invalidObjectException) {
			System.out.println("Test success");
		}
	}

}

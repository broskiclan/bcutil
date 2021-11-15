package tests.broskiclan.bcutil;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;
import org.broskiclan.bcutil.ref.SecureReference;
import org.broskiclan.bcutil.ref.SymmetricallySecureReference;
import org.junit.Test;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class ReferenceTests {

	//=================================================================
	// SYMMETRIC REFERENCE TESTS
	//=================================================================

	@SneakyThrows
	@Test
	public void round_trip_symmetric_storage() {
		System.out.println("String to store: " + "\"testString\"");
		@SuppressWarnings("scwbasic-protection-set_DataProtection-CryptographyAvoidcryptographicweaknessUsestrongsymmetriccryptographicalgorithm")
		SecureReference<String> secureReference = new SymmetricallySecureReference<>("testString", new SecureRandom(), 256, "AES", Cipher.getInstance("AES"));
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

}

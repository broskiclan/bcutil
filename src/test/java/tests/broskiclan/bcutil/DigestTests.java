package tests.broskiclan.bcutil;

import org.apache.commons.codec.binary.Hex;
import org.broskiclan.bcutil.digest.ObjectHashes;
import org.broskiclan.bcutil.digest.Salts;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

public class DigestTests {

	private static String hex(Hex hex, byte[] bytes) {
		return new String(hex.encode(bytes), StandardCharsets.ISO_8859_1);
	}

	@Test
	public void generateSalts() {
		var hex = new Hex(StandardCharsets.ISO_8859_1);
		System.out.println("====================================================================================================================================================================");
		System.out.println("       GENERATING SALTS       | CHARSET: ISO-8859-1");
		System.out.println("====================================================================================================================================================================");
		System.out.println("(java.awt) MouseInfo Salt     | HEX: " + hex(hex, Salts.ofMousePosition(64)));
		System.out.println("(PROVIDED) SecureRandom Salt  | HEX: " + hex(hex, Salts.ofSecureRandom(new SecureRandom(), 64)));
		System.out.println(" (PASSED)  SecureRandom Salt  | HEX: " + hex(hex, Salts.ofSecureRandom(64)));
		System.out.println("====================================================================================================================================================================");
	}

	@Test
	public void getObjectHashes() {
		var hex = new Hex(StandardCharsets.ISO_8859_1);
		var objectHashes = ObjectHashes.getInstance();
		System.out.println("====================================================================================================================================================================");
		System.out.println("      GENERATING HASHES       | CHARSET: ISO-8859-1");
		System.out.println("====================================================================================================================================================================");
		System.out.println("java.lang.Object  (IDENTITY)  | HEX: " + hex(hex, objectHashes.ofIdentity(new Object())));
		System.out.println("java.lang.String  (IDENTITY)  | HEX: " + hex(hex, objectHashes.ofIdentity("nothingHereMatters")));
		System.out.println("java.lang.String   (OBJECT)   | HEX: " + hex(hex, objectHashes.ofObject("nothingHereMatters")));
		System.out.println("java.lang.String (SERIALIZED) | HEX: " + hex(hex, objectHashes.ofSerializable("nothingHereMatters")));
		System.out.println("====================================================================================================================================================================");
	}

	@SuppressWarnings("EqualsWithItself")
	@Test
	public void compareSemanticObjectHashes() {
		var objectHashes = ObjectHashes.getInstance();
		System.out.println("====================================================================================================================================================================");
		System.out.println("                             COMPARING HASHES                             | CHARSET: ISO-8859-1 | PROCEDURE: ofObject()");
		System.out.println("====================================================================================================================================================================");
		System.out.println("Arrays.equals(objectHashes.ofObject(\"yes\"), objectHashes.ofObject(\"yes\")) | RESULT: " +
				Arrays.equals(objectHashes.ofObject("yes"), objectHashes.ofObject("yes"))
		);
		System.out.println("Arrays.equals(objectHashes.ofObject(\"yay\"), objectHashes.ofObject(\"nay\")) | RESULT: " +
				Arrays.equals(objectHashes.ofObject("yay"), objectHashes.ofObject("nay"))
		);
		System.out.println("====================================================================================================================================================================");
	}

}

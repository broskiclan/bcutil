package tests.broskiclan.bcutil;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.broskiclan.bcutil.auth.Credentials;
import org.broskiclan.bcutil.auth.Identity;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

public class AuthenticationTests {

	private static final Hex hex = new Hex(StandardCharsets.ISO_8859_1);

	@Before
	public void setup() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@SneakyThrows
	@Test
	public void sign_and_verify_identity() {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		keyPairGenerator.initialize(2048);
		Credentials credentials = new Credentials(
				MessageDigest.getInstance("SHA3-512"),
				keyPairGenerator,
				Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
				"testInstance"
		);
		Cipher.getInstance("AES/GCM/NoPadding");
		Identity identity = new Identity(
				"RSA",
				2048,
				new SecureRandom(),
				BouncyCastleProvider.PROVIDER_NAME,
				Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
				credentials
		);
		System.out.println("IDENTITY CREATED ==========================================================================================================");
		System.out.println("Signing message \"testString\"");
		byte[] signed = identity.sign("testString");
		System.out.println("MESSAGE SIGNED");
		System.out.println("===========================================================================================================================");
		System.out.println("HEX: " + new String(hex.encode(signed), StandardCharsets.ISO_8859_1));
		System.out.println("===========================================================================================================================");
		System.out.println("VERIFYING IDENTITY...");
		System.out.println("Identity verified: result " + Identity.verifyIdentity(signed, identity, null, null));
	}

	@SneakyThrows
	@Test
	public void sign_and_verify_identity_invalid() {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		keyPairGenerator.initialize(2048);
		Credentials credentials = new Credentials(
				MessageDigest.getInstance("SHA3-512"),
				keyPairGenerator,
				Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
				"testInstance"
		);
		Cipher.getInstance("AES/GCM/NoPadding");
		Identity identity = new Identity(
				"RSA",
				2048,
				new SecureRandom(),
				BouncyCastleProvider.PROVIDER_NAME,
				Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
				credentials
		);
		Credentials credentials2 = new Credentials(
				MessageDigest.getInstance("SHA3-512"),
				keyPairGenerator,
				Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
				"testInstance2"
		);
		Identity identity2 = new Identity(
				"RSA",
				2048,
				new SecureRandom(),
				BouncyCastleProvider.PROVIDER_NAME,
				Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
				credentials
		);
		System.out.println("IDENTITY CREATED ==========================================================================================================");
		System.out.println("Signing message \"testString\"");
		byte[] signed = identity.sign("testString");
		System.out.println("MESSAGE SIGNED");
		System.out.println("===========================================================================================================================");
		System.out.println("HEX: " + new String(hex.encode(signed), StandardCharsets.ISO_8859_1));
		System.out.println("===========================================================================================================================");
		System.out.println("VERIFYING IDENTITY...");
		System.out.println("Identity verified: result " + Identity.verifyIdentity(signed, identity2, null, null));
	}

}

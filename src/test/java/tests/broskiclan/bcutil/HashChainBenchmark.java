package tests.broskiclan.bcutil;

import lombok.SneakyThrows;
import org.apache.commons.lang3.time.StopWatch;
import org.broskiclan.bcutil.collections.HashChain;
import org.broskiclan.bcutil.collections.HashChainBlock;
import org.broskiclan.bcutil.collections.HashChains;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/*
	Classes to test benchmarking of BCUtil collections.
 */
public class HashChainBenchmark {

	private HashChain<Long> chain;

	@SneakyThrows
	@Before
	public void new_hash_chain_with_20K_random_longs() {
		var r = new Random();
		this.chain = new HashChain<Long>(MessageDigest.getInstance("SHA3-256")) {
			@Override
			public synchronized boolean validate() {
				int index = 0;
				var k = data;
				for(HashChainBlock o : data) {
					if(o != null) {
						if(!o.inheritsHashFromNullBlock()) { // ignore 2nd prevHash if it inherits a hash from a NullHashChainBlock.
							System.out.println("(" + index + ") GENESIS BLOCK | value " + o.getData());
							if(!o.getPrevHash2().equals(
									k[index - 2].getHash()
							)) return false;
						} else if(index != 0) {
							System.out.println("(" + index + ") ORDINARY BLOCK | value " + o.getData());
							if(!o.getPrevHash().equals(
									k[index - 1].getHash()
							)) return false;
						}
						System.out.println("HASH: " + o.getHash());
						System.out.println("==========================================================================================");
					}
					index++;
				}
				return true;
			}
		};
		for(int i = 1; i < 10000; i++) {
			chain.add(r.nextLong());
		}
	}

	@Test
	public void validate_hash_chain() {
		var s = new StopWatch();
		System.out.println("STARTING VALIDATION OF 10,000 BLOCKS\n");
		s.start();
		boolean b = chain.validate();
		s.stop();
		System.out.println("\n---- Result of " + b + " returned in validation ----\n" +
				"   Validation evaluated in " + s.getTime(TimeUnit.MILLISECONDS) + "ms " +
				"at " + LocalDateTime.now().format(DateTimeFormatter.ISO_DATE) + "\n" +
				"    Note that this is the approximate timing");
	}

	@SneakyThrows
	@Test
	public void store_and_read_hash_chain_in_file() {
		System.out.println("Storing HashChain in hashTest");
		var s = new StopWatch();
		s.start();
		HashChains.storeChain(chain, Paths.get("hashTest").toFile(), false);
		s.stop();
		var s2 = new StopWatch();
		s2.start();
		HashChain<Long> l = HashChains.readChain(Paths.get("hashTest").toFile());
		s2.stop();
		System.out.println("ELEMENTS FOUND: " + l.size());
		Thread.sleep(1000);
		System.out.println("----------------------------------------------------");
		for(HashChainBlock hashChainBlock : l.toBlockArray()) {
			System.out.println("HASH: " + hashChainBlock.getHash());
			System.out.println("DATA: " + hashChainBlock.getData());
			System.out.println(hashChainBlock.toJson());
			System.out.println("----------------------------------------------------");
		}
		System.out.println("Benchmarks completed ======================\n" +
				"Stored in " + s.getTime(TimeUnit.MILLISECONDS) + "ms" + "\n" +
				"Loaded in " + s2.getTime(TimeUnit.MILLISECONDS) + "ms");
	}

	public void cleanUp() {
		chain = null;
		System.gc();
	}

}

package org.broskiclan.bcutil.collections;

public interface IBlock {

	/**
	 * Retrieves the hash of the {@link IBlock} in a hexadecimal string.
	 * @return The hash in a hexadecimal string, such as <code>0x...</code>
	 */
	String getHash();


	/**
	 * Converts to a JSON string.
	 */
	String toString();


}

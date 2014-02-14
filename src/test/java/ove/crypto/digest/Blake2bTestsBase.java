/* !!! DOOST !!! */

/*
   A Java implementation of BLAKE2B cryptographic digest algorithm.

   Joubin Mohammad Houshyar <alphazero@sensesay.net>
   bushwick, nyc
   02-14-2014

   --

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

package ove.crypto.digest;

import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;

/** TODO document me */
abstract public class Blake2bTestsBase {

	@BeforeTest static public void initialize() {
		/* place holder to gen random ref data via blake2btest (from ref-impl) */
	}

	@AfterTest static public void cleanup() {
		/* place holder to gen random ref data via blake2btest (from ref-impl) */
	}

	/// data ///////////////////////////////////////////////////////////////////

	final protected byte[] getTestInputArray() {
		return Blake2BTestUtils.Reference.getKATInput();
	}

	/// Blake2b provider ///////////////////////////////////////////////////////

	/** extension point */
	abstract protected Blake2b newMessageDigest ();

}

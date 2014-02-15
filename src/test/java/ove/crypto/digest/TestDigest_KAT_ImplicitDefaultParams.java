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

/** TODO document me */
public class TestDigest_KAT_ImplicitDefaultParams extends TestDigestAbstractBase {

	/** create a Blake2b digest using explicit default params */
	@Override final protected Blake2b newMessageDigest() {
		return Blake2b.Digest.newInstance ();
	}
}

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

import org.testng.annotations.Test;
import static org.testng.Assert.*;

import static ove.test.Utils.*;

/**  */
@Test
public class TestParamAccessors {
	/** */
	public void digestLength () {
		logit (this, "digestLength");

		final Blake2b.Param p = new Blake2b.Param();

		final int max = Blake2b.Spec.max_digest_bytes;
		final int[] varr = random32BitValuesInclusive(1, max, 100);
		for (final int v : varr) {
			p.setDigestLength(v);
			assertEquals (v, p.getDigestLength(), eqFail("DigestLength"));
		}
	}
	/** */
	public void fanout () {
		logit (this, "fanout");

		final Blake2b.Param p = new Blake2b.Param();

		final int max = Blake2b.Spec.max_tree_fantout;
		final int[] varr = random32BitValuesInclusive(1, max, 100);

		for (final int v : varr) {
			p.setFanout(v);
			assertEquals ((byte) v, (byte) p.getFanout(), eqFail("fanout"));
		}
	}
	/** */
	public void depth () {
		logit (this, "depth");

		final Blake2b.Param p = new Blake2b.Param();

		final int max = Blake2b.Spec.max_tree_depth;
		final int[] varr = random32BitValuesInclusive(1, max, 100);

		for (final int v : varr) {
			p.setDepth(v);
			assertEquals ((byte) v, (byte) p.getDepth(), eqFail("depth"));
		}
	}
	/** */
	public void leafLength () {
		logit (this, "leafLength");

		final Blake2b.Param p = new Blake2b.Param();

		final int max = Blake2b.Spec.max_tree_depth;
		final int[] varr = random32BitValuesInclusive(1, max, 100);

		for (final int v : varr) {
			p.setLeafLength(v);
			assertEquals (v, p.getLeafLength(), eqFail("leafLength"));
		}
	}
}

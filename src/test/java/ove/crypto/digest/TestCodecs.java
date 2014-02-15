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

import static org.testng.Assert.assertEquals;
import static ove.test.Utils.*;

public class TestCodecs {
	final byte[] b32 = new byte [ 4 ];
	final byte[] b64 = new byte [ 8 ];
	/** */
	@Test public void testReadWriteInt () {
		logit(this, "testReadWriteInt");

		int[] varr = random32BitValuesInclusive(0, Integer.MAX_VALUE, 10000);
		for (final int v : varr ) {
			Blake2b.Engine.LittleEndian.writeInt (v, b32, 0);
			final int v0 = Blake2b.Engine.LittleEndian.readInt (b32, 0);
			assertEquals (v, v0, eqFail("readInt"));
		}
	}
	/** */
	@Test public void testReadWriteLong () {
		logit(this, "testReadWriteLong");

		long[] varr = random64BitValuesInclusive (10000);
		for (final long v : varr ) {
			Blake2b.Engine.LittleEndian.writeLong (v, b64, 0);
			final long v0 = Blake2b.Engine.LittleEndian.readLong (b64, 0);
			assertEquals (v, v0, eqFail("readLong"));
		}
	}
}

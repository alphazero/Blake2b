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

import static ove.test.Utils.*;
import static ove.crypto.digest.Blake2BTestUtils.*;

@Test
public class TestClonedParam {

	@Test
	public void testDefault() {
		logit (this, "testDefault");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	@Test
	public void testSetDepth() {
		logit (this, "testSetDepth");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setDepth(7);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	static final byte[] theKey = "Love".getBytes();

	@Test
	public void testSetKey() {
		logit (this, "testSetKey");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setKey (theKey);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	@Test
	public void testSetDigestLength() {
		logit (this, "testSetDigestLength");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setDigestLength(32);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	static final byte[] personal = "Bees Eyes".getBytes();

	@Test
	public void testSetPersonal() {
		logit (this, "testSetPersonal");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setPersonal(personal);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	static final byte[] theSalt = "BeTimelyBeTrue".getBytes();

	@Test
	public void testSetSalt() {
		logit (this, "testSetSalt");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setSalt(theSalt);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	@Test
	public void testSetFanout() {
		logit (this, "testSetFanout");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setFanout(512);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	@Test
	public void testSetInnerLength() {
		logit (this, "testSetInnerLength");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setInnerLength(512);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	@Test
	public void testSetLeafLength() {
		logit (this, "testSetLeafLength");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setLeafLength(512);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	@Test
	public void testSetNodeDepth() {
		logit (this, "testSetNodeDepth");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setNodeDepth(512);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}

	@Test
	public void testSetNodeOffset() {
		logit (this, "testSetNodeOffset");
		final Blake2b.Param param = Blake2BTestUtils.newDefaultParam();
		param.setNodeOffset(512);

		final Blake2b.Param clone = param.clone();

		compare(param, clone);
	}
}

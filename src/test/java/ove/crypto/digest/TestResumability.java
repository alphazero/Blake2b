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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Random;
import org.testng.Assert;
import org.testng.annotations.Test;

import static ove.test.Utils.logit;

/** @author Tim Boudreau */
public class TestResumability {

	private final Random rnd = new Random(523);
	@Test
	public void testResumability() throws Throwable {
		logit (this, "Resumable Digest");

		final int arrayCount = 200;
		final int arrayLength = 61;
		byte[][] data = new byte[arrayCount][];

		for (int i = 0; i < arrayCount; i++) {
			data[i] = new byte[arrayLength];
			rnd.nextBytes(data[i]);
		}
		Blake2b.Param param = new Blake2b.Param().setDigestLength(40).setSalt(new byte[] { 23, 53, 123, -57, -79});
		Blake2b normal = Blake2b.Digest.newInstance (param);
		Blake2b paused = Blake2b.Digest.newInstance (param);

		for (int i = 0; i < arrayCount; i++) {
			normal.update(data[i]);
			paused.update(data[i]);
			if (i == arrayCount / 2) {
				Blake2b.ResumeHandle oldState = paused.state();
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				ObjectOutputStream oout = new ObjectOutputStream(out);
				try {
					oout.writeObject(oldState);
				} finally {
					oout.close();
				}
				ObjectInputStream oin = new ObjectInputStream(new ByteArrayInputStream(out.toByteArray()));
				try {
					paused = ((Blake2b.ResumeHandle)oin.readObject()).resume(param);
				} finally {
					oin.close();
				}
			}
		}

		byte[] a = normal.digest();
		byte[] b = paused.digest();
		Assert.assertEquals(a, b);
	}
}

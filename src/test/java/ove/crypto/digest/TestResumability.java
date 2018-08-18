/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package ove.crypto.digest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Random;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 *
 * @author Tim Boudreau
 */
public class TestResumability {

	private final Random rnd = new Random(523);
	@Test
	public void testResumability() throws Throwable {
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

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

import org.testng.Assert;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

/** TODO document me */
public class Blake2BTestUtils {

	static public final byte[] nilsalt 		= new byte[ Blake2b.Spec.max_salt_bytes ];
	static public final byte[] nilpersonal 	= new byte[ Blake2b.Spec.max_personalization_bytes ];

	public static final File referenceDataDir = new File("src/test/resources/reference-impl");
	public static final String blake2b_kat = "blake2b-kat.out";
	public static final String blake2b_key_kat = "blake2b-key-kat.out";

	public static Blake2b.Param newDefaultParam() {
		final Blake2b.Param config = new Blake2b.Param();
		config.
				setDigestLength( Blake2b.Param.Default.digest_length ).
				setFanout( Blake2b.Param.Default.fanout ).
				setDepth( Blake2b.Param.Default.fanout ).
				setLeafLength( Blake2b.Param.Default.leaf_length ).
				setNodeOffset( Blake2b.Param.Default.node_offset ).
				setInnerLength(Blake2b.Param.Default.inner_length).
				setSalt( Blake2BTestUtils.nilsalt ).
				setPersonal( Blake2BTestUtils.nilpersonal );
		return config;
	}

	public static byte[] loadKATData (final String fname) {
		byte[] refbytes = null;
		try {
			final File refOut = new File(referenceDataDir, fname);
			final DataInputStream in = new DataInputStream(new FileInputStream(refOut));
			refbytes = new byte[(int) refOut.length()];
			in.readFully(refbytes);
		} catch (Throwable e) {
			Assert.fail("failed to load reference data from file " + fname);
		}
		return refbytes;
	}

	public static class Reference {
		/** new key byte[] per blake2/ref/blake2b-ref.c */
		public static byte[] getKATKey() {
			final byte[] key = new byte [Blake2b.Spec.max_key_bytes];
			for(int i = 0; i < key.length; i++) {
				key[ i ] = (byte) i ;
			}
			return key;
		}

		/** new input byte[] buffer per blake2/ref/blake2b-ref.c */
		public static byte[] getKATInput () {
			// generate KAT equiv
			final byte[] data = new byte[255];
			for(int i = 0; i < data.length; i++) {
				data[i] = (byte) i;
			}
			return data;
		}
	}
}

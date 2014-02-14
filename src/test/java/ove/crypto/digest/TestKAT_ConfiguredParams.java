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

import static ove.crypto.digest.Blake2b.Param.*;
import static ove.crypto.digest.Blake2b.*;

/** TODO document me */
public class TestKAT_ConfiguredParams extends TestKAT {
	@Override final protected Blake2b newMessageDigest() {

		final byte[] refbytes = Param.default_bytes;

		final byte[] nilsalt 		= new byte[ Spec.max_salt_bytes ];
		final byte[] nilpersonal 	= new byte[ Spec.max_personalization_bytes ];

		final Blake2b.Param config = new Blake2b.Param();
		config.
				setDigestLength( Default.digest_length ).
				setFanout( Default.fanout ).
				setDepth( Default.fanout ).
				setLeafLength( Default.leaf_length ).
				setNodeOffset( Default.node_offset ).
				setInnerDepth( Default.inner_depth ).
				setSalt( nilsalt ).
				setPersonal( nilpersonal );

		final byte[] confbytes = config.getBytes();

		return Blake2b.Digest.newInstance (config);
	}
}

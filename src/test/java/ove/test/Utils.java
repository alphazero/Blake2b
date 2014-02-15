/* !!! Doost !!! */

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

package ove.test;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Random;

public class Utils {

	public static final Random deterministic = new Random (0);
	public static final Random random = new Random (System.nanoTime());

	private static final File testoutDir = new File("src/test/out/");

	public static int[] random32BitValuesInclusive(final int from, final int to, int cnt) {
		if(cnt < 2) cnt = 2;

		final int[] varr = new int [cnt];
		varr[0] = from;
		varr[1] = to;
		final int lim0 = to - from;
		for (int i=2; i<cnt; i++) {
			varr[i] = random.nextInt(lim0) + from;
		}
		return varr;
	}
	public static long[] random64BitValuesInclusive(int cnt) {
		final long[] varr = new long [cnt];
		varr[0] = 0x0L;
		varr[1] = 0xFFFFFFFFFFFFFFF7L;
		varr[2] = 0x0000000000000008L;
		for (int i=3; i<cnt; i++) {
			varr[i] = random.nextLong();
		}
		return varr;
	}
	public static void logit (final Object test, final String method) {
		System.out.format("[TEST] - %s.%s \n", test.getClass().getSimpleName(), method);
	}
	public static String eqFail (final String what) {
		return String.format("%ss differ", what);
	}
	public static File getTestOutputDir () {
		if(!testoutDir.exists()) {
			testoutDir.mkdirs();
		}
		return testoutDir;
	}
	public static File createTestoutFile (final boolean deleteOnExit) {
		final File testoutDir = getTestOutputDir();
		final File testout;
		try {
			testout = File.createTempFile("blake2b.java", "kat", testoutDir);
			if(deleteOnExit) {
				testout.deleteOnExit();
			}
		} catch (IOException e) {
			e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
			throw new Error("on create test tempout file", e);
		}
		return testout;
	}
	public static PrintStream getPrintStreamForFile (final File f) throws RuntimeException {
		final PrintStream out;
		try {
			out = new PrintStream(f);
		} catch (IOException e) {
			throw new RuntimeException ("on create test tempout file", e);
		}
		return out;
	}
	public static void dumpBuffer (final PrintStream out, final String label, final byte[] b) {
		dumpBuffer(out, label, b, 0, b.length);
	}
	public static void dumpBuffer (final PrintStream out, final byte[] b) {
		dumpBuffer(out, null, b, 0, b.length);
	}
	public static void dumpBuffer (final PrintStream out, final byte[] b, final int offset, final int len) {
		dumpBuffer(out, null, b, offset, len);
	}
	public static void dumpBuffer (final PrintStream out, final String label, final byte[] b, final int offset, final int len) {
		if(label != null)
			out.format ( "-- DUMP -- %s: \n", label );
		out.format("{\n    ", label);
		for( int j = 0; j < len ; ++j ) {
			out.format ("%02X", b[j + offset]);
			if(j+1 < len) {
				if ((j+1)%8==0) out.print("\n    ");
				else out.print(' ');
			}
		}
		out.format("\n}\n");
	}
}

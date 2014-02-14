/* !!! DOOST !!! */
package ove.test;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;

public class Utils {
	private static final File testoutDir = new File("src/test/out/");

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

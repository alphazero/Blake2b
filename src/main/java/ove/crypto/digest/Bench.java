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

package ove.crypto.digest;

import ove.alphazero.util.CmdLineArgs;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

// REVU: let's keep the jar minimal. (TODO) move to a child project.
public class Bench implements Runnable {

	interface Default {
		int iterations = 1000;
		int datalen = 1024;
		String digest = "blake2b";
	}

	static volatile boolean f_run = true;

	static class Usage {
		private static void explain (final String opt, final String details) {
			System.out.format("%3s\t%s\n", opt, details);
		}
		static int usage () {
			System.out.println("usage: java -cp .. ove.crypto.digest.Bench [options]");
			System.out.println("[options]");
			explain ("-d",  "digest to bench, one of {blake2, sha1, md5}. default: blake2b");
			explain ("-i",  "number of iterations (digest function calls) per bench round. default: 1000");
			explain ("-n",  "size of the digested buffer in bytes. default: 1024 b / call");

			return -1;
		}
	}
	public static void main(final String... args) throws Exception{
		if(args.length == 0) {
			System.exit(Usage.usage());
		}
		final CmdLineArgs clargs = CmdLineArgs.parse(null, args);
		try {
			String md_name  = null;
			int iters;
			int datalen;

			md_name = clargs.getOption("d", Default.digest);
			iters = clargs.getIntOption("i", Default.iterations);
			datalen = clargs.getIntOption("n", Default.datalen);

			final Bench bench = new Bench (md_name, iters, datalen);
			final Thread brth = new Thread(bench, "bench-runner");
			brth.start();
			System.in.read();
			f_run = false;
			brth.join();

		} catch (Throwable e) {
			System.exit(Usage.usage());
		}

	}

	private final String md_name;
	private final int iters;
	private final int datalen;
	private final byte[] b;
	private final Call call;

	Bench (final String md_name, final int iters, final int datalen) {
		this.md_name = md_name;
		this.iters = iters;
		this.datalen = datalen;
		this.b = new byte[datalen];
		for(int i=0; i<b.length; i++) {
			b[i] = (byte)i;
		}
		this.call = getBenchedCall();
	}

	private Call getBenchedCall() {

		Call call = null;
		if (md_name.equalsIgnoreCase("blake2b")) {
			call = newCallBlake2b();
		} else {
			call = newCallJCEAlgorithm(md_name);
		}
		return call;
	}
	private static final void puts(final String s) {
		System.out.format("%s\n", s);
	}
	@Override public void run () {
		puts ("Bench - hit any key to stop.");
		puts ("");
		puts ("digest   | iterations | size (b/iter) | dt (nsec/iter) | throughput (b/usec)");
		while (f_run) {
			final long start = System.nanoTime();
			for(int i=0; i<iters; i++)
				call.func(b);
			final long delta = System.nanoTime() - start;

			final long delta_us = TimeUnit.NANOSECONDS.toMicros(delta);
			final double thrpt = ((double) b.length * iters) / delta_us;
			System.out.format("%-8s | %10d | %13d | %14d |    %16.6f\r", md_name, iters, b.length, delta/iters
					, thrpt);
		}
	}
	interface Call {
		byte[] func(final byte[] b);
	}

	public static Call newCallBlake2b ()  {
		final Blake2b digest = Blake2b.Digest.newInstance (new Blake2b.Param().setDigestLength(20));
		return new Call() {
			@Override final public byte[] func(byte[] b) {
				digest.update(b, 0, b.length);
				return digest.digest();
			}
		};
	}

	public static Call newCallJCEAlgorithm (final String md_name) {
		final MessageDigest digest = silentGet (md_name);
		return new Call() {
			@Override final public byte[] func(byte[] b) {
				digest.update(b, 0, b.length);
				return digest.digest();
			}
		};
	}
	public static MessageDigest silentGet (final String mdname) {
		try {
			return MessageDigest.getInstance(mdname);
		} catch (Throwable e) {
			throw new Error (String.format("Error getting instance of digest <%s>", mdname), e);
		}
	}
}

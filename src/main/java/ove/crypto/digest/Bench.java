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
		int warmup = 3; // seconds
		String digest = "blake2b-512";
	}

	static volatile boolean f_run = true;

	static class Usage {
		private static void explain (final String opt, final String optfmt, Object ... args) {
			final String fmtstr = String.format("%3s\t%s\n", opt, optfmt);
			System.out.format(fmtstr, args);
		}
		static int usage () {
			System.out.println("usage: java -cp .. ove.crypto.digest.Bench [options]");
			System.out.println("[options]");
			explain ("-d",  "digest algorithm to bench - one of " +
					"{blake2-256, blake2-256, sha1, sha-256, sha-512, md5}. default: %s", Default.digest);
			explain ("-w",  "warm-up delay in seconds. default: %d seconds", Default.warmup);

			return -1;
		}
	}

	public static void main(final String... args) {
		final CmdLineArgs clargs = CmdLineArgs.parse(null, args);
		if (clargs.isUsage()) {
			System.exit(Usage.usage());
		}
		try {
			String algorithm = clargs.getOption("d", Default.digest);
			int warmup = clargs.getIntOption("w", Default.warmup);

			final Bench bench = new Bench (algorithm, warmup);
			final Thread brth = new Thread(bench, "bench-runner");
			brth.start();
			System.in.read();
			f_run = false;
			brth.join();

		} catch (Throwable e) {
			System.exit(Usage.usage());
		}
	}

	private final String algorithm;
	private final int warmup;
	private final Call call;

	Bench (final String algorithm, final int warmup) {
		this.algorithm = algorithm;
		this.warmup = warmup;
		this.call = getBenchedCall();
	}

	private Call getBenchedCall() {

		Call call = null;
		if (algorithm.equalsIgnoreCase("blake2b-512")) {
			call = newCallBlake2b(64);
		} else if (algorithm.equalsIgnoreCase("blake2b-256")) {
			call = newCallBlake2b(32);
		} else {
			call = newCallJCEAlgorithm(algorithm);
		}
		return call;
	}
	private static final void puts(final String s) {
		System.out.format("%s\n", s);
	}
	@Override public void run () {

		System.out.printf("warming up ...");
		final long t0 = System.currentTimeMillis();
		byte[] b0 = new byte[5000];
		while (TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - t0) < warmup) {
			call.func(b0);
		}
		System.out.printf("\r");
		b0 = null;
		System.gc();

		puts ("Bench - hit any key to stop. (use -h to list options)");
		puts ("");
		puts ("digest       | iterations | size (B/iter) | dt (nsec/iter) | throughput (MB/sec)");

		int size = 64;
		int maxruns = 20;

		while(size < 1 << 23) {
			final double[] throughputs = new double[maxruns];
			boolean adjusting = true;
			int iters0 = 1;
			byte[] b = new byte[size];
			int run = 0;
			while (f_run && run < maxruns) {
				final long start = System.nanoTime();
				for (int i = 0; i < iters0; i++)
					call.func(b);
				final long delta = System.nanoTime() - start;

				final long delta_us = TimeUnit.NANOSECONDS.toMicros(delta);
				final double throughput = ((double) b.length * iters0) / delta_us;
				if (!adjusting) {
					throughputs[run] = throughput;
					run++;
					System.out.format("%-12s | %10d | %13d | %14d |    %16.6f            \r",
							algorithm, iters0, b.length, delta / iters0, average(throughputs, run));
				} else {
					System.out.format("%-12s | %10d | %13d | %14d |    %16.6f [adjusting]\r",
							algorithm, iters0, b.length, delta / iters0, throughput);

				}

				// adjust iteration to get delta t in the second range (if necessary)
				if (adjusting) {
					if ((float) (TimeUnit.NANOSECONDS.toMillis(delta) / 1000.0) < 0.2) {
						iters0 <<= 1;
					} else {
						adjusting = false;
					}
				}
			}
			size <<= 1;
			if(f_run) System.out.println();
			b = null;
			System.gc();
		}
		System.exit(0);
	}
	final double average(double[] throughputs, int n) {
		double sum = 0.0;
		for(int i=0; i<n; i++) {
			sum += throughputs[i];
		}
		return sum / (double) n;
	}
	interface Call {
		byte[] func(final byte[] b);
	}

	public static Call newCallBlake2b (final int size)  {
		final Blake2b digest = Blake2b.Digest.newInstance (new Blake2b.Param().setDigestLength(size));
		return new Call() {
			@Override final public byte[] func(byte[] b) {
				digest.reset();
				digest.update(b, 0, b.length);
				return digest.digest();
			}
		};
	}

	public static Call newCallJCEAlgorithm (final String md_name) {
		final MessageDigest digest = silentGet (md_name);
		return new Call() {
			@Override final public byte[] func(byte[] b) {
				digest.reset();
				digest.update(b, 0, b.length);
				return digest.digest();
			}
		};
	}
	public static MessageDigest silentGet (final String mdname) {
		try {
			return MessageDigest.getInstance(mdname);
		} catch (Throwable e) {
			final Error fault = new Error (String.format("Error getting instance of digest <%s>", mdname), e);
			System.err.printf("%s\n", fault.toString());
			throw fault;
		}
	}
}

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

package ove.alphazero.util;

import java.util.HashMap;
import java.util.Map;

// REVU: (TODO) add general bounds checks and default support for -h/--help
public final class CmdLineArgs {
	static final String PREFIX_FLAG = "--";
	static final String PREFIX_OPT = "-";
	/** */
	public interface Spec { /* nop for now */}

	/** */
	final Map<String, String> map;
	final Spec spec;
	final boolean usage;
	/** */
	private CmdLineArgs (final Spec spec, final Map<String, String> map){
		assert map != null : "map is null";
		this.spec = spec;
		this.map = map;
		this.usage = false;
	}
	private CmdLineArgs (){
		this.spec = null;
		this.map = null;
		this.usage = true;
	}
	public boolean isUsage() { return usage; }
	/** */
	public boolean checkFlag(String f) {
		return map.containsKey(flagKey(f));
	}
	/** */
	public String getOption(String k, final String defval) {
		String v = map.get(optKey(k));
		if(v == null) {
			v = defval;
		}
		return v;
	}
	/** */
	public String getOptionStrict(String k) {
		return assertNotNull(map.get(optKey(k)), "must specify required option " + k);
	}
	/** */
	public int getIntOption(String k, int defval) {
		int res = defval;
		final String optv = getOption(k, null);
		if(optv != null) {
			res = decodeInt(optv, "invalid value for numeric option " + k);
		}
		return res;
	}
	/** */
	public String getparam(int n) {
		return map.get(paramKey(n));
	}
	private static String paramKey(final int n) { return String.format("$%d", n);}
	private static String flagKey(final String f) { return String.format("%s%s", PREFIX_FLAG, f);}
	private static String optKey(final String o) { return String.format("%s%s", PREFIX_OPT, o);}
	/** */
	public static CmdLineArgs parse(final Spec spec, String...args) {
		if(args == null) return null;
		if(args.length==1 && (args[0].equals("-h") || args[0].equals("--h"))) {
			return new CmdLineArgs();
		}

		final Map<String, String> map = new HashMap<String, String>();
		int fn = 0;
		int on = 0;
		int pn = 0;
		for(int i=0; i<args.length; i++) {
			String k = null;
			String v = null;
			if ( args[i] == null ) continue;
			if ( args[i].startsWith (PREFIX_FLAG) ) {
				k = args[i];
				v = k;
				fn++;
			} else if( args[i].startsWith ( PREFIX_OPT ) ) {
				assert0 (args.length-1 > i, String.format("no value for arg %s at args end", args[i]));
				assert0 (!args[i+1].startsWith(PREFIX_OPT), String.format("no value for arg %s", args[i]));
				assert0 (!args[i+1].startsWith(PREFIX_FLAG), String.format("no value for arg %s", args[i]));
				k = args[i];
				i++;
				v = args[i];
				on++;
			} else {
				pn++;
				k = paramKey(pn);
				v = args[i];
			}
			map.put(k, v);
		}
		return new CmdLineArgs(spec, map);
	}

	public static void assert0 (final boolean prop, final String errmsg) throws IllegalStateException{
		if (!prop) throw new IllegalStateException(errmsg);
	}
	public static <T> T assertNotNull (final T o, final String errmsg) throws IllegalStateException{
		if (o == null) throw new IllegalStateException(errmsg);
		return o;
	}
	public static int decodeInt(final String spec, final String errmsg) throws IllegalArgumentException {
		int v;
		try{
			v = Integer.parseInt(spec);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException(String.format(errmsg, spec));
		}
		return v;
	}
}

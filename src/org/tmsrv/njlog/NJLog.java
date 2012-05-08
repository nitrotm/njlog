package org.tmsrv.njlog;

import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.jar.*;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;


/**
 * Java byte-code calls stripper
 *
 * @author nitro
 */
public class NJLog {
	/**
	 * Entry-point
	 *
	 * @param args command-line arguments
	 */
	public static void main(String [] args) throws Exception {
		// parse args
		String configuration, src, dst;
		List<URL> paths = new ArrayList<URL>();
		boolean debug = false;
		int i = 0;

		if (args.length > i && args[i].equals("-debug")) {
			debug = true;
			i++;
		}
		while (args.length > i + 1 && args[i].equals("-cl")) {
			paths.add(new File(args[i + 1]).toURI().toURL());
			i += 2;
		}
		if (args.length != (i + 3)) {
			System.err.println("usage: NJLog [ -debug ] [ -cl path ] config.cfg source.class destination.class");
			System.err.println("       NJLog [ -debug ] [ -cl path ] config.cfg source.jar destination.jar");
			System.exit(1);
		}
		configuration = args[i++];
		src = args[i++];
		dst = args[i++];

		// build class loader
		ClassLoader cl = new URLClassLoader(paths.toArray(new URL[0]), NJLog.class.getClassLoader());

		// transform
		try {
			Transformer transformer = new Transformer(
				cl,
				loadConfiguration(configuration, debug)
			);

			transform(transformer, src, dst);
		} catch (Throwable t) {
			t.printStackTrace();
			System.exit(1);
		}
	}


	private static Rules loadConfiguration(String path, boolean debug) throws Exception {
		Rules rules = new Rules(debug);
		BufferedReader br = new BufferedReader(
			new FileReader(path)
		);
		String line;

		while ((line = br.readLine()) != null) {
			rules.parseLine(line);
		}
		br.close();

		return rules;
	}

	private static void transform(Transformer transformer, String src, String dst) throws Exception {
		if (src.indexOf(".class") > 0 && dst.indexOf(".class") > 0 && !src.equals(dst)) {
			transformFiles(transformer, src, dst);
		} else if (src.indexOf(".jar") > 0 && dst.indexOf(".jar") > 0 && !src.equals(dst)) {
			transformJars(transformer, src, dst);
		} else {
			throw new Exception("invalid source/destination : " + src + " / " + dst);
		}
	}

	private static void transformFiles(Transformer transformer, String src, String dst) throws Exception {
		// open files
		FileInputStream fis = new FileInputStream(src);
		FileOutputStream fos = new FileOutputStream(dst);

		// load input data
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte [] buffer = new byte[1024];
		int br;

		do {
			br = fis.read(buffer);
			if (br > 0) {
				baos.write(buffer, 0, br);
			}
		} while (br >= 0);

		// transform class
		fos.write(
			transformer.transform(baos.toByteArray())
		);

		// close files
		fis.close();
		fos.close();
	}

	private static void transformJars(Transformer transformer, String src, String dst) throws Exception {
		// open jars
		JarInputStream jis = new JarInputStream(
			new FileInputStream(src)
		);
		JarOutputStream jos = new JarOutputStream(
			new FileOutputStream(dst),
			jis.getManifest()
		);

		// iterate all jar entries
		JarEntry entry;

		while ((entry = jis.getNextJarEntry()) != null) {
			// read jar entry data
			int size = (int)entry.getSize();
			int offset = 0;
			byte [] data = new byte[size];

			while (offset < size) {
				offset += jis.read(data, offset, size - offset);
			}
			jis.closeEntry();

			// transform class ?
			if (entry.getName().indexOf(".class") > 0) {
				data = transformer.transform(data);
				size = data.length;
			}

			// write jar entry
			JarEntry newEntry = new JarEntry(entry.getName());

			newEntry.setComment(entry.getComment());
			newEntry.setExtra(entry.getExtra());
			newEntry.setTime(entry.getTime());
			jos.putNextEntry(newEntry);
			jos.write(data, 0, size);
			jos.closeEntry();
		}

		// close jars
		jis.close();
		jos.close();
	}
}

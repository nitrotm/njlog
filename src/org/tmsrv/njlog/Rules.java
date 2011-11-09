package org.tmsrv.njlog;

import java.io.*;
import java.util.*;


public class Rules {
	private boolean debug;

	private List<Rule> rules = new LinkedList<Rule>();


	public Rules(boolean debug) {
		this.debug = debug;
	}


	public boolean isDebug() {
		return debug;
	}

	public boolean accept(String clazz, String method) {
		boolean ret = true;

		for (Rule rule : rules) {
			if (rule.match(clazz, method)) {
				switch (rule.getType()) {
				case KEEP:
					ret = true;
					break;

				case DROP:
					ret = false;
					break;
				}
			}
		}
		return ret;
	}


	public void parseLine(String line) {
		// skip comments
		line = line.trim();
		if (line.length() == 0 || line.startsWith("#")) {
			return;
		}

		// parse configuration line
		String [] parts = line.split("\\s");
		Rule.Type type = null;
		String clazz = "";
		String method = "";
		int i = 0;

		for (String part : parts) {
			part = part.trim();
			if (part.length() > 0) {
				switch (i) {
				case 0:
					type = Enum.valueOf(Rule.Type.class, part);
					break;

				case 1:
					clazz = part;
					break;

				case 2:
					method = part;
					break;

				default:
					throw new RuntimeException("invalid configuration line : " + line);
				}
				i++;
			}
		}
		if (type != null) {
			rules.add(
				new Rule(type, clazz, method)
			);
		}
	}
}

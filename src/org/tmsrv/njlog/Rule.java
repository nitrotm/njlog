package org.tmsrv.njlog;

import java.io.*;
import java.util.*;


public class Rule {
	public static enum Type {
		KEEP,

		DROP;
	}


	private Type type;

	private String clazz;

	private String method;


	public Rule(Type type, String clazz, String method) {
		this.type = type;
		this.clazz = clazz;
		this.method = method;
	}


	public int hashCode() {
		int h = 11;
		
		h = h * 31 + type.hashCode();
		h = h * 31 + clazz.hashCode();
		h = h * 31 + method.hashCode();
		return h;
	}

	public boolean equals(Object o) {
		if (o instanceof Rule) {
			Rule r = (Rule)o;
			
			return (type.equals(r.type) && clazz.equals(r.clazz) && method.equals(r.method));
		}
		return false;
	}


	public Type getType() {
		return type;
	}

	public String getClazz() {
		return clazz;
	}

	public String getMethod() {
		return method;
	}


	public boolean match(String clazz, String method) {
		if (this.clazz.length() > 0) {
			if (!clazz.matches(this.clazz)) {
				return false;
			}
		}
		if (this.method.length() > 0) {
			if (!method.matches(this.method)) {
				return false;
			}
		}
		return true;
	}
}

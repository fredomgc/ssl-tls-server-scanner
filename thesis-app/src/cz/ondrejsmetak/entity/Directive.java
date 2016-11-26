package cz.ondrejsmetak.entity;

import java.util.Objects;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Directive {
	private String name;
	private Object value;
	private Mode mode;

	public Directive(String name, Object value, Mode mode) {
		this.name = name;
		this.value = value;
		this.mode = mode;
	}

	public String getName() {
		return name;
	}

	public Object getValue() {
		return value;
	}

	public Mode getMode() {
		return mode;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 41 * hash + Objects.hashCode(this.name);
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final Directive other = (Directive) obj;
		if (!Objects.equals(this.name, other.name)) {
			return false;
		}
		return true;
	}
	
	
	
	
}

package cz.ondrejsmetak.entity;

import cz.ondrejsmetak.tool.Helper;
import java.util.Objects;

/**
 * Represents configuration directive
 * 
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Directive {

	/**
	 * Name of configuration directive
	 */
	private String name;
	
	/**
	 * Value of configuration directive
	 */
	private Object value;
	
	/**
	 * Mode of configuration directive
	 */
	private Mode mode;

	/**
	 * Creates new configuration directive with given name, value and mode
	 * @param name name of configuration directive
	 * @param value value of configuration directive
	 * @param mode mode of configuration directive
	 */
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

	/**
	 * If value of this configuration directive is interget, return it
	 * @return value of configuration directive as integer
	 */
	public Integer getValueInt() {
		if (!Helper.isInteger(String.valueOf(value))) {
			throw new IllegalArgumentException(String.format("Directive [%s] doesn't contains a integer value!", name));
		}

		return Integer.parseInt(String.valueOf(value));
	}

	public Mode getMode() {
		return mode;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("(");
		sb.append(name);
		sb.append(":");
		sb.append(value.toString());
		sb.append(")");
		return sb.toString();
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

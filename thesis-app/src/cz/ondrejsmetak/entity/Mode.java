package cz.ondrejsmetak.entity;

import java.util.Objects;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Mode {

	public enum Type {
		MUST_BE, MUST_NOT_BE, MAY_BE
	}

	private Type type = null;

	private static final String MUST_BE_STR = "mustBe";
	private static final String MUST_NOT_BE_STR = "mustNotBe";
	private static final String MAY_BE_STR = "mayBe";

	public Mode(Type type) {
		this.type = type;
	}

	public Mode(String type) {
		if (type.equals(MUST_BE_STR)) {
			this.type = Type.MUST_BE;
		}

		if (type.equals(MUST_NOT_BE_STR)) {
			this.type = Type.MUST_NOT_BE;
		}

		if (type.equals(MAY_BE_STR)) {
			this.type = Type.MAY_BE;
		}

		if (type == null) {
			throw new IllegalArgumentException(String.format("Unknown type of mode [%s]!", type));
		}
	}

	@Override
	public String toString() {
		return type.toString();
	}

	public Mode.Type getType() {
		return type;
	}

	public boolean isMustBeOrMustNotBe(){
		return type == Type.MUST_BE || type == Type.MUST_NOT_BE;
	}
	
	public boolean isMustBe(){
		return type == Type.MUST_BE;
	}
	
	public boolean isMustNotBe(){
		return type == Type.MUST_NOT_BE;
	}
	
	
	@Override
	public int hashCode() {
		int hash = 7;
		hash = 89 * hash + Objects.hashCode(this.type);
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
		final Mode other = (Mode) obj;
		if (this.type != other.type) {
			return false;
		}
		return true;
	}
	
	
	
}

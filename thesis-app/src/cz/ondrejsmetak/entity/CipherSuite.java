package cz.ondrejsmetak.entity;

import java.util.Objects;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class CipherSuite extends BaseEntity {

	private String name;
	private Mode mode;

	public CipherSuite(String name) {
		this(name, null);
	}
	
	public CipherSuite(String name, Mode mode) {
		this.name = name;
		this.mode = mode;
	}

	@Override
	public String toString() {
		return this.name;
	}

	public String getName() {
		return name;
	}

	public Mode getMode() {
		return mode;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 71 * hash + Objects.hashCode(this.name);
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
		final CipherSuite other = (CipherSuite) obj;
		if (!Objects.equals(this.name, other.name)) {
			return false;
		}
		return true;
	}
}

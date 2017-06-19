package cz.ondrejsmetak.entity;

import java.util.Objects;

/**
 * Represents cipher suite Cipher suite is being in SSL/TLS (for example in
 * Client Hello message) with behaviour affected by settings in scan profile
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class CipherSuite extends BaseEntity {

	/**
	 * Human representation of cipher suites
	 */
	private String name;

	/**
	 * Decides, how should be this cipher suite treated
	 */
	private Mode mode;

	/**
	 * Creates new cipher suite with given name and unknown mode
	 * @param name name of cipher suite
	 */
	public CipherSuite(String name) {
		this(name, null);
	}

	
	/**
	 * Creates new cipher suite with given name and mode
	 * @param name name of cipher suite
	 * @param mode mode of cipher suite
	 */
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

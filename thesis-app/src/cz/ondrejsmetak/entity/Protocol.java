package cz.ondrejsmetak.entity;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Protocol extends BaseEntity{

	public enum Type {
		SSLv2, SSLv3, TLSv10, TLSv11, TLSv12, TLSv13
	}

	private Type type = null;

	private static final String[] sslv2Aliases = {"SSLv2", "SSL 2.0", "SSL 2", "SSL2"};
	private static final String[] sslv3Aliases = {"SSLv3", "SSL 3.0", "SSL 3", "SSL3"};
	private static final String[] tlsv10Aliases = {"TLSv1.0", "TLS 1.0", "TLSv10", "TLS 10"};
	private static final String[] tlsv11Aliases = {"TLSv1.1", "TLS 1.1", "TLSv11", "TLS 11"};
	private static final String[] tlsv12Aliases = {"TLSv1.2", "TLS 1.2", "TLSv12", "TLS 12"};
	private static final String[] tlsv13Aliases = {"TLSv1.3", "TLS 1.3", "TLSv13", "TLS 13"};

	public Protocol(String protocolCodeName) {
		if (hasCodeName(protocolCodeName, sslv2Aliases)) {
			type = Type.SSLv2;
		}

		if (hasCodeName(protocolCodeName, sslv3Aliases)) {
			type = Type.SSLv2;
		}

		if (hasCodeName(protocolCodeName, tlsv10Aliases)) {
			type = Type.TLSv10;
		}

		if (hasCodeName(protocolCodeName, tlsv11Aliases)) {
			type = Type.TLSv11;
		}

		if (hasCodeName(protocolCodeName, tlsv12Aliases)) {
			type = Type.TLSv12;
		}

		if (hasCodeName(protocolCodeName, tlsv13Aliases)) {
			type = Type.TLSv13;
		}

		if (type == null) {
			throw new IllegalArgumentException("Unknown protocol codename (" + protocolCodeName + ")");
		}
	}

	public Protocol(Type type) {
		this.type = type;
	}

	private boolean hasCodeName(String codeName, String[] candidates) {
		for (int i = 0; i < candidates.length; i++) {
			if (codeName.equalsIgnoreCase(candidates[i])) {
				return true;
			}
		}

		return false;
	}

	public Type getType() {
		return type;
	}

	public static List<Protocol> getHigherProtocolsFrom(Type start, boolean includeStart) {
		List<Protocol> done = new ArrayList<>();
		if (includeStart) {
			done.add(new Protocol(start));
		}

		for (int i = start.ordinal(); i < Type.values().length; i++) {
			done.add(new Protocol(Type.values()[i]));
		}

		return done;
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 79 * hash + Objects.hashCode(this.type);
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
		final Protocol other = (Protocol) obj;
		if (this.type != other.type) {
			return false;
		}
		return true;
	}

}

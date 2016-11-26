package cz.ondrejsmetak.entity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Protocol extends BaseEntity {

	public enum Type {
		SSLv2, SSLv3, TLSv10, TLSv11, TLSv12, TLSv13
	}

	private Type type = null;

	private Mode mode;
	
	private static final String[] sslv2Aliases = {"SSLv2", "SSL 2.0", "SSL 2", "SSL2"};
	private static final String[] sslv3Aliases = {"SSLv3", "SSL 3.0", "SSL 3", "SSL3"};
	private static final String[] tlsv10Aliases = {"TLSv1.0", "TLS 1.0", "TLSv10", "TLS 10", "TLSv1"};
	private static final String[] tlsv11Aliases = {"TLSv1.1", "TLS 1.1", "TLSv11", "TLS 11"};
	private static final String[] tlsv12Aliases = {"TLSv1.2", "TLS 1.2", "TLSv12", "TLS 12"};
	private static final String[] tlsv13Aliases = {"TLSv1.3", "TLS 1.3", "TLSv13", "TLS 13"};

	public static List<Protocol.Type> getAllTypes() {
		return new ArrayList<>(Arrays.asList(new Protocol.Type[]{
			Type.SSLv2, Type.SSLv3, Type.TLSv10, Type.TLSv11, Type.TLSv12, Type.TLSv13
		}));
	}

	public Protocol(String protocolCodeName) {
		this(protocolCodeName, null);
	}
	

	public Protocol(Type type) {
		this(type, null);
	}
	
	
	public Protocol(String protocolCodeName, Mode mode) {
		if (hasCodeName(protocolCodeName, sslv2Aliases)) {
			type = Type.SSLv2;
		}

		if (hasCodeName(protocolCodeName, sslv3Aliases)) {
			type = Type.SSLv3;
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

		this.mode = mode;
	}

	public Protocol(Type type, Mode mode) {
		this.type = type;
		this.mode = mode;
	}

	@Override
	public String toString() {

		if (type == Type.SSLv2) {
			return sslv2Aliases[0];
		}

		if (type == Type.SSLv3) {
			return sslv3Aliases[0];
		}

		if (type == Type.TLSv10) {
			return tlsv10Aliases[0];
		}

		if (type == Type.TLSv11) {
			return tlsv11Aliases[0];
		}

		if (type == Type.TLSv12) {
			return tlsv12Aliases[0];
		}

		if (type == Type.TLSv13) {
			return tlsv13Aliases[0];
		}

		return "";
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

	public Mode getMode() {
		return mode;
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

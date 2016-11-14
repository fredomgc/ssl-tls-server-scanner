package cz.ondrejsmetak.entity;

import cz.ondrejsmetak.other.InstantiableFromXml;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Profile extends BaseEntity{

	private String name;
	private List<Protocol> protocols = new ArrayList<>();

	private boolean testCertificate = false;
	private boolean testVulnerabilities = false;

	public Profile() {
	}

	public String getName() {
		return name;
	}

	public List<Protocol> getProtocols() {
		return protocols;
	}

	public boolean isTestCertificate() {
		return testCertificate;
	}

	public boolean isTestVulnerabilities() {
		return testVulnerabilities;
	}

	
	
	public static Profile fromXml(String name, String safeProtocol, String safeProfileModifier, boolean certificate, boolean vulnerabilities) {
		Profile profile = new Profile();
		profile.setName(name);
		profile.setTestCertificate(certificate);
		profile.setTestVulnerabilities(vulnerabilities);

		/**
		 * Protocol(s)
		 */
		Protocol protocol = new Protocol(safeProtocol);
		profile.addToProtocols(protocol);
		if (!safeProfileModifier.isEmpty()) {
			profile.addToProtocols(Protocol.getHigherProtocolsFrom(protocol.getType(), false));
		}

		return profile;
	}

	public void setName(String name) {
		if (name.isEmpty()) {
			throw new IllegalArgumentException("Profile name can't be empty!");
		}

		this.name = name;
	}

	public void setTestCertificate(boolean testCertificate) {
		this.testCertificate = testCertificate;
	}

	public void setTestVulnerabilities(boolean testVulnerabilities) {
		this.testVulnerabilities = testVulnerabilities;
	}

	public void addToProtocols(Protocol protocol) {
		if (!protocols.contains(protocol)) {
			protocols.add(protocol);
		}
	}

	public void addToProtocols(String safeProtocol) {
		this.addToProtocols(new Protocol(safeProtocol));
	}

	public void addToProtocols(List<Protocol> protocols) {
		for (Protocol candidate : protocols) {
			if (this.protocols.contains(candidate)) {
				this.protocols.add(candidate);
			}
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name);
		sb.append("(");
		
		
		for(Protocol p : protocols){
			sb.append(p.getType());
			sb.append(", ");
		}
		
		sb.append("cert: ").append(this.testCertificate);
		sb.append("vulns: ").append(this.testVulnerabilities);
		
		sb.append(")");
		return super.toString();
	}
}

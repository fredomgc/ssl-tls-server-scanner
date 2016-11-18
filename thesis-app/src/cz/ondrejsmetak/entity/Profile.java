package cz.ondrejsmetak.entity;

import cz.ondrejsmetak.other.InstantiableFromXml;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Profile extends BaseEntity {
	
	private String name;
	private final List<Protocol> safeProtocols = new ArrayList<>();
	private final List<CipherSuite> safeCipherSuites = new ArrayList<>();
	
	private boolean testCertificate = false;
	private boolean testVulnerabilities = false;
	private boolean testSafeCipherSuites = false;
	
	public Profile() {
	}
	
	public String getName() {
		return name;
	}
	
	public List<Protocol> getSafeProtocols() {
		return safeProtocols;
	}
	
	public List<CipherSuite> getSafeCipherSuites() {
		return safeCipherSuites;
	}
	
	public boolean isTestCertificate() {
		return testCertificate;
	}
	
	public boolean isTestVulnerabilities() {
		return testVulnerabilities;
	}
	
	public boolean isTestSafeCipherSuites() {
		return testSafeCipherSuites;
	}
	
	public boolean isTestSafeProtocols() {
		return !safeProtocols.isEmpty();
	}
	
	
	public static Profile fromXml(String name, String safeProtocol, String safeProfileModifier, boolean certificate, boolean vulnerabilities, List<CipherSuite> safeCipherSuites) {
		Profile profile = new Profile();
		profile.setName(name);
		profile.setTestCertificate(certificate);
		profile.setTestVulnerabilities(vulnerabilities);
		profile.setTestSafeCipherSuites(!safeCipherSuites.isEmpty());

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
	
	public void setTestSafeCipherSuites(boolean testSafeCipherSuites) {
		this.testSafeCipherSuites = testSafeCipherSuites;
	}
	
	public void addToProtocols(Protocol protocol) {
		if (!safeProtocols.contains(protocol)) {
			safeProtocols.add(protocol);
		}
	}
	
	public void addToProtocols(String safeProtocol) {
		this.addToProtocols(new Protocol(safeProtocol));
	}
	
	public void addToProtocols(List<Protocol> protocols) {
		for (Protocol candidate : protocols) {
			addToProtocols(candidate);
		}
	}
	
	public void addToSafeCipherSuites(CipherSuite safeCipherSuite) {
		if (!safeCipherSuites.contains(safeCipherSuite)) {
			safeCipherSuites.add(safeCipherSuite);
		}
	}
	
	public void addToSafeCipherSuites(List<CipherSuite> safeCipherSuites) {
		for (CipherSuite candidate : safeCipherSuites) {
			addToSafeCipherSuites(candidate);
		}
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name);
		sb.append("(");
		
		for (Protocol p : safeProtocols) {
			sb.append(p.getType());
			sb.append(", ");
		}
		
		sb.append("cert: ").append(this.testCertificate);
		sb.append("vulns: ").append(this.testVulnerabilities);
		
		sb.append(")");
		return sb.toString();
	}
}

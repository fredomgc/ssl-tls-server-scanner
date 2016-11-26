package cz.ondrejsmetak.entity;

import cz.ondrejsmetak.other.InstantiableFromXml;
import cz.ondrejsmetak.tool.Pair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Profile extends BaseEntity {

	private String name;
	private final List<Protocol> protocols = new ArrayList<>();
	private final List<CipherSuite> cipherSuites = new ArrayList<>();
	private final List<Directive> certificateDirectives = new ArrayList<>();

	private Mode certificate;
	private Mode vulnerabilities;

	public static final String RSA_MINIMUM_PUBLIC_KEY_SIZE = "rsaMinimumPublicKeySize";
	public static final String RSA_MINIMUM_SIGNATURE_KEY_SIZE = "rsaMinimumSignatureKeySize";
	public static final String ECDSA_MINIMUM_PUBLIC_KEY_SIZE = "ecdsaMinimumPublicKeySize";
	public static final String ECDSA_MINIMUM_SIGNATURE_SIZE = "ecdsaMinimumSignatureKeySize";

	public Profile() {
	}

	public static List<String> getAllCertificateDirectives() {
		return new ArrayList<>(Arrays.asList(new String[]{RSA_MINIMUM_PUBLIC_KEY_SIZE, RSA_MINIMUM_SIGNATURE_KEY_SIZE, ECDSA_MINIMUM_PUBLIC_KEY_SIZE, ECDSA_MINIMUM_SIGNATURE_SIZE}));
	}

	public String getName() {
		return name;
	}

	public List<Protocol> getProtocols() {
		return protocols;
	}

//	public List<Protocol> getMustBeProtocols() {
//		return getProtocols(Mode.Type.MUST_BE);
//	}
//
//	public List<Protocol> getMustNotBeProtocols() {
//		return getProtocols(Mode.Type.MUST_NOT_BE);
//	}
//
//	private List<Protocol> getProtocols(Mode.Type mode) {
//		List<Protocol> done = new ArrayList<>();
//		for (Protocol protocol : protocols) {
//			if (protocol.getMode().getType().equals(mode)) {
//				done.add(protocol);
//			}
//		}
//		return done;
//	}
	public List<CipherSuite> getCipherSuites() {
		return cipherSuites;
	}

	public boolean isTestCertificate() {
		return certificate.isMustBe();
	}

	public boolean isTestVulnerabilities() {
		return vulnerabilities.isMustBe();
	}

	public boolean isTestCipherSuites() {
		return !cipherSuites.isEmpty();
	}

	public boolean isTestSafeProtocols() {
		return !protocols.isEmpty();
	}

	public static Profile fromXml(String name, List<Protocol> protocols, Mode certificate, List<Directive> certificateDirectives, Mode vulnerabilities, List<CipherSuite> cipherSuites) {
		Profile profile = new Profile();
		profile.setName(name);
		profile.addToProtocols(protocols);
		profile.setTestCertificate(certificate);
		profile.addToCertificateDirectives(certificateDirectives);
		profile.setTestVulnerabilities(vulnerabilities);
		profile.addToCipherSuites(cipherSuites);

		return profile;
	}

	public void setName(String name) {
		if (name.isEmpty()) {
			throw new IllegalArgumentException("Profile name can't be empty!");
		}

		this.name = name;
	}

	public void setTestCertificate(Mode testCertificate) {
		this.certificate = testCertificate;
	}

	public void setTestVulnerabilities(Mode testVulnerabilities) {
		this.vulnerabilities = testVulnerabilities;
	}

	public void addToProtocols(Protocol protocol) {
		if (!protocols.contains(protocol)) {
			protocols.add(protocol);
		}
	}

	public void addToProtocols(List<Protocol> protocols) {
		for (Protocol candidate : protocols) {
			addToProtocols(candidate);
		}
	}

	public void addToCipherSuites(CipherSuite safeCipherSuite) {
		if (!cipherSuites.contains(safeCipherSuite)) {
			cipherSuites.add(safeCipherSuite);
		}
	}

	public void addToCipherSuites(List<CipherSuite> safeCipherSuites) {
		for (CipherSuite candidate : safeCipherSuites) {
			addToCipherSuites(candidate);
		}
	}

	public void addToCertificateDirectives(Directive certificateDirective) {
		if (!this.certificateDirectives.contains(certificateDirective)) {
			certificateDirectives.add(certificateDirective);
		}
	}

	public void addToCertificateDirectives(List<Directive> certificateDirectives) {
		for (Directive directive : certificateDirectives) {
			addToCertificateDirectives(directive);
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name);
		sb.append("(");

		for (Protocol p : protocols) {
			sb.append(p.getType());
			sb.append(", ");
		}

		sb.append("cert: ").append(this.certificate);
		sb.append("vulns: ").append(this.vulnerabilities);

		sb.append(")");
		return sb.toString();
	}
}

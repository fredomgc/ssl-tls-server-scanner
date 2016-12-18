package cz.ondrejsmetak.entity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Profile, that defines scan settings. Profile is then assigned to target(s)
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Profile extends BaseEntity {

	/**
	 * Name of profile
	 */
	private String name;

	/**
	 * Collection of protocols, that will be checked during scanning
	 */
	private final List<Protocol> protocols = new ArrayList<>();

	/**
	 * Collection of cipher suites, that will be checked during scanning
	 */
	private final List<CipherSuite> cipherSuites = new ArrayList<>();

	/**
	 * Collection of certificate's settings directives, that will be checked
	 * during scanning
	 */
	private final Map<String, Directive> certificateDirectives = new HashMap<>();

	/**
	 * Mode that affects behavirour of checking certificate during scanning
	 */
	private Mode certificate;

	/**
	 * Mode that affects behavirour of checking vulnerabilities during scanning
	 */
	private Mode vulnerabilities;

	/**
	 * Names of certificate directives
	 */
	public static final String RSA_MINIMUM_PUBLIC_KEY_SIZE = "rsaMinimumPublicKeySize";
	public static final String RSA_MINIMUM_SIGNATURE_KEY_SIZE = "rsaMinimumSignatureKeySize";
	public static final String ECDSA_MINIMUM_PUBLIC_KEY_SIZE = "ecdsaMinimumPublicKeySize";
	public static final String ECDSA_MINIMUM_SIGNATURE_SIZE = "ecdsaMinimumSignatureKeySize";

	/**
	 * Creates new empty profile
	 */
	public Profile() {
	}

	/**
	 * Returns all supported certificate directives
	 *
	 * @return collection of all supported certificate directives
	 */
	public static List<String> getAllCertificateDirectives() {
		return new ArrayList<>(Arrays.asList(new String[]{RSA_MINIMUM_PUBLIC_KEY_SIZE, RSA_MINIMUM_SIGNATURE_KEY_SIZE, ECDSA_MINIMUM_PUBLIC_KEY_SIZE, ECDSA_MINIMUM_SIGNATURE_SIZE}));
	}

	public String getName() {
		return name;
	}

	public List<Protocol> getProtocols() {
		return protocols;
	}

	public List<CipherSuite> getCipherSuites() {
		return cipherSuites;
	}

	/**
	 * Is required to perform test of certificate?
	 *
	 * @return true, if test of certificate must be performed, false otherwise
	 */
	public boolean isTestCertificate() {
		return certificate.isMustBe();
	}

	/**
	 * Is required to perform test of vulnerabilities?
	 *
	 * @return true, if test of vulnerabilities must be performed, false
	 * otherwise
	 */
	public boolean isTestVulnerabilities() {
		return vulnerabilities.isMustBe();
	}

	/**
	 * Is required to perform test of vulnerabilities?
	 *
	 * @return true, if test of vulnerabilities must be performed, false
	 * otherwise
	 */
	public boolean isTestCipherSuites() {
		return !cipherSuites.isEmpty();
	}

	/**
	 * Is required to perform test of protocols?
	 *
	 * @return true, if test of protocols must be performed, false otherwise
	 */
	public boolean isTestProtocols() {
		return !protocols.isEmpty();
	}

	/**
	 * Returns mode that indicates behaviour during scanning of vulnerabilities
	 *
	 * @return mode indicating behaviour during scanning of vulnerabilities
	 */
	public Mode getModeVulnerabilities() {
		return vulnerabilities;
	}

	/**
	 * Returns mode that indicates behaviour during scanning of certificate
	 *
	 * @return mode indicating behaviour during scanning of certificate
	 */
	public Mode getModeCertificate() {
		return certificate;
	}

	/**
	 * Creates new profile with given attributes. Usefull shortcut
	 *
	 * @param name name of profile
	 * @param protocols protocols, that will be checked during scan
	 * @param certificate mode, that affects behaviour during scan of
	 * certificate
	 * @param certificateDirectives collection of directives, that alters
	 * behaviour during scan of certificate
	 * @param vulnerabilities mode, that affects behaviour during scan of
	 * vulnerabilities
	 * @param cipherSuites collection of cipher suites, that will be checked
	 * during scan
	 * @return created profile
	 */
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
		if (!this.certificateDirectives.containsKey(certificateDirective.getName())) {
			certificateDirectives.put(certificateDirective.getName(), certificateDirective);
		}
	}

	public void addToCertificateDirectives(List<Directive> certificateDirectives) {
		for (Directive directive : certificateDirectives) {
			addToCertificateDirectives(directive);
		}
	}

	public Directive getCertificateDirective(String key) {
		if (!getAllCertificateDirectives().contains(key)) {
			throw new IllegalArgumentException(String.format("Unsupported directive [%s]", key));
		}

		return certificateDirectives.get(key);
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

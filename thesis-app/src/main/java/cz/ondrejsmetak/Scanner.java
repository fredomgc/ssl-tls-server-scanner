package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.CipherSuite;
import cz.ondrejsmetak.entity.Directive;
import cz.ondrejsmetak.entity.Mode;
import cz.ondrejsmetak.entity.Profile;
import cz.ondrejsmetak.entity.Protocol;
import cz.ondrejsmetak.entity.ReportMessage;
import cz.ondrejsmetak.entity.Result;
import cz.ondrejsmetak.facade.OSaftFacade;
import cz.ondrejsmetak.facade.OSaftParser;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.tool.Helper;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Scanner {

	/**
	 * Facade over O-Saft tool
	 */
	private final OSaftFacade oSaft;

	/**
	 * Target, that will be scanned
	 */
	private final Target target;

	/**
	 * Messages with found vulneragilities
	 */
	private List<ReportMessage> vulnerableMessages;

	/**
	 * Messages with confirmed secure states
	 */
	private List<ReportMessage> safeMessages;

	/**
	 * Creates a new intance of scanner for the given target
	 *
	 * @param target target, that will be scanned
	 */
	public Scanner(Target target) {
		this.target = target;
		oSaft = new OSaftFacade(target);
	}

	/**
	 * Performs all required scan(s) for this target
	 */
	public void runScan() {
		oSaft.runScan();
		doReportMessages();
	}

	/**
	 * Return a collection of the report messages regarding cipher suites
	 *
	 * @return collection of the report messages
	 */
	private List<ReportMessage> getCipherSuites() {
		List<ReportMessage> vulns = new ArrayList<>();

		if (target.getProfile().isTestCipherSuites()) {
			for (CipherSuite cipherSuite : target.getProfile().getCipherSuites()) {
				if (cipherSuite.getMode().isMustBe() && !oSaft.getParser().getSupportedCipherSuites().contains(cipherSuite)) {
					vulns.add(new ReportMessage("Cipher suite " + cipherSuite + " MUST BE supported!", ReportMessage.Category.CIPHER, cipherSuite.getMode()));
				} else if (cipherSuite.getMode().isMustNotBe() && oSaft.getParser().getSupportedCipherSuites().contains(cipherSuite)) {
					vulns.add(new ReportMessage("Cipher suite " + cipherSuite + " MUST NOT BE supported!", ReportMessage.Category.CIPHER, cipherSuite.getMode()));
				}
			}
		}

		return vulns;
	}

	/**
	 * Return a collection of the report messages regarding vulnerabilities
	 *
	 * @return collection of the report messages
	 */
	private List<ReportMessage> getVulnerabilities() {
		List<ReportMessage> vulns = new ArrayList<>();

		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to BEAST!", oSaft.getParser().getBeast(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to CRIME!", oSaft.getParser().getCrime(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to DROWN!", oSaft.getParser().getDrown(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to FREAK!", oSaft.getParser().getFreak(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Heartbleed!", oSaft.getParser().getHeartbleed(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Logjam!", oSaft.getParser().getLogjam(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Lucky 13!", oSaft.getParser().getLucky13(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to POODLE!", oSaft.getParser().getPoodle(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("RC4 ciphers are supported (but they are assumed to be broken)!", oSaft.getParser().getRc4(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Sweet32!", oSaft.getParser().getSweet32(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("SSLv2 supported!", oSaft.getParser().getSslv2NotSupported(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("SSLv3 supported!", oSaft.getParser().getSslv3NotSupported(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("PFS (perfect forward secrecy) not supported!", oSaft.getParser().getPfs(), ReportMessage.Category.VULNERABILITY));
		Helper.addIfNotNull(vulns, doPrintVulnerability("TLS session ticket doesn't contain random value!", oSaft.getParser().getRandomTlsSessionTicket(), ReportMessage.Category.VULNERABILITY));

		return vulns;
	}

	/**
	 * Return a collection of the report messages regarding tests of the
	 * certificate
	 *
	 * @return collection of the report messages
	 */
	private List<ReportMessage> getCertificateChecks() {
		List<ReportMessage> vulns = new ArrayList<>();

		Helper.addIfNotNull(vulns, doPrintVulnerability("Mismatch between hostname and certificate subject.", oSaft.getParser().getCertificateHostnameMatch(), ReportMessage.Category.CERTIFICATE));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Mismatch between given hostname and reverse resolved hostname.", oSaft.getParser().getCertificateReverseHostnameMatch(), ReportMessage.Category.CERTIFICATE));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate expired.", oSaft.getParser().getCertificateNotExpired(), ReportMessage.Category.CERTIFICATE));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate isn't valid.", oSaft.getParser().getCertificateIsValid(), ReportMessage.Category.CERTIFICATE));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate fingerprint is MD5.", oSaft.getParser().getCertificateFingerprintNotMd5(), ReportMessage.Category.CERTIFICATE));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate Private Key Signature isn't SHA2.", oSaft.getParser().getCertificatePrivateKeySha2(), ReportMessage.Category.CERTIFICATE));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate is self-signed.", oSaft.getParser().getCertificateNotSelfSigned(), ReportMessage.Category.CERTIFICATE));

		vulns.addAll(getCertificateKeysCheck());
		return vulns;
	}

	/**
	 * Return a collection of the report messages regarding test of the
	 * certificate's keys
	 *
	 * @return collection of the report messages
	 */
	private List<ReportMessage> getCertificateKeysCheck() {
		List<ReportMessage> vulns = new ArrayList<>();
		Directive rsaDirective;
		Directive ecdsaDirective;
		boolean rsaVulnerable;
		boolean ecdsaVulnerable;

		/**
		 * Public key
		 */
		rsaDirective = target.getProfile().getCertificateDirective(Profile.RSA_MINIMUM_PUBLIC_KEY_SIZE);
		ecdsaDirective = target.getProfile().getCertificateDirective(Profile.ECDSA_MINIMUM_PUBLIC_KEY_SIZE);

		rsaVulnerable = oSaft.getParser().getCertificatePublicKeyAlgorithm().equals(OSaftParser.Algorithm.RSA)
				&& rsaDirective.getMode().isMustBe()
				&& rsaDirective.getValueInt() > oSaft.getParser().getCertificatePublicKeySize();
		ecdsaVulnerable = oSaft.getParser().getCertificatePublicKeyAlgorithm().equals(OSaftParser.Algorithm.ECDSA)
				&& ecdsaDirective.getMode().isMustBe()
				&& ecdsaDirective.getValueInt() > oSaft.getParser().getCertificateSignatureKeySize();

		if (rsaVulnerable || ecdsaVulnerable) {
			String note = String.format("actual size [%s] is lesser then expected minimum size [%s]", oSaft.getParser().getCertificatePublicKeySize(), rsaVulnerable ? rsaDirective.getValueInt() : ecdsaDirective.getValueInt());
			vulns.add(doPrintVulnerability("Wrong size of certificate's public key", Result.getVulnerable(note), ReportMessage.Category.CERTIFICATE));
		}

		/**
		 * Signature key
		 */
		rsaDirective = target.getProfile().getCertificateDirective(Profile.RSA_MINIMUM_SIGNATURE_KEY_SIZE);
		ecdsaDirective = target.getProfile().getCertificateDirective(Profile.ECDSA_MINIMUM_SIGNATURE_SIZE);

		rsaVulnerable = oSaft.getParser().getCertificateSignatureAlgorithm().equals(OSaftParser.Algorithm.RSA)
				&& rsaDirective.getMode().isMustBe()
				&& rsaDirective.getValueInt() > oSaft.getParser().getCertificatePublicKeySize();
		ecdsaVulnerable = oSaft.getParser().getCertificateSignatureAlgorithm().equals(OSaftParser.Algorithm.ECDSA)
				&& ecdsaDirective.getMode().isMustBe()
				&& ecdsaDirective.getValueInt() > oSaft.getParser().getCertificateSignatureKeySize();

		if (rsaVulnerable || ecdsaVulnerable) {
			String note = String.format("actual size [%s] is lesser then expected minimum size [%s]", oSaft.getParser().getCertificateSignatureKeySize(), rsaVulnerable ? rsaDirective.getValueInt() : ecdsaDirective.getValueInt());
			vulns.add(doPrintVulnerability("Wrong size of certificate's signature key", Result.getVulnerable(note), ReportMessage.Category.CERTIFICATE));
		}

		return vulns;
	}

	/**
	 * Creates a new report message with the given body, result and category
	 *
	 * @param vulnerableMessage message in text form
	 * @param result result of the test
	 * @param category category of the test
	 * @return a newly created report message
	 */
	private ReportMessage doPrintVulnerability(String vulnerableMessage, Result result, ReportMessage.Category category) {
		ReportMessage vulnerable = null;

		StringBuilder out = new StringBuilder();
		out.append(vulnerableMessage);
		if (result.hasNote()) {
			out.append(" [").append(result.getNote()).append("]");
		}

		if (result.isVulnerable()) {
			vulnerable = new ReportMessage(out.toString(), category, this.target.getProfile().getModeVulnerabilities());
		} else if (result.isUnknown() && ConfigurationRegister.getInstance().isUnknownTestResultIsError()) {
			vulnerable = new ReportMessage(out.toString(), category, this.target.getProfile().getModeVulnerabilities());
		}

		return vulnerable;
	}

	/**
	 * Return a collection of the report messages regarding protocols
	 *
	 * @return collection of the report messages
	 */
	private List<ReportMessage> getProtocols() {
		List<ReportMessage> vulns = new ArrayList<>();

		for (Protocol protocol : target.getProfile().getProtocols()) {
			if (protocol.getMode().isMustBe() && !oSaft.getParser().getSupportedProtocols().contains(protocol)) {
				vulns.add(new ReportMessage("Protocol " + protocol + " MUST BE supported!", ReportMessage.Category.PROTOCOL, protocol.getMode()));
			} else if (protocol.getMode().isMustNotBe() && oSaft.getParser().getSupportedProtocols().contains(protocol)) {
				vulns.add(new ReportMessage("Protocol " + protocol + " MUST NOT BE supported!", ReportMessage.Category.PROTOCOL, protocol.getMode()));
			}
		}

		return vulns;
	}

	/**
	 * Creates a safe messages for the categories with zero found
	 * vulnerabilities
	 *
	 * @param vulnerabilities collection of the found vulnerabilities
	 * @param category category of found vulnerabilities
	 * @param requiredMode mode used during testing
	 */
	private void doSplitSafeAndVulnerable(List<ReportMessage> vulnerabilities, ReportMessage.Category category, Mode requiredMode) {
		if (vulnerabilities.isEmpty()) {
			safeMessages.add(new ReportMessage("OK", category, requiredMode, ReportMessage.Type.SUCCESS));
		} else {
			vulnerableMessages.addAll(vulnerabilities);
		}
	}

	private void doAddNotTested(ReportMessage.Category category, Mode requiredMode) {
		safeMessages.add(new ReportMessage("OK (by default, not tested due to profile configuration)", category, requiredMode, ReportMessage.Type.SUCCESS));
	}

	private void doAddTargetNotRunning() {
		vulnerableMessages.add(new ReportMessage("Can't make any connection to the target (is " + target.getDestination() + " up and running?)", ReportMessage.Category.PROTOCOL, new Mode(Mode.Type.MUST_BE), ReportMessage.Type.ERROR));
	}

	private void doReportMessages() {
		vulnerableMessages = new ArrayList<>();
		safeMessages = new ArrayList<>();

		if (!oSaft.getParser().isSuccesfulConnection()) {
			doAddTargetNotRunning();
			return; //stop here and return just single vulnerable message about unsuccessful connection.
		}

		if (target.getProfile().isTestCipherSuites()) {
			doSplitSafeAndVulnerable(getCipherSuites(), ReportMessage.Category.CIPHER, null);
		} else {
			doAddNotTested(ReportMessage.Category.CIPHER, null);
		}

		if (target.getProfile().isTestVulnerabilities()) {
			doSplitSafeAndVulnerable(getVulnerabilities(), ReportMessage.Category.VULNERABILITY, target.getProfile().getModeVulnerabilities());
		} else {
			doAddNotTested(ReportMessage.Category.VULNERABILITY, target.getProfile().getModeVulnerabilities());
		}

		if (target.getProfile().isTestCertificate()) {
			doSplitSafeAndVulnerable(getCertificateChecks(), ReportMessage.Category.CERTIFICATE, target.getProfile().getModeCertificate());
		} else {
			doAddNotTested(ReportMessage.Category.CERTIFICATE, target.getProfile().getModeCertificate());
		}

		if (target.getProfile().isTestProtocols()) {
			doSplitSafeAndVulnerable(getProtocols(), ReportMessage.Category.PROTOCOL, null);
		} else {
			doAddNotTested(ReportMessage.Category.PROTOCOL, null);
		}
	}

	public List<ReportMessage> getVulnerableMessages() {
		return vulnerableMessages;
	}

	public List<ReportMessage> getSafeMessages() {
		return safeMessages;
	}
}

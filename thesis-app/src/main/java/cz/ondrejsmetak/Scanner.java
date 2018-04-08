package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.CipherSuite;
import cz.ondrejsmetak.entity.ClientCertificate;
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
	 * Test regarding custom certificate authority
	 */
	private final CustomCertificateAuthorityTest customCa;

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
		customCa = new CustomCertificateAuthorityTest(target);
	}

	/**
	 * Performs all required scan(s) for this target
	 */
	public void runScan() {
		oSaft.runScan();
		if (!target.getProfile().getCustomCertificateAuthority().getMode().isCanBe()) {
			customCa.runScan();
		}
		doReportMessages();
	}

	/**
	 * Return a collection of the report messages regarding cipher suites
	 *
	 * @return collection of the report messages
	 */
	private List<ReportMessage> getCipherSuites() {
		List<ReportMessage> vulns = new ArrayList<>();
		boolean unableToTestError = oSaft.getParser().getSupportedCipherSuites().isEmpty();
		String prefix = unableToTestError ? "[Unable to test] " : "";
		
		if (target.getProfile().isTestCipherSuites()) {
			for (CipherSuite cipherSuite : target.getProfile().getCipherSuites()) {
				if (cipherSuite.getMode().isMustBe() && !oSaft.getParser().getSupportedCipherSuites().contains(cipherSuite)) {
					vulns.add(new ReportMessage(prefix + "Cipher suite " + cipherSuite + " MUST BE supported!", ReportMessage.Category.CIPHER, cipherSuite.getMode()));
				} else if (cipherSuite.getMode().isMustNotBe() && oSaft.getParser().getSupportedCipherSuites().contains(cipherSuite)) {
					vulns.add(new ReportMessage(prefix + "Cipher suite " + cipherSuite + " MUST NOT BE supported!", ReportMessage.Category.CIPHER, cipherSuite.getMode()));
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
		Mode mode = this.target.getProfile().getModeVulnerabilities();

		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to BEAST!", oSaft.getParser().getBeast(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to CRIME!", oSaft.getParser().getCrime(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to DROWN!", oSaft.getParser().getDrown(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to FREAK!", oSaft.getParser().getFreak(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Heartbleed!", oSaft.getParser().getHeartbleed(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Logjam!", oSaft.getParser().getLogjam(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Lucky 13!", oSaft.getParser().getLucky13(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to POODLE!", oSaft.getParser().getPoodle(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("RC4 ciphers are supported (but they are assumed to be broken)!", oSaft.getParser().getRc4(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Vulnerable to Sweet32!", oSaft.getParser().getSweet32(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("SSLv2 supported!", oSaft.getParser().getSslv2NotSupported(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("SSLv3 supported!", oSaft.getParser().getSslv3NotSupported(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("PFS (perfect forward secrecy) not supported!", oSaft.getParser().getPfs(), ReportMessage.Category.VULNERABILITY, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("TLS session ticket doesn't contain random value!", oSaft.getParser().getRandomTlsSessionTicket(), ReportMessage.Category.VULNERABILITY, mode));

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
		Mode mode = this.target.getProfile().getModeCertificate();

		Helper.addIfNotNull(vulns, doPrintVulnerability("Mismatch between hostname and certificate subject.", oSaft.getParser().getCertificateHostnameMatch(), ReportMessage.Category.CERTIFICATE, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate expired.", oSaft.getParser().getCertificateNotExpired(), ReportMessage.Category.CERTIFICATE, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate isn't valid.", oSaft.getParser().getCertificateIsValid(), ReportMessage.Category.CERTIFICATE, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate fingerprint is MD5.", oSaft.getParser().getCertificateFingerprintNotMd5(), ReportMessage.Category.CERTIFICATE, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate Private Key Signature isn't SHA2.", oSaft.getParser().getCertificatePrivateKeySha2(), ReportMessage.Category.CERTIFICATE, mode));
		Helper.addIfNotNull(vulns, doPrintVulnerability("Certificate is self-signed.", oSaft.getParser().getCertificateNotSelfSigned(), ReportMessage.Category.CERTIFICATE, mode));

		/**
		 * How about custom certificate authority?
		 */
		ClientCertificate ca = this.target.getProfile().getCustomCertificateAuthority();
		Mode caMode = ca.getMode();

		if (caMode.isMustBe() && !customCa.isConnectionSuccessful()) {
			String message = String.format("Target isn't accepting connection when using custom certificate authority [%s].", ca.getName());
			vulns.add(doPrintVulnerability(message, Result.getVulnerable(), ReportMessage.Category.CERTIFICATE, caMode));
		}

		if (caMode.isMustNotBe() && customCa.isConnectionSuccessful()) {
			String message = String.format("Target is accepting connection when using custom certificate authority [%s].", ca.getName());
			vulns.add(doPrintVulnerability(message, Result.getVulnerable(), ReportMessage.Category.CERTIFICATE, caMode));
		}

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
			Mode mode = rsaVulnerable ? rsaDirective.getMode() : ecdsaDirective.getMode();
			vulns.add(doPrintVulnerability("Wrong size of certificate's public key", Result.getVulnerable(note), ReportMessage.Category.CERTIFICATE, mode));
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
			Mode mode = rsaVulnerable ? rsaDirective.getMode() : ecdsaDirective.getMode();
			vulns.add(doPrintVulnerability("Wrong size of certificate's signature key", Result.getVulnerable(note), ReportMessage.Category.CERTIFICATE, mode));
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
	private ReportMessage doPrintVulnerability(String vulnerableMessage, Result result, ReportMessage.Category category, Mode mode) {
		ReportMessage vulnerable = null;

		StringBuilder out = new StringBuilder();
		out.append(vulnerableMessage);
		if (result.hasNote()) {
			out.append(" [").append(result.getNote()).append("]");
		}

		if (result.isVulnerable() && !mode.isCanBe()) {
			vulnerable = new ReportMessage(out.toString(), category, mode);
		} else if (result.isUnknown() && this.target.getProfile().isUnknownTestResultIsError()) {
			vulnerable = new ReportMessage("[Unable to test] " + out.toString(), category, mode);
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

		List<Protocol> protocols = this.target.getProfile().getProtocols();
		for (Protocol protocol : protocols) {
			switch (protocol.getType()) {
				case SSLv2:
					Helper.addIfNotNull(vulns, doPrintVulnerability("Support for SSLv2 protocol.", oSaft.getParser().getProtocolSslv2(), ReportMessage.Category.PROTOCOL, protocol.getMode()));
					break;
				case SSLv3:
					Helper.addIfNotNull(vulns, doPrintVulnerability("Support for SSLv3 protocol.", oSaft.getParser().getProtocolSslv3(), ReportMessage.Category.PROTOCOL, protocol.getMode()));
					break;
				case TLSv10:
					Helper.addIfNotNull(vulns, doPrintVulnerability("Support for TLSv1.0 protocol.", oSaft.getParser().getProtocolTlsv10(), ReportMessage.Category.PROTOCOL, protocol.getMode()));
					break;
				case TLSv11:
					Helper.addIfNotNull(vulns, doPrintVulnerability("Support for TLSv1.1 protocol.", oSaft.getParser().getProtocolTlsv11(), ReportMessage.Category.PROTOCOL, protocol.getMode()));
					break;
				case TLSv12:
					Helper.addIfNotNull(vulns, doPrintVulnerability("Support for TLSv1.2 protocol.", oSaft.getParser().getProtocolTlsv12(), ReportMessage.Category.PROTOCOL, protocol.getMode()));
					break;
				case TLSv13:
					//TLS 1.3 is draft
					//Helper.addIfNotNull(vulns, doPrintVulnerability("Support for TLSv1.3 protocol.", oSaft.getParser().getProtocolTlsv13(), ReportMessage.Category.PROTOCOL, protocol.getMode()));
					break;
				default:
					break;
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
			doSplitSafeAndVulnerable(getCipherSuites(), ReportMessage.Category.CIPHER, new Mode(Mode.Type.MUST_BE));
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
			doSplitSafeAndVulnerable(getProtocols(), ReportMessage.Category.PROTOCOL, new Mode(Mode.Type.MUST_BE));
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

/*
 * Spusteni scannovani, vraceni vysledku testu
 */
package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.CipherSuite;
import cz.ondrejsmetak.entity.Directive;
import cz.ondrejsmetak.entity.Profile;
import cz.ondrejsmetak.entity.Protocol;
import cz.ondrejsmetak.entity.Result;
import cz.ondrejsmetak.facade.OSaftFacade;
import cz.ondrejsmetak.facade.OSaftParser;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.tool.Helper;
import cz.ondrejsmetak.tool.Log;
import javax.crypto.Cipher;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Scanner {

	private final OSaftFacade oSaft;
	private final Target target;

	public Scanner(Target target) {
		this.target = target;
		oSaft = new OSaftFacade(target);
	}

	public void runScan() {
		oSaft.runScan();
	}

	private int printCipherSuites() {
		int vulns = 0;

		if (target.getProfile().isTestCipherSuites()) {
			for (CipherSuite cipherSuite : target.getProfile().getCipherSuites()) {
				if (cipherSuite.getMode().isMustBe() && !oSaft.getParser().getSupportedCipherSuites().contains(cipherSuite)) {
					Log.errorln("Cipher suite " + cipherSuite + " MUST BE supported!");
					vulns++;
				} else if (cipherSuite.getMode().isMustNotBe() && oSaft.getParser().getSupportedCipherSuites().contains(cipherSuite)) {
					Log.errorln("Cipher suite " + cipherSuite + " MUST NOT BE supported!");
					vulns++;
				}
			}
		}

		return vulns;
	}

	private int printVulnerabilities() {
		int vulns = 0;

		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to BEAST!", oSaft.getParser().getBeast()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to CRIME!", oSaft.getParser().getCrime()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to DROWN!", oSaft.getParser().getDrown()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to FREAK!", oSaft.getParser().getFreak()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to Heartbleed!", oSaft.getParser().getHeartbleed()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to Logjam!", oSaft.getParser().getLogjam()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to Lucky 13!", oSaft.getParser().getLucky13()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to POODLE!", oSaft.getParser().getPoodle()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("RC4 ciphers are supported (but they are assumed to be broken)!", oSaft.getParser().getRc4()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Vulnerable to Sweet32!", oSaft.getParser().getSweet32()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("SSLv2 supported!", oSaft.getParser().getSslv2NotSupported()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("SSLv3 supported!", oSaft.getParser().getSslv3NotSupported()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("PFS (perfect forward secrecy) not supported!", oSaft.getParser().getPfs()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("TLS session ticket doesn't contain random value!", oSaft.getParser().getRandomTlsSessionTicket()));

		return vulns;
	}

	private int printCertificateChecks() {
		int vulns = 0;

		vulns += Helper.booleanToInteger(doPrintVulnerability("Mismatch between hostname and certificate subject.", oSaft.getParser().getCertificateHostnameMatch()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Mismatch between given hostname and reverse resolved hostname.", oSaft.getParser().getCertificateReverseHostnameMatch()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Certificate expired.", oSaft.getParser().getCertificateNotExpired()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Certificate isn't valid.", oSaft.getParser().getCertificateIsValid()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Certificate fingerprint is MD5.", oSaft.getParser().getCertificateFingerprintNotMd5()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Certificate Private Key Signature isn't SHA2.", oSaft.getParser().getCertificatePrivateKeySha2()));
		vulns += Helper.booleanToInteger(doPrintVulnerability("Certificate is self-signed.", oSaft.getParser().getCertificateNotSelfSigned()));
		vulns += printCertificateKeysCheck();
		return vulns;
	}

	private int printCertificateKeysCheck() {
		int vulns = 0;
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
			doPrintVulnerability("Wrong size of certificate's public key", Result.getVulnerable(note));
			vulns++;
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
			doPrintVulnerability("Wrong size of certificate's signature key", Result.getVulnerable(note));
			vulns++;
		}
		
		return vulns;
	}

	private boolean doPrintVulnerability(String vulnerableMessage, Result result) {
		boolean safe = true;

		StringBuilder out = new StringBuilder();
		out.append(vulnerableMessage);
		if (result.hasNote()) {
			out.append(" [").append(result.getNote()).append("]");
		}

		if (result.isVulnerable()) {
			Log.errorln(out.toString());
			safe = false;
		} else if (result.isUnknown() && ConfigurationRegister.getInstance().isUnknownTestResultIsError()) {
			Log.errorln(out.toString());
			safe = false;
		}

		return safe;
	}

	private int printProtocols() {
		int vulns = 0;

		for (Protocol protocol : target.getProfile().getProtocols()) {
			if (protocol.getMode().isMustBe() && !oSaft.getParser().getSupportedProtocols().contains(protocol)) {
				Log.errorln("Protocol " + protocol + " MUST BE supported!");
				vulns++;
			} else if (protocol.getMode().isMustNotBe() && oSaft.getParser().getSupportedProtocols().contains(protocol)) {
				Log.errorln("Protocol " + protocol + " MUST NOT BE supported!");
				vulns++;
			}
		}

		return vulns;
	}

	public void printResult() {
		if (oSaft == null) {
			throw new IllegalArgumentException("No data  for print!");
		}

		int vulns = 0;
		if (target.getProfile().isTestCipherSuites()) {
			vulns += printCipherSuites();
		}

		if (target.getProfile().isTestVulnerabilities()) {
			vulns += printVulnerabilities();
		}

		if (target.getProfile().isTestCertificate()) {
			vulns += printCertificateChecks();
		}

		if (target.getProfile().isTestSafeProtocols()) {
			vulns += printProtocols();
		}

		if (vulns <= 0) {
			Log.infoln("Target " + target.getDestination() + " is SAFE.");
		}

	}

}

/*
 * Spusteni scannovani, vraceni vysledku testu
 */
package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.CipherSuite;
import cz.ondrejsmetak.entity.Result;
import cz.ondrejsmetak.facade.OSaftFacade;
import cz.ondrejsmetak.facade.OSaftParser;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.tool.Log;
import javax.crypto.Cipher;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Scanner {

	private OSaftFacade oSaft;
	private Target target;

	public Scanner(Target target) {
		this.target = target;
		oSaft = new OSaftFacade(target);
	}

	public void runScan() {
		oSaft.runScan();
	}

	private void printCipherSuites() {
		if (target.getProfile().isTestSafeCipherSuites()) {
			for (CipherSuite test : oSaft.getParser().getSupportedCipherSuites()) {
				if (!this.target.getProfile().getSafeCipherSuites().contains(test)) {
					Log.errorln("Cipher suite " + test + " isn't considered safe, but is supported!");
				}
			}
		}
	}

	private void printVulnerabilities() {
		doPrintVulnerability("Vulnerable to BEAST!", oSaft.getParser().getBeast());
		doPrintVulnerability("Vulnerable to CRIME!", oSaft.getParser().getCrime());
		doPrintVulnerability("Vulnerable to DROWN!", oSaft.getParser().getDrown());
		doPrintVulnerability("Vulnerable to FREAK!", oSaft.getParser().getFreak());
		doPrintVulnerability("Vulnerable to Heartbleed!", oSaft.getParser().getHeartbleed());
		doPrintVulnerability("Vulnerable to Logjam!", oSaft.getParser().getLogjam());
		doPrintVulnerability("Vulnerable to Lucky 13!", oSaft.getParser().getLucky13());
		doPrintVulnerability("Vulnerable to POODLE!", oSaft.getParser().getPoodle());
		doPrintVulnerability("RC4 ciphers are supported (but they are assumed to be broken)!", oSaft.getParser().getRc4());
		doPrintVulnerability("Vulnerable to Sweet32!", oSaft.getParser().getSweet32());
		doPrintVulnerability("SSLv2 supported!", oSaft.getParser().getSslv2NotSupported());
		doPrintVulnerability("SSLv3 supported!", oSaft.getParser().getSslv3NotSupported());
		doPrintVulnerability("PFS (perfect forward secrecy) not supported!", oSaft.getParser().getPfs());
		doPrintVulnerability("TLS session ticket doesn't contain random value!", oSaft.getParser().getRandomTlsSessionTicket());
	}

	private void printCertificateChecks() {
		doPrintVulnerability("Mismatch between hostname and certificate subject.", oSaft.getParser().getCertificateHostnameMatch());
		doPrintVulnerability("Mismatch between given hostname and reverse resolved hostname.", oSaft.getParser().getCertificateReverseHostnameMatch());
		doPrintVulnerability("Certificate expired.", oSaft.getParser().getCertificateNotExpired());
		doPrintVulnerability("Certificate isn't valid.", oSaft.getParser().getCertificateIsValid());
		doPrintVulnerability("Certificate fingerprint is MD5.", oSaft.getParser().getCertificateFingerprintNotMd5());
		doPrintVulnerability("Certificate Private Key Signature isn't SHA2.", oSaft.getParser().getCertificatePrivateKeySha2());
		doPrintVulnerability("Certificate is self-signed.", oSaft.getParser().getCertificateNotSelfSigned());
		doPrintVulnerability("Wrong size of certificate's public key.", oSaft.getParser().getCertificatePublicKeySize());
		doPrintVulnerability("Wrong size of certificate's signature key.", oSaft.getParser().getCertificateSignatureKeySize());
	}

	private void doPrintVulnerability(String vulnerableMessage, Result result) {
		StringBuilder out = new StringBuilder();
		out.append(vulnerableMessage);
		if (result.hasNote()) {
			out.append(" (").append(result.getNote()).append(")");
		}

		if (result.isVulnerable()) {
			Log.errorln(out.toString());
		} else if (result.isUnknown() && ConfigurationRegister.getInstance().getUnknownTestResultIsError()) {
			Log.errorln(out.toString());
		}
	}

	public void printResult() {
		if (oSaft == null) {
			throw new IllegalArgumentException("No data  for print!");
		}

		printCipherSuites();

		printVulnerabilities();

		printCertificateChecks();

	}

}

package cz.ondrejsmetak.facade;

import cz.ondrejsmetak.ConfigurationRegister;
import cz.ondrejsmetak.entity.CipherSuite;
import cz.ondrejsmetak.entity.Protocol;
import cz.ondrejsmetak.entity.Result;
import cz.ondrejsmetak.tool.Helper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class OSaftParser {

	public enum Algorithm {
		RSA, ECDSA, OTHER
	}

	private List<String> data;

	private static final String YES = "yes";
	private static final String NO = "no";
	private static final String NOTE_REGEX = "(yes|no) (\\(.*\\))";
	private static final String NOT_AVAILABLE = "N/A";

	/**
	 * Vulnerabilities
	 */
	public static final String BEAST_HEADER = "Connection is safe against BEAST attack";
	public static final String BREACH_HEADER = "Connection is safe against BREACH attack"; //but currently (november 2016) not supported by O-Saft
	public static final String CRIME_HEADER = "Connection is safe against CRIME attack";
	public static final String DROWN_HEADER = "Connection is safe against DROWN attack";
	public static final String FREAK_HEADER = "Connection is safe against FREAK attack";
	public static final String HEARTBLEED_HEADER = "Connection is safe against Heartbleed attack";
	public static final String LOGJAM_HEADER = "Connection is safe against Logjam attack";
	public static final String LUCKY_13_HEADER = "Connection is safe against Lucky 13 attack";
	public static final String POODLE_HEADER = "Connection is safe against POODLE attack";
	public static final String RC4_HEADER = "Connection is safe against RC4 attack";
	public static final String SWEET_32_HEADER = "Connection is safe against Sweet32 attack";
	public static final String SSLv2_NOT_SUPPORTED_HEADER = "Target does not support SSLv2"; //is also used in Protocols section
	public static final String SSLv3_NOT_SUPPORTED_HEADER = "Target does not support SSLv3"; //is also used in Protocols section
	public static final String PFS_HEADER = "Target supports PFS (selected cipher)";
	public static final String RANDOM_TLS_SESSION_TICKET_HEADER = "Target TLS Session Ticket is random";

	/**
	 * Basic certificate checks
	 */
	public static final String CERTIFICATE_VALIDITY_HOSTNAME = "Validity Hostname"; //used to compare hostname and CN in certificate 
	public static final String CERTIFICATE_VALIDITY_ALTERNATE_NAMES = "Validity Alternate Names"; //used to compare hostname and CN in certificate 
	public static final String CERTIFICATE_NOT_EXPIRED_HEADER = "Certificate is not expired";
	public static final String CERTIFICATE_IS_VALID_HEADER = "Certificate is valid";
	public static final String CERTIFICATE_FINGERPRINT_NOT_MD5_HEADER = "Certificate Fingerprint is not MD5";
	public static final String CERTIFICATE_PRIVATE_KEY_SHA2_HEADER = "Certificate Private Key Signature SHA2";
	public static final String CERTIFICATE_CHAIN = "Certificate Chain"; //used to test self-signed certificate
	public static final String CERTIFICATE_PUBLIC_KEY_SIZE_HEADER = "Certificate Public Key Length";
	public static final String CERTIFICATE_SIGNATURE_KEY_SIZE_HEADER = "Certificate Signature Key Length";
	public static final String CERTIFICATE_SIGNATURE_ALGORITHM_HEADER = "Certificate Signature Algorithm";
	public static final String CERTIFICATE_PUBLIC_KEY_ALGORITHM_HEADER = "Certificate Public Key Algorithm";

	/**
	 * Others
	 */
	public static final String CANT_MAKE_CONNECTION = "Can't make a connection to";

	/**
	 * Protocols
	 */
	public static final String TLS_1_HEADER = "Target supports TLSv1";
	public static final String TLS_1_1_HEADER = "Target supports TLSv1.1";
	public static final String TLS_1_2_HEADER = "Target supports TLSv1.2";
	public static final String TLS_1_3_HEADER = "Target supports TLSv1.3";

	/**
	 * Vulnerabilities
	 */
	private Result beast = Result.getUnknown();
	private Result breach = Result.getUnknown();
	private Result crime = Result.getUnknown();
	private Result drown = Result.getUnknown();
	private Result freak = Result.getUnknown();
	private Result heartbleed = Result.getUnknown();
	private Result logjam = Result.getUnknown();
	private Result lucky13 = Result.getUnknown();
	private Result poodle = Result.getUnknown();
	private Result rc4 = Result.getUnknown();
	private Result sweet32 = Result.getUnknown();
	private Result sslv2NotSupported = Result.getUnknown();
	private Result sslv3NotSupported = Result.getUnknown();
	private Result pfs = Result.getUnknown();
	private Result randomTlsSessionTicket = Result.getUnknown();

	/**
	 * Certificate checks
	 */
	private Result certificateHostnameMatch = Result.getUnknown();
	private Result certificateNotExpired = Result.getUnknown();
	private Result certificateIsValid = Result.getUnknown();
	private Result certificateFingerprintNotMd5 = Result.getUnknown();
	private Result certificatePrivateKeySha2 = Result.getUnknown();
	private Result certificateNotSelfSigned = Result.getUnknown();
	private String tempValidityHostname = "";
	private String tempValidityAlternateNames = "";

	/**
	 * Certificate signature checks
	 */
	private int certificatePublicKeySize = 0;
	private int certificateSignatureKeySize = 0;
	private Algorithm certificateSignatureAlgorithm = Algorithm.OTHER;
	private Algorithm certificatePublicKeyAlgorithm = Algorithm.OTHER;

	/**
	 * Cipher suites
	 */
	private static final List<CipherSuite> supportedCipherSuites = new ArrayList<>();

	/**
	 * Supported protocols
	 */
	private Result protocolSslv2 = Result.getUnknown();
	private Result protocolSslv3 = Result.getUnknown();
	private Result protocolTlsv10 = Result.getUnknown();
	private Result protocolTlsv11 = Result.getUnknown();
	private Result protocolTlsv12 = Result.getUnknown();
	private Result protocolTlsv13 = Result.getUnknown();

	/**
	 * Other
	 */
	private boolean succesfulConnection = true; //we assume, that target is up and running
	private boolean isReadingCertificateChain = false; //are we currently parsing certificate chain
	private Integer certificateChainDepth = 0;

	/**
	 * Konstruktor
	 *
	 * @param data
	 */
	public OSaftParser(List<String> data) {
		this.data = data;

		parseData();
	}

	private void parseData() {
		for (String line : data) {
			parseUnsuccessfulConnection(line);
			parseVulnerabilities(line);
			parseCertificate(line);
			parseCipherSuites(line);
			parseProtocols(line);
		}
	}

	private void parseUnsuccessfulConnection(String line) {
		if (line.contains(CANT_MAKE_CONNECTION)) {
			succesfulConnection = false;
		}
	}

	private void parseProtocols(String line) {
		this.protocolSslv2 = parseResult(line, SSLv2_NOT_SUPPORTED_HEADER, YES, this.protocolSslv2);
		this.protocolSslv3 = parseResult(line, SSLv3_NOT_SUPPORTED_HEADER, YES, this.protocolSslv3);
		this.protocolTlsv10 = parseResult(line, TLS_1_HEADER, YES, this.protocolTlsv10);
		this.protocolTlsv11 = parseResult(line, TLS_1_1_HEADER, YES, this.protocolTlsv11);
		this.protocolTlsv12 = parseResult(line, TLS_1_2_HEADER, YES, this.protocolTlsv12);

		//TLS 1.3 is draft
		//this.protocolTlsv13 = parseResult(line, TLS_1_3_HEADER, YES, this.protocolSslv3);
	}

	private void parseCipherSuites(String line) {
		String[] pieces = line.split(", ");
		/**
		 * Cipher has exactly eight items in array and fifth item is hex code defined in RFC
		 */
		if (pieces.length == 8 && pieces[5].trim().startsWith("0x")) {
			String name = pieces[6].trim();
			supportedCipherSuites.add(new CipherSuite(name));
		}
	}

	private void parseCertificate(String line) {
		this.certificateNotExpired = parseResult(line, CERTIFICATE_NOT_EXPIRED_HEADER, YES, this.certificateNotExpired);
		this.certificateIsValid = parseResult(line, CERTIFICATE_IS_VALID_HEADER, YES, this.certificateIsValid);
		this.certificateFingerprintNotMd5 = parseResult(line, CERTIFICATE_FINGERPRINT_NOT_MD5_HEADER, YES, this.certificateFingerprintNotMd5);
		this.certificatePrivateKeySha2 = parseResult(line, CERTIFICATE_PRIVATE_KEY_SHA2_HEADER, YES, this.certificatePrivateKeySha2);

		/**
		 * Following tests are not straightforward
		 */
		parseCertificateKeySize(line);
		parseCertificateHostnameMatch(line);
		parseCertificateSelfSigned(line);
	}

	private void parseCertificateSelfSigned(String line) {
		/**
		 * There is (in my opinion) bug
		 * https://github.com/OWASP/O-Saft/issues/65 so we can't use result of
		 * self-signed test directly from O-Saft. Instead, we will check
		 * certificate chain.
		 */
		boolean isCertificateChainLine = line.contains("s:/") || line.contains("i:/");

		if (isHeader(line, CERTIFICATE_CHAIN)) {
			isReadingCertificateChain = true; //we just started parsing certificate chain
			certificateChainDepth = 0; //so current depth is zero
			return; //nothing to do now, we must read following lines (in future iterations)
		}

		if (isReadingCertificateChain && isCertificateChainLine) {
			String chain = line.trim();
			if (!chain.isEmpty() && Character.isDigit(chain.charAt(0))) {
				certificateChainDepth = Math.max(certificateChainDepth, Character.getNumericValue(chain.charAt(0)));
				this.certificateNotSelfSigned = certificateChainDepth > 0 ? Result.getSafe() : Result.getVulnerable();
			}
		}
	}

	private void parseCertificateKeySize(String line) {
		/**
		 * Public key
		 */
		certificatePublicKeySize = doParseCertificateKeySize(line, CERTIFICATE_PUBLIC_KEY_SIZE_HEADER, certificatePublicKeySize);
		certificatePublicKeyAlgorithm = doParseAlgorithm(line, CERTIFICATE_PUBLIC_KEY_ALGORITHM_HEADER, certificatePublicKeyAlgorithm);

		/**
		 * Signature key
		 */
		certificateSignatureKeySize = doParseCertificateKeySize(line, CERTIFICATE_SIGNATURE_KEY_SIZE_HEADER, certificateSignatureKeySize);
		certificateSignatureAlgorithm = doParseAlgorithm(line, CERTIFICATE_SIGNATURE_ALGORITHM_HEADER, certificateSignatureAlgorithm);
	}

	private void parseCertificateHostnameMatch(String line) {
		if (isHeader(line, CERTIFICATE_VALIDITY_HOSTNAME) && tempValidityHostname.isEmpty()) {
			tempValidityHostname = parseValue(line, CERTIFICATE_VALIDITY_HOSTNAME);
			return;
		}

		if (isHeader(line, CERTIFICATE_VALIDITY_ALTERNATE_NAMES) && tempValidityAlternateNames.isEmpty()) {
			tempValidityAlternateNames = parseValue(line, CERTIFICATE_VALIDITY_ALTERNATE_NAMES);
			return;
		}

		Pattern pattern;
		Matcher matcher;

		//1) Check, if hostname matches CN in certificate
		pattern = Pattern.compile("Given hostname '(.+)' matches CN '(.+)' in certificate");
		matcher = pattern.matcher(tempValidityHostname);
		if (matcher.matches()) {
			certificateHostnameMatch = Result.getSafe();
			return;
		}

		//2) Check, if some hostname matches some alternate name in certificate
		//2) It also covers check for wildcard certificate
		pattern = Pattern.compile("Given hostname '(.+)' matches alternate name '(.+)' in certificate");
		matcher = pattern.matcher(tempValidityAlternateNames);
		if (matcher.matches()) {
			certificateHostnameMatch = Result.getSafe();
			return;
		}

		//3) If we get here, it means vulnerable result
		pattern = Pattern.compile("Given hostname '(.+)' does not match CN '(.+)' in certificate");
		matcher = pattern.matcher(tempValidityHostname);
		if (matcher.matches()) {
			String givenHostname = matcher.group(1);
			String commonName = matcher.group(2);
			String vulnerableMessage = givenHostname + " <> " + commonName;
			certificateHostnameMatch = Result.getVulnerable(vulnerableMessage);

		}
	}

	private Algorithm doParseAlgorithm(String line, String header, Algorithm previousAlgorithm) {
		if (isHeader(line, header)) {
			String value = parseValue(line, header);

			if (value.toLowerCase().contains("rsa")) {
				return Algorithm.RSA;
			}

			if (value.toLowerCase().contains("ecdsa")) {
				return Algorithm.ECDSA;
			}
		}

		return previousAlgorithm;
	}

	private int doParseCertificateKeySize(String line, String header, int previousSize) {
		if (isHeader(line, header)) {
			String value = parseValue(line, header);
			value = value.replace(" bits", "");

			if (!Helper.isInteger(value)) {
				return -1;
			} else {
				return Integer.parseInt(value);
			}
		}

		return previousSize;
	}

	private void parseVulnerabilities(String line) {
		this.beast = parseResult(line, BEAST_HEADER, YES, this.beast);
		this.breach = parseResult(line, BREACH_HEADER, YES, this.breach);
		this.crime = parseResult(line, CRIME_HEADER, YES, this.crime);
		this.drown = parseResult(line, DROWN_HEADER, YES, this.drown);
		this.freak = parseResult(line, FREAK_HEADER, YES, this.freak);
		this.heartbleed = parseResult(line, HEARTBLEED_HEADER, YES, this.heartbleed);
		this.logjam = parseResult(line, LOGJAM_HEADER, YES, this.logjam);
		this.lucky13 = parseResult(line, LUCKY_13_HEADER, YES, this.lucky13);
		this.poodle = parseResult(line, POODLE_HEADER, YES, this.poodle);
		this.rc4 = parseResult(line, RC4_HEADER, YES, this.rc4);
		this.sweet32 = parseResult(line, SWEET_32_HEADER, YES, this.sweet32);
		this.sslv2NotSupported = parseResult(line, SSLv2_NOT_SUPPORTED_HEADER, YES, this.sslv2NotSupported);
		this.sslv3NotSupported = parseResult(line, SSLv3_NOT_SUPPORTED_HEADER, YES, this.sslv3NotSupported);
		this.pfs = parseResult(line, PFS_HEADER, YES, this.pfs);
		this.randomTlsSessionTicket = parseResult(line, RANDOM_TLS_SESSION_TICKET_HEADER, YES, this.randomTlsSessionTicket);
	}

	private String parseValue(String line, String header) {
		if (line.startsWith(header)) {
			String[] pieces = line.split("\t");

			if (pieces.length >= 2) {
				return pieces[1];
			}
		}

		return "";
	}

	/**
	 * Na řádku je rovnou uvedeno ano/ne, jestli je daný test safe nebo ne
	 *
	 * @param line
	 * @param header
	 * @param safeResult
	 * @param previousResult
	 * @return
	 */
	private Result parseResult(String line, String header, String safeResult, Result previousResult) {
		if (isHeader(line, header)) {
			String[] pieces = line.split("\t");
			if (pieces.length >= 2) {
				return parseBoolean(pieces[1], safeResult);
			}
		}

		return previousResult;
	}

	private boolean isHeader(String line, String header) {
		String[] pieces = line.split("\t");
		if (pieces.length >= 1) {
			return pieces[0].equals(header);
		}

		return false;
	}

	private String parseNote(String line) {
		String tmp = line;
		tmp = tmp.replace(YES + " ", "");
		tmp = tmp.replace(NO + " ", "");

		return tmp;
	}

	private Result parseBoolean(String value, String safeResult) {
		boolean hasNote = value.matches(NOTE_REGEX);
		boolean isUnknown = parseNote(value).contains(NOT_AVAILABLE);

		if (isUnknown) {
			return hasNote ? Result.getUnknown(parseNote(value)) : Result.getUnknown();
		}

		if (value.startsWith(YES) && safeResult.equals(YES)) {
			return hasNote ? Result.getSafe(parseNote(value)) : Result.getSafe();
		}

		if (value.startsWith(NO) && safeResult.equals(NO)) {
			return hasNote ? Result.getSafe(parseNote(value)) : Result.getSafe();
		}

		if ((value.startsWith(NO) || value.startsWith(YES))) {
			return hasNote ? Result.getVulnerable(parseNote(value)) : Result.getVulnerable();
		}

		return createUnexpectedValue();
	}

	private Result createUnexpectedValue() {
		return Result.getUnknown("O-Saft returned unexpected value");
	}

	public Result getBeast() {
		return beast;
	}

	public Result getBreach() {
		return breach;
	}

	public Result getCrime() {
		return crime;
	}

	public Result getDrown() {
		return drown;
	}

	public Result getFreak() {
		return freak;
	}

	public Result getHeartbleed() {
		return heartbleed;
	}

	public Result getLogjam() {
		return logjam;
	}

	public Result getLucky13() {
		return lucky13;
	}

	public Result getPoodle() {
		return poodle;
	}

	public Result getRc4() {
		return rc4;
	}

	public Result getSweet32() {
		return sweet32;
	}

	public Result getSslv2NotSupported() {
		return sslv2NotSupported;
	}

	public Result getSslv3NotSupported() {
		return sslv3NotSupported;
	}

	public Result getPfs() {
		return pfs;
	}

	public Result getRandomTlsSessionTicket() {
		return randomTlsSessionTicket;
	}

	public Result getCertificateHostnameMatch() {
		return certificateHostnameMatch;
	}

	public Result getCertificateNotExpired() {
		return certificateNotExpired;
	}

	public Result getCertificateIsValid() {
		return certificateIsValid;
	}

	public Result getCertificateFingerprintNotMd5() {
		return certificateFingerprintNotMd5;
	}

	public Result getCertificatePrivateKeySha2() {
		return certificatePrivateKeySha2;
	}

	public Result getCertificateNotSelfSigned() {
		return certificateNotSelfSigned;
	}

	public int getCertificatePublicKeySize() {
		return certificatePublicKeySize;
	}

	public int getCertificateSignatureKeySize() {
		return certificateSignatureKeySize;
	}

	public Algorithm getCertificatePublicKeyAlgorithm() {
		return certificatePublicKeyAlgorithm;
	}

	public Algorithm getCertificateSignatureAlgorithm() {
		return certificateSignatureAlgorithm;
	}

	public List<CipherSuite> getSupportedCipherSuites() {
		return supportedCipherSuites;
	}

	public Result getProtocolSslv2() {
		return protocolSslv2;
	}

	public Result getProtocolSslv3() {
		return protocolSslv3;
	}

	public Result getProtocolTlsv10() {
		return protocolTlsv10;
	}

	public Result getProtocolTlsv11() {
		return protocolTlsv11;
	}

	public Result getProtocolTlsv12() {
		return protocolTlsv12;
	}

	public Result getProtocolTlsv13() {
		return protocolTlsv13;
	}

	public boolean isSuccesfulConnection() {
		return succesfulConnection;
	}
}

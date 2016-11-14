package cz.ondrejsmetak.facade;

import cz.ondrejsmetak.ConfigurationRegister;
import cz.ondrejsmetak.entity.Result;
import cz.ondrejsmetak.tool.Helper;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class OSaftParser {

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
	public static final String SSLv2_NOT_SUPPORTED_HEADER = "Target does not support SSLv2";
	public static final String SSLv3_NOT_SUPPORTED_HEADER = "Target does not support SSLv3";
	public static final String PFS_HEADER = "Target supports PFS (selected cipher)";
	public static final String RANDOM_TLS_SESSION_TICKET_HEADER = "Target TLS Session Ticket is random";

	/**
	 * Basic certificate checks
	 */
	public static final String HOSTNAME_MATCH_HEADER = "Connected hostname matches certificate's subject";
	public static final String REVERSE_HOSTNAME_MATCH_HEADER = "Given hostname is same as reverse resolved hostname";
	public static final String CERTIFICATE_NOT_EXPIRED = "Certificate is not expired";
	public static final String CERTIFICATE_IS_VALID = "Certificate is valid";
	public static final String CERTIFICATE_FINGERPRINT_NOT_MD5 = "Certificate Fingerprint is not MD5";
	public static final String CERTIFICATE_PRIVATE_KEY_SHA2 = "Certificate Private Key Signature SHA2";
	public static final String CERTIFICATE_NOT_SELF_SIGNED = "Certificate is not self-signed";
	public static final String CERTIFICATE_PUBLIC_KEY_SIZE = "Certificate Public Key size";
	public static final String CERTIFICATE_SIGNATURE_KEY_SIZE = "Certificate Signature Key size";

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
	private Result hostnameMatch = Result.getUnknown();
	private Result reverseHostnameMatch = Result.getUnknown();
	private Result certificateNotExpired = Result.getUnknown();
	private Result certificateIsValid = Result.getUnknown();
	private Result certificateFingerprintNotMd5 = Result.getUnknown();
	private Result certificatePrivateKeySha2 = Result.getUnknown();
	private Result certificateNotSelfSigned = Result.getUnknown();
	private Result certificatePublicKeySize = Result.getUnknown();
	private Result certificateSignatureKeySize = Result.getUnknown();

	public OSaftParser(List<String> data) {
		this.data = data;

		parseData();
	}

	private void parseData() {
		for (String line : data) {
			//parseVulnerabilities(line);
			parseCertificate(line);
		}
	}

	private void parseCertificate(String line) {
		this.hostnameMatch = parseResult(line, HOSTNAME_MATCH_HEADER, YES, this.hostnameMatch);
		this.reverseHostnameMatch = parseResult(line, REVERSE_HOSTNAME_MATCH_HEADER, YES, this.reverseHostnameMatch);
		this.certificateNotExpired = parseResult(line, REVERSE_HOSTNAME_MATCH_HEADER, YES, this.certificateNotExpired);
		this.certificateIsValid = parseResult(line, REVERSE_HOSTNAME_MATCH_HEADER, YES, this.certificateIsValid);
		this.certificateFingerprintNotMd5 = parseResult(line, REVERSE_HOSTNAME_MATCH_HEADER, YES, this.certificateFingerprintNotMd5);
		this.certificatePrivateKeySha2 = parseResult(line, REVERSE_HOSTNAME_MATCH_HEADER, YES, this.certificatePrivateKeySha2);
		this.certificateNotSelfSigned = parseResult(line, REVERSE_HOSTNAME_MATCH_HEADER, YES, this.certificateNotSelfSigned);

		/**
		 * Následující testy jsou složitější
		 */
		parseCertificatePublicKeySize(line);

	}

	private void parseCertificatePublicKeySize(String line) {
		if (isHeader(line, CERTIFICATE_PUBLIC_KEY_SIZE)) {
			String value = parseValue(line, CERTIFICATE_PUBLIC_KEY_SIZE);
			value = value.replace(" bits", "");

			int minimum = ConfigurationRegister.getInstance().getCertificateMinimumKeySize();

			if (!Helper.isInteger(value)) {
				this.certificatePublicKeySize = createUnexpectedValue();
			} else if (Integer.valueOf(value) < minimum) {
				this.certificatePublicKeySize = Result.getVulnerable(String.format("Expected certificate public key size was at least %s, but current value is %s",
						String.valueOf(minimum), value));
			} else {
				this.certificatePublicKeySize = Result.getSafe(String.format("%s >= %s", value, minimum));
			}
		}
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
		return line.startsWith(header);
	}

	private String parseNote(String line) {
		String tmp = line;
		tmp = tmp.replace(YES + " ", "");
		tmp = tmp.replace(NO + " ", "");

		return tmp;
	}

	private Result parseBoolean(String value, String safeResult) {
		boolean hasNote = value.matches(NOTE_REGEX);

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

	public Result getHostnameMatch() {
		return hostnameMatch;
	}

	public Result getReverseHostnameMatch() {
		return reverseHostnameMatch;
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
	
	public Result getCertificatePublicKeySize() {
		return certificatePublicKeySize;
	}
	
	public Result getCertificateSignatureKeySize() {
		return certificateSignatureKeySize;
	}
}

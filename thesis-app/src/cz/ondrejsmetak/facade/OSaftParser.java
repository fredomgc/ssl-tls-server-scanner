package cz.ondrejsmetak.facade;

import cz.ondrejsmetak.other.Result;
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
	private static final String NOTE_REGEX = "(yes|no) (\\(<<.*>>\\))";
	private static final String NOT_AVAILABLE = "N/A";

	private static final String BEAST_HEADER = "Connection is safe against BEAST attack";
	private static final String BREACH_HEADER = "Connection is safe against BREACH attack"; //but currently (november 2016) not supported by O-Saft
	private static final String CRIME_HEADER = "Connection is safe against CRIME attack";
	private static final String DROWN_HEADER = "Connection is safe against DROWN attack";
	private static final String FREAK_HEADER = "Connection is safe against FREAK attack";
	private static final String HEARTBLEED_HEADER = "Connection is safe against Heartbleed attack";
	private static final String LOGJAM_HEADER = "Connection is safe against Logjam attack";
	private static final String LUCKY_13_HEADER = "Connection is safe against Lucky 13 attack";
	private static final String POODLE_HEADER = "Connection is safe against POODLE attack";
	private static final String RC4_HEADER = "Connection is safe against RC4 attack";
	private static final String SWEET_32_HEADER = "Connection is safe against Sweet32 attack";
	private static final String SSLv2_NOT_SUPPORTED_HEADER = "Target does not support SSLv2";
	private static final String SSLv3_NOT_SUPPORTED_HEADER = "Target does not support SSLv3";
	private static final String PFS_HEADER = "Target supports PFS (selected cipher)";
	private static final String RANDOM_TLS_SESSION_TICKET_HEADER = "Target TLS Session Ticket is random";

	/**
	 * ^^
	 *
	 * Connection is safe against BEAST attack (any cipher):	no ( TLSv1 TLSv11)
	 * Connection is safe against BREACH attack:	no (<<NOT YET IMPLEMENTED>>)
	 * Connection is safe against CRIME attack:	yes Connection is safe against
	 * DROWN attack:	yes Connection is safe against FREAK attack:	yes Connection
	 * is safe against Heartbleed attack:	yes Connection is safe against Logjam
	 * attack:	yes Connection is safe against Lucky 13 attack:	yes Connection is
	 * safe against POODLE attack:	yes Connection is safe against RC4 attack:
	 * yes Connection is safe against Sweet32 attack:	yes Target does not
	 * support SSLv2: yes Target does not support SSLv3: yes Target supports PFS
	 * (selected cipher):	yes Target TLS Session Ticket is random:	yes
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
	
	public OSaftParser(List<String> data) {
		this.data = data;

		parseData();
	}

	private void parseData() {
		for (String line : data) {
			this.beast = parseVulnerability(line, BEAST_HEADER, this.beast);
			this.breach = parseVulnerability(line, BREACH_HEADER, this.breach);
			this.crime = parseVulnerability(line, CRIME_HEADER, this.crime);
			this.drown = parseVulnerability(line, DROWN_HEADER, this.drown);
			this.freak = parseVulnerability(line, FREAK_HEADER, this.freak);
			this.heartbleed = parseVulnerability(line, HEARTBLEED_HEADER, this.heartbleed);
			this.logjam = parseVulnerability(line, LOGJAM_HEADER, this.logjam);
			this.lucky13 = parseVulnerability(line, LUCKY_13_HEADER, this.lucky13);
			this.poodle = parseVulnerability(line, POODLE_HEADER, this.poodle);
			this.rc4 = parseVulnerability(line, RC4_HEADER, this.rc4);
			this.sweet32 = parseVulnerability(line, SWEET_32_HEADER, this.sweet32);
			this.sslv2NotSupported = parseVulnerability(line, SSLv2_NOT_SUPPORTED_HEADER, this.sslv2NotSupported);
			this.sslv3NotSupported = parseVulnerability(line, SSLv3_NOT_SUPPORTED_HEADER, this.sslv3NotSupported);
			this.pfs = parseVulnerability(line, PFS_HEADER, this.pfs);
			this.randomTlsSessionTicket = parseVulnerability(line, RANDOM_TLS_SESSION_TICKET_HEADER, this.randomTlsSessionTicket);
		}
	}

	private Result parseVulnerability(String line, String header, Result previousResult) {
		if (line.startsWith(header)) {
			String[] pieces = line.split("\t");
			if (pieces.length >= 2) {
				return parseBoolean(pieces[1]);
			}
		}

		return previousResult;
	}
	
	private Result parseBoolean(String value) {

		if (value.equals(YES)) {
			return Result.getSafe();
		}

		if (value.equals(NO)) {
			return Result.getVulnerable();
		}

		if (value.matches(NOTE_REGEX)) {
			if ((value.startsWith(NO) && value.contains(NOT_AVAILABLE)) || (value.startsWith(NO))) {
				return Result.getUnknown(value.replace(NO + " ", ""));
			}
		}

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


	
	
	
}

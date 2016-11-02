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

	private static final String HEARTBLEED_HEADER = "Connection is safe against Heartbleed attack";
	private static final String BREACH_HEADER = "Connection is safe against BREACH attack";

	private Result heartbleed = Result.getUnknown();
	private Result breach = Result.getUnknown();

	public OSaftParser(List<String> data) {
		this.data = data;

		parseData();
	}

	private void parseData() {
		for (String line : data) {
			parseHeartbleed(line);
			parseBreach(line);
		}
	}

	private void parseHeartbleed(String line) {
		if (line.startsWith(HEARTBLEED_HEADER)) {
			String[] pieces = line.split("\t");
			if (pieces.length >= 2) {
				this.heartbleed = parseBoolean(pieces[1]);
			}
		}
	}

	private void parseBreach(String line) {
		if (line.startsWith(BREACH_HEADER)) {
			String[] pieces = line.split("\t");
			//System.err.println("Pieces je: " + Arrays.toString(pieces));

			if (pieces.length >= 2) {
				this.breach = parseBoolean(pieces[1]);
			}
		}
	}

	private Result parseBoolean(String value) {
		//System.err.println("Testuji " + value);

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

	public Result getHeartbleed() {
		return heartbleed;
	}
	
	public Result getBreach() {
		return breach;
	}
	
}

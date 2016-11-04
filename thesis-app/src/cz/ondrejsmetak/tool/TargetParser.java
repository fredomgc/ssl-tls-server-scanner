package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.other.Target;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser of configuration file, that contains targets of scanning
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class TargetParser {

	private static final String COMMENT = "#";
	private static final String DELIMITER = ";";

	public List<Target> parse() {
		List<Target> targets = new ArrayList<>();

		try (BufferedReader br = new BufferedReader(new FileReader("targets.cfg"))) {
			for (String line; (line = br.readLine()) != null;) {
				Target target = parseLine(line);
				if (target != null) {
					targets.add(target);
				}
			}
		} catch (IOException ex) {
			Log.errorln(ex.toString());
		}

		return targets;
	}

	private Target parseLine(String line) {
		if (line.startsWith(COMMENT)) { //comment
			return null;
		}

		String[] pieces = line.split(DELIMITER);
		if (pieces.length < 2) {
			return null; //wrong format
		}

		String target = pieces[0];
		List<String> scans = new ArrayList<>();

		for (int i = 1; i < pieces.length; i++) {
			scans.add(pieces[i]);
		}

		return new Target(target, scans);
	}

}

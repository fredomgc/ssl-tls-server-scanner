package cz.ondrejsmetak;

import cz.ondrejsmetak.other.Target;
import cz.ondrejsmetak.tool.Log;
import cz.ondrejsmetak.tool.TargetParser;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ScannerManager {

	public void perform() {
		Log.infoln("Reading configuration, looking for targets...");
		TargetParser targetParser = new TargetParser();
		List<Target> targets = targetParser.parse();

		if (!targets.isEmpty()) {
			Log.infoln("Targets found, performing scans...");
		}

		for (Target target : targets) {
			Log.infoln("***");
			Log.infoln("Running scan of " + target.getTarget());
			Scanner scanner = new Scanner(target);
			scanner.performScan();
			scanner.printResult(target);

			Log.infoln("Scan finished");
		}

	}

}

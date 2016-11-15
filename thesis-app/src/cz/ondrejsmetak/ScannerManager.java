package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.other.XmlParserException;
import cz.ondrejsmetak.tool.ConfigurationParser;
import cz.ondrejsmetak.tool.Log;
import cz.ondrejsmetak.tool.TargetParser;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ScannerManager {

	public void perform() {
		try {
			Log.infoln("Parsing \"configuration.xml\" for application configuration...");
			ConfigurationParser configurationParser = new ConfigurationParser();
			configurationParser.parse();
			Log.infoln("Parsing \"targets.xml\" for targets...");
			TargetParser targetParser = new TargetParser();
			List<Target> targets = targetParser.parse();
			
			if (!targets.isEmpty()) {
				Log.infoln("Targets found, performing scans...");
			}

			for (Target target : targets) {
				Log.infoln("***");
				Log.infoln("Running scan of " + target.getDestination());
				Scanner scanner = new Scanner(target);
				scanner.runScan();
				scanner.printResult();

				Log.infoln("Scan finished");
			}
			
		} catch (XmlParserException ex) {
			Logger.getLogger(ScannerManager.class.getName()).log(Level.SEVERE, null, ex);
		}

	}

}

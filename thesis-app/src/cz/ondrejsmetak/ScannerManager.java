package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.Report;
import cz.ondrejsmetak.entity.ReportMessage;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.other.XmlParserException;
import cz.ondrejsmetak.tool.ConfigurationParser;
import cz.ondrejsmetak.tool.HtmlExport;
import cz.ondrejsmetak.tool.Log;
import cz.ondrejsmetak.tool.TargetParser;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ScannerManager {

	ConfigurationParser configurationParser = new ConfigurationParser();
	TargetParser targetParser = new TargetParser();

	private boolean createDefault() throws IOException {
		boolean created = false;

		if (!configurationParser.hasFile()) {
			configurationParser.createDefault();
			Log.infoln("Creating default " + ConfigurationParser.FILE + " in application folder.");
		}

		if (!targetParser.hasFile()) {
			targetParser.createDefault();
			Log.infoln("Creating default " + TargetParser.FILE + " in application folder.");
		}

		return created;
	}

	/**
	 * Performs all required scans and creates report (as HTML file)
	 * @return true, if all targets are safe, false otherwise (at least one vulnerable)
	 */
	public boolean perform() {
		try {
			if (createDefault()) {
				Log.infoln("Please review configuration in XML files and run application again.");
				return false;
			}

			Log.infoln("Parsing " + ConfigurationParser.FILE + " for application configuration.");
			configurationParser.parse();
			List<String> missingDirectives = ConfigurationRegister.getInstance().getMissingDirectives();

			if (!missingDirectives.isEmpty()) {
				Log.errorln("Following configurationd directives are missing " + missingDirectives + ", can't continue without them!");
				return false;
			}

			Log.infoln("Parsing " + TargetParser.FILE + " for targets.");
			List<Target> targets = targetParser.parse();

			if (!targets.isEmpty()) {
				Log.infoln("Targets found, performing scans...");
			}

			List<Report> reports = new ArrayList<>();
			int vulns = 0;

			for (Target target : targets) {
				Log.infoln("***");
				Log.infoln("Running scan of " + target.getDestination());
				Scanner scanner = new Scanner(target);
				scanner.runScan();

				List<ReportMessage> vulnerableMessages = scanner.getVulnerableMessages();
				vulns += vulnerableMessages.size();

				
				target.getProfile().isTestCertificate();
				reports.add(new Report(target, vulnerableMessages, scanner.getSafeMessages()));
				Log.infoln("Scan finished");
			}

			HtmlExport export = new HtmlExport();
			String report = export.export(reports);
			Log.infoln(String.format("Scan report saved in [%s]", report));
			
			return vulns == 0;
		} catch (XmlParserException | IOException ex) {
			Log.errorln(ex);
		}

		return false;
	}

}

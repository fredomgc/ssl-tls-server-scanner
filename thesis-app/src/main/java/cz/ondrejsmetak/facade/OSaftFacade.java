package cz.ondrejsmetak.facade;

import cz.ondrejsmetak.ConfigurationRegister;
import cz.ondrejsmetak.entity.Result;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.tool.Helper;
import cz.ondrejsmetak.tool.Log;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * API for O-Saft tool
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class OSaftFacade extends BaseFacade {

	/**
	 * Target, that will be scanned
	 */
	private Target target;

	/**
	 * Raw data returned by O-Saft tool
	 */
	private List<String> data = new ArrayList<>();

	/**
	 * Parser for (raw) data returned by O-Saft tool
	 */
	private OSaftParser parser;

	/**
	 * Creates new O-Saft API for given target
	 *
	 * @param target
	 */
	public OSaftFacade(Target target) {
		this.target = target;
	}

	/**
	 * Run O-Saft tool and parse results
	 */
	public void runScan() {
		data.clear();
		data.addAll(getData());
		parser = new OSaftParser(data);
	}

	/**
	 * Data returned by O-Saft tool
	 *
	 * @return collection of lines. Each line represents same line returned by
	 * O-Saft tool
	 */
	private List<String> getData() {
		if (data.isEmpty()) {
			if (target.getProfile().isTestVulnerabilities()) {
				data.addAll(doCmd(target.getDestination(), "+check"));
			}

			if (target.getProfile().isTestCipherSuites()){
				data.addAll(doCmd(target.getDestination(), "+cipherall"));
			}
			
			if (target.getProfile().isTestCertificate()) {
				data.addAll(doCmd(target.getDestination(), "+info"));
				data.addAll(doCmd(target.getDestination(), "+chain"));
			}

			if (target.getProfile().isTestProtocols()) {
				data.addAll(doCmd(target.getDestination(), "+protocols"));
			}
		}
		
		//data.forEach(System.out::println);
		
		return data;
	}

	/**
	 * Runs O-Saft tool with given parameters
	 *
	 * @param args collection of arguments, that will be passed to O-Saft tool
	 * @return data returned by O-Saft tool
	 */
	private List<String> doCmd(String... args) {
		String[] rawArgs = new String[args.length + 3];
		rawArgs[0] = ConfigurationRegister.getInstance().getOSaftFolderAbsolutePath() + "o-saft.pl"; //first arg is path to tool
		rawArgs[1] = "--legacy=quick"; //second arg for easier parsing
		rawArgs[2] = "--no-header"; //third arg for easier parsing

		int i = 3;
		for (String arg : args) {
			rawArgs[i++] = arg; //following args are passed ones
		}

		Log.infoln("Running O-Saft with args: " + Arrays.toString(rawArgs));
		return Helper.doCmd(rawArgs); //run a command
	}

	/**
	 * Returns O-Saft parser
	 *
	 * @return O-Saft parser
	 */
	public OSaftParser getParser() {
		return parser;
	}
}

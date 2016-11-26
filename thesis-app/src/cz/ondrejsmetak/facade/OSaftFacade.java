/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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

	private Target target;

	private List<String> data = new ArrayList<>();

	private OSaftParser parser;

	public OSaftFacade(Target target) {
		this.target = target;
	}

	public void runScan() {
		data.clear();
		data.addAll(getData());
		parser = new OSaftParser(data);
	}

	private List<String> getData() {
		if (data.isEmpty()) {
			if (target.getProfile().isTestCipherSuites() || target.getProfile().isTestVulnerabilities()) {
				data.addAll(doCmd(target.getDestination(), "+check"));
			}

			if (target.getProfile().isTestCertificate()) {
				data.addAll(doCmd(target.getDestination(), "+info"));
			}

			if (target.getProfile().isTestSafeProtocols()) {
				data.addAll(doCmd(target.getDestination(), "+protocols"));
			}
		}
		return data;
	}

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

	public OSaftParser getParser() {
		return parser;
	}
}

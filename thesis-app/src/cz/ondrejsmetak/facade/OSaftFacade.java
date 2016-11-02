/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.ondrejsmetak.facade;

import cz.ondrejsmetak.other.Result;
import cz.ondrejsmetak.tool.Helper;
import cz.ondrejsmetak.tool.Log;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class OSaftFacade extends BaseFacade {

	private String target;

	private static final String O_SAFT_LOCATION = "/home/fredomgc/thesis/o-saft/"; //TODO - napsat normalne

	private List<String> data = new ArrayList<>();
	
	
	private OSaftParser parser;
	
	public OSaftFacade(String target) {
		this.target = target;
	}

	private void doScan() {

	}

	public void doSomething() {
		data.clear();
		data.addAll(getData());
		parser = new OSaftParser(data);
		
		
	}

	/**
	 * Je zranitelné na heartbleed
	 *
	 * @return
	 */
	public Result isHeartbleed() {

		
		
		return null;
	}

	private List<String> getData() {
		if (data.isEmpty()) {
			//spustime scan
			data.addAll(doCmd(target, "+check"));
		}

		return data;
	}

	private List<String> doCmd(String... args) {
		String[] rawArgs = new String[args.length + 3];
		rawArgs[0] = O_SAFT_LOCATION + "o-saft.pl"; //first arg is path to tool
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

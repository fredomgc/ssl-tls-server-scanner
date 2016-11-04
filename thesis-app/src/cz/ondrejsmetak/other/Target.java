/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.ondrejsmetak.other;

import java.util.List;
import java.util.logging.Logger;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Target {

	private static final String SCAN_HEARTBLEED = "heartbleed";
	private static final String SCAN_BREACH = "heartbleed";

	private String target = "";
	private boolean scanHeartbleed = false;
	private boolean scanBreach = false;

	public Target(String target, List<String> scans) {
		this.target = target;
		parseScans(scans);
	}

	private void parseScans(List<String> scans) {
		for (String scan : scans) {
			parseScan(scan);
		}
	}

	private void parseScan(String scan) {
		this.scanHeartbleed = scanHeartbleed || doMatch(scan, SCAN_HEARTBLEED);
		this.scanBreach = scanBreach || doMatch(scan, SCAN_BREACH);
	}

	private boolean doMatch(String scan, String expectedCodeName) {
		return scan.equalsIgnoreCase(expectedCodeName);
	}
	
	public String getTarget() {
		return target;
	}

	public boolean isScanHeartbleed() {
		return scanHeartbleed;
	}

	public boolean isScanBreach() {
		return scanBreach;
	}
}

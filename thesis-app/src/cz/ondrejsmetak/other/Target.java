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
	
	private static final String SCAN_BEAST = "beast";
	private static final String SCAN_BREACH = "breach";
	private static final String SCAN_CRIME = "crime";
	private static final String SCAN_DROWN = "drown";
	private static final String SCAN_FREAK = "freak";
	private static final String SCAN_HEARTBLEED = "heartbleed";
	private static final String SCAN_LOGJAM = "logjam";
	private static final String SCAN_LUCKY_13 = "lucky13";
	private static final String SCAN_POODLE = "poodle";
	private static final String SCAN_RC4 = "rc4";
	private static final String SCAN_SWEET32 = "sweet32";
	private static final String SCAN_SSLv2_NOT_SUPPORTED = "!sslv2";
	private static final String SCAN_SSLv3_NOT_SUPPORTED = "!sslv3";
	private static final String SCAN_PFS = "pfs";
	private static final String SCAN_RANDOM_TLS_SESSION_TICKET = "randomTlsSessionTicket";
	

	private String target = "";
	
	private boolean scanBeast = false;
	private boolean scanBreach = false;
	private boolean scanCrime = false;
	private boolean scanDrown = false;
	private boolean scanFreak = false;
	private boolean scanHeartbleed = false;
	private boolean scanLogjam = false;
	private boolean scanLucky13 = false;
	private boolean scanPoodle = false;
	private boolean scanRc4 = false;
	private boolean scanSweet32 = false;
	private boolean scanSSLv2NotSupported = false;
	private boolean scanSSLv3NotSupported = false;
	private boolean scanPFS = false;
	private boolean scanRandomTlsSessionTicket = false;
	
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
		this.scanBeast = scanBeast || doMatch(scan, SCAN_BEAST);
		this.scanBreach = scanBreach || doMatch(scan, SCAN_BREACH);
		this.scanCrime = scanCrime || doMatch(scan, SCAN_CRIME);
		this.scanDrown = scanDrown || doMatch(scan, SCAN_DROWN);
		this.scanFreak = scanFreak || doMatch(scan, SCAN_FREAK);
		this.scanHeartbleed = scanHeartbleed || doMatch(scan, SCAN_HEARTBLEED);
		this.scanLogjam = scanLogjam || doMatch(scan, SCAN_LOGJAM);
		this.scanLucky13 = scanLucky13 || doMatch(scan, SCAN_LUCKY_13);
		this.scanPoodle = scanPoodle || doMatch(scan, SCAN_POODLE);
		this.scanRc4 = scanRc4 || doMatch(scan, SCAN_RC4);
		this.scanSweet32 = scanSweet32 || doMatch(scan, SCAN_SWEET32);
		this.scanSSLv2NotSupported = scanSSLv2NotSupported || doMatch(scan, SCAN_SSLv2_NOT_SUPPORTED);
		this.scanSSLv3NotSupported = scanSSLv3NotSupported || doMatch(scan, SCAN_SSLv3_NOT_SUPPORTED);
		this.scanPFS = scanPFS || doMatch(scan, SCAN_PFS);
		this.scanRandomTlsSessionTicket = scanRandomTlsSessionTicket || doMatch(scan, SCAN_RANDOM_TLS_SESSION_TICKET);
	}

	private boolean doMatch(String scan, String expectedCodeName) {
		return scan.equalsIgnoreCase(expectedCodeName);
	}
	
	public String getTarget() {
		return target;
	}

	public boolean isScanBeast() {
		return scanBeast;
	}

	public boolean isScanBreach() {
		return scanBreach;
	}

	public boolean isScanCrime() {
		return scanCrime;
	}

	public boolean isScanDrown() {
		return scanDrown;
	}

	public boolean isScanFreak() {
		return scanFreak;
	}

	public boolean isScanHeartbleed() {
		return scanHeartbleed;
	}

	public boolean isScanLogjam() {
		return scanLogjam;
	}

	public boolean isScanLucky13() {
		return scanLucky13;
	}

	public boolean isScanPoodle() {
		return scanPoodle;
	}

	public boolean isScanRc4() {
		return scanRc4;
	}

	public boolean isScanSweet32() {
		return scanSweet32;
	}

	public boolean isScanSSLv2NotSupported() {
		return scanSSLv2NotSupported;
	}

	public boolean isScanSSLv3NotSupported() {
		return scanSSLv3NotSupported;
	}

	public boolean isScanPFS() {
		return scanPFS;
	}

	public boolean isScanRandomTlsSessionTicket() {
		return scanRandomTlsSessionTicket;
	}
}

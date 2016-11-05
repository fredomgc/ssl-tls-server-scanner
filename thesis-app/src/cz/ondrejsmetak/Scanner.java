/*
 * Spusteni scannovani, vraceni vysledku testu
 */
package cz.ondrejsmetak;

import cz.ondrejsmetak.facade.OSaftFacade;
import cz.ondrejsmetak.other.Target;
import cz.ondrejsmetak.tool.Log;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Scanner {

	private OSaftFacade oSaft;
	private Target target;

	public Scanner(Target target) {
		this.target = target;
		oSaft = new OSaftFacade(target);
	}

	public void performScan() {
		oSaft.doSomething();
	}

	public void printResult(Target target) {
		if (oSaft == null) {
			throw new IllegalArgumentException("No data  for print!");
		}
		
		//TODO - vypisovat jen testy, které neprošli
		//napsat jednu nějakou univerzálnějí metodu
		
		if (target.isScanBeast()) {
			Log.infoln("Beast: " + oSaft.getParser().getBeast());
		}
		
		if (target.isScanBreach()) {
			Log.infoln("Breach: " + oSaft.getParser().getBreach());
		}
		
		if (target.isScanCrime()) {
			Log.infoln("Crime: " + oSaft.getParser().getCrime());
		}
		
		if (target.isScanDrown()) {
			Log.infoln("Drown: " + oSaft.getParser().getDrown());
		}
		
		if (target.isScanFreak()) {
			Log.infoln("Freak: " + oSaft.getParser().getFreak());
		}
		
		if (target.isScanHeartbleed()) {
			Log.infoln("Heartbleed: " + oSaft.getParser().getHeartbleed());
		}
		
		if (target.isScanLogjam()) {
			Log.infoln("Logjam: " + oSaft.getParser().getLogjam());
		}
		
		if (target.isScanLucky13()) {
			Log.infoln("Lucky13: " + oSaft.getParser().getLucky13());
		}
		
		if (target.isScanPoodle()) {
			Log.infoln("Poodle: " + oSaft.getParser().getPoodle());
		}
		
		if (target.isScanRc4()) {
			Log.infoln("Rc4: " + oSaft.getParser().getRc4());
		}
		
		if (target.isScanSweet32()) {
			Log.infoln("Sweet32: " + oSaft.getParser().getSweet32());
		}
		
		if (target.isScanSSLv2NotSupported()) {
			Log.infoln("SSLv2 not supported: " + oSaft.getParser().getSslv2NotSupported());
		}
		
		if (target.isScanSSLv3NotSupported()) {
			Log.infoln("SSLv3 not supported: " + oSaft.getParser().getSslv3NotSupported());
		}
		
		if (target.isScanPFS()) {
			Log.infoln("PFS: " + oSaft.getParser().getPfs());
		}
		
		if (target.isScanRandomTlsSessionTicket()) {
			Log.infoln("Random TLS session ticket: " + oSaft.getParser().getRandomTlsSessionTicket());
		}
		
	}

}

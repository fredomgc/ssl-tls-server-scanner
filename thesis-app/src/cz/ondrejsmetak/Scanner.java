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
			throw new IllegalArgumentException("Data missing for print!");
		}

		if(target.isScanHeartbleed()){
			Log.infoln("Heartbleed: " + oSaft.getParser().getHeartbleed());
		}
		
		if(target.isScanBreach()){
			Log.infoln("Breach: " + oSaft.getParser().getBreach());
		}
	}

}

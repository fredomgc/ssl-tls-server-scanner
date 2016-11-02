/*
 * Spusteni scannovani, vraceni vysledku testu
 */
package cz.ondrejsmetak;

import cz.ondrejsmetak.facade.OSaftFacade;
import cz.ondrejsmetak.tool.Log;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Scanner {
	
	private OSaftFacade oSaft;
	
	
	public void runScan(String target){
		 oSaft = new OSaftFacade(target); 
		 oSaft.doSomething();
	}
	
	public void printResult(){
		if(oSaft == null){
			throw new IllegalArgumentException("Data missing for print!");
		}
		
		Log.infoln("Heartbleed: " + oSaft.getParser().getHeartbleed());
		Log.infoln("Breach: " + oSaft.getParser().getBreach());
	}
	
}

package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ConfigurationRegister;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Log {

	public static void info(Object message) {
		System.out.print(message);
	}

	public static void infoln(Object message) {
		System.out.println(message);
	}
	
	public static void error(Object message) {
		System.out.print("! ERROR: " + message);
	}

	public static void errorln(Object message) {
		System.out.println("! ERROR: " + message);
	}
	
	public static void warning(Object message) {
		System.out.print("WARNING: " + message);
	}

	public static void warningln(Object message) {
		System.out.println("WARNING: " + message);
	}
	
	public static void debugException(Throwable exception){
		if(ConfigurationRegister.getInstance().isDebug()){
			System.out.println("DEBUG: " + exception.toString());
		}
	}
}

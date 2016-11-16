package cz.ondrejsmetak.tool;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Helper {

	public static boolean isInteger(String input) {
		return true; //TODO
	}

	/**
	 * Is input boolean value in its text form?
	 * @param input
	 * @return 
	 */
	public static boolean isBooleanStr(String input) {
		return input.equalsIgnoreCase("true") || input.equalsIgnoreCase("false");
	}

	public static boolean parseBooleanStr(String input){
		return input.equalsIgnoreCase("true");
	}
	
	/**
	 * Direct command line access
	 *
	 * @param args arguments for command line
	 * @return output of command
	 */
	public static List<String> doCmd(String... args) {
		List<String> output = new ArrayList<>();

		try {
			ProcessBuilder ps = new ProcessBuilder(args);

			/**
			 * Initially, this property is false, meaning that the standard
			 * output and error output of a subprocess are sent to two separate
			 * streams
			 */
			ps.redirectErrorStream(true);

			Process pr = ps.start();
			BufferedReader in = new BufferedReader(new InputStreamReader(pr.getInputStream()));
			String line;
			while ((line = in.readLine()) != null) {
				output.add(line);
			}
			pr.waitFor();

			return output;
		} catch (InterruptedException | IOException ex) {
			ex.printStackTrace(); //todo, pridat nejakou command line arg typu debug true/false
			return new ArrayList<>();
		}
	}
}

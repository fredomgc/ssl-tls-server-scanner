package cz.ondrejsmetak.tool;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Helper {

	
	public static void addIfNotNull(Collection collection, Object item){
		if(item != null){
			collection.add(item);
		}
	}
	
	public static String getFormattedDateTime(Date date, boolean dash) {
		DateFormat dateFormat = new SimpleDateFormat( dash ? "yyyy-MM-dd-HH-mm-ss" : "yyyy-MM-dd HH:mm:ss" );
		return dateFormat.format(date);
	}

	public static int booleanToInteger(Boolean value) {
		return value ? 1 : 0;
	}

	public static String getWorkingDirectory() {
		return System.getProperty("user.dir");
	}
	
	public static String getContentoOfFile(File file) throws FileNotFoundException{
		//http://stackoverflow.com/a/3403112
		return new Scanner(file).useDelimiter("\\Z").next();
	}

	/**
	 * Removes from string leading and trailing part, that matches given regex
	 *
	 * @param string
	 * @param regex
	 * @return
	 */
	public static String trim(String string, String regex) {
		String s = string;
		s = s.replaceAll("^" + regex + "+", "");
		s = s.replaceAll(regex + "+$", "");
		return s;
	}

	private static boolean isInteger(String s, int radix) {
		Scanner sc = new Scanner(s.trim());
		if (!sc.hasNextInt(radix)) {
			return false;
		}
		sc.nextInt(radix);
		return !sc.hasNext();
	}

	public static boolean isInteger(String input) {
		return isInteger(input, 10);
	}

	/**
	 * Is input boolean value in its text form?
	 *
	 * @param input
	 * @return
	 */
	public static boolean isBooleanStr(String input) {
		return input.equalsIgnoreCase("true") || input.equalsIgnoreCase("false");
	}

	public static boolean parseBooleanStr(String input) {
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
			Log.debugException(ex);
			return new ArrayList<>();
		}
	}
}

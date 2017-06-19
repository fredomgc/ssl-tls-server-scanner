package cz.ondrejsmetak.tool;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Collection of usefull methods and shortcuts
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Helper {

	/**
	 * Adds item to collection, if this item is not null
	 *
	 * @param collection collection of objects
	 * @param item item, that may be added
	 */
	public static void addIfNotNull(Collection collection, Object item) {
		if (item != null) {
			collection.add(item);
		}
	}

	/**
	 * Returns date formatted to human readable format
	 *
	 * @param date date, that will be formatted
	 * @param dash use dash during formatting date or not
	 * @return formatted date
	 */
	public static String getFormattedDateTime(Date date, boolean dash) {
		DateFormat dateFormat = new SimpleDateFormat(dash ? "yyyy-MM-dd-HH-mm-ss" : "yyyy-MM-dd HH:mm:ss");
		return dateFormat.format(date);
	}

	/**
	 * Converts boolean value to integer
	 *
	 * @param value booolean value
	 * @return integer value
	 */
	public static int booleanToInteger(Boolean value) {
		return value ? 1 : 0;
	}

	/**
	 * Returns path to current working directory
	 *
	 * @return path to current working directory
	 */
	public static String getWorkingDirectory() {
		return System.getProperty("user.dir");
	}

	/**
	 * Returns whole content of the given file
	 *
	 * @param file file, that will be read
	 * @return content of file
	 * @throws FileNotFoundException if case of error
	 */
	public static String getContentOfFile(File file) throws FileNotFoundException {
		//http://stackoverflow.com/a/3403112
		return new Scanner(file).useDelimiter("\\Z").next();
	}

	/**
	 * Returns whole content of the given file input stream
	 *
	 * @param inputStream file input stream, that will be read
	 * @return content of file
	 */
	public static String getContentOfFile(InputStream inputStream) {
		StringBuilder sb = new StringBuilder();
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
			String line;
			while ((line = br.readLine()) != null) {
				sb.append(line);
			}
		} catch (IOException ex) {
			Log.debugException(ex);
			return "";
		}

		return sb.toString();
	}

	/**
	 * Removes from string leading and trailing part, that matches given regex
	 *
	 * @param string text value
	 * @param regex pattern
	 * @return trimmed text value
	 */
	public static String trim(String string, String regex) {
		String s = string;
		s = s.replaceAll("^" + regex + "+", "");
		s = s.replaceAll(regex + "+$", "");
		return s;
	}

	/**
	 * Checks, if string contains properly formatted integer value
	 *
	 * @param s
	 * @param radix
	 * @return
	 */
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

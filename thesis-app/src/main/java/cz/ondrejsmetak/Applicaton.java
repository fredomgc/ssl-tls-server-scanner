package cz.ondrejsmetak;

/**
 * Main application class
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Applicaton {

	/**
	 * Main method
	 *
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		ScannerManager manager = new ScannerManager();
		boolean safe = manager.perform();
		System.exit(safe ? 0 : -1);
	}

}

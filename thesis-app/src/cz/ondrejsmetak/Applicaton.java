package cz.ondrejsmetak;

import cz.ondrejsmetak.other.XmlParserException;
import cz.ondrejsmetak.tool.TargetParser;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Applicaton {

	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		ScannerManager manager = new ScannerManager();
		manager.perform();
	}

}

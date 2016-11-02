package cz.ondrejsmetak;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Applicaton {

	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		// TODO code application logic here
		
		//TODO : precteni command line argumentu
		//TODO : precteni XML (?) obsahujiciho co scannovat a jak
		
		Scanner scanner = new Scanner();
		scanner.runScan("https://127.0.0.1/");
		scanner.printResult();
	}
	
}

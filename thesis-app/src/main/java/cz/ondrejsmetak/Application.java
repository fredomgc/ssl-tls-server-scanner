package cz.ondrejsmetak;

import cz.ondrejsmetak.tool.Log;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Main application class
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Application {

	/**
	 * Main method
	 *
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		try {
			
			KeyStore keystore = createKeyStoreFromPath("/home/fredomgc/Plocha/ssos.certifikaty/keystore.jks", "changeit");
			
			//default
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			
			//my socket
			//SSLSocketFactory sslsocketfactory = createSSLServerSocketFactory(keystore, "changeit");
			
			
			URL url = new URL("https://www.seznam.cz/" /*"https://is.ssos.cz/"*/);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setSSLSocketFactory(sslsocketfactory);
			InputStream inputstream = conn.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

			String string = null;
			while ((string = bufferedreader.readLine()) != null) {
				System.out.println("Received " + string);
			}
			
			
			
			
			
			//toto nize nechat, zbytek zde smazat

			//ScannerManager manager = new ScannerManager();
			//boolean safe = manager.perform();
			//System.exit(safe ? 0 : -1);
		} catch (IOException ex) {
			Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
		}
	}
	
	public static KeyStore createKeyStoreFromPath(String path, String password) {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(new File(path)), password.toCharArray());
			return ks;
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
			throw new IllegalArgumentException("Can't initialize KeyStore.", ex);
		}
	}
	
	
	public static SSLSocketFactory createSSLServerSocketFactory(KeyStore certificate, String password) {

		try {
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(certificate, password.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(certificate);

			SSLContext sslContext = SSLContext.getInstance("TLSv1.2"); //be aware, this value is not respected by JDK 

			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());

			return sslContext.getSocketFactory();
		} catch (Exception ex) {
			Log.debugException(ex);
			return null;
		}

	}
}

package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.ClientCertificate;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.tool.Log;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Tests, if connection with custom certificate authority to the target is
 * sucesfull or not
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class CustomCertificateAuthorityTest {

	private Target target;

	private Boolean isConnectionSuccessful = null;

	public CustomCertificateAuthorityTest(Target target) {
		this.target = target;
	}

	public void runScan() {
		Log.infoln("Testing connection with custom certificate authority...");
		this.isConnectionSuccessful = doIsConnectionSuccessful();
		Log.infoln("Test finished. Connection " + (isConnectionSuccessful ? "was" : "wasn't") + " successful");
	}

	public boolean isConnectionSuccessful() {
		if (isConnectionSuccessful == null) {
			throw new IllegalStateException("You must first run a scan to determine!");
		}

		return isConnectionSuccessful;
	}

	/**
	 * Perform connection to determine, it this action will be succesfull or not
	 *
	 * @return true in case of successful connection, false otherwise
	 */
	private boolean doIsConnectionSuccessful() {
		try {
			SSLSocketFactory sslsocketfactory = createSSLServerSocketFactory(target.getProfile().getCustomCertificateAuthority());

			URL url = new URL(target.getDestination());
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setSSLSocketFactory(sslsocketfactory);
			InputStream inputstream = conn.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

			String string = null;
			while ((string = bufferedreader.readLine()) != null) {
				//we actually don't care about content
			}

			return true;
		} catch (IOException ex) {
			return false;
		}
	}

	/**
	 * Creates SSLServerSocketFactory that will be using specified KeyStore
	 *
	 * @param certificate specified by user
	 * @return object of SSLServerSocketFactory
	 */
	private SSLSocketFactory createSSLServerSocketFactory(ClientCertificate certificate) {

		try {
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(certificate.getKeystore(), certificate.getPassword().toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(certificate.getKeystore());

			SSLContext sslContext = SSLContext.getInstance("TLSv1.2"); //be aware, this value is not respected by JDK 

			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());

			return sslContext.getSocketFactory();
		} catch (Exception ex) {
			Log.debugException(ex);
			return null;
		}

	}

}

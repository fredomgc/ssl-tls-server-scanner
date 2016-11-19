package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ProfileRegister;
import cz.ondrejsmetak.ResourceManager;
import cz.ondrejsmetak.entity.CipherSuite;
import cz.ondrejsmetak.entity.Profile;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.other.XmlParserException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Parser of configuration file, that contains targets of scanning
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class TargetParser extends BaseParser {

	public static final String FILE = "targets.xml";

	@Override
	public void createDefault() throws IOException {
		Path source = ResourceManager.getDefaultConfigurationXml().toPath();
		Path destination = new File(FILE).toPath();
		Files.copy(source, destination);
	}

	@Override
	public boolean hasFile() {
		return Files.exists(new File(FILE).toPath());
	}

	public List<Target> parse() throws XmlParserException {
		try {
			File fXmlFile = new File(FILE);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(fXmlFile);
			doc.getDocumentElement().normalize();

			/**
			 * Parse profiles
			 */
			ProfileRegister.getInstance().registerProfiles(parseProfiles(doc));

			/**
			 * Parse targets
			 */
			return parseTargets(doc);

		} catch (ParserConfigurationException | SAXException | IllegalArgumentException | IOException ex) {
			throw new XmlParserException(ex);
		}
	}

	/**
	 * Přečte profily z <targets></targets>
	 *
	 * @param doc
	 * @return
	 */
	private List<Target> parseTargets(Document doc) {
		List<Target> done = new ArrayList<>();

		NodeList roots = doc.getElementsByTagName("targets");
		if (roots.getLength() != 1) {
			return new ArrayList<>();
		}

		Node root = roots.item(0);
		if (root.getNodeType() != Node.ELEMENT_NODE) {
			return new ArrayList<>();
		}

		Element element = (Element) root;
		NodeList profiles = element.getElementsByTagName("target");

		for (int i = 0; i < profiles.getLength(); i++) {
			done.add(parseTarget(profiles.item(i)));
		}

		return done;
	}

	/**
	 * Přečte profily z <profiles></profiles>
	 *
	 * @param doc
	 * @return
	 */
	private List<Profile> parseProfiles(Document doc) throws XmlParserException {
		List<Profile> done = new ArrayList<>();

		NodeList roots = doc.getElementsByTagName("profiles");
		if (roots.getLength() != 1) {
			return new ArrayList<>();
		}

		Node root = roots.item(0);
		if (root.getNodeType() != Node.ELEMENT_NODE) {
			return new ArrayList<>();
		}

		Element element = (Element) root;
		NodeList profiles = element.getElementsByTagName("profile");

		for (int i = 0; i < profiles.getLength(); i++) {
			done.add(parseProfile(profiles.item(i)));
		}

		return done;
	}

	/**
	 * Přečte <target></target>
	 *
	 * @param node
	 * @return
	 */
	private Target parseTarget(Node node) {
		if (node.getNodeType() != Node.ELEMENT_NODE) {
			return null;
		}
		Element target = (Element) node;

		/**
		 * Name
		 */
		String destination = target.getAttribute("destination");
		String profile = target.getAttribute("profile");
		String name = target.getAttribute("name");

		return Target.fromXml(destination, profile, name);
	}

	/**
	 * Přečte <profile></profile>
	 *
	 * @param node
	 * @return
	 */
	private Profile parseProfile(Node node) throws XmlParserException {
		if (node.getNodeType() != Node.ELEMENT_NODE) {
			return null;
		}
		Element profile = (Element) node;

		/**
		 * Name
		 */
		String name = profile.getAttribute("name");

		/**
		 * Protocol
		 */
		Element protocol = getElementByTagName(profile, "protocol");
		String safeProtocol = (protocol == null ? "" : protocol.getAttribute("safe"));
		String safeProtocolModifier = (protocol == null ? "" : protocol.getAttribute("modifier"));

		if (!safeProtocolModifier.isEmpty() && !safeProtocolModifier.equals(Profile.MODIFIER_AND_HIGHER)) {
			throw new XmlParserException("Unknown protocol modifier [" + safeProtocolModifier + "] in profile [" + name + "]!");
		}

		if (!safeProtocolModifier.isEmpty() && safeProtocol.isEmpty()) {
			throw new XmlParserException("Protocol modifier is used, but safe atribute is empty in profile [" + name + "]!");
		}

		/**
		 * Vulnerabilities
		 */
		Element vulnerabilities = getElementByTagName(profile, "vulnerabilities");

		/**
		 * Certificate
		 */
		Element certificate = getElementByTagName(profile, "certificate");

		/**
		 * Safe cipher suites
		 */
		Element ciphers = getElementByTagName(profile, "ciphers");
		List<CipherSuite> cipherSuites = ciphers == null ? new ArrayList<>() : parseCipherSuites(ciphers);

		return Profile.fromXml(name, safeProtocol, safeProtocolModifier, certificate != null, vulnerabilities != null, cipherSuites);
	}

	private List<CipherSuite> parseCipherSuites(Element ciphers) {
		List<CipherSuite> done = new ArrayList<>();

		NodeList safe = ciphers.getElementsByTagName("safe");

		for (int i = 0; i < safe.getLength(); i++) {
			done.add(parseCipherSuite(safe.item(i)));
		}

		return done;
	}

	private CipherSuite parseCipherSuite(Node node) {
		if (node.getNodeType() != Node.ELEMENT_NODE) {
			return null;
		}

		Element cipherSuite = (Element) node;
		String name = cipherSuite.getAttribute("name");
		return new CipherSuite(name);
	}

}

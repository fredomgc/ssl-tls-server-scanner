package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ProfileRegister;
import cz.ondrejsmetak.ResourceManager;
import cz.ondrejsmetak.entity.CipherSuite;
import cz.ondrejsmetak.entity.Directive;
import cz.ondrejsmetak.entity.Mode;
import cz.ondrejsmetak.entity.Mode.Type;
import cz.ondrejsmetak.entity.Profile;
import cz.ondrejsmetak.entity.Protocol;
import cz.ondrejsmetak.entity.Target;
import cz.ondrejsmetak.other.XmlParserException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
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

	private static final String TAG_CONFIGURATION = "configuration";
	private static final String TAG_PROFILES = "profiles";
	private static final String TAG_PROFILE = "profile";
	private static final String TAG_PROTOCOLS = "protocols";
	private static final String TAG_PROTOCOL = "protocol";
	private static final String TAG_VULNERABILITIES_FREE = "vulnerabilitiesFree";
	private static final String TAG_CERTIFICATE_VALID = "certificateValid";
	private static final String TAG_DIRECTIVE = "directive";
	private static final String TAG_CIPHERS = "ciphers";
	private static final String TAG_CIPHER = "cipher";
	private static final String TAG_TARGETS = "targets";
	private static final String TAG_TARGET = "target";

	private static final String ATTRIBUTE_NAME = "name";
	private static final String ATTRIBUTE_VALUE = "value";
	private static final String ATTRIBUTE_MODE = "mode";
	private static final String ATTRIBUTE_DESTINATION = "destination";
	private static final String ATTRIBUTE_PROFILE = "profile";

	private static final String MODE_MUST_BE = "mustBe";
	private static final String MODE_CAN_BE = "mayBe";

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

	private Mode parseMode(String codename, String tagName, Mode.Type... forbidden) throws XmlParserException {
		Mode mode = null;
		try {
			mode = new Mode(codename);
		} catch (IllegalArgumentException ex) {
			throw new XmlParserException(ex);
		}

		for (Type type : forbidden) {
			if (type.equals(mode.getType())) {
				throw new XmlParserException("Mode value [%s] is forbidden in tag [%s]", type, forbidden);
			}
		}

		return mode;
	}

	private void checkAttributesOfNode(Node node, String... expectedAttributes) throws XmlParserException {
		List<String> expectedAttributesList = new ArrayList<>(Arrays.asList(expectedAttributes));

		for (String actualAttribute : getAttributesByTag(node)) {

			if (!expectedAttributesList.contains(actualAttribute)) {
				throw new XmlParserException("Unknown attribute [%s]. You must use only supported attributes!", actualAttribute);
			}
		}
	}

	private void checkNode(Node node) throws XmlParserException {
		if (!getSupportedTags().contains(node.getNodeName())) {
			throw new XmlParserException("Unknown tag [%s]. You must use only supported tags!", node.getNodeName());
		}

		//System.err.println("AA: " + node.getParentNode()); //TODO
		/**
		 * Tag "profile" must have attribute "name"
		 */
		if (node.getNodeName().equals(TAG_PROFILE)) {
			checkAttributesOfNode(node, ATTRIBUTE_NAME);
		}

		/**
		 * Tag "protocol" must have attribute "name" and "mode"
		 */
		if (node.getNodeName().equals(TAG_PROTOCOL)) {
			checkAttributesOfNode(node, ATTRIBUTE_NAME, ATTRIBUTE_MODE);
		}

		/**
		 * Tag "vulnerabilitiesFree" must have attribute "mode"
		 */
		if (node.getNodeName().equals(TAG_VULNERABILITIES_FREE)) {
			checkAttributesOfNode(node, ATTRIBUTE_MODE);
		}

		/**
		 * Tag "certificateValid" must have attribute "mode"
		 */
		if (node.getNodeName().equals(TAG_CERTIFICATE_VALID)) {
			checkAttributesOfNode(node, ATTRIBUTE_MODE);
		}

		/**
		 * Tag "cipher" must have attribute "name" and "mode"
		 */
		if (node.getNodeName().equals(TAG_CIPHER)) {
			checkAttributesOfNode(node, ATTRIBUTE_NAME, ATTRIBUTE_MODE);
		}

		/**
		 * Tag "target" must have attribute "destination", "profile" and "name"
		 */
		if (node.getNodeName().equals(TAG_TARGET)) {
			checkAttributesOfNode(node, ATTRIBUTE_DESTINATION, ATTRIBUTE_PROFILE, ATTRIBUTE_NAME);
		}
	}

	public List<Target> parse() throws XmlParserException {
		try {
			File fXmlFile = new File(FILE);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(fXmlFile);
			doc.getDocumentElement().normalize();

			NodeList elements = doc.getElementsByTagName("*");

			/**
			 * XML validation
			 */
			for (int i = 0; i < elements.getLength(); i++) {
				Node node = elements.item(i);
				checkNode(node);
			}

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

	private Directive parseCertificateDirective(Node certificateDirective) throws XmlParserException {
		if (!(certificateDirective instanceof Element)) {
			return null;
		}
		checkAttributesOfNode(certificateDirective, ATTRIBUTE_NAME, ATTRIBUTE_VALUE, ATTRIBUTE_MODE);

		Element element = (Element) certificateDirective;
		Mode mode = parseMode(element.getAttribute(ATTRIBUTE_MODE), TAG_DIRECTIVE, Type.MUST_NOT_BE);
		String name = element.getAttribute(ATTRIBUTE_NAME);
		String valueStr = element.getAttribute(ATTRIBUTE_VALUE);

		if (!Profile.getAllCertificateDirectives().contains(name)) {
			throw new XmlParserException("Unknown directive [%s] for certificateValid!");
		}

		if (!Helper.isInteger(valueStr) || Integer.valueOf(valueStr) <= 0) {
			throw new XmlParserException("Value for certificateValid directive [%s] must be integer >= 0!", name);
		}

		return new Directive(name, Integer.valueOf(valueStr), mode);
	}

	private List<Directive> parseCertificateDirectives(Element certificateValidTag) throws XmlParserException {
		if (!(certificateValidTag instanceof Element)) {
			throw new XmlParserException("Tag certificateValid is missing!");
		}

		List<Directive> done = new ArrayList<>();
		checkAttributesOfNode(certificateValidTag, ATTRIBUTE_MODE);
		NodeList directives = certificateValidTag.getElementsByTagName(TAG_DIRECTIVE);
		List<String> expectedDirectives = Profile.getAllCertificateDirectives();

		for (int i = 0; i < directives.getLength(); i++) {
			Directive directive = parseCertificateDirective(directives.item(i));
			if (!(directive instanceof Directive)) {
				continue;
			}
			expectedDirectives.remove(directive.getName());
			done.add(directive);
		}

		if (!expectedDirectives.isEmpty()) {
			throw new XmlParserException("For certificateValid, following directive(s) is/are missing: %s", expectedDirectives.toString());
		}

		return done;

	}

	/**
	 * Reads <protocols></protocols>
	 * Will check, if all available protocols are properly defined
	 *
	 * @param node tag <protocols></protocols>
	 * @return protocols, whose support is required on target machine
	 */
	private List<Protocol> parseProtocols(Element node) throws XmlParserException {
		List<Protocol> willBeTested = new ArrayList<>();

		NodeList protocols = node.getElementsByTagName(TAG_PROTOCOL);
		List<Protocol.Type> expectedProtocols = Protocol.getAllTypes();
		expectedProtocols.remove(Protocol.Type.TLSv13); //not published yet

		for (int i = 0; i < protocols.getLength(); i++) {
			Protocol protocol = parseProtocol(protocols.item(i));
			expectedProtocols.remove(protocol.getType());

			willBeTested.add(protocol);
		}

		if (!expectedProtocols.isEmpty()) {
			throw new XmlParserException("Missing declaration for following protocol(s): %s", expectedProtocols.toString());
		}

		return willBeTested;
	}

	private Protocol parseProtocol(Node node) throws XmlParserException {
		if (!(node instanceof Element)) {
			return null;
		}
		checkAttributesOfNode(node, ATTRIBUTE_MODE, ATTRIBUTE_NAME);

		Element element = (Element) node;
		Mode mode = parseMode(element.getAttribute(ATTRIBUTE_MODE), TAG_PROTOCOL);
		Protocol protocol = new Protocol(element.getAttribute(ATTRIBUTE_NAME), mode);

		return protocol;
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
		String name = profile.getAttribute(ATTRIBUTE_NAME);

		/**
		 * Protocols
		 */
		Element protocolsTag = getElementByTagName(profile, TAG_PROTOCOLS);
		List<Protocol> protocols = parseProtocols(protocolsTag);

		/**
		 * Vulnerabilities
		 */
		Element vulnerabilitiesTag = getElementByTagName(profile, TAG_VULNERABILITIES_FREE);
		checkAttributesOfNode(vulnerabilitiesTag, ATTRIBUTE_MODE);
		Mode vulnerabilities = parseMode(vulnerabilitiesTag.getAttribute(ATTRIBUTE_MODE), TAG_VULNERABILITIES_FREE, Type.MUST_NOT_BE);

		/**
		 * Certificate
		 */
		Element certificateTag = getElementByTagName(profile, TAG_CERTIFICATE_VALID);
		Mode certificate = parseMode(certificateTag.getAttribute(ATTRIBUTE_MODE), TAG_CERTIFICATE_VALID, Type.MUST_NOT_BE);
		List<Directive> certificateDirectives = parseCertificateDirectives(certificateTag);

		/**
		 * Safe cipher suites
		 */
		Element ciphers = getElementByTagName(profile, TAG_CIPHERS);
		List<CipherSuite> cipherSuites = parseCipherSuites(ciphers);

		return Profile.fromXml(name, protocols, certificate, certificateDirectives, vulnerabilities, cipherSuites);
	}

	private List<CipherSuite> parseCipherSuites(Element ciphers) throws XmlParserException {
		if (!(ciphers instanceof Element)) {
			throw new XmlParserException("Tag ciphers is missing!");
		}

		List<CipherSuite> done = new ArrayList<>();
		NodeList safe = ciphers.getElementsByTagName(TAG_CIPHER);
		for (int i = 0; i < safe.getLength(); i++) {
			CipherSuite cipherSuite = parseCipherSuite(safe.item(i));
			if (!(cipherSuite instanceof CipherSuite)) {
				continue;
			}

			done.add(cipherSuite);
		}

		return done;
	}

	private CipherSuite parseCipherSuite(Node node) throws XmlParserException {
		if (node.getNodeType() != Node.ELEMENT_NODE) {
			return null;
		}

		checkAttributesOfNode(node, ATTRIBUTE_NAME, ATTRIBUTE_MODE);
		Element cipherSuite = (Element) node;
		String name = cipherSuite.getAttribute(ATTRIBUTE_NAME);
		Mode mode = parseMode(cipherSuite.getAttribute(ATTRIBUTE_MODE), TAG_CIPHER);

		return new CipherSuite(name, mode);
	}

	private List<String> getSupportedTags() {
		return new ArrayList<>(Arrays.asList(new String[]{TAG_CONFIGURATION, TAG_PROFILES, TAG_PROFILE, TAG_PROTOCOLS, TAG_PROTOCOL,
			TAG_VULNERABILITIES_FREE, TAG_DIRECTIVE, TAG_CERTIFICATE_VALID, TAG_CIPHERS, TAG_CIPHER, TAG_TARGETS, TAG_TARGET}));
	}

	private List<String> getSupportedAttributes() {
		return new ArrayList<>(Arrays.asList(new String[]{ATTRIBUTE_NAME, ATTRIBUTE_MODE, ATTRIBUTE_DESTINATION, ATTRIBUTE_PROFILE}));
	}

}

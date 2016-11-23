package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ConfigurationRegister;
import cz.ondrejsmetak.ResourceManager;
import cz.ondrejsmetak.other.XmlParserException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ConfigurationParser extends BaseParser {

	public static final String FILE = "configuration.xml";

	private static final String TAG_CONFIGURATION = "configuration";
	private static final String TAG_DIRECTIVE = "directive";

	private static final String ATTRIBUTE_NAME = "name";
	private static final String ATTRIBUTE_VALUE = "value";

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

	/**
	 * Checks if node is recognized by this parser. If not, exception is thrown.
	 * We are strict during parsing content of xml. Only supported tags and
	 * atributes must be used.
	 *
	 * @param node node, that will be checked
	 * @throws XmlParserException
	 */
	private void checkNode(Node node) throws XmlParserException {
		ArrayList supportedTags = new ArrayList<>(Arrays.asList(new String[]{TAG_CONFIGURATION, TAG_DIRECTIVE}));
		ArrayList supportedAttributes = new ArrayList<>(Arrays.asList(new String[]{ATTRIBUTE_NAME, ATTRIBUTE_VALUE}));

		if (!supportedTags.contains(node.getNodeName())) {
			throw new XmlParserException("Unknown tag [%s]. You must use only supported tags!", node.getNodeName());
		}

		/**
		 * Tag "directive" must have "name" and "value" atribute
		 */
		if (node.getNodeName().equals(TAG_DIRECTIVE)) {
			NamedNodeMap attributes = node.getAttributes();
			for (int i = 0; i < attributes.getLength(); i++) {
				Node attribute = attributes.item(i);
				if (!supportedAttributes.contains(attribute.getNodeName())) {
					throw new XmlParserException("Unknown attribute [%s]. You must use only supported attributes!", attribute.getNodeName());
				}

			}
		}
	}

	public void parse() throws XmlParserException {
		try {
			File fXmlFile = new File(FILE);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(fXmlFile);
			doc.getDocumentElement().normalize();

			NodeList directives = doc.getElementsByTagName("*");

			/**
			 * Parse configuration directives and store them
			 */
			for (int i = 0; i < directives.getLength(); i++) {
				checkNode(directives.item(i));
				parseDirective(directives.item(i));
			}

		} catch (ParserConfigurationException | SAXException | IllegalArgumentException | IOException ex) {
			throw new XmlParserException(ex);
		}
	}

	private boolean parseDirective(Node node) throws XmlParserException {
		if (node.getNodeType() != Node.ELEMENT_NODE) {
			return false;
		}
		Element profile = (Element) node;

		String name = profile.getAttribute(ATTRIBUTE_NAME);
		String value = profile.getAttribute(ATTRIBUTE_VALUE);
		setDirective(name, value);
		return true;
	}

	private void setDirective(String name, String value) throws XmlParserException {
		setDebug(name, value);
		setDirectiveCertificateMinimumKeySize(name, value);
		setDirectiveCertificateMinimumSignatureKeySize(name, value);
		setDirectiveUnknownTestResultIsError(name, value);
		setDirectiveOSaftFolderAbsolutePath(name, value);
	}

	private void setDebug(String name, String value) throws XmlParserException {
		if (name.equalsIgnoreCase(ConfigurationRegister.DEBUG)) {
			if (!Helper.isBooleanStr(value)) {
				throw new XmlParserException("Value for directive " + ConfigurationRegister.DEBUG + " must be [true] or [false]!");
			}

			ConfigurationRegister.getInstance().setDebug(Helper.parseBooleanStr(value));
		}
	}

	private void setDirectiveCertificateMinimumKeySize(String name, String value) throws XmlParserException {
		if (name.equalsIgnoreCase(ConfigurationRegister.CERTIFICATE_MINIMUM_KEY_SIZE)) {
			if (!Helper.isInteger(value) || Integer.valueOf(value) <= 0) {
				throw new XmlParserException("Value for directive " + ConfigurationRegister.CERTIFICATE_MINIMUM_KEY_SIZE + " must be integer >= 0!");
			}

			ConfigurationRegister.getInstance().setCertificateMinimumKeySize(Integer.valueOf(value));
		}
	}

	private void setDirectiveCertificateMinimumSignatureKeySize(String name, String value) throws XmlParserException {
		if (name.equalsIgnoreCase(ConfigurationRegister.CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE)) {
			if (!Helper.isInteger(value) || Integer.valueOf(value) <= 0) {
				throw new XmlParserException("Value for directive " + ConfigurationRegister.CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE + " must be integer >= 0!");
			}

			ConfigurationRegister.getInstance().setCertificateMinimumSignatureKeySize(Integer.valueOf(value));
		}
	}

	private void setDirectiveUnknownTestResultIsError(String name, String value) throws XmlParserException {
		if (name.equalsIgnoreCase(ConfigurationRegister.UNKNOWN_TEST_RESULT_IS_ERROR)) {
			if (!Helper.isBooleanStr(value)) {
				throw new XmlParserException("Value for directive " + ConfigurationRegister.UNKNOWN_TEST_RESULT_IS_ERROR + " must be [true] or [false]!");
			}

			ConfigurationRegister.getInstance().setUnknownTestResultIsError(Helper.parseBooleanStr(value));
		}
	}

	private void setDirectiveOSaftFolderAbsolutePath(String name, String value) throws XmlParserException {
		if (name.equalsIgnoreCase(ConfigurationRegister.O_SAFT_FOLDER_ABSOLUTE_PATH)) {
			if (!value.endsWith(File.separator)) {
				value += File.separator;
			}

			String[] args = new String[]{value + "o-saft.pl", "+version"};
			List<String> output = Helper.doCmd(args);
			String lastLine = output.size() >= 1 ? output.get(output.size() - 1) : "";

			if (!lastLine.contains("osaft")) {
				throw new XmlParserException("Can't find or use O-Saft in directory [" + value + "] !");
			}

			ConfigurationRegister.getInstance().setOSaftFolderAbsolutePath(value);
		}
	}

}

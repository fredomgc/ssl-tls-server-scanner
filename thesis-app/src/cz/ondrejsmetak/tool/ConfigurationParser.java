package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ConfigurationRegister;
import cz.ondrejsmetak.ResourceManager;
import cz.ondrejsmetak.other.XmlParserException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ConfigurationParser extends BaseParser {

	public static final String FILE = "configuration.xml";

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

	public void parse() throws XmlParserException {
		try {
			File fXmlFile = new File(FILE);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(fXmlFile);
			doc.getDocumentElement().normalize();

			NodeList directives = doc.getElementsByTagName("directive");

			/**
			 * Parse configuration directives and store them
			 */
			for (int i = 0; i < directives.getLength(); i++) {
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

		String name = profile.getAttribute("name");
		String value = profile.getAttribute("value");
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

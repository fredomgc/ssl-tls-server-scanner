package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ResourceManager;
import cz.ondrejsmetak.other.XmlParserException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Base abstract class for all XML parsers in the application
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public abstract class BaseParser {

	/**
	 * Creates default configuration file, that is being used during parsing
	 *
	 * @throws IOException in case of any error
	 */
	public abstract void createDefault() throws IOException;

	/**
	 * Checks, if XML file, that should be parsed, even exists
	 *
	 * @return true, if XML file exists, false otherwise
	 */
	public abstract boolean hasFile();

	/**
	 * Returns a child element with given name of the given parent source or
	 * null, if such child element doesn't exists
	 *
	 * @param source parent element
	 * @param tagName name of child element
	 * @return child element
	 * @throws XmlParserException if source element hasn't any child element
	 */
	protected Element getElementByTagName(Element source, String tagName) throws XmlParserException {
		NodeList candidates = source.getElementsByTagName(tagName);

		if (candidates.getLength() == 0) {
			throw new XmlParserException("Tag [%s] not found in XML file!", tagName);
		}

		if (candidates.getLength() != 1) {
			return null; //logic error
		}

		Node node = candidates.item(0);

		if (node.getNodeType() != Node.ELEMENT_NODE) {
			return null;
		}

		return (Element) node;
	}

	/**
	 * Returns a collection of all attributes of the given tag
	 *
	 * @param tag tag
	 * @return collection of all attributes
	 */
	protected List<String> getAttributesByTag(Node tag) {
		List<String> done = new ArrayList<>();

		NamedNodeMap attributes = tag.getAttributes();
		for (int i = 0; i < attributes.getLength(); i++) {
			Node attribute = attributes.item(i);
			done.add(attribute.getNodeName());
		}

		return done;
	}
}

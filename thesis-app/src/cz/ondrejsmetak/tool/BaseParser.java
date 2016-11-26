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
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public abstract class BaseParser {

	public abstract void createDefault() throws IOException;

	public abstract boolean hasFile();

	protected Element getElementByTagName(Element source, String tagName) {
		NodeList candidates = source.getElementsByTagName(tagName);

		if (candidates.getLength() != 1) {
			return null;
		}

		Node node = candidates.item(0);

		if (node.getNodeType() != Node.ELEMENT_NODE) {
			return null;
		}

		return (Element) node;
	}

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

package cz.ondrejsmetak.tool;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class BaseParser {
	
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
}

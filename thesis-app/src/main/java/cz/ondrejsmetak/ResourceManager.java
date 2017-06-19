package cz.ondrejsmetak;

import java.io.InputStream;

/**
 * ResourceManager manager
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ResourceManager {

	/**
	 * Return stream of file, that is used as default configuration
	 *
	 * @return stream of file used as default configuration
	 */
	public static InputStream getDefaultConfigurationXml() {
		return getResourceAsStream("configuration.xml");
	}

	/**
	 * Return stream of file, that is used as default specification of the targets
	 *
	 * @return stream of file used as default specification of the targets
	 */
	public static InputStream getDefaultTargetsXml() {
		return getResourceAsStream("targets.xml");
	}

	/**
	 * Return stream of file, that is used as template during generating HTML report
	 *
	 * @return stream of file used as template during generating HTML report
	 */
	public static InputStream getHtmlTemplate() {
		return getResourceAsStream("template.html");
	}

	/**
	 * Finds a resource in "resource" folder and returns it
	 *
	 * @param name name of the resource, that will be found in folder
	 * @return stream of resource
	 */
	public static InputStream getResourceAsStream(String name) {
		return ResourceManager.class.getResourceAsStream("/" + name);
	}

}

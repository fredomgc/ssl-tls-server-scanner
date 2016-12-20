package cz.ondrejsmetak;

import java.io.File;
import java.io.InputStream;
import java.net.URL;

/**
 * Resource manager
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ResourceManager {

	/**
	 * Return file, that is used as default configuration
	 *
	 * @return file used as default configuration
	 */
	public static File getDefaultConfigurationXml() {
		return new File(getResource("configuration.xml").getFile());
	}

	/**
	 * Return file, that is used as default specification of the targets
	 *
	 * @return file used as default specification of the targets
	 */
	public static File getDefaultTargetsXml() {
		return new File(getResource("targets.xml").getFile());
	}

	/**
	 * Return file, that is used as template during generating HTML report
	 *
	 * @return file used as template during generating HTML report
	 */
	public static File getHtmlTemplate() {
		return new File(getResource("template.html").getFile());
	}

	/**
	 * Finds a resource in "resources" folder and returns it
	 *
	 * @param name name of the resource, that will be found in folder
	 * @return URL of resource
	 */
	public static URL getResource(String name) {
		return ResourceManager.class.getResource("resources/" + name);
	}

	/**
	 * Finds a resource in "resources" folder and returns it
	 *
	 * @param name name of the resource, that will be found in folder
	 * @return stream of resource
	 */
	public static InputStream getResourceAsStream(String name) {
		return ResourceManager.class.getResourceAsStream("resources/" + name);
	}

}

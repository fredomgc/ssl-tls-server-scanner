package cz.ondrejsmetak;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * Holds all the configuration directives. Singleton pattern.
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ConfigurationRegister {

	/**
	 * Instance of this class
	 */
	private static ConfigurationRegister instance = null;
	/**
	 * Register of all directives
	 */
	private final HashMap<String, Object> register = new HashMap<>();

	/**
	 * Directives in a text form
	 */
	public static final String DEBUG = "debug";
	public static final String O_SAFT_FOLDER_ABSOLUTE_PATH = "oSaftFolderAbsolutePath";
	public static final String CERTIFICATE_MINIMUM_KEY_SIZE = "certificateMinimumPublicKeySize";
	public static final String CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE = "certificateMinimumSignatureKeySize";
	public static final String UNKNOWN_TEST_RESULT_IS_ERROR = "unknownTestResultIsError";

	protected ConfigurationRegister() {
		//no direct instantiation
	}

	/**
	 * Returns a instance of this class
	 *
	 * @return instance of this class
	 */
	public static ConfigurationRegister getInstance() {
		if (instance == null) {
			instance = new ConfigurationRegister();
			instance.setDirective(DEBUG, true); //by default, debug is enabled
		}
		return instance;
	}

	/**
	 * Sets directive with the given name to the given value
	 *
	 * @param name name of the directive
	 * @param value value
	 */
	private void setDirective(String name, Object value) {
		if (!isSupportedDirective(name)) {
			throw new IllegalArgumentException("Unknown configuration directive [" + name + "] !");
		}

		register.put(name, value);
	}

	/**
	 * Obtains value for the given directive
	 *
	 * @param name name of the directive
	 * @return value of the given directive
	 */
	private Object getDirective(String name) {
		if (!register.containsKey(name)) {
			throw new IllegalArgumentException("Configuration directive [" + name + "] not found!");
		}

		return register.get(name);
	}

	/**
	 * Checks, if this register already contains directive with the given name
	 *
	 * @param name of the directive
	 * @return true, if such the directive already exists, false otherwise
	 */
	private boolean hasDirective(String name) {
		return register.containsKey(name);
	}

	/**
	 * Checks, if this this register contains all the required directives. If
	 * not, this application can't run.
	 *
	 * @return true, if all the directives are set, false otherwise
	 */
	public boolean hasAllDirectives() {
		for (String directive : getDirectives()) {
			if (!hasDirective(directive)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Returns a collection of the missing directives, that are required for run
	 * of this application
	 *
	 * @return collection of the missing directives
	 */
	public List<String> getMissingDirectives() {
		List<String> missing = new ArrayList<>();
		for (String directive : getDirectives()) {
			if (!hasDirective(directive)) {
				missing.add(directive);
			}
		}

		return missing;
	}

	/**
	 * Returns collection with the names of all the supported directives
	 *
	 * @return collection with the names of all the supported directives
	 */
	private List<String> getDirectives() {
		String[] directives = {DEBUG, O_SAFT_FOLDER_ABSOLUTE_PATH, CERTIFICATE_MINIMUM_KEY_SIZE,
			CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE, UNKNOWN_TEST_RESULT_IS_ERROR};
		return new ArrayList<>(Arrays.asList(directives));
	}

	/**
	 * Is the given name recognized as supported directive
	 *
	 * @param name name of the candidate
	 * @return true, if such name is recognized, false otherwise
	 */
	private boolean isSupportedDirective(String name) {
		return getDirectives().contains(name);
	}
	
	public void setOSaftFolderAbsolutePath(String value) {
		setDirective(O_SAFT_FOLDER_ABSOLUTE_PATH, value);
	}

	public String getOSaftFolderAbsolutePath() {
		return (String) getDirective(O_SAFT_FOLDER_ABSOLUTE_PATH);
	}

	public void setDebug(Boolean value) {
		setDirective(DEBUG, value);
	}

	public Boolean isDebug() {
		return (Boolean) getDirective(DEBUG);
	}

	public void setCertificateMinimumKeySize(Integer value) {
		setDirective(CERTIFICATE_MINIMUM_KEY_SIZE, value);
	}

	public int getCertificateMinimumKeySize() {
		return (Integer) getDirective(CERTIFICATE_MINIMUM_KEY_SIZE);
	}

	public void setCertificateMinimumSignatureKeySize(Integer value) {
		setDirective(CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE, value);
	}

	public int getCertificateMinimumSignatureKeySize() {
		return (Integer) getDirective(CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE);
	}

	public void setUnknownTestResultIsError(boolean value) {
		setDirective(UNKNOWN_TEST_RESULT_IS_ERROR, value);
	}

	public boolean isUnknownTestResultIsError() {
		return (Boolean) getDirective(UNKNOWN_TEST_RESULT_IS_ERROR);
	}

}

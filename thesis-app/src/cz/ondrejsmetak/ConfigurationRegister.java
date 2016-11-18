package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.Profile;
import cz.ondrejsmetak.tool.Helper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ConfigurationRegister {

	private static ConfigurationRegister instance = null;
	private final HashMap<String, Object> register = new HashMap<>();

	public static final String DEBUG = "debug";
	public static final String O_SAFT_FOLDER_ABSOLUTE_PATH = "oSaftFolderAbsolutePath";
	public static final String CERTIFICATE_MINIMUM_KEY_SIZE = "certificateMinimumPublicKeySize";
	public static final String CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE = "certificateMinimumSignatureKeySize";
	public static final String UNKNOWN_TEST_RESULT_IS_ERROR = "unknownTestResultIsError";

	protected ConfigurationRegister() {
		//no direct instantiation.
	}

	public static ConfigurationRegister getInstance() {
		if (instance == null) {
			instance = new ConfigurationRegister();
		}
		return instance;
	}

	private void setDirective(String name, Object value) {
		if (!isSupportedDirective(name)) {
			throw new IllegalArgumentException("Unknown configuration directive [" + name + "] !");
		}

		register.put(name, value);
	}

	private Object getDirective(String name) {
		if (!register.containsKey(name)) {
			throw new IllegalArgumentException("Configuration directive [" + name + "] not found!");
		}

		return register.get(name);
	}

	private boolean hasDirective(String name) {
		return register.containsKey(name);
	}

	public boolean hasAllDirectives() {
		for (String directive : getDirectives()) {
			if (!hasDirective(directive)) {
				return false;
			}
		}

		return true;
	}

	private List<String> getDirectives() {
		String[] directives = {DEBUG, O_SAFT_FOLDER_ABSOLUTE_PATH, CERTIFICATE_MINIMUM_KEY_SIZE,
			CERTIFICATE_MINIMUM_SIGNATURE_KEY_SIZE, UNKNOWN_TEST_RESULT_IS_ERROR};
		return new ArrayList<>(Arrays.asList(directives));
	}

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

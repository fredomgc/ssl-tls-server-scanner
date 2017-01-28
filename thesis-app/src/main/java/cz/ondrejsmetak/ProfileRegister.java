package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.Profile;
import java.util.HashMap;
import java.util.List;

/**
 * Holds all the test profiles. Singleton pattern.
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ProfileRegister {

	/**
	 * Instance of this class
	 */
	private static ProfileRegister instance = null;

	/**
	 * Register of all profiles
	 */
	private final HashMap<String, Profile> register = new HashMap<>();

	protected ProfileRegister() {
		//no direct instantiation
	}

	/**
	 * Returns a instance of this class
	 *
	 * @return instance of this class
	 */
	public static ProfileRegister getInstance() {
		if (instance == null) {
			instance = new ProfileRegister();
		}
		return instance;
	}

	/**
	 * Adds a collection of new profiles to the register
	 *
	 * @param profiles collection of profiles
	 */
	public void registerProfiles(List<Profile> profiles) {
		for (Profile profile : profiles) {
			registerProfile(profile);
		}
	}

	/**
	 * Adds a new profiles to the register
	 *
	 * @param profile a new profile
	 */
	public void registerProfile(Profile profile) {
		if (register.containsKey(profile.getName())) {
			throw new IllegalArgumentException("Profile with name [" + profile.getName() + "] already exists!");
		}

		register.put(profile.getName(), profile);
	}

	/**
	 * Checks, if profile with the given name is registered
	 *
	 * @param profileCodeName name of the profile
	 * @return true, if such profile exists, false otherwise
	 */
	public boolean hasProfile(String profileCodeName) {
		return register.containsKey(profileCodeName);
	}

	/**
	 * Returns the profile with given name or null, if such profiles doesn't
	 * exists
	 *
	 * @param profileCodeName name of the profile
	 * @return found profile, if null in case of any error
	 */
	public Profile getProfile(String profileCodeName) {
		return register.get(profileCodeName);
	}

}

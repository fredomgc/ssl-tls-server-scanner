package cz.ondrejsmetak;

import cz.ondrejsmetak.entity.Profile;
import java.util.HashMap;
import java.util.List;

/**
 * Udržuje všechny profily, se kterými aplikaace umí pracovat
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ProfileRegister {

	private static ProfileRegister instance = null;
	private final HashMap<String, Profile> register = new HashMap<>();

	protected ProfileRegister() {
		//no direct instantiation.
	}

	public static ProfileRegister getInstance() {
		if (instance == null) {
			instance = new ProfileRegister();
		}
		return instance;
	}

	public void registerProfiles(List<Profile> profiles) {
		for (Profile profile : profiles) {
			registerProfile(profile);
		}
	}

	public void registerProfile(Profile profile) {
		if (register.containsKey(profile.getName())) {
			throw new IllegalArgumentException("Profile with name [" + profile.getName() + "] already exists!");
		}

		register.put(profile.getName(), profile);
	}

	public boolean hasProfile(String profileCodeName) {
		return register.containsKey(profileCodeName);
	}

	public Profile getProfile(String profileCodeName) {
		return register.get(profileCodeName);
	}

}

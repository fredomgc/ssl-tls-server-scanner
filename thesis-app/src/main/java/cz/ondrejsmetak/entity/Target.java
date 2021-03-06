package cz.ondrejsmetak.entity;

import cz.ondrejsmetak.ProfileRegister;

/**
 * Target, that will be scanned
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Target extends BaseEntity {

	/**
	 * Destination. Could be IP, URL or hostname
	 */
	private String destination;

	/**
	 * Profile united with this target
	 */
	private String profile;

	/**
	 * Name of target. Just for user convenience
	 */
	private String name = "";

	/**
	 * Creates new target with given attributes
	 *
	 * @param destination target destination
	 * @param profile target profile
	 * @param name target name
	 */
	public Target(String destination, String profile, String name) {
		if (destination.isEmpty()) {
			throw new IllegalArgumentException("Destination can't be empty!");
		}

		if (profile.isEmpty()) {
			throw new IllegalArgumentException("Profile can't be empty!");
		}

		if (!ProfileRegister.getInstance().hasProfile(profile)) {
			throw new IllegalArgumentException("Profile with name [" + profile + "] not found!");
		}

		this.destination = destination;
		this.profile = profile;
		this.name = name;
	}

	public String getDestination() {
		return destination;
	}

	public Profile getProfile() {
		return ProfileRegister.getInstance().getProfile(profile);
	}

	public String getName() {
		return name;
	}

	/**
	 * Creates new target with given attributes. Usefull shortcut
	 *
	 * @param destination target destination
	 * @param profile target profile
	 * @param name target name
	 * @return newly created target
	 */
	public static Target fromXml(String destination, String profile, String name) {
		Target target = new Target(destination, profile, name);
		return target;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(destination);
		sb.append(" (").append(name);
		sb.append(" ; ").append(profile);
		sb.append(")");

		return sb.toString();
	}

}

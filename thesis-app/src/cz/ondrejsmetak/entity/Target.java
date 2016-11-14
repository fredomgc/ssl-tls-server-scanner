package cz.ondrejsmetak.entity;

import cz.ondrejsmetak.ProfileRegister;
import java.util.List;
import java.util.logging.Logger;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Target extends BaseEntity {

	private String destination;
	private String profile;
	private String name = "";

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

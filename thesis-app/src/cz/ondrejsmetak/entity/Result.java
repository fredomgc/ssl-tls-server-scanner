package cz.ondrejsmetak.entity;

/**
 * Represents result of scan
 *
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Result extends BaseEntity {

	/**
	 * Type of result
	 */
	private enum Type {
		SAFE, VULNERABLE, UNKNOWN
	}

	/**
	 * Type of this result
	 */
	private Type type;

	/**
	 * Optional note to result
	 */
	private String note;

	public Result() {
		type = Type.UNKNOWN;
	}

	public void setSafe() {
		this.type = Type.SAFE;
	}

	public void setVulnerable() {
		this.type = Type.VULNERABLE;
	}

	public void setUnknown() {
		this.type = Type.UNKNOWN;
	}

	public void setUnknown(String note) {
		this.type = Type.UNKNOWN;
		setNote(note);
	}

	private void setNote(String note) {
		this.note = note;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(type);
		if (note != null && !note.isEmpty()) {
			sb.append(" [").append(note).append("]");
		}

		return sb.toString();
	}

	public boolean isVulnerable() {
		return this.type == Type.VULNERABLE;
	}

	public boolean isSafe() {
		return this.type == Type.SAFE;
	}

	public boolean isUnknown() {
		return this.type == Type.UNKNOWN;
	}

	public String getNote() {
		return this.note;
	}

	public boolean hasNote() {
		return this.note != null && !this.note.isEmpty();
	}

	/**
	 * Creates new safe result
	 *
	 * @return new safe result
	 */
	public static Result getSafe() {
		Result o = new Result();
		o.setSafe();
		return o;
	}

	/**
	 * Creates new safe result with given note
	 *
	 * @param note note for newly created result
	 * @return new safe result
	 */
	public static Result getSafe(String note) {
		Result o = new Result();
		o.setSafe();
		o.setNote(note);
		return o;
	}

	/**
	 * Creates new vulnerable result
	 *
	 * @return new vulnerable result
	 */
	public static Result getVulnerable() {
		Result o = new Result();
		o.setVulnerable();
		return o;
	}

	/**
	 * Creates new vulnerable result with given note
	 *
	 * @param note note for newly created result
	 * @return new vulnerable result
	 */
	public static Result getVulnerable(String note) {
		Result o = new Result();
		o.setVulnerable();
		o.setNote(note);
		return o;
	}

	/**
	 * Creates new unknown result
	 *
	 * @return new unknown result
	 */
	public static Result getUnknown() {
		Result o = new Result();
		o.setUnknown();
		return o;
	}

	/**
	 * Creates new unknown result with given note
	 *
	 * @param note note for newly created result
	 * @return new unknown result
	 */
	public static Result getUnknown(String note) {
		Result o = new Result();
		o.setNote(note);
		return o;
	}
}

package cz.ondrejsmetak.entity;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Result extends BaseEntity {

	private enum Type {
		SAFE, VULNERABLE, UNKNOWN
	}

	private Type type;
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
		//TODO, odstranit uvodni a koncovou ( ) pokud to obsahuje
		this.note = note.matches("\\(.*\\)") ? note : note;
	}

	
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(type);
		if (note != null && !note.isEmpty()) {
			sb.append(" ").append(note);
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

	public String getNote(){
		return this.note;
	}
	
	public boolean hasNote(){
		return this.note != null && !this.note.isEmpty();
	}
	
	public static Result getSafe() {
		Result o = new Result();
		o.setSafe();
		return o;
	}

	public static Result getSafe(String note) {
		Result o = new Result();
		o.setSafe();
		o.setNote(note);
		return o;
	}

	public static Result getVulnerable() {
		Result o = new Result();
		o.setVulnerable();
		return o;
	}

	public static Result getVulnerable(String note) {
		Result o = new Result();
		o.setVulnerable();
		o.setNote(note);
		return o;
	}

	public static Result getUnknown() {
		Result o = new Result();
		o.setUnknown();
		return o;
	}

	public static Result getUnknown(String note) {
		Result o = new Result();
		o.setNote(note);
		return o;
	}
}

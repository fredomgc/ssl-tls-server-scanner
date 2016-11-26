package cz.ondrejsmetak.entity;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class ReportMessage {

	public enum Category {
		PROTOCOL, VULNERABILITY, CERTIFICATE, CIPHER
	}
	
	public enum Type {
		ERROR, SUCCESS
	}

	private String message;
	private Category category;
	private Type type;
	
	public ReportMessage(String message, Category category) {
		this.message = message;
		this.category = category;
		this.type = Type.ERROR;
	}

	public ReportMessage(String message, Category category, Type type) {
		this.message = message;
		this.category = category;
		this.type = type;
	}

	public String getMessage() {
		return message;
	}

	public Category getCategory() {
		return category;
	}

	public Type getType() {
		return type;
	}
}

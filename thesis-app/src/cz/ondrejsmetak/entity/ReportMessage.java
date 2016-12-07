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
	private Mode requiredMode;
	
	public ReportMessage(String message, Category category, Mode requiredMode) {
		this.message = message;
		this.category = category;
		this.requiredMode = requiredMode;
		this.type = Type.ERROR;
	}

	public ReportMessage(String message, Category category, Mode requiredMode, Type type) {
		this.message = message;
		this.category = category;
		this.requiredMode = requiredMode;
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
	
	public Mode getRequiredMode(){
		return requiredMode;
	}
	
	public String getRequiredModeHuman(){		
		if(requiredMode.isCanBe()){
			return "can be";
		}
		
		if(requiredMode.isMustBe()){
			return "must be";
		}
		
		if(requiredMode.isMustNotBe()){
			return "must not be";
		}
		
		return "-";
	}
}

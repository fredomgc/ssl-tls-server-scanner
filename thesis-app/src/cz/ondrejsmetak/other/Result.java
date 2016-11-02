package cz.ondrejsmetak.other;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Result {

	private enum Type {
		SAFE, VULNERABLE, UNKNOWN
	}

	private Type type;
	private String unknownReason;

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
	
	public void setUnknown(String reason) {
		this.type = Type.UNKNOWN;
		setUnknownReason(reason);
	}

	private void setUnknownReason(String reason){
		this.unknownReason = reason.matches("\\(.*\\)") ? reason : "(" + reason + ")";
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(type);
		if(unknownReason != null && !unknownReason.isEmpty()){
			sb.append(" ").append(unknownReason);
		}
		
		return sb.toString();
	}
	
	
	
	public static Result getSafe(){
		Result o = new Result();
		o.setSafe();
		return o;
	}
	
	public static Result getVulnerable(){
		Result o = new Result();
		o.setVulnerable();
		return o;
	}
	
	public static Result getUnknown(){
		Result o = new Result();
		o.setUnknown();
		return o;
	}
	public static Result getUnknown(String reason){
		Result o = new Result();
		o.setUnknown(reason);
		return o;
	}

}

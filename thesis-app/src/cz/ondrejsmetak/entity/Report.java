package cz.ondrejsmetak.entity;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Report {

	private Target target;
	private List<ReportMessage> vulnerabilitiesMessages;
	private List<ReportMessage> safeMessages;

	public Report(Target target, List<ReportMessage> vulnerabilities, List<ReportMessage> safe) {
		this.target = target;
		this.vulnerabilitiesMessages = vulnerabilities;
		this.safeMessages = safe;
	}

	public List<ReportMessage> getAllMessages() {
		List<ReportMessage> mixed = new ArrayList<>();
		mixed.addAll(vulnerabilitiesMessages);
		mixed.addAll(safeMessages);
		return mixed;
	}

	public Target getTarget() {
		return target;
	}
	
	
}

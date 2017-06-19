package cz.ondrejsmetak.entity;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents collection of messages. Messages are related to scan results. Each
 * report is always related to one target.
 *
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class Report {

	/**
	 * Target, that was checked
	 */
	private Target target;

	/**
	 * Collection of messages, that are related to found vulnerabilities and
	 * security issuses
	 */
	private final List<ReportMessage> vulnerabilitiesMessages;

	/**
	 * Collection of messages, that are related to confirmed safe states
	 */
	private List<ReportMessage> safeMessages;

	public Report(Target target, List<ReportMessage> vulnerabilities, List<ReportMessage> safe) {
		this.target = target;
		this.vulnerabilitiesMessages = vulnerabilities;
		this.safeMessages = safe;
	}

	/**
	 * Returns all types of messages
	 * @return collection of messages
	 */
	public List<ReportMessage> getAllMessages() {
		List<ReportMessage> mixed = new ArrayList<>();
		mixed.addAll(vulnerabilitiesMessages);
		mixed.addAll(safeMessages);
		return mixed;
	}

	/**
	 * Returns target related to this report
	 * @return target related to this report
	 */
	public Target getTarget() {
		return target;
	}

}

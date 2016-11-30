package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ResourceManager;
import cz.ondrejsmetak.entity.Report;
import cz.ondrejsmetak.entity.ReportMessage;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ondřej Směták <posta@ondrejsmetak.cz>
 */
public class HtmlExport {

	private static final String CONTENT_HOOK = "#CONTENT#";

	private String getTemplate() throws FileNotFoundException {
		return Helper.getContentoOfFile(ResourceManager.getHtmlTemplate());
	}

	private String getContent(List<Report> reports, Date timestamp) throws FileNotFoundException {
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("<h1>SSL/TLS scan report <small>created %s</small></h1>", Helper.getFormattedDateTime(timestamp, false)));
		
		for (Report report : reports) {
			sb.append(doReport(report));
			sb.append("<hr />");
		}

		String template = getTemplate();
		template = template.replace(CONTENT_HOOK, sb.toString());
		//todo, zmenit cas vygenerovani
		
		return template;
	}

	private String doReport(Report report) {
		List<ReportMessage> protocol = new ArrayList<>();
		List<ReportMessage> certificate = new ArrayList<>();
		List<ReportMessage> cipher = new ArrayList<>();
		List<ReportMessage> vulnerability = new ArrayList<>();

		for (ReportMessage reportMessage : report.getAllMessages()) {
			if (reportMessage.getCategory().equals(ReportMessage.Category.PROTOCOL)) {
				protocol.add(reportMessage);
			}

			if (reportMessage.getCategory().equals(ReportMessage.Category.CERTIFICATE)) {
				certificate.add(reportMessage);
			}

			if (reportMessage.getCategory().equals(ReportMessage.Category.VULNERABILITY)) {
				vulnerability.add(reportMessage);
			}

			if (reportMessage.getCategory().equals(ReportMessage.Category.CIPHER)) {
				cipher.add(reportMessage);
			}
		}
		
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("<h2>Target: %s (%s)</h2>", report.getTarget().getDestination(), report.getTarget().getName()));
		sb.append("<table class=\"table table-striped table-hover\">");
		sb.append("<thead><tr><th>Category</th><th>Status</th></tr></thead>");
		sb.append("<tbody>");
		sb.append(doCreateTableSegment("Protocols", protocol));
		sb.append(doCreateTableSegment("Certificate", certificate));
		sb.append(doCreateTableSegment("Cipher suites", cipher));
		sb.append(doCreateTableSegment("Vulnerabilities", vulnerability));
		sb.append("</tbody>");
		sb.append("</table>");
		return sb.toString();
	}

	private String doCreateTableSegment(String segmentName, List<ReportMessage> messages) {
		if (messages.isEmpty()) {
			return "";
		}

		StringBuilder sb = new StringBuilder();
		sb.append(String.format("<tr> <th scope=\"row\" rowspan=\"%s\" class=\"col-xs-1\">%s</th>", messages.size(), segmentName));

		boolean first = true;
		for (ReportMessage message : messages) {
			if (!first) {
				sb.append("<tr>");
			}
			sb.append(String.format("<td class=\"%s\">%s</td> </tr>", typeToCssClass(message.getType()), message.getMessage()));

			first = false;
		}

		return sb.toString();
	}

	private String typeToCssClass(ReportMessage.Type type) {
		if (type.equals(ReportMessage.Type.ERROR)) {
			return "danger";
		}

		if (type.equals(ReportMessage.Type.SUCCESS)) {
			return "success";
		}

		return "";
	}

	public String export(List<Report> reports) {
		Date timestamp = new Date();
		File target = new File(Helper.getWorkingDirectory() + File.separator + "report_" + Helper.getFormattedDateTime(timestamp, true) + ".htm");

		Writer writer = null;

		//todo, try with resources
		try {

			writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(target.getAbsolutePath()), "utf-8"));
			writer.write(getContent(reports, timestamp));
			writer.flush();
			writer.close();

		} catch (IOException ex) {
			// report
		} finally {
			try {
				writer.close();
			} catch (Exception ex) {/*ignore*/
			}
		}

		return target.getAbsolutePath();
	}

}

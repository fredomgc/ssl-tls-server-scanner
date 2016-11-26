package cz.ondrejsmetak.tool;

import cz.ondrejsmetak.ResourceManager;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
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

	public void export() {
		File target = new File(Helper.getWorkingDirectory() + File.separator + "report_" + Helper.getCurrentDateTime() + ".htm");

		Writer writer = null;

		try {

			String content = getTemplate();
			content = content.replace(CONTENT_HOOK, "LOLOL");

			writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(target.getAbsolutePath()), "utf-8"));
			writer.write(content);
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

	}

}

package chessmail;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;

import org.apache.commons.io.FilenameUtils;
import org.jsoup.Connection;
import org.jsoup.Connection.Response;
import org.jsoup.Jsoup;

public class CMDownloadRunnable extends CMConnection implements Runnable
{
	private String downloadFolder, filenamePGN;

	CMDownloadRunnable(String url, List<String> cookies, String downloadFolder, String filenamePGN)
	{
		super(url, cookies);
		this.downloadFolder = downloadFolder;
		this.filenamePGN = filenamePGN;
	}

	@Override
	public void run()
	{
		download_finished_games(this.url);
	}

	private void download_finished_games(String downloadURL)
	{
		try
		{
			Connection con = Jsoup.connect(downloadURL);
			con.header("Accept-Encoding", "gzip, deflate, br");
			con.userAgent(USER_AGENT);
			con.ignoreContentType(true);
			con.maxBodySize(0);
			con.timeout(600000);
			Response resp = con.execute();
			byte[] bytes = resp.bodyAsBytes();
			String savedFileName = FilenameUtils.getName(downloadURL);

			Matcher mFilename = pFilename.matcher(resp.header("Content-Disposition"));
			if (mFilename.find())
				savedFileName = mFilename.group(1);

			FileOutputStream fos = new FileOutputStream(FilenameUtils.concat(this.downloadFolder, this.filenamePGN), true);
			synchronized (fos)
			{
				fos.write(bytes);
				fos.write(System.getProperty("line.separator").getBytes());
				fos.close();
			}

			Chessmail_PGN_Tool.printMe("PGN added: " + savedFileName + " [count: " + Chessmail_PGN_Tool.count.incrementAndGet() + "]");
		}
		catch (IOException e)
		{
			Chessmail_PGN_Tool.printMe("Could not read the file at '" + downloadURL + "'.");
			e.printStackTrace();
		}
	}
}

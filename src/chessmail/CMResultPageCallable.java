package chessmail;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.List;
import java.util.concurrent.Callable;

import javax.net.ssl.HttpsURLConnection;

public class CMResultPageCallable extends CMConnection implements Callable<String>
{
	CMResultPageCallable(String url, List<String> cookies)
	{
		super(url, cookies);
	}

	@Override
	public String call() throws Exception
	{
		if (Chessmail_PGN_Tool.Verbose)
			Chessmail_PGN_Tool.printMe("Processing page " + url);
		else
			Chessmail_PGN_Tool.printMe(".", true, false);

		return GetPageContent(this.url);
	}

	private String GetPageContent(String url) throws Exception
	{
		URL obj = new URL(url);
		conn = (HttpsURLConnection) obj.openConnection();

		conn.setRequestMethod("GET");

		conn.setUseCaches(false);

		conn.setRequestProperty("User-Agent", USER_AGENT);
		conn.setRequestProperty("Accept",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
		conn.setRequestProperty("Accept-Language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7");
		conn.setRequestProperty("Host", "www.chessmail.de");
		conn.setRequestProperty("sec-ch-ua", "\"Chromium\";v=\"110\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"110\"");
		conn.setRequestProperty("sec-ch-ua-mobile", "?0");
		conn.setRequestProperty("sec-ch-ua-platform", "Windows");
		conn.setRequestProperty("Sec-Fetch-Dest", "document");
		conn.setRequestProperty("Sec-Fetch-Mode", "navigate");
		conn.setRequestProperty("Sec-Fetch-Site", "same-origin");
		conn.setRequestProperty("Sec-Fetch-User", "?1");
		conn.setRequestProperty("Upgrade-Insecure-Requests", "1");
		conn.setRequestProperty("Referer", "https://www.chessmail.de/login");

		if (cookies != null)
		{
			for (String cookie : this.cookies)
			{
				conn.addRequestProperty("Cookie", cookie.split(";", 1)[0]);
			}
		}

		BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null)
		{
			response.append(inputLine);
		}
		in.close();

		return response.toString();
	}
}

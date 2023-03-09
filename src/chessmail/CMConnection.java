package chessmail;

import java.util.List;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

public abstract class CMConnection
{
	protected final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36";
	protected final Pattern pFilename = Pattern.compile("filename=(.*)");

	protected volatile String url = "";
	protected volatile List<String> cookies;
	protected volatile HttpsURLConnection conn;

	CMConnection(String url, List<String> cookies)
	{
		this.url = url;
		this.cookies = cookies;
	}

	public void setURL(String url)
	{
		this.url = url;
	}

	public void setCookies(List<String> cookies)
	{
		this.cookies = cookies;
	}
}

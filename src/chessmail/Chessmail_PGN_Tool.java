package chessmail;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.FileSystems;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class Chessmail_PGN_Tool
{
	private List<String> cookies;
	private HttpsURLConnection conn;

	private final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36";
	private final Pattern pPageCount = Pattern.compile("(.*p=)(\\d+)");
	private final Pattern pHash = Pattern.compile("const z = '(.*)'");
	private final Pattern pCMCookie = Pattern.compile("document\\.cookie\\ =\\ \"tk=([^\"]+)\"");
	static AtomicInteger count;
	static Boolean Verbose = false;
	private int maxThreads;
	private String Filter_minMoves, Filter_openingString, Filter_wonBy, Filter_opponentname, Filter_includeTimeoutGames, Filter_onlyRatedGames, check, username,
			password, downloadFolder;
	private static Options options = new Options();
	private static String filenamePGN = "chessmail_export.pgn";
	private static final String URL_base = "https://www.chessmail.de";
	private static final String URL_login = URL_base + "/login";
	private static final String URL_logout = URL_base + "/logout.html";
	private static String URL_download = "https://www.chessmail.de/game/download/chessmail-game.pgn?key=#GAME#";

	enum FilterWonBy
	{
		w("white"),
		b("black"),
		d("draw"),
		i("user"),
		o("opponent");

		private String filter;

		FilterWonBy(String filter)
		{
			this.filter = filter;
		}

		public String getValue()
		{
			return filter;
		}
	}

	public static void main(String[] args) throws Exception
	{
		Chessmail_PGN_Tool http = new Chessmail_PGN_Tool();

		Option verbose = new Option("v", "verbose");
		verbose.setRequired(false);
		options.addOption(verbose);

		Option folder = new Option("f", true, "output folder");
		verbose.setRequired(false);
		options.addOption(folder);

		Option filename = new Option("n", true, "filename");
		filename.setRequired(false);
		options.addOption(filename);

		Option username = new Option("u", true, "username");
		username.setRequired(true);
		options.addOption(username);

		Option password = new Option("p", true, "password");
		password.setRequired(true);
		options.addOption(password);

		Option maxThreads = new Option("t", true, "max threads");
		maxThreads.setRequired(false);
		options.addOption(maxThreads);

		Option includeTimeoutGames = new Option("Ft", true, "include timeout games? (true | false)");
		includeTimeoutGames.setRequired(false);
		options.addOption(includeTimeoutGames);

		Option onlyRatedGames = new Option("Fr", true, "only rated games? (true | false)");
		onlyRatedGames.setRequired(false);
		options.addOption(onlyRatedGames);

		Option minMoves = new Option("Fm", true, "minimum move count");
		minMoves.setRequired(false);
		options.addOption(minMoves);

		Option openingString = new Option("Fop", true, "opening name");
		openingString.setRequired(false);
		options.addOption(openingString);

		Option wonBy = new Option("Fw", true, "won by -> (w)hite | (b)lack | (d)raw | (i) win | (o)pponent wins");
		wonBy.setRequired(false);
		options.addOption(wonBy);

		Option opponentname = new Option("Fon", true, "opponent name");
		opponentname.setRequired(false);
		options.addOption(opponentname);

		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();
		CommandLine cmd = null;

		try
		{
			cmd = parser.parse(options, args);
		}
		catch (ParseException e)
		{
			System.out.println(e.getMessage());
			formatter.printHelp("utility-name", options);
			System.exit(1);
		}

		Verbose = cmd.hasOption(verbose);
		http.downloadFolder = cmd.getOptionValue(folder, FileSystems.getDefault().getPath("").toAbsolutePath().toString());
		http.username = cmd.getOptionValue(username);
		http.password = cmd.getOptionValue(password);
		http.maxThreads = Integer.parseInt(cmd.getOptionValue(maxThreads, "1"));

		http.Filter_includeTimeoutGames = cmd.getOptionValue(includeTimeoutGames, "true");
		http.Filter_minMoves = cmd.getOptionValue(minMoves, "");
		http.Filter_onlyRatedGames = cmd.getOptionValue(onlyRatedGames, "false");
		http.Filter_openingString = cmd.getOptionValue(openingString, "");
		http.Filter_opponentname = cmd.getOptionValue(opponentname, "");
		try
		{
			http.Filter_wonBy = FilterWonBy.valueOf(cmd.getOptionValue(wonBy, "")).getValue();
		}
		catch (Exception e2)
		{
			http.Filter_wonBy = "";
		}
		filenamePGN = cmd.getOptionValue(filename, filenamePGN);

		LocalDateTime startTime = LocalDateTime.now();
		Chessmail_PGN_Tool.printMe("Starting at " + startTime.truncatedTo(ChronoUnit.SECONDS).format(DateTimeFormatter.ISO_LOCAL_TIME), true, true);

		String URL_start = "https://www.chessmail.de/game/list/finished.html?";
		URL_start += "includeTimeoutGames=#INCLUDETIMEOUTGAMES#&";
		URL_start += "_onlyRatedGames=on&";
		URL_start += "onlyRatedGames=#ONLYRATEDGAMES#&";
		URL_start += "search=Suchen&";
		URL_start += "minMoves=#MINMOVES#&";
		URL_start += "openingString=#OPENINGSTRING#&";
		URL_start += "wonBy=#WONBY#&";
		URL_start += "opponentname=#OPPONENTNAME#&";
		URL_start += "d-49280-p=#PAGENO#&";
		URL_start += "sent=true&";
		URL_start += "_includeTimeoutGames=on";

		CookieHandler.setDefault(new CookieManager());

		http.setCookies(Arrays.asList(http.getCMCookieInfo()));

		String page = http.GetPageContent(URL_login);
		Matcher mHash = http.pHash.matcher(page);
		String hash_comp;
		if (mHash.find())
		{
			hash_comp = mHash.group(1);
			http.check = DigestUtils.md5Hex(http.username + hash_comp).toString();
		}
		else
		{
			if (Verbose)
			{
				try (FileOutputStream fsout = new FileOutputStream("login.html"))
				{
					fsout.write(page.getBytes());
					fsout.flush();
				}
			}

			throw new IllegalArgumentException("Es konnte kein Hash für den Login ermittelt werden!");
		}

		String postParams = http.getFormParams(page, http.username, http.password);

		Chessmail_PGN_Tool.printMe("Logging in...", true, false);
		String result = http.sendPost(URL_login, postParams);
		Chessmail_PGN_Tool.printMe("ok", true, true);

		String nextUrl = URL_start.replace("#USER#", http.username);
		nextUrl = nextUrl.replace("#INCLUDETIMEOUTGAMES#", http.Filter_includeTimeoutGames.toString());
		nextUrl = nextUrl.replace("#ONLYRATEDGAMES#", http.Filter_onlyRatedGames.toString());
		nextUrl = nextUrl.replace("#MINMOVES#", http.Filter_minMoves);
		nextUrl = nextUrl.replace("#OPENINGSTRING#", http.Filter_openingString);
		nextUrl = nextUrl.replace("#WONBY#", http.Filter_wonBy);
		nextUrl = nextUrl.replace("#OPPONENTNAME#", http.Filter_opponentname);

		String basePageURL = nextUrl;

		nextUrl = nextUrl.replace("#PAGENO#", "1");
		result = http.GetPageContent(nextUrl);

		Document doc = Jsoup.parse(result);
		Element ele = doc.select(".searchfound").get(0);

		count = new AtomicInteger(0);

		Integer pagingCount = 0;
		if (doc.select("span.icon.icon-angles-right.size-1.set-solid").size() > 0)
		{
			ele = doc.select("span.icon.icon-angles-right.size-1.set-solid").get(0);
			Matcher mPageCount = http.pPageCount.matcher(ele.parent().absUrl("href"));
			if (mPageCount.find())
			{
				pagingCount = Integer.parseInt(mPageCount.group(2));
			}
		}

		ArrayList<String> urlArray = new ArrayList<String>();
		if (pagingCount > 0)
		{
			for (int i = 1; i <= pagingCount; i++)
			{
				urlArray.add(basePageURL.replace("#PAGENO#", String.valueOf(i)));
			}
		}
		else
		{
			urlArray.add(nextUrl);
		}

		if (!Verbose)
			Chessmail_PGN_Tool.printMe("Processing", true, false);

		FileUtils.deleteQuietly(new File(FilenameUtils.concat(http.downloadFolder, filenamePGN)));

		ExecutorService executor = Executors.newFixedThreadPool(http.maxThreads);
		List<Callable<String>> taskList = new ArrayList<>();

		urlArray.forEach(url -> taskList.add(new CMResultPageCallable(url, http.cookies)));

		List<Future<String>> resultList = null;
		try
		{
			resultList = executor.invokeAll(taskList);
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
		executor.shutdownNow();

		List<CMDownloadRunnable> downloads = new ArrayList<CMDownloadRunnable>();
		for (Future<String> url : resultList)
		{
			try
			{
				Document docT = Jsoup.parse(url.get());

				for (Element e : docT.select("#game tbody tr"))
				{
					String gameID = e.selectFirst("td a").attr("href").replace("/game/", "");
					CMDownloadRunnable download = new CMDownloadRunnable(URL_download.replace("#GAME#", gameID), http.cookies, http.downloadFolder,
							Chessmail_PGN_Tool.filenamePGN);
					downloads.add(download);
				}
			}
			catch (Exception ex)
			{
				ex.printStackTrace();
			}
		}

		CompletableFuture<?>[] completableFutures = downloads.stream().map(CompletableFuture::runAsync).toArray(CompletableFuture<?>[]::new);
		CompletableFuture.allOf(completableFutures).get();
		// while (!CompletableFuture.allOf(completableFutures).isDone())
		// {
		// Thread.sleep(500);
		// }

		if (!Verbose)
			System.out.println();

		Chessmail_PGN_Tool.printMe("Logging out...", true, true);

		http.GetPageContent(URL_logout);

		LocalDateTime endTime = LocalDateTime.now();
		Chessmail_PGN_Tool.printMe("Done at " + endTime.truncatedTo(ChronoUnit.SECONDS).format(DateTimeFormatter.ISO_LOCAL_TIME), true, true);
		long hours = ChronoUnit.HOURS.between(startTime, endTime);
		long minutes = ChronoUnit.MINUTES.between(startTime, endTime) % 60;
		long seconds = ChronoUnit.SECONDS.between(startTime, endTime) % 60;
		Chessmail_PGN_Tool.printMe("Duration: " + hours + " hours " + minutes + " minutes " + seconds + " seconds", true, true);
		Chessmail_PGN_Tool.printMe("Games count: " + Chessmail_PGN_Tool.count, true, true);
	}

	static void printMe(String msg, Boolean force, Boolean newLine)
	{
		if (Verbose || force)
		{
			if (newLine)
				System.out.println(msg);
			else
				System.out.print(msg);
		}
	}

	static void printMe(String msg)
	{
		printMe(msg, false, true);
	}

	private String sendPost(String url, String postParams) throws Exception
	{
		URL obj = new URL(url);
		conn = (HttpsURLConnection) obj.openConnection();

		conn.setUseCaches(false);
		conn.setRequestMethod("POST");
		conn.setRequestProperty("Host", "www.chessmail.de");
		conn.setRequestProperty("User-Agent", USER_AGENT);
		conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		conn.setRequestProperty("Accept-Language", "de,en-US,en;q=0.5");
		for (String cookie : this.cookies)
		{
			conn.addRequestProperty("Cookie", cookie.split(";", 1)[0]);
		}
		conn.setRequestProperty("Connection", "keep-alive");
		conn.setRequestProperty("Origin", URL_base);
		conn.setRequestProperty("Referer", URL_login);
		conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

		String contentLength = Integer.toString(postParams.length());

		conn.setRequestProperty("Content-Length", contentLength);

		conn.setDoOutput(true);

		DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
		wr.writeBytes(postParams);
		wr.flush();
		wr.close();

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

	public String getCMCookieInfo()
	{
		String cmCookie = "";

		try
		{
			String body = Jsoup.connect(URL_base).execute().body();

			Matcher mCookie = this.pCMCookie.matcher(body);
			if (mCookie.find())
			{
				cmCookie = "tk=" + mCookie.group(1);
			}
		}
		catch (IOException e)
		{
			if (Verbose)
				printMe(e.getLocalizedMessage());
		}

		return cmCookie;
	}

	public String getFormParams(String html, String username, String password)
			throws UnsupportedEncodingException
	{
		Document doc = Jsoup.parse(html);

		Element loginform = doc.getElementById("loginForm");
		Elements inputElements = loginform.getElementsByTag("input");
		List<String> paramList = new ArrayList<String>();
		for (Element inputElement : inputElements)
		{
			String key = inputElement.attr("name");

			if (!key.equalsIgnoreCase("loginPermanent"))
			{
				String value = inputElement.attr("value");

				if (key.equals("username"))
					value = username;
				else if (key.equals("password"))
					value = password;
				else if (key.equals("check"))
					value = this.check;
				paramList.add(key + "=" + URLEncoder.encode(value, "UTF-8"));
			}
		}

		StringBuilder result = new StringBuilder();
		for (String param : paramList)
		{
			if (result.length() == 0)
			{
				result.append(param);
			}
			else
			{
				result.append("&" + param);
			}
		}
		return result.toString();
	}

	public List<String> getCookies()
	{
		return cookies;
	}

	public void setCookies(List<String> cookies)
	{
		this.cookies = cookies;
	}

}
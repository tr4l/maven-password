package ninja.stealing.maven.password;

import java.util.Base64;

public class Utils {
	public static String b64(String input){
		String encodedString = Base64.getEncoder().encodeToString(input.getBytes());
		return encodedString;
	}
}

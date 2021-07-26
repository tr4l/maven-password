package ninja.stealing.maven.password.extractor.maven;

import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.crypto.DefaultSettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;

public class DumpObject {
	public enum Type {
		SERVER, PROXY
	}

	private String username;
	private String password;
	private Proxy refProxy;
	private Server refServer;
	private String id;
	private Type type;

	public DumpObject(Proxy proxy) {
		this.type = Type.PROXY;
		this.refProxy = proxy;
		this.password = proxy.getPassword();
		this.username = proxy.getUsername();
		this.id = proxy.getId();
	}

	public DumpObject(Server server) {
		this.type = Type.SERVER;
		this.refServer = server;
		this.password = server.getPassword();
		this.username = server.getUsername();
		this.id = server.getId();
	}

	public String getDecryptedPassword(SettingsDecrypter settingsDecrypter) {
		SettingsDecryptionRequest decryptionRequest = null;
		if (type == Type.PROXY) {
			decryptionRequest = new DefaultSettingsDecryptionRequest(refProxy);
		} else if (type == Type.SERVER) {
			decryptionRequest = new DefaultSettingsDecryptionRequest(refServer);
		}
		SettingsDecryptionResult decryptionResult = settingsDecrypter.decrypt(decryptionRequest);

		if (decryptionResult.getProblems().isEmpty()) {
			if (type == Type.PROXY) {
				return decryptionResult.getProxy().getPassword();
			} else if (type == Type.SERVER) {
				return decryptionResult.getServer().getPassword();
			}
		}

		return null;
	}

	public String getId() {
		return id;
	}

	public String getPassword() {
		return password;
	}

	public String getType() {
		if (type == Type.PROXY) {
			return "Proxy";
		} else if (type == Type.SERVER) {
			return "Server";
		}
		return null;
	}

	public String getUsername() {
		return username;
	}
}


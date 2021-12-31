package ninja.stealing.maven.password.Logger;

public class NoLogger implements Logger{
    @Override
    public void info(String s) {
        //do nothing
    }

    @Override
    public void warn(String s) {
        //do nothing

    }
}

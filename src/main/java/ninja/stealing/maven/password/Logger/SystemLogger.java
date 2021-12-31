package ninja.stealing.maven.password.Logger;

public class SystemLogger implements Logger{

    @Override
    public void info(String s) {
        System.out.println("Info: "+s);
    }

    @Override
    public void warn(String s) {
        System.out.println("Warn: "+s);
    }
}

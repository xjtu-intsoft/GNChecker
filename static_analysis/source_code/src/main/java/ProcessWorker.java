import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * @description:
 * @author: xxx
 * @date: 2023/8/12 11:20
 **/
public class ProcessWorker extends Thread{
    private final Process process;
    private volatile int exitCode = -99;
    private volatile boolean completed = false;

    ProcessWorker(Process process) {
        this.process = process;
    }

    @Override
    public void run() {
        try {
            InputStreamReader reader = new InputStreamReader(process.getInputStream());
            BufferedReader in = new BufferedReader(reader);
            String line = null;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
            in.close();
            exitCode = process.waitFor();
            completed = true;
        } catch (InterruptedException | IOException e) {
            Thread.currentThread().interrupt();
        }
    }

    public int getExitCode() {
        return exitCode;
    }

    public boolean isCompleted() {
        return completed;
    }
}

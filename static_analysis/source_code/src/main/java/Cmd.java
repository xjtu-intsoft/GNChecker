import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * @description:
 * @author: xxx
 * @date: 2023/8/12 11:31
 **/
public class Cmd {
    public static int execCmd(String[] command, int timeoutSecond) throws IOException, TimeoutException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        // 合并错误输出流
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        ProcessWorker processWorker = new ProcessWorker(process);
        int exitCode = processWorker.getExitCode();
        processWorker.start();
        try {
            processWorker.join(timeoutSecond);
            if (processWorker.isCompleted()) {
                exitCode = processWorker.getExitCode();
            } else {
                process.destroy();
                processWorker.interrupt();
                System.out.println("超时");
                throw new TimeoutException("进程执行时间超时");
            }
        } catch (InterruptedException e) {
            processWorker.interrupt();
        }
        return exitCode;
    }

}

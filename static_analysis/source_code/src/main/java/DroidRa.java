import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * @description: droidra 命令行运行
 * @author: xxx
 * @date: 2023/9/25 16:04
 **/
public class DroidRa {

    public static void droidRa(String droidRaJar,String apk,String androidJar,String reflectionSimpleModel,String reflectionModel,
                               String dynamicLoadingModel,String fiedCallsTxt,String output,int timeout) throws IOException, TimeoutException {
        String[] cmd=new String[]{"java", "-jar", droidRaJar, apk, androidJar, reflectionSimpleModel, reflectionModel,dynamicLoadingModel, fiedCallsTxt, output};
        Cmd.execCmd(cmd,timeout);
    }
}

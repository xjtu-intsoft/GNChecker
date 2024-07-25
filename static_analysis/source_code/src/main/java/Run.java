import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;

/**
 * @description:
 * @author: xxx
 * @date: 2023/10/11 10:36
 **/
public class Run {
    public static void main(String[] args) throws XmlPullParserException, IOException {

        Main.run1("D:\\cert\\案例\\final\\apk\\网易新闻v94.1.apk",
                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source.json",
                "C:\\Users\\77294\\Desktop\\certdroid\\input\\sink1.json",
                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source_sinks.txt",
                "D:\\github_project\\FastDroid-master\\Files\\EasyTaintWrapperSource.txt",
                "C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms",
                "D:\\cert\\input\\callbacktest.txt",
                "D:\\anaconda\\python",
                "F:\\pythonProject\\test\\cg_process_java2.py",
                "D:\\cert\\案例\\final\\result");
//        Main.run1(args[0],args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9]);
    }
}

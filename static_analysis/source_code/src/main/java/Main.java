import my.*;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;
import soot.util.Chain;
import secondstage.taintanalysis.TaintLauncher;

import java.io.*;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeoutException;

/**
 * @description:
 * @author: xxx
 * @date: 2023/7/9 17:24
 **/
public class Main {

    public static void run(String apk,String apiFile,String sourceAndSinks,String easyTaintWrapper,String urlRegexTxt,String sdkPlatforms,String androidCallbacksTxt,String outPutPath) throws XmlPullParserException, IOException {
        //数据收集&数据使用
        String sensitive_scenes;
        String api_used;
        String outPut;
        System.out.println("data collecting.......");
        long t1 = System.nanoTime();
        try {
            String regex = urlRegexTxt;
            InfoflowAndroidConfiguration conf = new InfoflowAndroidConfiguration();
            // androidDirPath是你的android sdk中platforms目录的路径
            conf.getAnalysisFileConfig().setAndroidPlatformDir(sdkPlatforms);
            // apkFilePath是你要分析的apk的文件路径
//        conf.getAnalysisFileConfig().setSourceSinkFile("C:\\Users\\77294\\Desktop\\cert_境外非法传输+数据使用目的分析\\input\\SourcesAndSinks.txt");
            conf.getAnalysisFileConfig().setTargetAPKFile(apk);
            // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
            conf.setMergeDexFiles(true);
            // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
            conf.getAccessPathConfiguration().setAccessPathLength(-1);
            // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
            conf.getSolverConfiguration().setMaxAbstractionPathLength(-1);
            conf.getPathConfiguration().setMaxCallStackSize(-1);
            conf.getPathConfiguration().setMaxPathLength(-1);
            Options.v().set_soot_classpath(""+ File.pathSeparator+"");
            SetupApplication setup = new SetupApplication(conf);
            // 设置Callback的声明文件（不显式地设置好像FlowDroid会找不到）
            setup.setCallbackFile(androidCallbacksTxt);
            setup.initializeSoot();
            setup.parseAppResources();

            String packageName = setup.getMainfest().getPackageName();
           outPut = new File(outPutPath,packageName).getAbsolutePath();
            File file = new File(outPut);
            file.mkdirs();
            
            sensitive_scenes=new File(outPut,"sensitive_scenes.json").getAbsolutePath();
            api_used = new File(outPut, "api_used.json").getAbsolutePath();

            Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
            CallGraph callGraph = new CallGraph();
            Map<String, Object> map = Util.callGraphGenerate(applicationClasses,callGraph,outPut);
            Map<String,Long> nodes=(Map) map.get("nodes");
            Map<Long,String> nodeReverse=(Map)map.get("node_reverse");
            Map<Long, List> parents_info=(Map)map.get("parents_info");

            Thread dataThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Map apiUsed = ApiUsed.findSensitiveApiUsedWithUI(apiFile, nodes, nodeReverse, parents_info,api_used);
                        Util.writeMapToJson(api_used,apiUsed,false);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            });
            dataThread.start();
            final CountDownLatch cd=new CountDownLatch(1);
            Map<String, Object> scenes1 = new ConcurrentHashMap<>();
            Thread netTransThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        List<Map> netTransPlus = FindDataTransmission.findNetTransPlus(nodes,nodeReverse,parents_info, packageName, regex);
                        scenes1.put("net_trans", netTransPlus);
                        Util.writeMapToJson(sensitive_scenes, scenes1, false);
                        List<Map> crossCountryTransPlus = FindDataTransmission.findCrossCountryTransPlus(netTransPlus);
                        scenes1.put("cross_country_trans",crossCountryTransPlus);
                        Util.writeMapToJson(sensitive_scenes, scenes1, false);
                    }catch (Exception e){
                        e.printStackTrace();
                    }catch (OutOfMemoryError oe){
                        oe.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread crossAppThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        List<Map> crossAppTransPlus = FindDataTransmission.findCrossAppTransPlus(packageName,nodes,nodeReverse,parents_info);
                        scenes1.put("cross_app_trans", crossAppTransPlus);
                        Util.writeMapToJson(sensitive_scenes, scenes1, false);
                    }catch (Exception e){
                        e.printStackTrace();
                    }catch (OutOfMemoryError oe){
                        oe.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread dbThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try{
                        List<Map> dataIntoDBPlus = FindDataTransmission.findDataIntoDBPlus(nodes,nodeReverse,parents_info);
                        scenes1.put("data_into_db", dataIntoDBPlus);
                        Util.writeMapToJson(sensitive_scenes, scenes1, false);
                    }catch (Exception e){
                        e.printStackTrace();
                    }catch (OutOfMemoryError oe){
                        oe.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread fileThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try{
                        List<Map> dataIntoFilePlus = FindDataTransmission.findDataIntoFilePlus(nodes,nodeReverse,parents_info);
                        scenes1.put("data_into_file", dataIntoFilePlus);
                        Util.writeMapToJson(sensitive_scenes, scenes1, false);
                    }catch (Exception e){
                        e.printStackTrace();
                    }catch (OutOfMemoryError oe){
                        oe.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread smsThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        List<Map> dataIntoSmsPlus = FindDataTransmission.findDataIntoSmsPlus(nodes,nodeReverse,parents_info);
                        scenes1.put("data_into_sms", dataIntoSmsPlus);
                        Util.writeMapToJson(sensitive_scenes, scenes1, false);
                    }catch (Exception e){
                        e.printStackTrace();
                    }catch (OutOfMemoryError oe){
                        oe.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread encodeThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        List<Map> dataEncodeTransPlus = FindDataTransmission.findDataEncodeTransPlus(nodes,nodeReverse,parents_info);
                        scenes1.put("data_encode",dataEncodeTransPlus);
                        Util.writeMapToJson(sensitive_scenes, scenes1, false);
                    }catch (Exception e){
                        e.printStackTrace();
                    }catch (OutOfMemoryError oe){
                        oe.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            netTransThread.start();
//            crossAppThread.start();
//            dbThread.start();
//            fileThread.start();
//            smsThread.start();
//            encodeThread.start();
            try {
                cd.await();
            }catch (InterruptedException e){
                e.printStackTrace();
            }
            try {
                Util.writeMapToJson(sensitive_scenes, scenes1, false);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            System.out.println("analyse successfully!!!");
        }catch (Exception e){
            System.out.println("analyse failed!!!");
            throw e;
        }
        long t2 = System.nanoTime();
        //class聚簇
        System.out.println("class clustering.......");
        classClustering("D:\\anaconda\\python", "F:\\pythonProject\\test\\cg_process_java.py", api_used,sensitive_scenes, outPut);
        long t3 = System.nanoTime();
        //数据流
        System.out.println("data flow.......");
        String classJson=new File(outPut,"class.json").getAbsolutePath();
        TaintLauncher.run(apk,sdkPlatforms,classJson,easyTaintWrapper,sourceAndSinks,androidCallbacksTxt,outPut);
        long t4 = System.nanoTime();
        System.out.println("all done !!!");
        System.out.println("data collect: "+(t2-t1) / 1.0E9d);
        System.out.println("class cluster : "+(t3-t2) / 1.0E9d);
        System.out.println("data flow: "+(t4-t3) / 1.0E9d);
        System.out.println("all : "+(t4-t1) / 1.0E9d);
    }
    public static void run1(String apk,String sources,String sinks,String sourceAndSinks,String easyTaintWrapper,
                            String sdkPlatforms,String androidCallbacksTxt,String pythonEnv,String pythonFile,String outPutPath) throws XmlPullParserException, IOException {
        //数据收集&数据使用
        String sensitive_scenes;
        String api_used;
        String outPut;
        System.out.println("data collecting.......");
        int classLength=-1;
        long t1 = System.nanoTime();
        try {
            InfoflowAndroidConfiguration conf = new InfoflowAndroidConfiguration();
            // androidDirPath是你的android sdk中platforms目录的路径
            conf.getAnalysisFileConfig().setAndroidPlatformDir(sdkPlatforms);
            // apkFilePath是你要分析的apk的文件路径
//        conf.getAnalysisFileConfig().setSourceSinkFile("C:\\Users\\77294\\Desktop\\cert_境外非法传输+数据使用目的分析\\input\\SourcesAndSinks.txt");
            conf.getAnalysisFileConfig().setTargetAPKFile(apk);
            // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
            conf.setMergeDexFiles(true);
            // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
            conf.getAccessPathConfiguration().setAccessPathLength(-1);
            // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
            conf.getSolverConfiguration().setMaxAbstractionPathLength(-1);
            conf.getPathConfiguration().setMaxCallStackSize(-1);
            conf.getPathConfiguration().setMaxPathLength(-1);
            Options.v().set_soot_classpath(""+ File.pathSeparator+"");
            SetupApplication setup = new SetupApplication(conf);
            // 设置Callback的声明文件（不显式地设置好像FlowDroid会找不到）
            setup.setCallbackFile(androidCallbacksTxt);
            setup.initializeSoot();
            setup.parseAppResources();

            String packageName = setup.getMainfest().getPackageName();
            outPut = new File(outPutPath,packageName).getAbsolutePath();
            File file = new File(outPut);
            file.mkdirs();

            sensitive_scenes=new File(outPut,"sensitive_scenes_df.json").getAbsolutePath();
            api_used = new File(outPut, "api_used_df.json").getAbsolutePath();

            Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
            CallGraph callGraph = new CallGraph();
            Map<String, Object> map = Util.callGraphGenerate(applicationClasses,callGraph,outPut);
            Map<String,Long> nodes=(Map) map.get("nodes");
            Map<Long,String> nodeReverse=(Map)map.get("node_reverse");
            Map<Long, List> parents_info=(Map)map.get("parents_info");
            Util.activityTransGraphGenerate(setup,outPut);
            final CountDownLatch cd=new CountDownLatch(2);
            Thread dataThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                       ApiUsed.findSensitiveApiUsedWithUI(sources, nodes, nodeReverse, parents_info,api_used);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread scenesThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                   ApiUsed.findSensitiveApiUsedWithUI(sinks, nodes, nodeReverse, parents_info,sensitive_scenes);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            dataThread.start();
            scenesThread.start();
            try {
                cd.await();
            }catch (InterruptedException e){
                e.printStackTrace();
            }
            System.out.println("analyse successfully!!!");
        }catch (Exception e){
            System.out.println("analyse failed!!!");
            throw e;
        }
        long t2 = System.nanoTime();
        //class聚簇
        System.out.println("class clustering.......");
        classClustering(pythonEnv, pythonFile, api_used,sensitive_scenes, outPut);
        long t3 = System.nanoTime();
        //数据流
        System.out.println("data flow.......");
        String classJson=new File(outPut,"class.json").getAbsolutePath();
        TaintLauncher.run(apk,sdkPlatforms,classJson,easyTaintWrapper,sourceAndSinks,androidCallbacksTxt,outPut);
        long t4 = System.nanoTime();
        System.out.println("all done !!!");
        System.out.println("data collect: "+(t2-t1) / 1.0E9d);
        System.out.println("class cluster : "+(t3-t2) / 1.0E9d);
        System.out.println("data flow: "+(t4-t3) / 1.0E9d);
        System.out.println("all : "+(t4-t1) / 1.0E9d);
    }

    public static void run_dex(String dexDir,String sources,String sinks,String sourceAndSinks,String easyTaintWrapper,String sdkPlatforms,
                               String androidCallbacksTxt,String pythonEnv,String pythonFile,String outPutPath,String packageName) throws XmlPullParserException, IOException {
        //数据收集&数据使用
        String sensitive_scenes;
        String api_used;
        String outPut;
        System.out.println("data collecting.......");
        long t1 = System.nanoTime();
        try {

            initializeSoot(dexDir,sdkPlatforms);
            outPut = new File(outPutPath,packageName).getAbsolutePath();
            File file = new File(outPut);
            file.mkdirs();

            sensitive_scenes=new File(outPut,"sensitive_scenes_df.json").getAbsolutePath();
            api_used = new File(outPut, "api_used_df.json").getAbsolutePath();

            Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
            CallGraph callGraph = new CallGraph();
            Map<String, Object> map = Util.callGraphGenerate(applicationClasses,callGraph,outPut);
            Map<String,Long> nodes=(Map) map.get("nodes");
            Map<Long,String> nodeReverse=(Map)map.get("node_reverse");
            Map<Long, List> parents_info=(Map)map.get("parents_info");
            final CountDownLatch cd=new CountDownLatch(2);
            Thread dataThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        ApiUsed.findSensitiveApiUsedWithUI(sources, nodes, nodeReverse, parents_info,api_used);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread scenesThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        ApiUsed.findSensitiveApiUsedWithUI(sinks, nodes, nodeReverse, parents_info,sensitive_scenes);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            dataThread.start();
            scenesThread.start();
            try {
                cd.await();
            }catch (InterruptedException e){
                e.printStackTrace();
            }
            System.out.println("analyse successfully!!!");
        }catch (Exception e){
            System.out.println("analyse failed!!!");
            throw e;
        }
        long t2 = System.nanoTime();
        //class聚簇
        System.out.println("class clustering.......");
        classClustering(pythonEnv, pythonFile, api_used,sensitive_scenes, outPut);
        long t3 = System.nanoTime();
        //数据流
        System.out.println("data flow.......");
        String classJson=new File(outPut,"class.json").getAbsolutePath();
        TaintLauncher.run_dex(sdkPlatforms,classJson,easyTaintWrapper,sourceAndSinks,androidCallbacksTxt,outPut);
        long t4 = System.nanoTime();
        System.out.println("all done !!!");
        System.out.println("data collect: "+(t2-t1) / 1.0E9d);
        System.out.println("class cluster : "+(t3-t2) / 1.0E9d);
        System.out.println("data flow: "+(t4-t3) / 1.0E9d);
        System.out.println("all : "+(t4-t1) / 1.0E9d);
    }
    public static void run2(String apk,String sources,String sinks,String sourceAndSinks,
                            String easyTaintWrapper,String sdkPlatforms,String androidCallbacksTxt,
                            String droidRaJar,String androidJar,String reflectionSimpleModel,
                            String reflectionModel, String dynamicLoadingModel,String fiedCallsTxt,
                            String pythonEnv,String pythonFile,
                            String outPutPath) throws XmlPullParserException, IOException, TimeoutException {
        //数据收集&数据使用
        String sensitive_scenes;
        String api_used;
        String outPut;
        System.out.println("data collecting.......");
        int classLength=-1;
        long t1 = System.nanoTime();
        try {
            InfoflowAndroidConfiguration conf = new InfoflowAndroidConfiguration();
            // androidDirPath是你的android sdk中platforms目录的路径
            conf.getAnalysisFileConfig().setAndroidPlatformDir(sdkPlatforms);
            // apkFilePath是你要分析的apk的文件路径
//        conf.getAnalysisFileConfig().setSourceSinkFile("C:\\Users\\77294\\Desktop\\cert_境外非法传输+数据使用目的分析\\input\\SourcesAndSinks.txt");
            conf.getAnalysisFileConfig().setTargetAPKFile(apk);
            // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
            conf.setMergeDexFiles(true);
            // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
            conf.getAccessPathConfiguration().setAccessPathLength(-1);
            // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
            conf.getSolverConfiguration().setMaxAbstractionPathLength(-1);
            conf.getPathConfiguration().setMaxCallStackSize(-1);
            conf.getPathConfiguration().setMaxPathLength(-1);
            Options.v().set_soot_classpath(""+ File.pathSeparator+"");
            SetupApplication setup = new SetupApplication(conf);
            // 设置Callback的声明文件（不显式地设置好像FlowDroid会找不到）
            setup.setCallbackFile(androidCallbacksTxt);
            setup.initializeSoot();
            setup.parseAppResources();

            String packageName = setup.getMainfest().getPackageName();
            outPut = new File(outPutPath,packageName).getAbsolutePath();
            File file = new File(outPut);
            file.mkdirs();

            DroidRa.droidRa(droidRaJar, apk, androidJar, reflectionSimpleModel, reflectionModel,dynamicLoadingModel, fiedCallsTxt, outPut,1000000000);

            sensitive_scenes=new File(outPut,"sensitive_scenes_df.json").getAbsolutePath();
            api_used = new File(outPut, "api_used_df.json").getAbsolutePath();
            Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
            CallGraph callGraph = new CallGraph();
            Map<String, Object> map = Util.callGraphGenerateWithReflection(applicationClasses,callGraph,new File(outPut,"reflection.json").getAbsolutePath(),outPut);
            Map<String,Long> nodes=(Map) map.get("nodes");
            Map<Long,String> nodeReverse=(Map)map.get("node_reverse");
            Map<Long, List> parents_info=(Map)map.get("parents_info");
            Util.activityTransGraphGenerate(setup,outPut);
            final CountDownLatch cd=new CountDownLatch(2);
            Thread dataThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        ApiUsed.findSensitiveApiUsedWithUI(sources, nodes, nodeReverse, parents_info,api_used);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            Thread scenesThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        ApiUsed.findSensitiveApiUsedWithUI(sinks, nodes, nodeReverse, parents_info,sensitive_scenes);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    cd.countDown();
                }
            });
            dataThread.start();
            scenesThread.start();
            try {
                cd.await();
            }catch (InterruptedException e){
                e.printStackTrace();
            }
            System.out.println("analyse successfully!!!");
        }catch (Exception e){
            System.out.println("analyse failed!!!");
            throw e;
        }
        long t2 = System.nanoTime();
        //class聚簇
        System.out.println("class clustering.......");
        classClustering(pythonEnv, pythonFile, api_used,sensitive_scenes, outPut);
        long t3 = System.nanoTime();
        //数据流
        System.out.println("data flow.......");
        String classJson=new File(outPut,"class.json").getAbsolutePath();
        TaintLauncher.run(apk,sdkPlatforms,classJson,easyTaintWrapper,sourceAndSinks,androidCallbacksTxt,outPut);
        long t4 = System.nanoTime();
        System.out.println("all done !!!");
        System.out.println("data collect: "+(t2-t1) / 1.0E9d);
        System.out.println("class cluster : "+(t3-t2) / 1.0E9d);
        System.out.println("data flow: "+(t4-t3) / 1.0E9d);
        System.out.println("all : "+(t4-t1) / 1.0E9d);
    }
    public static void initializeSoot(String dexDir,String sdk){
        G.reset();
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_process_dir(Collections.singletonList(dexDir));
        Options.v().set_force_android_jar(sdk);
        Options.v().set_src_prec(Options.src_prec_apk_class_jimple);
        Options.v().set_keep_offset(false);
        Options.v().set_keep_line_number(false);
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().setPhaseOption("jb", "use-original-names:true");
//        Options.v().set_soot_classpath(getClasspath());
        soot.Main.v().autoSetOptions();
        Scene.v().loadNecessaryClasses();
        // Make sure that we have valid Jimple bodies
        PackManager.v().getPack("wjpp").apply();
    }
    public static void classClustering(String python, String pythonFile, String api_used, String sensitive_scenes, String classJson){
        Process proc;
        try {

            String[] args1=new String[]{python, pythonFile, api_used, sensitive_scenes, classJson};
            proc = Runtime.getRuntime().exec(args1);
            BufferedReader in = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line = null;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
            in.close();
            proc.waitFor();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) throws XmlPullParserException, IOException, TimeoutException {
//        run("D:\\cert\\案例\\5.9\\5.11_apk\\驴妈妈旅游.apk",
//                "D:\\cert\\input\\source.json",
//                "C:\\Users\\77294\\Desktop\\fastdroid_test\\source_sinks.txt",
//                "D:\\github_project\\FastDroid-master\\Files\\EasyTaintWrapperSource.txt",
//                "D:\\cert\\input\\regex.txt",
//                "C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms",
//                "D:\\cert\\input\\callbacktest.txt",
//                "C:\\Users\\77294\\Desktop\\fastdroid_test\\output\\1");
        long before = System.nanoTime();
        run1("C:\\Users\\77294\\Desktop\\12\\beihai365_5.6.26_64.apk",
                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source.json",
                "C:\\Users\\77294\\Desktop\\certdroid\\input\\sink.json",
                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source_sinks.txt",
                "D:\\github_project\\FastDroid-master\\Files\\EasyTaintWrapperSource.txt",
                "C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms",
                "D:\\cert\\input\\callbacktest.txt",
                "D:\\anaconda\\python",
                "F:\\pythonProject\\test\\cg_process_java2.py",
                "C:\\Users\\77294\\Desktop\\12");

        long after = System.nanoTime();
        System.out.println((after-before)/1.0E9d);
//        run2("C:\\Users\\77294\\Desktop\\fastdroid_test\\DroidBench3.0\\apk\\Reflection\\Reflection8.apk",
//                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source.json",
//                "C:\\Users\\77294\\Desktop\\certdroid\\input\\sink1.json",
//                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source_sinks.txt",
//                "D:\\github_project\\FastDroid-master\\Files\\EasyTaintWrapperSource.txt",
//                "C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms",
//                "D:\\cert\\input\\callbacktest.txt",
//                "D:\\cert\\code\\droidra\\code\\DroidRA\\target\\DroidRA-2.0-SNAPSHOT.jar",
//                "C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms\\android-14\\android.jar",
//                "D:\\cert\\code\\droidra\\code\\DroidRA\\res\\reflection_simple.model",
//                "D:\\cert\\code\\droidra\\code\\DroidRA\\res\\reflection.model",
//                "D:\\cert\\code\\droidra\\code\\DroidRA\\res\\dynamic_code_loading.model",
//                "D:\\cert\\code\\droidra\\code\\DroidRA\\res\\FieldCalls.txt",
//                "D:\\cert\\案例\\final\\result"
//        );
//                run_dex("C:\\Users\\77294\\Desktop\\fastdroid_test\\DroidBench3.0-158\\DroidBench\\myresult\\amandroid\\ActivityCommunication6\\test",
//                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source.json",
//                "C:\\Users\\77294\\Desktop\\certdroid\\input\\sink1.json",
//                "C:\\Users\\77294\\Desktop\\certdroid\\input\\source_sinks.txt",
//                "D:\\github_project\\FastDroid-master\\Files\\EasyTaintWrapperSource.txt",
//                "C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms",
//                "D:\\cert\\input\\callbacktest.txt",
//                        "D:\\anaconda\\python",
//                        "F:\\pythonProject\\test\\cg_process_java2.py",
//                "D:\\cert\\案例\\final\\result",
//                        "test");
    }
}

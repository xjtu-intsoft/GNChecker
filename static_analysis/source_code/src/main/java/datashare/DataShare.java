package datashare;

import my.ApiUsed;
import my.Util;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JStaticInvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;
import soot.util.Chain;
import secondstage.taintanalysis.TaintLauncher;
import secondstage.taintanalysis.taint.StmLocation;
import secondstage.taintanalysis.taint.TaintValue;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Pattern;

public class DataShare {
    public static void main(String[] args) throws XmlPullParserException, IOException {


        run(6,args[0],args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10]);
//        consistency_run(args[0],args[1]);
    }
    public static void consistency_run(String apk_root,String out_root){
        scaleRun(6,apk_root,out_root);
    }
    public static void wdj_top100(){
        String apk_root="D:\\cert\\实验\\wdj_top_apk";
        String out_root="D:\\cert\\实验\\static_test";
        scaleRun(6,apk_root,out_root);
    }
    public static void urlDetectRate(){
        String apk_root="D:\\cert\\实验\\url_detction_rate\\apk";
        String out_root="D:\\cert\\实验\\url_detction_rate\\result";
        for(int i=1;i<9;i++){
            File out_dir_file = new File(out_root, "anzhi_" + i);
            out_dir_file.mkdirs();
            scaleRun(i,apk_root,out_dir_file.getAbsolutePath());

        }
    }

    public static void scaleRun(int searchDepth,String apk_root,String output){
//        String apk_root="D:\\apks\\google_apk";
//        String output="D:\\cert\\实验\\datashare\\";
        File file = new File(apk_root);
        File[] files = file.listFiles();
        int succeed=0;
        for(File apk:files){
            try {
//                run(         apk.getAbsolutePath(),
//                        "/data1/xxx528/xxx/data_share/input/data_share_source.json",
//                        "/data1/xxx528/xxx/data_share/input/data_share_sink.json",
//                        "/data1/xxx528/xxx/data_share/input/data_share_source_sinks.txt",
//                        "/data1/xxx528/xxx/data_share/input/regex.txt",
//                        "/data1/xxx528/xxx/data_share/input/EasyTaintWrapperSource.txt",
//                        "/data1/xxx528/cert/urlFlask/sdk/platforms/",
//                        "/data1/xxx528/xxx/data_share/input/callbacktest.txt",
//                        "python",
//                        "/data1/xxx528/xxx/data_share/input/cg_process_java2.py",
//                        output
//                );
                run(    searchDepth,
                        apk.getAbsolutePath(),
                        "C:\\Users\\77294\\Desktop\\certdroid\\input\\data_share_source.json",
                        "C:\\Users\\77294\\Desktop\\certdroid\\input\\data_share_sink.json",
                        "C:\\Users\\77294\\Desktop\\certdroid\\input\\data_share_source_sinks.txt",
                        "C:\\Users\\77294\\Desktop\\certdroid\\input\\regex.txt",
                        "D:\\github_project\\FastDroid-master\\Files\\EasyTaintWrapperSource.txt",
                        "C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms",
                        "D:\\cert\\input\\callbacktest.txt",
                        "D:\\anaconda\\python",
                        "F:\\pythonProject\\test\\cg_process_java2.py",
                        output
                );
                succeed+=1;
                System.out.println(succeed);
            }catch (Exception e){
                e.printStackTrace();
                continue;
            }catch (OutOfMemoryError e){
                e.printStackTrace();
                continue;
            }
        }
        System.out.println("成功："+succeed);
    }
    public static void run(int searchDepth,String apk,String sources,String sinks,String sourceAndSinks,String regexTxt,String easyTaintWrapper,
                            String sdkPlatforms,String androidCallbacksTxt,String pythonEnv,String pythonFile,String outPutPath) throws XmlPullParserException, IOException {
        //数据收集&数据使用
        String sensitive_scenes;
        String api_used;
        String outPut;
        System.out.println("data collecting.......");
        int classLength=-1;
        long t1 = System.nanoTime();
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
        outPut = new File(outPutPath,packageName+"_"+new File(apk).getName()).getAbsolutePath();
        File file = new File(outPut);
        if(file.isDirectory()){
            return;
        }
        file.mkdirs();
        File dataSharingFile = new File(outPut, "data_sharing.json");
//        if(dataSharingFile.isFile()){
//            return;
//        }
        sensitive_scenes=new File(outPut,"sensitive_scenes_df.json").getAbsolutePath();
        api_used = new File(outPut, "api_used_df.json").getAbsolutePath();

        Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
        CallGraph callGraph = new CallGraph();
        Map<String, Object> map = Util.callGraphGenerate(applicationClasses,callGraph,outPut);
        Map<String,Long> nodes=(Map) map.get("nodes");
        Map<Long,String> nodeReverse=(Map)map.get("node_reverse");
        Map<Long, List> parents_info=(Map)map.get("parents_info");
        Map<Long, List> children_info=(Map)map.get("children_info");
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

        long t2 = System.nanoTime();
        //class聚簇
        System.out.println("class clustering.......");
        classClustering(pythonEnv, pythonFile, api_used,sensitive_scenes, outPut);
        long t3 = System.nanoTime();
        //数据流
        System.out.println("data flow.......");
        String classJson=new File(outPut,"class.json").getAbsolutePath();
        ArrayList<List> taintFlowsBefore = TaintLauncher.run(apk, sdkPlatforms, classJson, easyTaintWrapper, sourceAndSinks, androidCallbacksTxt, outPut);
        //去重
        HashSet<String> taintFlowSet = new HashSet<>();
        ArrayList<List> taintFlows = new ArrayList<>();
        for(List flow:taintFlowsBefore){
            String tmp = flowToString(flow).toString();
            if(!taintFlowSet.contains(tmp)){
                taintFlowSet.add(tmp);
                taintFlows.add(flow);
            }
        }

        long t4 = System.nanoTime();
        System.out.println("all done !!!");
        System.out.println("data collect: "+(t2-t1) / 1.0E9d);
        System.out.println("class cluster : "+(t3-t2) / 1.0E9d);
        System.out.println("data flow: "+(t4-t3) / 1.0E9d);

        List<Map> sinkList = Util.readJsonToList(sinks);
        HashMap<String, Set> sinkSet = new HashMap<>();
        HashSet<String> netSinkSet = new HashSet<>();
        HashSet<String> crossAppSinkSet = new HashSet<>();
        for(Map sink : sinkList){
            String category = (String) sink.get("category");
            if(category.equals("net")){
                netSinkSet.add((String) sink.get("sign"));
            }else if(category.equals("cross_app")){
                crossAppSinkSet.add((String) sink.get("sign"));
            }
        }
        sinkSet.put("net",netSinkSet);
        sinkSet.put("cross_app",crossAppSinkSet);
        ArrayList<List> netTransCandidate = new ArrayList<>();
        ArrayList<List> crossTransCandidate = new ArrayList<>();
        for(List<TaintValue> flow:taintFlows){
            TaintValue taintValue = flow.get(flow.size() - 1);
            StmLocation sl = taintValue.getSL();
            for(String sink :netSinkSet){
                if(sl.toString().contains(sink)){
                    netTransCandidate.add(flow);
                    break;
                }
            }
            for(String sink :crossAppSinkSet){
                if(sl.toString().contains(sink)){
                    crossTransCandidate.add(flow);
                    break;
                }
            }
        }
        //数据字典
        List<Map> soucesLists = Util.readJsonToList(sources);
        HashMap<String, String> dataMap = new HashMap<>();
        for(Map sourceData:soucesLists){
            dataMap.put((String) sourceData.get("sign"),(String) sourceData.get("category"));
        }
        //跨APP传输地址解析
        List<Map> crossAppTrans = crossAppTransAddressParse(packageName, crossTransCandidate, dataMap);
        long t5 = System.nanoTime();
        System.out.println("cross app: "+(t5-t4) / 1.0E9d);
        //网络传输地址解析
        //正则pattern
        List<String> regexes = Util.readFile(regexTxt);
        Pattern ipRegex = Pattern.compile(regexes.get(0));
        Pattern urlRegex = Pattern.compile(regexes.get(1));
        Pattern urlRegex1 = Pattern.compile(regexes.get(2));
        List<Map> netTrans = netTransAddressParse(searchDepth,netTransCandidate, ipRegex, urlRegex, urlRegex1, dataMap,nodes,nodeReverse,parents_info,children_info);
        long t6 = System.nanoTime();
        System.out.println("net trans: "+(t6-t5) / 1.0E9d);
        System.out.println("----------------------------------");
        System.out.println("find net trans: "+netTrans.size());
        System.out.println("find cross app trans: "+crossAppTrans.size());
        System.out.println("----------------------------------");
        HashMap<String, List> results = new HashMap<>();
        results.put("net_trans",netTrans);
        results.put("cross_app_trans",crossAppTrans);
        Util.writeMapToJson(new File(outPut,"data_sharing.json").getAbsolutePath(),results,false);
        System.out.println("all : "+(t6-t1) / 1.0E9d);

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

    public static List<Map> crossAppTransAddressParse(String packageName,ArrayList<List> crossAppTransCandidate,Map<String,String> dataMap) {
        List<Map> result = new ArrayList<>();
        //app跳转
        for (List<TaintValue> flow:crossAppTransCandidate) {
            try {
                String data = "";
                String sourceString = flow.get(0).toString();
                for(String key:dataMap.keySet()){
                    if(sourceString.contains(key)){
                        data=dataMap.get(key);
                    }
                }

                String parent = (String) flow.get(flow.size()-1).getContext().getsMethod().getSignature();
                SootMethod source = Scene.v().grabMethod(parent);
                Body body = source.retrieveActiveBody();
                UnitPatchingChain bodyUnits = body.getUnits();
                Iterator<Unit> unitIterator = bodyUnits.iterator();
                while (unitIterator.hasNext()) {
                    Unit next = unitIterator.next();
                    if (next.getClass().getSimpleName().equals("JInvokeStmt")) {
                        JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
                        InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                        String methodRef = invokeExpr.getMethodRef().toString();
                        if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String,android.net.Uri)>")) {
                            Value arg = invokeExpr.getArg(1);
                            String argType = arg.getClass().getSimpleName();
                            if (argType.equals("JimpleLocal")) {
                                Iterator<Unit> iterator1 = bodyUnits.iterator();
                                while (iterator1.hasNext()) {
                                    Unit next1 = iterator1.next();
                                    if (next1.getClass().getSimpleName().equals("JAssignStmt")) {
                                        JAssignStmt jIAssiStmt = (JAssignStmt) next1;
                                        if (jIAssiStmt.getLeftOp().equals(arg)) {
                                            Value rightOp = jIAssiStmt.getRightOp();
                                            if (rightOp.getClass().getSimpleName().equals("JStaticInvokeExpr")) {
                                                JStaticInvokeExpr rightOp1 = (JStaticInvokeExpr) rightOp;
                                                if (rightOp1.getMethodRef().toString().equals("<android.net.Uri: android.net.Uri parse(java.lang.String)>")) {
                                                    Value arg1 = rightOp1.getArg(0);
                                                    if (arg.getClass().getSimpleName().equals("StringConstant")) {
                                                        String s = arg.toString();
                                                        String argStr = s.substring(1, s.length() - 1);
                                                        if (!argStr.contains(packageName)) {
                                                            Map<String, Object> map = new HashMap<>();
                                                            map.put("type", "UrlScheme");
                                                            map.put("taint_flow", flowToString(flow));
                                                            map.put("target", argStr);
                                                            //intent 携带数据待补充
                                                            map.put("data", data);
                                                            result.add(map);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                }
                            } else if (argType.equals("JInvokeExpr")) {
                                //待补充
                            }
                        }
                        //init() setAction()
                        else if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String)>") || methodRef.equals("<android.content.Intent: android.content.Intent setAction(java.lang.String)>")) {
                            Value arg = invokeExpr.getArg(0);
                            String s = arg.toString();
                            String argStr = s.substring(1, s.length() - 1);
                            //SEND类型
                            if (argStr.equals("android.intent.action.SEND")) {
                                Map<String, Object> map = new HashMap<>();
                                map.put("type", "android.intent.action.SEND");
                                map.put("target", "");
                                map.put("taint_flow", flowToString(flow));
                                map.put("data", data);
                                result.add(map);
                            }
                        }
                        //显示跳转 setClassName()
                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setClassName(java.lang.String,java.lang.String)>") || methodRef.equals("<android.content.Intent: android.content.Intent setClassName(android.content.Context,java.lang.String)>")) {
                            Value arg1 = invokeExpr.getArg(1);
                            if (arg1.getClass().getSimpleName().equals("StringConstant")) {
                                String s = arg1.toString();
                                String argStr = s.substring(1, s.length() - 1);
                                if (!argStr.contains(packageName)) {
                                    Map<String, Object> map = new HashMap<>();
                                    map.put("type", "setClassName");
                                    map.put("target", argStr);
                                    map.put("taint_flow",flowToString(flow));
                                    map.put("data", data);
                                    result.add(map);
                                }
                            }
                        }
                        //setComponent()
                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setComponent(android.content.ComponentName)>")) {
                            Iterator<Unit> iterator1 = bodyUnits.iterator();
                            while (iterator1.hasNext()) {
                                Unit next1 = iterator1.next();
                                if (next1.getClass().getSimpleName().equals("JInvokeStmt")) {
                                    JInvokeStmt jInvokeStmt1 = (JInvokeStmt) next1;
                                    InvokeExpr invokeExpr1 = jInvokeStmt1.getInvokeExpr();
                                    String methodRef1 = invokeExpr1.getMethodRef().toString();
                                    //Componentname(str,str)||Componentname(context,str)
                                    if (methodRef1.equals("<android.content.ComponentName: void <init>(java.lang.String,java.lang.String)>") || methodRef1.equals("<android.content.ComponentName: void <init>(android.content.Context,java.lang.String)>")) {
                                        Value arg = invokeExpr1.getArg(1);
                                        if (arg.getClass().getSimpleName().equals("StringConstant")) {
                                            String s = arg.toString();
                                            String argStr = s.substring(1, s.length() - 1);
                                            if (!argStr.contains(packageName)) {
                                                Map<String, Object> map = new HashMap<>();
                                                map.put("type", "setComponentName");
                                                map.put("target", argStr);
                                                map.put("taint_flow", flowToString(flow));
                                                map.put("data", data);
                                                result.add(map);
                                            }
                                        }
                                        break;
                                    } else if (methodRef1.equals(methodRef)) {
                                        break;
                                    }

                                }
                            }

                        }
                        //setComponentName
                        else if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String,android.net.Uri)>")) {
                            Iterator<Unit> iterator1 = bodyUnits.iterator();
                            while (iterator1.hasNext()) {
                                Unit next1 = iterator1.next();
                                if (next1.getClass().getSimpleName().equals("JInvokeStmt")) {
                                    JInvokeStmt jInvokeStmt1 = (JInvokeStmt) next1;
                                    InvokeExpr invokeExpr1 = jInvokeStmt1.getInvokeExpr();
                                    String methodRef1 = invokeExpr1.getMethodRef().toString();
                                    //Componentname(str,str)||Componentname(context,str)
                                    if (methodRef1.equals("<android.content.ComponentName: void <init>(java.lang.String,java.lang.String)>") || methodRef1.equals("<android.content.ComponentName: void <init>(android.content.Context,java.lang.String)>")) {
                                        Value arg = invokeExpr1.getArg(1);
                                        if (arg.getClass().getSimpleName().equals("StringConstant")) {
                                            String s = arg.toString();
                                            String argStr = s.substring(1, s.length() - 1);
                                            if (!argStr.contains(packageName)) {
                                                Map<String, Object> map = new HashMap<>();
                                                map.put("type", "setComponentName");
                                                map.put("target", argStr);
                                                map.put("taint_flow", flowToString(flow));
                                                map.put("data", data);
                                                result.add(map);
                                            }
                                        }
                                        break;
                                    } else if (methodRef1.equals(methodRef)) {
                                        break;
                                    }

                                }
                            }
                        }
                    }

                }
            }catch (Exception e){
                continue;
            }
        }

        //broadcast
//        Set<String> broadcastMethodSig = broadcastMethodSig();
//        Iterator<String> iterator = broadcastMethodSig.iterator();
//        while (iterator.hasNext()){
//            String next = iterator.next();
//            List<List> broadPathes = Util.getPathes(next, nodes,nodeReverse,parents_info);
//            for(int i=0;i<broadPathes.size();i++){
//                List chain = broadPathes.get(i);
//                String parent = (String) chain.get(chain.size()-2);
//                SootMethod source = Scene.v().grabMethod(parent);
//                Body body = source.retrieveActiveBody();
//                UnitPatchingChain bodyUnits = body.getUnits();
//                Iterator<Unit> unitIterator = bodyUnits.iterator();
//                Boolean notFindTaret=true;
//                while (unitIterator.hasNext()) {
//                    Unit next1 = unitIterator.next();
//                    if (next.getClass().getSimpleName().equals("JInvokeStmt")) {
//                        JInvokeStmt jInvokeStmt = (JInvokeStmt) next1;
//                        InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
//                        String methodRef = invokeExpr.getMethodRef().toString();
//                        if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String,android.net.Uri)>")) {
//                            Value arg = invokeExpr.getArg(1);
//                            String argType = arg.getClass().getSimpleName();
//                            if (argType.equals("JimpleLocal")) {
//                                Iterator<Unit> iterator1 = bodyUnits.iterator();
//                                while (iterator1.hasNext()) {
//                                    Unit next11 = iterator1.next();
//                                    if (next1.getClass().getSimpleName().equals("JAssignStmt")) {
//                                        JAssignStmt jIAssiStmt = (JAssignStmt) next11;
//                                        if (jIAssiStmt.getLeftOp().equals(arg)) {
//                                            Value rightOp = jIAssiStmt.getRightOp();
//                                            if (rightOp.getClass().getSimpleName().equals("JStaticInvokeExpr")) {
//                                                JStaticInvokeExpr rightOp1 = (JStaticInvokeExpr) rightOp;
//                                                if (rightOp1.getMethodRef().toString().equals("<android.net.Uri: android.net.Uri parse(java.lang.String)>")) {
//                                                    Value arg1 = rightOp1.getArg(0);
//                                                    if (arg.getClass().getSimpleName().equals("StringConstant")) {
//                                                        String s = arg.toString();
//                                                        String argStr = s.substring(1, s.length() - 1);
//                                                        if (!argStr.contains(packageName)) {
//                                                            notFindTaret=false;
//                                                            Map<String, Object> map = new HashMap<>();
//                                                            map.put("type", "Broadcast");
//                                                            map.put("target", argStr);
//                                                            map.put("invoke_chain",chain);
//                                                            map.put("sendType",next);
//                                                            //intent 携带数据待补充
//                                                            String data = "";
//                                                            map.put("data", data);
//                                                            result.add(map);
//                                                        }
//                                                    }else {
//                                                        //是否补充有待商榷
//                                                        notFindTaret=false;
//                                                        Map<String, Object> map = new HashMap<>();
//                                                        map.put("type", "Broadcast");
//                                                        map.put("target", "");
//                                                        map.put("invoke_chain",chain);
//                                                        //intent 携带数据待补充
//                                                        String data = "";
//                                                        map.put("data", data);
//                                                        result.add(map);
//                                                    }
//                                                }
//                                            }
//                                        }
//
//
//                                    }
//
//                                }
//                            } else if (argType.equals("JInvokeExpr")) {
//                                //待补充
//                            }
//                        }
//                        //显示跳转 setClassName()
//                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setClassName(java.lang.String,java.lang.String)>") || methodRef.equals("<android.content.Intent: android.content.Intent setClassName(android.content.Context,java.lang.String)>")) {
//                            Value arg1 = invokeExpr.getArg(1);
//                            if (arg1.getClass().getSimpleName().equals("StringConstant")) {
//                                String s = arg1.toString();
//                                String argStr = s.substring(1, s.length() - 1);
//                                if (!argStr.contains(packageName)) {
//                                    notFindTaret=false;
//                                    Map<String, Object> map = new HashMap<>();
//                                    map.put("type", "Broadcast");
//                                    map.put("target", argStr);
//                                    map.put("invoke_chain",chain);
//                                    map.put("sendType",next);
//                                    //intent 携带数据待补充
//                                    String data = "";
//                                    map.put("data", data);
//                                    result.add(map);
//                                }
//                            }
//                        }
//                        //setComponent()
//                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setComponent(android.content.ComponentName)>")) {
//                            Iterator<Unit> iterator1 = bodyUnits.iterator();
//                            while (iterator1.hasNext()) {
//                                Unit next11 = iterator1.next();
//                                if (next1.getClass().getSimpleName().equals("JInvokeStmt")) {
//                                    JInvokeStmt jInvokeStmt1 = (JInvokeStmt) next11;
//                                    InvokeExpr invokeExpr1 = jInvokeStmt1.getInvokeExpr();
//                                    String methodRef1 = invokeExpr1.getMethodRef().toString();
//                                    //Componentname(str,str)||Componentname(context,str)
//                                    if (methodRef1.equals("<android.content.ComponentName: void <init>(java.lang.String,java.lang.String)>") || methodRef1.equals("<android.content.ComponentName: void <init>(android.content.Context,java.lang.String)>")) {
//                                        Value arg = invokeExpr1.getArg(1);
//                                        if (arg.getClass().getSimpleName().equals("StringConstant")) {
//                                            String s = arg.toString();
//                                            String argStr = s.substring(1, s.length() - 1);
//                                            if (!argStr.contains(packageName)) {
//                                                notFindTaret=false;
//                                                Map<String, Object> map = new HashMap<>();
//                                                map.put("type", "Broadcast");
//                                                map.put("target", argStr);
//                                                map.put("invoke_chain",chain);
//                                                map.put("sendType",next);
//                                                //intent 携带数据待补充
//                                                String data = "";
//                                                map.put("data", data);
//                                                result.add(map);
//                                            }
//                                        }
//                                        break;
//                                    } else if (methodRef1.equals(methodRef)) {
//                                        break;
//                                    }
//
//                                }
//                            }
//
//                        }
//
//
//                    }
//
//                }
//                if(notFindTaret){
//                    Map<String, Object> map = new HashMap<>();
//                    map.put("type", "Broadcast");
//                    map.put("target", "");
//                    map.put("invoke_chain",chain);
//                    map.put("sendType",next);
//                    //intent 携带数据待补充
//                    String data = "";
//                    map.put("data", data);
//                    result.add(map);
//                }
//
//            }
//
//        }

//        ContentProvider
//        List<List> contentProviderPathes = Util.getPathes("<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,android.content.ContentValues)>", nodes,nodeReverse,parents_info);
//        contentProviderPathes.addAll(Util.getPathes("<android.content.ContentResolver: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])>",nodes,nodeReverse,parents_info));
//        for(int i=0;i<contentProviderPathes.size();i++){
//            List chain =contentProviderPathes.get(i);
//            String parent = (String) chain.get(chain.size()-2);
//            SootMethod source = Scene.v().grabMethod(parent);
//            Body body = source.retrieveActiveBody();
//            UnitPatchingChain bodyUnits = body.getUnits();
//
//            Iterator<Unit> unitIterator = bodyUnits.iterator();
//            String target="";
//            while (unitIterator.hasNext()) {
//                Unit next = unitIterator.next();
//                if (next.getClass().getSimpleName().equals("JInvokeStmt")) {
//                    JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
//                    InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
//                    String methodRef = invokeExpr.getMethodRef().toString();
//                    if (methodRef.equals("<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,android.content.ContentValues)>")||methodRef.equals("<android.content.ContentResolver: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])>")) {
//                        Value arg = invokeExpr.getArg(0);
//                        String argType = arg.getClass().getSimpleName();
//                        if (argType.equals("JimpleLocal")) {
//                            Iterator<Unit> iterator1 = bodyUnits.iterator();
//                            while (iterator1.hasNext()) {
//                                Unit next1 = iterator1.next();
//                                if (next1.getClass().getSimpleName().equals("JAssignStmt")) {
//                                    JAssignStmt jIAssiStmt = (JAssignStmt) next1;
//                                    if (jIAssiStmt.getLeftOp().equals(arg)) {
//                                        Value rightOp = jIAssiStmt.getRightOp();
//                                        if (rightOp.getClass().getSimpleName().equals("JStaticInvokeExpr")) {
//                                            JStaticInvokeExpr rightOp1 = (JStaticInvokeExpr) rightOp;
//                                            if (rightOp1.getMethodRef().toString().equals("<android.net.Uri: android.net.Uri parse(java.lang.String)>")) {
//                                                Value arg1 = rightOp1.getArg(0);
//                                                if (arg.getClass().getSimpleName().equals("StringConstant")) {
//                                                    String s = arg.toString();
//                                                    target= s.substring(1, s.length() - 1);
//                                                }
//                                            }
//                                        }
//                                    }
//
//
//                                }
//
//                            }
//                        } else if (argType.equals("JInvokeExpr")) {
//                            //待补充
//                        }
//                    }
//                }
//
//            }
//            Map<String, Object> map = new HashMap<>();
//            map.put("type", "ContentProvider");
//            map.put("target", target);
//            map.put("invoke_chain",chain);
//            //intent 携带数据待补充
//            String data = "";
//            map.put("data", data);
//            result.add(map);
//
//        }
        return result;
    }
    public static List<Map> netTransAddressParse(int searchDepth,ArrayList<List> netTransCandidate,Pattern ipRegex,Pattern urlRegex,Pattern urlRegex1,Map<String,String> dataMap,
                                                 Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parent_info,Map<Long,List> children_info){
        ArrayList<Map> results = new ArrayList<>();
        for(List<TaintValue> flow:netTransCandidate){
            String sourceCode="";
            for(int n=0;n<flow.size();n++){
                try {
                    TaintValue taintValue = flow.get(n);
                    SootMethod sig = taintValue.getContext().getsMethod();
                    sourceCode=sourceCode+Util.getMethodBody(sig.getSignature()).toString();
                }catch (Exception e){
                    continue;
                }
            }
            Map<String, Set> urlMap = Util.urlRegexMatching(sourceCode, ipRegex, urlRegex, urlRegex1);
            ArrayList<String> targets = new ArrayList<>();
            Set<String> ips = urlMap.get("ip");
            Set<String> urls = urlMap.get("url");
            for(String ip:ips){
                targets.add(ip);
            }
            for(String url:urls){
                targets.add(url);
            }

            if(targets.isEmpty()){
                Map<String, Set> urlsInInvokeChain = findUrlsInInvokeChain(searchDepth, nodes, nodeReverse, parent_info, children_info, flow, ipRegex, urlRegex, urlRegex1);
                ips = urlsInInvokeChain.get("ip");
                urls = urlsInInvokeChain.get("url");
                for(String ip:ips){
                    targets.add(ip);
                }
                for(String url:urls){
                    targets.add(url);
                }
            }



//            if(targets.isEmpty()){
//                continue;
//            }
            Map<String, Object> map = new HashMap<>();
            map.put("taint_flow",flowToString(flow));
            map.put("target",targets);

            //携带数据
            String data = "";
            String sourceString = flow.get(0).toString();
            for(String key:dataMap.keySet()){
                if(sourceString.contains(key)){
                    data=dataMap.get(key);
                }
            }
            map.put("data", data);
            results.add(map);
        }

        return results;
    }
    public static List<String> flowToString(List<TaintValue> flow){
        ArrayList<String> strings = new ArrayList<>();
        Iterator<TaintValue> iterator = flow.iterator();
        while (iterator.hasNext()){
            TaintValue next = (TaintValue)iterator.next();
            String tv= next.toString();
            strings.add(tv);
        }
        return strings;

    }
    public static Map<String,Set> findUrlsInInvokeChain(int depth,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parent_info,Map<Long,List> children_info,
                                                        List<TaintValue> flow,Pattern ipRegex,Pattern urlRegex,Pattern urlRegex1){

        TaintValue tv = flow.get(flow.size() - 1);
        String parentMethod = tv.getContext().getsMethod().getSignature();
        String tvString = tv.toString();
        int begin = tvString.indexOf("<");
        int end = tvString.indexOf(">");
        String sink = tvString.substring(begin, end + 1);
        HashSet<Long> methodsId = new HashSet<>();
        String parent=parentMethod;
        String child=sink;
        List<Long> children = Util.getChildren(parent,nodes, children_info);
        List<Long> candidate=getCandidateChild(child,children,nodes);
        methodsId.addAll(candidate);
        depth-=1;
        if(depth>0){
            child=parent;
            candidate=dfs(depth,child,nodes,nodeReverse,parent_info,children_info);
        }
        methodsId.addAll(candidate);
        Set<String> methods = new HashSet<>();
        for(Long id:methodsId){
            String sig = nodeReverse.get(id);
            methods.add(sig);
            try {
                SootMethod method = Scene.v().getMethod(sig);
                String initMethod = method.getDeclaringClass().getMethod("void <init>()").toString();
                methods.add(initMethod);
            }catch (Exception e){
                continue;
            }
        }
        String sourceCode="";
        for(String sig:methods){
            try {
                sourceCode+=Util.getMethodBody(sig).toString();
            }catch (Exception e){
//                e.printStackTrace();
                continue;
            }
        }
        Map<String, Set> res = Util.urlRegexMatching(sourceCode, ipRegex, urlRegex, urlRegex1);
        return res;
    }

    private static List<Long> dfs(int depth, String child, Map<String, Long> nodes,Map<Long,String> nodeReverse, Map<Long, List> parent_info, Map<Long, List> children_info) {
        ArrayList<Long> res = new ArrayList<>();
        if(depth==0){
            return res;
        }else {
            depth-=1;
            List<Long> parents = Util.getParents(child, nodes, parent_info);
            Set<Long> tmp = new HashSet<>();
            for(Long parentId:parents){
                String parent=nodeReverse.get(parentId);
                List<Long> children = Util.getChildren(parent,nodes, children_info);
                List<Long> candidate=getCandidateChild(child,children,nodes);
                tmp.add(parentId);
                tmp.addAll(candidate);
                List<Long> dfs = dfs(depth, parent, nodes, nodeReverse, parent_info, children_info);
                tmp.addAll(dfs);
            }
            res.addAll(tmp);
        }
        return res;
    }

    private static List<Long> getCandidateChild(String child, List<Long> children, Map<String, Long> nodes) {
        ArrayList<Long> res = new ArrayList<>();
        try {
            Long childId = nodes.get(child);
            int i=0;
            long value= Long.valueOf(-1);
            while (childId!=value){
                value=children.get(i);
                i+=1;
                res.add(value);
            }
            res.add(childId);
        }catch (Exception e){
//            e.printStackTrace();
        }
        return res;
    }


}

package my;

import org.xmlpull.v1.XmlPullParserException;
import soot.Scene;
import soot.SootClass;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.util.Chain;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/**
 * @description:给定API，找组件UI信息
 * @author: xxx
 * @date: 2023/3/20 15:28
 **/
public class ApiUsed {

    public static void run(String apk,String sdkPlatforms,String apiFile,String outPutPath) throws XmlPullParserException, IOException {
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

            SetupApplication setup = new SetupApplication(conf);
            setup.initializeSoot();
            setup.parseAppResources();
            Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
            String packageName = setup.getMainfest().getPackageName();
            String apk_name = new File(apk).getName();
            String outPut = new File(outPutPath,packageName+"_"+apk_name).getAbsolutePath();
            File file = new File(outPut);
            file.mkdirs();
            Map<String, Object> map = Util.callGraphGenerate(applicationClasses,outPut);
//            Map<String, Object> map = Util.callGraphGenerateEnre("D:\\cert\\cg\\test\\src-tgt.json",outPut);
            Map<String,Long> nodes=(Map) map.get("nodes");
            Map<Long,String> nodeReverse=(Map)map.get("node_reverse");
            Map<Long,List> parents_info=(Map)map.get("parents_info");


            findSensitiveApiUsedWithUI(apiFile, nodes,nodeReverse,parents_info,"");
            List<Map> sensorFromCoed = Sensor.findSensorFromCoed(nodes,nodeReverse,parents_info);
            List<Map> usedPermissionFromCodePlus = Permission.findUsedPermissionFromCodePlus(nodes,nodeReverse,parents_info);
            HashMap<String, Object> sensorAndPer = new HashMap<>();
            sensorAndPer.put("sensors",sensorFromCoed);
            sensorAndPer.put("permissions",usedPermissionFromCodePlus);
            Util.writeMapToJson(new File(outPut,"sensor_permissions.json").getAbsolutePath(),sensorAndPer,false);

        }catch (Exception ex){
            throw ex;
        }
    }
    public static Map findSensitiveApiUsedWithUI(String apiFile,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info,String output) throws IOException {
        Map<String,Object> res=new ConcurrentHashMap<>();
        List<Map> list = readApiFromJsonFile(apiFile);
        final CountDownLatch cd=new CountDownLatch(list.size());
        for(Map map:list){
            new Thread(new Runnable() {
                @Override
                public void run() {
                    HashMap<String, Object> tmpMap = new HashMap<>();
                    String api=(String) map.get("api");
                    List<List> pathes = Util.getPathes(api,nodes,nodeReverse,parents_info);
                    List<Map> invokeList=new ArrayList<>();
                    for(List path:pathes){
                        Map<String,Object> newMap=new HashMap<>();
                        newMap.put("invoke_chain",path);
                        invokeList.add(newMap);
                    }
                    tmpMap.put("used",invokeList);
//                    tmpMap.put("category",map.get("category"));
//                    tmpMap.put("des",map.get("des"));
                    res.put(api,tmpMap);
                    try {
                        Util.writeMapToJson(output,res,false);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    cd.countDown();
                }
            }).start();
        }
        try {
            cd.await();
        }catch (InterruptedException e){
            e.printStackTrace();
        }
        Util.writeMapToJson(output,res,false);
        return res;
    }
    public static Map findSensitiveApiUsedWithUI(String apiFile,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info) throws IOException {
        Map<String,Object> res=new ConcurrentHashMap<>();
        List<Map> list = readApiFromJsonFile(apiFile);
        final CountDownLatch cd=new CountDownLatch(list.size());
        for(Map map:list){
            new Thread(new Runnable() {
                @Override
                public void run() {
                    HashMap<String, Object> tmpMap = new HashMap<>();
                    String api=(String) map.get("api");
                    List<List> pathes = Util.getPathes(api,nodes,nodeReverse,parents_info);
                    List<Map> invokeList=new ArrayList<>();
                    for(List path:pathes){
                        Map<String,Object> newMap=new HashMap<>();
                        newMap.put("invoke_chain",path);
                        invokeList.add(newMap);
                    }
                    tmpMap.put("used",invokeList);
//                    tmpMap.put("category",map.get("category"));
//                    tmpMap.put("des",map.get("des"));
                    res.put(api,tmpMap);
                    cd.countDown();
                }
            }).start();
        }
        try {
            cd.await();
        }catch (InterruptedException e){
            e.printStackTrace();
        }
        return res;
    }
    public static Map findSensitiveApiUsedWithUI(String apiFile,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info,String screenJson,Map componentInfo, Map<String, Object> activityInfo, SetupApplication setup,String outPut) throws IOException {
        Map<String,Object> res=new ConcurrentHashMap<>();
        List<Map> list = readApiFromJsonFile(apiFile);
        for(Map map:list){
            new Thread(new Runnable() {
                @Override
                public void run() {
                    HashMap<String, Object> tmpMap = new HashMap<>();
                    String api=(String) map.get("api");
                    List<List> pathes = Util.getPathes(api,nodes,nodeReverse,parents_info);
                    List<Map> invokeList=new ArrayList<>();
                    for(List path:pathes){
                        Map<String,Object> newMap=new HashMap<>();
                        newMap.put("invoke_chain",path);
                        invokeList.add(newMap);
                    }
                    List<Map> invokeChainActivityBinding = null;
                    try {
                        invokeChainActivityBinding = SensitiveScenes.invokeChainActivityBinding(componentInfo, activityInfo, setup, invokeList, screenJson);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    tmpMap.put("used",invokeChainActivityBinding);
//                    tmpMap.put("category",map.get("category"));
//                    tmpMap.put("des",map.get("des"));
                    res.put(api,tmpMap);
                    try {
                        Util.writeMapToJson(new File(outPut,"api_used.json").getAbsolutePath(),res,false);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
        Util.writeMapToJson(new File(outPut,"api_used.json").getAbsolutePath(),res,false);
        return res;
    }
    public static List readApiFromJsonFile(String jsonPath) throws IOException {
        List<Map> res=new ArrayList<>();
        List<Map> list = Util.readJsonToList(jsonPath);
        for(Map map:list){
            HashMap<String, Object> tmpMap = new HashMap<>();
            tmpMap.put("api",  map.get("sign"));
//            tmpMap.put("category",  map.get("category"));
//            tmpMap.put("des", map.get("description"));
            res.add(tmpMap);
        }
        return res;
    }
    public static Map findSensitiveApiUsed(String apiFile,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info,String outPut) throws IOException {
        Map<String,Object> res=new ConcurrentHashMap<>();
        List<Map> list = readApiFromJsonFile(apiFile);
        for(Map map:list){
            new Thread(new Runnable() {
                @Override
                public void run() {
                    HashMap<String, Object> tmpMap = new HashMap<>();
                    String api=(String) map.get("api");
                    List<List> pathes = Util.getPathes(api,nodes,nodeReverse,parents_info);
                    List<Map> invokeList=new ArrayList<>();
                    for(List path:pathes){
                        Map<String,Object> newMap=new HashMap<>();
                        newMap.put("invoke_chain",path);
                        invokeList.add(newMap);
                    }
                    tmpMap.put("used",invokeList);
//                    tmpMap.put("category",map.get("category"));
//                    tmpMap.put("des",map.get("des"));
                    res.put(api,tmpMap);
                    try {
                        Util.writeMapToJson(new File(outPut,"api_used.json").getAbsolutePath(),res,false);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
        Util.writeMapToJson(new File(outPut,"api_used.json").getAbsolutePath(),res,false);
        return res;
    }


}
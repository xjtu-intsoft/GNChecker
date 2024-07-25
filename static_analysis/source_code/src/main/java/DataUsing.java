import my.*;
import org.xmlpull.v1.XmlPullParserException;
import soot.Scene;
import soot.SootClass;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.manifest.IComponentContainer;
import soot.jimple.infoflow.android.manifest.binary.BinaryManifestActivity;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;
import soot.util.Chain;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/**
 * @description:
 * @author: xxx
 * @date: 2024/3/19 21:35
 **/
public class DataUsing {

    public static void run(String apk,String sourceJson,String sdkPlatforms,String androidCallbacksTxt,String outPutPath) throws XmlPullParserException, IOException {
        String outPut;
        System.out.println("data collecting.......");
        long t1 = System.nanoTime();
        try {
            InfoflowAndroidConfiguration conf = new InfoflowAndroidConfiguration();
            // androidDirPath是你的android sdk中platforms目录的路径
            conf.getAnalysisFileConfig().setAndroidPlatformDir(sdkPlatforms);
            // apkFilePath是你要分析的apk的文件路径
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

            IComponentContainer activities = setup.getMainfest().getActivities();
            List<BinaryManifestActivity> list = activities.asList();
            Map<String,Map> activityMap = new HashMap<String,Map>();
            for(BinaryManifestActivity b :list){
                HashMap hashMap = new HashMap() {{
                    put("api_used", new ArrayList<>());
                    put("permissions", new ArrayList<>());
                    put("sensors", new ArrayList<>());
                }};
                activityMap.put(b.getNameString(),hashMap);
            }
            System.out.println(activityMap.keySet());



            Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
            CallGraph callGraph = new CallGraph();
            Map<String, Object> map = Util.callGraphGenerate(applicationClasses,callGraph,outPut);
            Map<String,Long> nodes=(Map) map.get("nodes");
            Map<Long,String> nodeReverse=(Map)map.get("node_reverse");
            Map<Long, List> parents_info=(Map)map.get("parents_info");
            ConcurrentHashMap<String, Object> apiUsedAndSensorAndPer = new ConcurrentHashMap<>();
            CountDownLatch dataCount = new CountDownLatch(2);
            Thread dataThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Map apiUsed = ApiUsed.findSensitiveApiUsedWithUI(sourceJson, nodes, nodeReverse, parents_info);
                        apiUsedAndSensorAndPer.put("api_used",apiUsed);

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    dataCount.countDown();
                }
            });
            Thread permissionThread=new Thread(new Runnable() {
                @Override
                public void run() {
                    List<Map> sensorFromCoed = Sensor.findSensorFromCode1(nodes,nodeReverse,parents_info);
                    List<Map> usedPermissionFromCodePlus = Permission.findUsedPermissionFromCodePlus1(nodes,nodeReverse,parents_info);
                    apiUsedAndSensorAndPer.put("sensors",sensorFromCoed);
                    apiUsedAndSensorAndPer.put("permissions",usedPermissionFromCodePlus);
                    dataCount.countDown();
                }
            });
            dataThread.start();
            permissionThread.start();
            try {
                dataCount.await();
            }catch (Exception e){
                e.printStackTrace();
            }
            Set<String> activitySet = activityMap.keySet();
            Map<String,Map> api_used = (Map)apiUsedAndSensorAndPer.get("api_used");
            for(String api:api_used.keySet()){
                Map map1 = api_used.get(api);
                List<Map> used = (List) map1.get("used");
                for(Map invoke_chain: used){
                    List<String> chain_list = (List)invoke_chain.get("invoke_chain");
                    String activity=findActivityOfChain(chain_list,activitySet);
                    if(activity!=null){
                        Map<String,List> map2 = activityMap.get(activity);
                        List api_used1 = map2.get("api_used");
                        api_used1.add(invoke_chain);
                    }
                }
            }

            List<Map> sensors = (List<Map>) apiUsedAndSensorAndPer.get("sensors");
            for(Map sensorMap:sensors){
                List<String> chain_list = (List<String>) sensorMap.get("invoke_chain");
                String activity=findActivityOfChain(chain_list,activitySet);
                if(activity!=null){
                    Map<String,List> map2 = activityMap.get(activity);
                    map2.get("sensors").add(sensorMap);
                }
            }

            List<Map> permissions = (List<Map>) apiUsedAndSensorAndPer.get("permissions");
            for(Map permissionMap:permissions){
                List<String> chain_list = (List<String>) permissionMap.get("invoke_chain");
                String activity=findActivityOfChain(chain_list,activitySet);
                if(activity!=null){
                    Map<String,List> map2 = activityMap.get(activity);
                    map2.get("permissions").add(permissionMap);
                }
            }

            Util.writeMapToJson(new File(outPut,"api_used.json").getAbsolutePath(),api_used,false);
            Util.writeListToJson(new File(outPut,"sensors.json.json").getAbsolutePath(),sensors,false);
            Util.writeListToJson(new File(outPut,"permissions.json").getAbsolutePath(),permissions,false);

            String data_collect_json = new File(outPut, "data_collect.json").getAbsolutePath();
            Util.writeMapToJson(data_collect_json,activityMap,false);
            System.out.println("analyse successfully!!!");

        }catch (Exception e){
            System.out.println("analyse failed!!!");
            throw e;
        }

    }

    private static String findActivityOfChain(List<String> chain_list, Set<String> activitySet) {
        int deep=3;
        if (chain_list.size()<3){
            deep=1;
        }
        for(int i=0;i<deep;i++){
            String sig = chain_list.get(i);
            for(String activityName:activitySet){
                if(sig.contains(activityName)){
                    return activityName;
                }
            }
        }
        return null;
    }
}

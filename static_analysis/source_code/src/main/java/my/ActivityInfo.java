package my;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.manifest.IComponentContainer;
import soot.jimple.infoflow.android.manifest.binary.BinaryManifestActivity;
import soot.jimple.infoflow.android.resources.ARSCFileParser;

import java.io.IOException;
import java.util.*;

/**
 * @description:
 * @author: xxx
 * @date: 2023/2/15 19:55
 **/
public class ActivityInfo {
    public Map<String,Object> activityInfoMap;

    public static Map<String, Object> activityInfoInitialize(Map componentInfo,SetupApplication setupApplication,String screenJson) throws IOException {
        Map<String, Object> activity = getActivity(setupApplication);
        Map<String, Object> componentIdForActivity = findComponentIdForActivity(activity);
        componentInfoBinding(componentInfo,setupApplication,componentIdForActivity);
        activityScreenShotBinding(setupApplication,componentIdForActivity,screenJson);
        return componentIdForActivity;
    }
    public static Map<String, Object> activityScreenShotBinding(SetupApplication setupApplication,Map<String, Object> activityInfoMap,String screenJson) throws IOException {
        Map screenMap = Util.readJsonToMap(screenJson);
        ArrayList<String> keys = new ArrayList<>(activityInfoMap.keySet());
        for(String activity:keys){
            Map map = (Map) activityInfoMap.get(activity);
            String finalScreen="";
            int size=0;
            Set acomponents = (Set) map.get("component_id_name");
            Set<String> screens = screenMap.keySet();
            for(String screen:screens){
                Map map1 = (Map) screenMap.get(screen);
                HashSet<String> scomponents = new HashSet<>();
                scomponents.addAll((List)map1.get("id_set"));
                //取交集
                scomponents.retainAll(acomponents);
                if(scomponents.size()>size){
                    size=scomponents.size();
                    finalScreen=screen;
                }
            }
            map.put("screen_shot",finalScreen);
        }
        return activityInfoMap;
    }

//    private static Set idToIntId(SetupApplication setup, Set<String> set) {
//        Set<String> results = new HashSet<>();
//        ARSCFileParser resources = setup.getResources();
//        for(String id:set){
//            try{
//                ARSCFileParser.AbstractResource resource = resources.findResource(Integer.valueOf(id));
//                String idName=resource.getResourceName();
//                results.add(idName);
//            }catch (Exception e){
//                continue;
//            }
//        }
//        return results;
//    }

    public static Map readScreenInfo(String jsonPath) throws IOException {
        Map map = Util.readJsonToMap(jsonPath);
        return map;
    }
    public static Map<String,Object> findComponentIdForActivity(Map<String,Object> activities){
        HashMap<String, Object> results = new HashMap<>();
        Set<String> keys = activities.keySet();
        for(String activity:keys){
            Set<String> ids=new HashSet<>();
            SootClass activityClass = Scene.v().getSootClassUnsafe(activity);
            List<SootMethod> methods = activityClass.getMethods();
            for(SootMethod method:methods){
                Set<String> componentIdInMethod = Util.findComponentIdInMethod(method);
                ids.addAll(componentIdInMethod);
            }
            Map<String,Object> map=new HashMap<>();
            map.put("components",ids);
            map.put("attr",activities.get(activity));
            results.put(activity,map);
        }
        return results;
    }
    public static Map<String,Object> getActivity(SetupApplication setupApplication){
        HashMap<String, Object> results = new HashMap<>();
        IComponentContainer activities = setupApplication.getMainfest().getActivities();
        Iterator iterator = activities.iterator();
        while (iterator.hasNext()){
            BinaryManifestActivity next = (BinaryManifestActivity) iterator.next();
            results.put(next.getNameString(),next.getAXmlNode().getAttributes());
        }
        return results;
    }
    public static void componentInfoBinding(Map componentInfo,SetupApplication setup,Map<String,Object> activityInfoMap) throws IOException {
        ARSCFileParser resources = setup.getResources();
        Set<String> keys = activityInfoMap.keySet();
        for(String key:keys){
            Map map = (Map) activityInfoMap.get(key);
            Set<String> components =(Set) map.get("components");
            List<Map> componentInfoBinding=new ArrayList<>();
            Set<String> componentIdName=new HashSet<>();
            if(components.size()>0){
                for(String id:components){
                    try {
                        ARSCFileParser.AbstractResource resource = resources.findResource(Integer.valueOf(id));
                        String idName=resource.getResourceName();

                        if(componentInfo.containsKey(idName)){
                            Map map1=(Map) componentInfo.get(idName);
                            map1.put("int_id",id);
                            componentIdName.add(idName);
                            componentInfoBinding.add(map1);
                        }
                    }catch (Exception e){
                        continue;
                    }
                }
            }
            map.put("component_info",componentInfoBinding);
            map.put("component_id_name",componentIdName);
        }
    }
}

package my;

import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.resources.ARSCFileParser;

import java.io.IOException;
import java.util.*;

/**
 * @description: 从UI组件链到敏感API
 * @author: xxx
 * @date: 2023/2/16 9:11
 **/
public class SensitiveScenes {
    public static List<Map> invokeChainActivityBinding(Map componentInfo, Map<String, Object> activityInfo, SetupApplication setup,List<Map> netTrans,String screenJson) throws IOException {
    List<Map> results=new ArrayList<>();
    ARSCFileParser resources = setup.getResources();
    Set<String> activities = activityInfo.keySet();
    List<Map> sensitiveScenes = Util.findViewIdForSensitiveScenes(netTrans);
    for(Map<String,Object> scene:sensitiveScenes){
        List<Map> sceneCompoment=(List) scene.get("component_id");
        Set<String> scomponents=new HashSet<>();
        for(Map component:sceneCompoment){
            Set<String> set = component.keySet();
            for(String key:set){
                scomponents.addAll((Set)component.get(key));
            }
        }
        if(scomponents.size()>0){
            int s_size=0;
            String s_activity="";
            ArrayList<Map> final_components =new ArrayList<>();
            for(String activity:activities){
                Map map = (Map)activityInfo.get(activity);
                HashSet<String> acomponent = new HashSet<>();
                acomponent.addAll((Set)map.get("components"));
                //取交集
                HashSet<String> sameSet = new HashSet<>();
                sameSet.addAll(scomponents);
                sameSet.retainAll(acomponent);
                if(sameSet.size()>s_size){
                    for(String id :sameSet){
                        ArrayList<Map> maps =new ArrayList<>();
                        try {
                            ARSCFileParser.AbstractResource resource = resources.findResource(Integer.valueOf(id));
                            String resourceName = resource.getResourceName();
                            Map map1 = (Map) componentInfo.get(resourceName);
                            maps.add(map1);
                        }catch (Exception e){
                            HashMap<String, String> exceptMap = new HashMap<>();
                            exceptMap.put("id",id);
                            maps.add(exceptMap);
                        }
                        s_size=sameSet.size();
                        s_activity=activity;
                        final_components=maps;
                    }
                }
            }
            Map<String,Object> tmp1=new HashMap<>();
            tmp1.put("components",final_components);
            tmp1.put("activity",s_activity);
            Map map = (Map) activityInfo.get(s_activity);
            if(map!=null){tmp1.put("screen_shot",map.get("screen_shot"));}else { tmp1.put("screen_shot","");}
            scene.put("static",tmp1);
            //动态
            Set<String> scomponentName=new HashSet<>();
            for(String id:scomponents){
                try {
                    ARSCFileParser.AbstractResource resource = resources.findResource(Integer.valueOf(id));
                    String resourceName = resource.getResourceName();
                    scomponentName.add(resourceName);
                }catch (Exception e){
                    continue;
                }
            }

            Map screenMap = Util.readJsonToMap(screenJson);
            Set<String> screens = screenMap.keySet();
            int size=0;
            String finalScreen="";
            List<Map> finalSet=new ArrayList<>();
            for(String screen:screens){
                Map screenmap = (Map) screenMap.get(screen);
                HashSet<String> components = new HashSet<>();
                components.addAll((List)screenmap.get("id_set"));
                //取交集
                components.retainAll(scomponentName);
                if(components.size()>size){
                    size=scomponents.size();
                    finalScreen=screen;
                    Map id_attr = (Map)screenmap.get("id_attr");
                    ArrayList<Map> maps = new ArrayList<>();
                    for(String id:components){
                        maps.add((Map) id_attr.get(id));
                    }
                    finalSet=maps;
                }

            }
            Map<String,Object> tmp=new HashMap<>();
            tmp.put("screen_shot",finalScreen);
            tmp.put("components",finalSet);
            tmp.put("activity","");
            scene.put("dynamic",tmp);
            results.add(scene);
        }
        else {
            scene.put("static",new HashMap<>());
            scene.put("dynamic",new HashMap<>());
            results.add(scene);
        }

    }
    return results;
}
    public static List<Map> invokeChainActivityBinding(List<Map> netTrans) throws IOException {
        List<Map> results=new ArrayList<>();
        List<Map> sensitiveScenes = Util.findViewIdForSensitiveScenes(netTrans);
        for(Map<String,Object> scene:sensitiveScenes){
            List<Map> sceneCompoment=(List) scene.get("component_id");
            Set<String> scomponents=new HashSet<>();
            for(Map component:sceneCompoment){
                Set<String> set = component.keySet();
                for(String key:set){
                    scomponents.addAll((Set)component.get(key));
                }
            }
        }
        return results;
    }
}

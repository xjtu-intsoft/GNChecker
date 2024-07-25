package my;
import com.alibaba.fastjson.JSON;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.IComponentContainer;
import soot.jimple.infoflow.android.manifest.binary.BinaryManifestActivity;
import soot.jimple.internal.AbstractInvokeExpr;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JNewExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.util.Chain;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @description:
 * @author: xxx
 * @date: 2023/7/4 17:07
 **/
public class test {

    public static void activityTransGraphGenerate(SetupApplication setupApplication,String outPut) throws UnsupportedEncodingException {
        HashMap<String, List> graph = new HashMap<>();
        IComponentContainer activities = setupApplication.getMainfest().getActivities();
        System.out.println(activities);
        HashMap<String, List> activityTargetActionMap= new HashMap<>();
        ArrayList<String> activityStrings = new ArrayList<>();
        Iterator iterator = activities.iterator();
        while (iterator.hasNext()){
            BinaryManifestActivity next = (BinaryManifestActivity)iterator.next();
            String activity = next.getNameString();
            activityStrings.add(activity);
            List<AXmlNode> children = next.getAXmlNode().getChildren();
            ArrayList<String> actions = new ArrayList<>();
            for(AXmlNode child:children){
                if(child.getTag().equals("intent-filter")){
                    List<AXmlNode> children1 = child.getChildren();
                    for(AXmlNode child1:children1){
                        if(child1.getTag().equals("action")){
                            String action = (String) child1.getAttribute("name").getValue();
                            actions.add(action);
                        }
                    }
                }
            }
            activityTargetActionMap.put(activity,actions);
        }

        //通过action跳转
        Iterator iterator1 = activities.iterator();
        while (iterator1.hasNext()){
            BinaryManifestActivity next = (BinaryManifestActivity)iterator1.next();
            String activity = next.getNameString();
            String onCreate="<"+activity+": void onCreate(android.os.Bundle)>";
            String onCreateBody = Util.getMethodBody(onCreate).toString();

            for(String target:activityTargetActionMap.keySet()){
                List<String> actionList = activityTargetActionMap.get(target);
                for(String action:actionList){
                    if(onCreateBody.contains(action)){
                        if(graph.containsKey(activity)){
                            graph.get(activity).add(target);
                        }else {
                            ArrayList<String> tmp = new ArrayList<>();
                            tmp.add(target);
                            graph.put(activity,tmp);
                        }
                        break;
                    }
                }
            }
        }

        //通过classname跳转
        Iterator iterator2 = activities.iterator();
        while (iterator2.hasNext()){
            BinaryManifestActivity next = (BinaryManifestActivity)iterator2.next();
            String activity = next.getNameString();
            String onCreate="<"+activity+": void onCreate(android.os.Bundle)>";
            String onCreateBody = Util.getMethodBody(onCreate).toString();
            for(String target:activityStrings){
                if(target.equals(activity)){
                    continue;
                }
                String[] split = target.split("\\.");
                String activityName = split[split.length - 1];
                if(onCreateBody.contains(activityName+".class")){
                    if(graph.containsKey(activity)){
                        graph.get(activity).add(target);
                    }else {
                        ArrayList<String> tmp = new ArrayList<>();
                        tmp.add(target);
                        graph.put(activity,tmp);
                    }
                    break;
                }else if(onCreateBody.contains(target)){
                    if(graph.containsKey(activity)){
                        graph.get(activity).add(target);
                    }else {
                        ArrayList<String> tmp = new ArrayList<>();
                        tmp.add(target);
                        graph.put(activity,tmp);
                    }
                    break;
                }else if(onCreateBody.contains(target.replace(".","/"))){
                    if(graph.containsKey(activity)){
                        graph.get(activity).add(target);
                    }else {
                        ArrayList<String> tmp = new ArrayList<>();
                        tmp.add(target);
                        graph.put(activity,tmp);
                    }
                    break;
                }
            }
        }
        Util.writeListToJson1(new File(outPut,"activities.json").getAbsolutePath(),activityStrings,false);
        Util.writeMapToJson(new File(outPut,"activity_trans_graph.json").getAbsolutePath(),graph,false);
        System.out.println(1);
    }
}

package secondstage.taintanalysis.taint;

import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.GraphWalk;
import secondstage.taintanalysis.analyzer.TaintAnalyzer;
import secondstage.taintanalysis.analyzer.PositionState;
import secondstage.taintanalysis.analyzer.shortcut.Path;
import secondstage.taintanalysis.analyzer.shortcut.ShortCutTree;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.tagkit.JimpleLineNumberTag;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;

import java.util.*;


public class TaintResult {
    public ArrayList<TaintValue> Sinks;
    public ArrayList<TaintValue> Mays;
    public TaintSet taintSet;
    public CallGraph cg;
    private TaintFlow tree;
    private HashMap<Integer, ArrayList<TaintValue>> sinkIndexes;
    private HashMap<Integer, ArrayList<TaintValue>> mayIndexes;
    private ArrayList<TaintValue> FlowTemp;
    private UnitGraph CfgNow;
    private ShortCutTree shortCutTree;
    private int indexofTree;
    private int sinkHasBeenFound;
    private int mayHasBeenFound;
    public ArrayList<FlowResult> taintFlowsResult = new ArrayList<>();
    public ArrayList<FlowResult> mayFlowsResult = new ArrayList<>();
    public ArrayList<FlowResult> taintFlows = new ArrayList<>();
    public ArrayList<ArrayList<TaintValue>> mayTaintFlows = new ArrayList<>();
    private HashMap<Integer, ShortCutTree> shortCutTrees = new HashMap<>();

    public TaintResult(TaintSet taintSet, CallGraph cg, ArrayList<TaintValue> sinks, ArrayList<TaintValue> mays) {
        this.Sinks = sinks;
        this.Mays = mays;
        this.taintSet = taintSet;
        this.cg = cg;
    }

    private PositionState postionRelation(TaintValue tvNow, TaintValue tvNext) {
        Context cxNext = tvNext.getContext();
        Context cxNow = tvNow.getContext();
        TaintWay tWay = tvNext.getTW();
        if (cxNow.inSameMethod(cxNext)) {
            if ((tWay == TaintWay.ClassFieldThis && tvNext.gettMethod().contains(SootMethod.constructorName)) || (tvNext.getTW() == TaintWay.AliasBefore && tvNow.getTW() == TaintWay.Identity)) {
                return PositionState.Flexible;
            }
            if (tvNext.getKind() == ValueKind.StaticField || tvNow.getKind() == ValueKind.StaticField) {
                return PositionState.Ignore;
            }
            if (tvNow.getTW() == TaintWay.Identity) {
                return PositionState.Ignore;
            }
            switch (tWay) {
                case Normal:
                case Param:
                case TaintWrapper:
                case Sink:
                case ClassFieldThis:
                case Return:
                    return PositionState.After;
                case Aug:
                    return PositionState.CheckInvokePoint;
                case Identity:
                    return PositionState.Ignore;
                case Alias:
                    return PositionState.Flexible;
                case AliasBefore:
                    return PositionState.Before;
                case ThisIdentity:
                case ParamReturn:
                    return PositionState.HoldToEnd;
                default:
                    return PositionState.Default;
            }
        } else if (tvNext.getKind() == ValueKind.StaticField || tvNow.getKind() == ValueKind.StaticField) {
            return PositionState.Ignore;
        } else {
            switch (tWay) {
                case Aug:
                case ReturnBack:
                    return PositionState.CheckInvokePoint;
                case Identity:
                case ParamIdentity:
                case ClassField:
                    return PositionState.Ignore;
                case Alias:
                case AliasBefore:
                case ThisIdentity:
                case ParamReturn:
                default:
                    return PositionState.Default;
            }
        }
    }

    public void createAndCheckFLows() {
        for (int indexTree = 0; indexTree < this.taintSet.allTFlows.size(); indexTree++) {
            this.sinkHasBeenFound = 0;
            this.mayHasBeenFound = 0;
            this.tree = this.taintSet.allTFlows.get(indexTree);
            this.indexofTree = indexTree;
            this.sinkIndexes = new HashMap<>();
            this.mayIndexes = new HashMap<>();
            for (int index = 0; index < this.tree.Flow.size(); index++) {
                ArrayList<TaintValue> sinkList = new ArrayList<>();
                ArrayList<TaintValue> mayList = new ArrayList<>();
                TaintValue node = this.tree.Flow.get(index);
                Iterator<TaintValue> it = this.Mays.iterator();
                while (it.hasNext()) {
                    TaintValue may = it.next();
                    if (may.equals(node)) {
                        mayList.add(may);
                    }
                }
                if (!mayList.isEmpty()) {
                    this.mayIndexes.put(Integer.valueOf(index), mayList);
                }
                Iterator<TaintValue> it2 = this.Sinks.iterator();
                while (it2.hasNext()) {
                    TaintValue sink = it2.next();
                    if (sink.equals(node)) {
                        sinkList.add(sink);
                    }
//                    if(sink.gettMethod().equals(node.gettMethod())&&sink.gettClass().equals(node.gettClass())){
//                        sinkList.add(sink);
//                    }
                }
                if (!sinkList.isEmpty()) {
                    this.sinkIndexes.put(Integer.valueOf(index), sinkList);
                }
            }
            if (!this.sinkIndexes.isEmpty() || !this.mayIndexes.isEmpty()) {
                findFlows(indexTree);
            }
        }
    }

    public void findFlows(int indexTree) {
        this.FlowTemp = new ArrayList<>();
        this.shortCutTree = null;
        this.shortCutTree = new ShortCutTree();
        this.shortCutTrees.put(Integer.valueOf(indexTree), this.shortCutTree);
        Path pathCurrent = new Path();
        HashSet<StmLocation> cleanAliasList = new HashSet<>();
        checkFlow(-2, 0, pathCurrent, cleanAliasList);
    }

    private void checkFlow(int indexNow, int indexNext, Path pathCurrent, HashSet<StmLocation> cleanAliasListCopy) {
        PositionState state;
        boolean stop = false;
        if ((!this.sinkIndexes.isEmpty() || (!this.mayIndexes.isEmpty() && this.mayHasBeenFound < TaintAnalyzer.OneSourceHasMaxMays)) && this.sinkHasBeenFound < TaintAnalyzer.OneSourceHasMaxSinks) {
            TaintValue tvNow = null;
            TaintValue tvNext = this.tree.Flow.get(indexNext);
            HashSet<StmLocation> cleanList = new HashSet<>();
            HashSet<StmLocation> cleanAliasList = new HashSet<>();
            if (indexNow == -2) {
                state = PositionState.Ignore;
            } else {
                tvNow = this.tree.Flow.get(indexNow);
                cleanList.addAll(tvNow.getCleanLocations());
                cleanAliasList.addAll(cleanAliasListCopy);
                state = postionRelation(tvNow, tvNext);
                cleanList.addAll(cleanAliasList);
            }
            switch (state) {
                case After:
                    if (checkPath(tvNow, tvNext, cleanList)) {
                        this.FlowTemp.add(tvNext);
                        indexNow = indexNext;
                        cleanAliasList.clear();
                        pathCurrent.add(indexNext);
                        checkSinkandMay(indexNext, pathCurrent);
                        break;
                    } else {
                        stop = true;
                        Path pathCut = new Path(pathCurrent);
                        pathCut.cut(indexNext);
                        this.shortCutTree.addPath(pathCut, null);
                        break;
                    }
                case Before:
                    if (checkPath(tvNow, tvNext, null)) {
                        stop = true;
                        Path pathCut2 = new Path(pathCurrent);
                        pathCut2.cut(indexNext);
                        this.shortCutTree.addPath(pathCut2, null);
                        break;
                    } else if (checkPath(tvNext, tvNow, tvNext.getCleanLocations())) {
                        this.FlowTemp.add(tvNext);
                        if (tvNext.getCleanLocations() != null) {
                            cleanAliasList.addAll(tvNext.getCleanLocations());
                        }
                        pathCurrent.add(indexNext);
                        checkSinkandMay(indexNext, pathCurrent);
                        break;
                    } else {
                        stop = true;
                        Path pathCut3 = new Path(pathCurrent);
                        pathCut3.cut(indexNext);
                        this.shortCutTree.addPath(pathCut3, null);
                        break;
                    }
                case Flexible:
                    if (checkPath(tvNow, tvNext, cleanList)) {
                        this.FlowTemp.add(tvNext);
                        if (tvNext.getCleanLocations() != null) {
                            cleanAliasList.addAll(tvNow.getCleanLocations());
                        }
                        indexNow = indexNext;
                        pathCurrent.add(indexNext);
                        checkSinkandMay(indexNext, pathCurrent);
                        break;
                    } else if (checkPath(tvNext, tvNow, tvNext.getCleanLocations())) {
                        this.FlowTemp.add(tvNext);
                        if (tvNext.getCleanLocations() != null) {
                            cleanAliasList.addAll(tvNext.getCleanLocations());
                        }
                        pathCurrent.add(indexNext);
                        checkSinkandMay(indexNext, pathCurrent);
                        break;
                    } else {
                        stop = true;
                        Path pathCut4 = new Path(pathCurrent);
                        pathCut4.cut(indexNext);
                        this.shortCutTree.addPath(pathCut4, null);
                        break;
                    }
                case HoldToEnd:
                    if (tvNext.getCleanLocations() != null && isCleanedtoEnd(tvNext, tvNext.getCleanLocations())) {
                        stop = true;
                        Path pathCut5 = new Path(pathCurrent);
                        pathCut5.cut(indexNext);
                        this.shortCutTree.addPath(pathCut5, null);
                        break;
                    } else {
                        this.FlowTemp.add(tvNext);
                        indexNow = indexNext;
                        cleanAliasList.clear();
                        pathCurrent.add(indexNext);
                        checkSinkandMay(indexNext, pathCurrent);
                        break;
                    }
                case CheckInvokePoint:
                    if (isTaintThrough(tvNow, tvNext, this.FlowTemp) == 2 || isTaintThrough(tvNow, tvNext, this.FlowTemp) == 0) {
                        this.FlowTemp.add(tvNext);
                        indexNow = indexNext;
                        cleanAliasList.clear();
                        pathCurrent.add(indexNext);
                        checkSinkandMay(indexNext, pathCurrent);
                        break;
                    } else {
                        stop = true;
                        Path pathCut6 = new Path(pathCurrent);
                        pathCut6.cut(indexNext);
                        this.shortCutTree.addPath(pathCut6, null);
                        break;
                    }
                case Ignore:
                    this.FlowTemp.add(tvNext);
                    indexNow = indexNext;
                    cleanAliasList.clear();
                    pathCurrent.add(indexNext);
                    checkSinkandMay(indexNext, pathCurrent);
                    break;
                default:
                    stop = true;
                    break;
            }
            if (!stop) {
                Set<DefaultEdge> edges = this.tree.Pairs.outgoingEdgesOf(Integer.valueOf(indexNext));
                ArrayList<Integer> nodes = new ArrayList<>();
                for (DefaultEdge edge : edges) {
                    nodes.add(this.tree.Pairs.getEdgeTarget(edge));
                }
                Iterator<Integer> it = nodes.iterator();
                while (it.hasNext()) {
                    int nextNode = it.next().intValue();
                    if (pathCurrent.getPathString().length() < 300) {
                        checkFlow(indexNow, nextNode, new Path(pathCurrent), cleanAliasList);
                    }
                }
            }
        }
    }

    private boolean checkPath(TaintValue Source, TaintValue Target, HashSet<StmLocation> cleanList) {
        Context ctxSource = Source.getContext();
        Context ctxTarget = Target.getContext();
        if (ctxSource.inSameMethod(ctxTarget)) {
            SootMethod sMethod = ctxSource.getsMethod();
            Unit uSource = ctxSource.getLocation().getStatement();
            Unit uTarget = ctxTarget.getLocation().getStatement();
            if (cleanList != null && cleanList.isEmpty()) {
                Iterator<StmLocation> it = cleanList.iterator();
                while (it.hasNext()) {
                    StmLocation clean = it.next();
                    if (!clean.getSM().equals(sMethod.getName()) || !clean.getSC().equals(sMethod.getDeclaringClass().getName())) {
                        cleanList.remove(clean);
                    }
                }
            }
            if (!sMethod.hasActiveBody()) {
                return false;
            }
            this.CfgNow = new ExceptionalUnitGraph(sMethod.getActiveBody());
            JimpleLineNumberTag sTag = (JimpleLineNumberTag) uSource.getTag("JimpleLineNumberTag");
            int slineTag = sTag == null ? -1 : sTag.getLineNumber();
            JimpleLineNumberTag NTag = (JimpleLineNumberTag) uTarget.getTag("JimpleLineNumberTag");
            int lineTag = NTag == null ? -1 : NTag.getLineNumber();
            if (slineTag == lineTag) {
                return true;
            }
            if (lineTag > -1 && findUnitPath(uSource, lineTag, cleanList)) {
                return true;
            }
            return false;
        }
        return false;
    }

    private boolean checkSinkandMay(int indexCheck, Path pathCurrent) {
        boolean result = false;
        if (this.sinkIndexes.containsKey(Integer.valueOf(indexCheck))) {
            TaintValue tvNow = this.tree.Flow.get(indexCheck);
            HashSet<StmLocation> cleanList = tvNow.getCleanLocations();
            Iterator<TaintValue> it = this.sinkIndexes.get(Integer.valueOf(indexCheck)).iterator();
            while (it.hasNext()) {
                TaintValue tvNext = it.next();
                if (checkPath(tvNow, tvNext, cleanList)) {
                    ArrayList<TaintValue> flow = new ArrayList<>();
                    flow.addAll(this.FlowTemp);
                    flow.add(tvNext);
                    Path pathSink = new Path(pathCurrent);
                    pathSink.addSink();
                    this.shortCutTree.addPath(pathSink, null);
                    FlowResult newFlow = new FlowResult(this.tree, this.indexofTree, flow, null);
                    this.taintFlowsResult.add(newFlow);
                    this.sinkHasBeenFound++;
                    result = true;
                }
            }
            if (result) {
                this.sinkIndexes.remove(Integer.valueOf(indexCheck));
            }
        }
        if (this.mayIndexes.containsKey(Integer.valueOf(indexCheck))) {
            TaintValue tvNow2 = this.tree.Flow.get(indexCheck);
            HashSet<StmLocation> cleanList2 = tvNow2.getCleanLocations();
            Iterator<TaintValue> it2 = this.mayIndexes.get(Integer.valueOf(indexCheck)).iterator();
            while (it2.hasNext()) {
                TaintValue tvNext2 = it2.next();
                if (checkPath(tvNow2, tvNext2, cleanList2)) {
                    ArrayList<TaintValue> flow2 = new ArrayList<>();
                    flow2.addAll(this.FlowTemp);
                    flow2.add(tvNext2);
                    Path pathMay = new Path(pathCurrent, null);
                    pathMay.addMay();
                    this.shortCutTree.addPath(pathMay, null);
                    FlowResult newFlow2 = new FlowResult(this.tree, this.indexofTree, flow2, null);
                    this.mayFlowsResult.add(newFlow2);
                    this.mayHasBeenFound++;
                    result = true;
                }
            }
            if (result) {
                this.mayIndexes.remove(Integer.valueOf(indexCheck));
            }
        }
        return result;
    }

    public boolean findUnitPath(Unit source, int lineTarget, HashSet<StmLocation> cleanList) {
        LinkedList<Unit> queue = new LinkedList<>();
        HashSet<Unit> visit = new HashSet<>();
        visit.add(source);
        queue.addLast(source);
        while (!queue.isEmpty()) {
            Unit u1 = queue.removeFirst();
            List<Unit> uNexts = this.CfgNow.getSuccsOf(u1);
            for (Unit uNeib : uNexts) {
                if (!visit.contains(uNeib)) {
                    int res = checkUnit(uNeib, lineTarget, cleanList);
                    visit.add(uNeib);
                    if (res == 1) {
                        return true;
                    }
                    if (res == 0) {
                        queue.addLast(uNeib);
                    }
                }
            }
        }
        return false;
    }

    private int checkUnit(Unit uCheck, int lineTarget, HashSet<StmLocation> cleanList) {
        JimpleLineNumberTag NTag = (JimpleLineNumberTag) uCheck.getTag("JimpleLineNumberTag");
        int lineChecks = NTag == null ? -1 : NTag.getLineNumber();
        if (lineChecks == -1) {
            return -1;
        }
        if (cleanList != null) {
            Iterator<StmLocation> it = cleanList.iterator();
            while (it.hasNext()) {
                StmLocation clean = it.next();
                if (lineChecks == clean.getST()) {
                    return -1;
                }
            }
        }
        if (lineChecks == lineTarget) {
            return 1;
        }
        return 0;
    }

    private boolean isCleanedtoEnd(TaintValue Source, HashSet<StmLocation> cleanList) {
        SootMethod sMethod = Source.getContext().getsMethod();
        Unit u = Source.getContext().getLocation().getStatement();
        this.CfgNow = new ExceptionalUnitGraph(sMethod.getActiveBody());
        List<Unit> uEndList = this.CfgNow.getTails();
        Iterator<StmLocation> it = cleanList.iterator();
        while (it.hasNext()) {
            StmLocation clean = it.next();
            if (!clean.getSM().equals(sMethod.getName()) || !clean.getSC().equals(sMethod.getDeclaringClass().getName())) {
                cleanList.remove(clean);
            }
        }
        for (Unit uEnd : uEndList) {
            JimpleLineNumberTag NTag = (JimpleLineNumberTag) uEnd.getTag("JimpleLineNumberTag");
            int lineTag = NTag == null ? -1 : NTag.getLineNumber();
            if (lineTag > -1 && findUnitPath(u, lineTag, cleanList)) {
                return false;
            }
        }
        return true;
    }

    private int isTaintThrough(TaintValue tvreturn, TaintValue tvBack, ArrayList<TaintValue> Flow) {
        Context contextTV = tvBack.getContext();
        Iterator<TaintValue> it = Flow.iterator();
        while (it.hasNext()) {
            TaintValue tvFlow = it.next();
            if (tvFlow.getKind() == ValueKind.Param && !tvFlow.equals(tvreturn) && tvreturn.gettClass().equals(tvFlow.gettClass()) && tvreturn.gettMethod().equals(tvFlow.gettMethod())) {
                if (contextTV.equals(tvFlow.getContext())) {
                    return 2;
                }
                return 1;
            }
        }
        return 0;
    }

    @Deprecated
    public void createMayFlowsFromSet() {
        int indexTree = 0;
        Iterator<TaintFlow> it = this.taintSet.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow tree = it.next();
            Iterator<TaintValue> it2 = tree.Flow.iterator();
            while (it2.hasNext()) {
                TaintValue node = it2.next();
                Iterator<TaintValue> it3 = this.Mays.iterator();
                while (it3.hasNext()) {
                    TaintValue may = it3.next();
                    if (may.equals(node)) {
                        createMayFlowFromNode(may, tree, indexTree);
                    }
                }
            }
            indexTree++;
        }
    }

    @Deprecated
    private void createMayFlowFromNode(TaintValue may, TaintFlow tree, int indexTree) {
        int mayIndex = tree.Flow.indexOf(may);
        AllDirectedPaths<Integer, DefaultEdge> pathFinder = new AllDirectedPaths<>(tree.Pairs);
        List<GraphPath<Integer, DefaultEdge>> pathList = pathFinder.getAllPaths(0, (int) Integer.valueOf(mayIndex), true, Integer.valueOf(tree.Pairs.edgeSet().size()));
        for (GraphPath<Integer, DefaultEdge> path : pathList) {
            ArrayList<TaintValue> flowTemp = new ArrayList<>();
            System.out.println(path.getVertexList().toString());
            for (Integer index : path.getVertexList()) {
                flowTemp.add(tree.Flow.get(index.intValue()));
            }
            flowTemp.add(may);
            this.mayTaintFlows.add(flowTemp);
        }
    }

    @Deprecated
    public void createFlowsFromSet() {
        int treeIndex = 0;
        Iterator<TaintFlow> it = this.taintSet.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow tree = it.next();
            Iterator<TaintValue> it2 = tree.Flow.iterator();
            while (it2.hasNext()) {
                TaintValue node = it2.next();
                int sinkNo = 1;
                Iterator<TaintValue> it3 = this.Sinks.iterator();
                while (it3.hasNext()) {
                    TaintValue sink = it3.next();
                    if (sink.equals(node) || sink.isPrefixOf(node)) {
                        createFlowFromNode(sink, sinkNo, node, tree, treeIndex);
                    }
                    sinkNo++;
                }
            }
            treeIndex++;
        }
    }

    @Deprecated
    private void createFlowFromNode(TaintValue sink, int sinkNo, TaintValue node, TaintFlow tree, int treeIndex) {
        int sinkIndex = tree.getIndexAllEqual(node);
        AllDirectedPaths<Integer, DefaultEdge> pathFinder = new AllDirectedPaths<>(tree.Pairs);
        List<GraphPath<Integer, DefaultEdge>> pathList = pathFinder.getAllPaths(0, (int) Integer.valueOf(sinkIndex), true, Integer.valueOf(tree.Pairs.edgeSet().size()));
        for (GraphPath<Integer, DefaultEdge> path : pathList) {
            ArrayList<TaintValue> flowTemp = new ArrayList<>();
            ArrayList<Integer> IndexsTemp = new ArrayList<>();
            for (Integer index : path.getVertexList()) {
                flowTemp.add(tree.Flow.get(index.intValue()));
                IndexsTemp.add(index);
            }
            flowTemp.add(sink);
            IndexsTemp.add(Integer.valueOf(1000 + sinkNo));
            this.taintFlows.add(new FlowResult(tree, treeIndex, flowTemp, IndexsTemp));
        }
    }

    public void printTaintNum() {
        System.out.println("---------Taint Flow number is:" + this.taintFlowsResult.size());
        System.out.println("------May Taint Flow number is:" + this.mayFlowsResult.size());
    }

    public void printTaint() {
        int i = 0;
        Iterator<FlowResult> it = this.taintFlowsResult.iterator();
        while (it.hasNext()) {
            FlowResult tf = it.next();
            System.out.println("Taintflow" + i + ":from TaintGraph:" + tf.getIndexofTree());
            int m = 0;
            Iterator<TaintValue> it2 = tf.getFlow().iterator();
            while (it2.hasNext()) {
                TaintValue tv = it2.next();
                int i2 = m;
                m++;
                System.out.print(i2 + ":");
                System.out.println(tv.toString());
            }
            i++;
        }
    }

    public void printTaintSimple() {
        int i = 0;
        Iterator<FlowResult> it = this.taintFlowsResult.iterator();
        while (it.hasNext()) {
            FlowResult tf = it.next();
            System.out.println("Taintflow" + i + ":from TaintGraph:" + tf.getIndexofTree());
            System.out.print("Source:");
            System.out.println(tf.getFlow().get(0).toString());
            System.out.print("Sink:");
            System.out.println(tf.getFlow().get(tf.getFlow().size() - 1).toString());
            i++;
        }
    }

    public void printPath() {
        for (Integer num : this.shortCutTrees.keySet()) {
            int i = num.intValue();
            System.out.println("TaintTree" + i);
            ShortCutTree tree = this.shortCutTrees.get(Integer.valueOf(i));
            tree.print();
        }
    }

    public void printMayTaint() {
        int i = 0;
        Iterator<FlowResult> it = this.mayFlowsResult.iterator();
        while (it.hasNext()) {
            FlowResult tf = it.next();
            System.out.println("MayTaintflow" + i + ":from TaintGraph:" + tf.getIndexofTree());
            int m = 0;
            Iterator<TaintValue> it2 = tf.getFlow().iterator();
            while (it2.hasNext()) {
                TaintValue tv = it2.next();
                int i2 = m;
                m++;
                System.out.print(i2 + ":");
                System.out.println(tv.toString());
            }
            i++;
        }
    }

    public ArrayList<List> createFlows() {
        ArrayList<List> taintFlow = new ArrayList<>();
        for (int indexTree = 0; indexTree < this.taintSet.allTFlows.size(); indexTree++) {
            this.sinkHasBeenFound = 0;
            this.mayHasBeenFound = 0;
            this.tree = this.taintSet.allTFlows.get(indexTree);
            this.indexofTree = indexTree;
            this.sinkIndexes = new HashMap<>();
            this.mayIndexes = new HashMap<>();
            ArrayList<Integer> sinkList = new ArrayList<>();
            HashSet<TaintValue> sinked = new HashSet<>();
            for (int index = 0; index < this.tree.Flow.size(); index++) {
                TaintValue node = this.tree.Flow.get(index);
                Iterator<TaintValue> it2 = this.Sinks.iterator();
                while (it2.hasNext()) {
                    TaintValue sink = it2.next();
                    if(!sinked.contains(sink)){
                        if(sink.gettMethod().equals(node.gettMethod())&&sink.gettClass().equals(node.gettClass())){
                            sinkList.add(index);
                            sinked.add(sink);
                        }
                    }
                }
            }
            if (!sinkList.isEmpty()) {
                List flows = findFlows(sinkList);
                taintFlow.add(flows);
            }
        }
        return taintFlow;
    }


    private List findFlows(ArrayList<Integer> sinkList) {
//        DijkstraShortestPath dijkstraShortestPath = new DijkstraShortestPath(this.tree.Pairs);
//        Iterator<Integer> iterator = sinkList.iterator();
//        ArrayList<List> pathes = new ArrayList<>();
//        ArrayList<List> tvPathes = new ArrayList<>();
//        while (iterator.hasNext()){
//            Integer next = iterator.next();
//            List<Integer> shortestPath = dijkstraShortestPath.getPath(0, next).getVertexList();
//            pathes.add(shortestPath);
//            ArrayList<TaintValue> taintValues = new ArrayList<>();
//            Iterator<Integer> iterator1 = shortestPath.iterator();
//            while (iterator1.hasNext()){
//                Integer next1 = iterator1.next();
//                taintValues.add(this.tree.Flow.get(next1));
//            }
//
//            tvPathes.add(taintValues);
//        }
        AllDirectedPaths allDirectedPaths = new AllDirectedPaths(this.tree.Pairs);
        Iterator<Integer> iterator = sinkList.iterator();
        ArrayList<List> tvPathes = new ArrayList<>();
        while (iterator.hasNext()){
            Integer next = iterator.next();
            List<GraphWalk> allPaths = allDirectedPaths.getAllPaths(0, next, true, 1000);
            Iterator iterator1 = allPaths.iterator();
            while (iterator1.hasNext()){
                GraphWalk next1 = (GraphWalk) iterator1.next();
                List vertexList = next1.getVertexList();
                ArrayList<TaintValue> taintValues = new ArrayList<>();
                Iterator<Integer> iterator2 = vertexList.iterator();
                while (iterator2.hasNext()){
                    Integer next2 = iterator2.next();
                    taintValues.add(this.tree.Flow.get(next2));
                }
                tvPathes.add(taintValues);

            }
        }
        return tvPathes;
    }

    public void checkFlows(ArrayList<List> taintResultFlows) {
        Iterator<List> iterator = taintResultFlows.iterator();
        while (iterator.hasNext()){
            List<List> next = iterator.next();
            Iterator<List> iterator1 = next.iterator();
            while (iterator1.hasNext()){
                List next1 = iterator1.next();
                int size = next1.size();
                TaintValue sink = (TaintValue) next1.get(size - 1);
                Iterator<TaintValue> iterator2 = this.Sinks.iterator();
                Boolean sinkAdded=false;
                TaintValue sinkTmp=null;
                while (iterator2.hasNext()){
                    TaintValue next2 = iterator2.next();
                    if(next2.equals(sink)){
                        sinkAdded=true;
                        break;
                    }
                    if(sink.gettMethod().equals(next2.gettMethod())&&sink.gettClass().equals(next2.gettClass())){
                        sinkTmp=next2;
                        break;
                    }
                }
                if(!sinkAdded){
                    next1.add(sinkTmp);
                }
            }
        }
//        System.out.println(taintResultFlows);

    }

}

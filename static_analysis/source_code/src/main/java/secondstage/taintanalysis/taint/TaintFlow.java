package secondstage.taintanalysis.taint;

import org.jgrapht.alg.shortestpath.BFSShortestPath;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleDirectedGraph;
import secondstage.taintanalysis.analyzer.ClassAnalyzer;
import secondstage.taintanalysis.analyzer.TaintAnalyzer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;


public class TaintFlow {
    public int taintFlowID;
    public static int MaxTaintValue = TaintAnalyzer.MaxTaintTreeLength;
    public ArrayList<TaintValue> Flow = new ArrayList<>();
    public SimpleDirectedGraph<Integer, DefaultEdge> Pairs = new SimpleDirectedGraph<>(DefaultEdge.class);

    public int hashCode() {
        int result = (31 * 1) + this.taintFlowID;
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        TaintFlow other = (TaintFlow) obj;
        if (this.taintFlowID != other.taintFlowID) {
            return false;
        }
        return true;
    }

    public TaintFlow(TaintValue tv, int ID) {
        this.taintFlowID = ID;
        this.Flow.add(tv);
        this.Pairs.addVertex(0);
    }

    public boolean equalsTo(TaintFlow TF) {
        boolean isEqual = true;
        if (this.Flow.size() != TF.Flow.size()) {
            return false;
        }
        int i = 0;
        while (true) {
            if (i >= this.Flow.size()) {
                break;
            } else if (this.Flow.get(i).posequals(TF.Flow.get(i))) {
                i++;
            } else {
                isEqual = false;
                break;
            }
        }
        return isEqual;
    }

    public boolean hasSameSource(TaintFlow TF) {
        if (this.Flow.get(0).equals(TF.Flow.get(0))) {
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void printAllTV() {
        int index = 0;
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            System.out.print(index + ":");
            System.out.println(tv.toString());
            index++;
        }
        printPairs();
    }

    void printPairs() {
        for (DefaultEdge edge : this.Pairs.edgeSet()) {
            System.out.println(this.Pairs.getEdgeSource(edge) + "-->" + this.Pairs.getEdgeTarget(edge));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean cleanTVConcernContext(TaintValue tvclean, Context context) {
        boolean clean = false;
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.equals(tvclean) && !tv.getContext().equals(context)) {
                tv.addCleanLocation(context);
                clean = true;
            }
        }
        return clean;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean cleanTV(TaintValue tvclean, Context context) {
        if (this.Flow.contains(tvclean) && this.Flow.get(this.Flow.indexOf(tvclean)).addCleanLocation(context)) {
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean cleanTV(TaintValue tvClean, TaintValue tvExist, Context context) {
        if (this.Flow.contains(tvClean) && !this.Flow.contains(tvExist) && this.Flow.get(this.Flow.indexOf(tvClean)).addCleanLocation(context)) {
            return true;
        }
        return false;
    }

    private boolean positionStab(TaintWay tw) {
        if (tw == TaintWay.Normal || tw == TaintWay.TaintWrapper || tw == TaintWay.Return || tw == TaintWay.Aug || tw == TaintWay.ClassFieldThis) {
            return true;
        }
        return false;
    }

    private boolean isRepalceble(TaintWay tw) {
        if (tw == TaintWay.Normal || tw == TaintWay.TaintWrapper || tw == TaintWay.Alias || tw == TaintWay.Aug || tw == TaintWay.AliasBefore || tw == TaintWay.ClassFieldThis) {
            return true;
        }
        return false;
    }

    boolean hasSameTV(TaintValue tv) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tvFlow = it.next();
            if (tvFlow.allequals(tv)) {
                return true;
            }
        }
        return false;
    }

    boolean addEdgewithTVEXContext(int tvIndex, TaintValue tvEX) {
        int indexEX = 0;
        boolean result = false;
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tvinFlow = it.next();
            if (tvinFlow.equals(tvEX)) {
                try {
                    this.Pairs.addEdge(Integer.valueOf(indexEX), Integer.valueOf(tvIndex));
                    result = true;
                } catch (Exception e) {
                    return false;
                }
            }
            indexEX++;
        }
        return result;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getIndexAllEqual(TaintValue tv) {
        int index = 0;
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tvinFlow = it.next();
            if (tvinFlow.allequals(tv)) {
                return index;
            }
            index++;
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean addTVConcernContext(TaintValue tv, TaintValue tvEX) {
        boolean returnV = false;
        if (hasSameTV(tv)) {
            int tvIndex = getIndexAllEqual(tv);
            for (int indexEx = 0; indexEx < this.Flow.size(); indexEx++) {
                TaintValue tvin = this.Flow.get(indexEx);
                if (tvin.equals(tvEX)) {
                    int MaxEdge = TaintAnalyzer.MaxEdgeCount;
                    if (!this.Pairs.containsEdge(Integer.valueOf(indexEx), Integer.valueOf(tvIndex)) && indexEx != tvIndex && !this.Pairs.containsEdge(Integer.valueOf(tvIndex), Integer.valueOf(indexEx)) && BFSShortestPath.findPathBetween(this.Pairs, Integer.valueOf(tvIndex), Integer.valueOf(indexEx)) == null && this.Pairs.degreeOf(Integer.valueOf(indexEx)) <= MaxEdge && this.Pairs.degreeOf(Integer.valueOf(tvIndex)) <= MaxEdge) {
                        this.Pairs.addEdge(Integer.valueOf(indexEx), Integer.valueOf(tvIndex));
                        returnV = true;
                    }
                }
            }
        } else if (this.Flow.size() < MaxTaintValue) {
            if (tv.getKind() == ValueKind.ThisRef) {
                Iterator<TaintValue> it = this.Flow.iterator();
                while (it.hasNext()) {
                    TaintValue tvinFlow = it.next();
                    if (tvinFlow.getKind() == ValueKind.ClassThis && tvinFlow.gettClass().equals(tv.gettClass()) && tvinFlow.gettMethod().equals(tv.gettMethod()) && tvinFlow.getName().substring(10).equals(tv.getName().substring(5))) {
                        return false;
                    }
                }
            }
            if (this.Flow.add(tv)) {
                int indexTv = getIndexAllEqual(tv);
                this.Pairs.addVertex(Integer.valueOf(indexTv));
                addEdgewithTVEXContext(indexTv, tvEX);
                returnV = true;
            } else {
                return false;
            }
        }
        return returnV;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean addTV(TaintValue tv, TaintValue tvEX) {
        boolean reNew = false;
        if (this.Flow.contains(tv)) {
            int indexEx = this.Flow.indexOf(tvEX);
            int indexTv = this.Flow.indexOf(tv);
            if (this.Pairs.containsEdge(Integer.valueOf(indexEx), Integer.valueOf(indexTv))) {
                TaintValue tVReal = this.Flow.get(indexTv);
                TaintValue tvEX2 = this.Flow.get(indexEx);
                if (tv.getSL() != null && isRepalceble(tVReal.getTW()) && isRepalceble(tv.getTW())) {
                    StmLocation tvRealLoc = tVReal.getSL();
                    StmLocation tvNowLoc = tv.getSL();
                    StmLocation tvEXLoc = tvEX2.getSL();
                    if (!tvRealLoc.equals(tvNowLoc) && positionStab(tv.getTW()) && tv.gettClass().equals(tvEX2.gettClass()) && tv.gettMethod().equals(tvEX2.gettMethod()) && tvNowLoc.getST() > tvEXLoc.getST() && (tvRealLoc.getST() < tvEXLoc.getST() || tvNowLoc.getST() - tvEXLoc.getST() < tvRealLoc.getST() - tvEXLoc.getST())) {
                        this.Flow.set(indexTv, tv);
                        reNew = true;
                    }
                }
            }
            if (ClassAnalyzer.pathSen) {
                if (this.Pairs.containsEdge(Integer.valueOf(indexEx), Integer.valueOf(indexTv))) {
                    return reNew;
                }
                this.Pairs.addEdge(Integer.valueOf(indexEx), Integer.valueOf(indexTv));
                return true;
            } else if (this.Pairs.containsEdge(Integer.valueOf(indexEx), Integer.valueOf(indexTv)) || this.Pairs.containsEdge(Integer.valueOf(indexTv), Integer.valueOf(indexEx)) || BFSShortestPath.findPathBetween(this.Pairs, Integer.valueOf(indexTv), Integer.valueOf(indexEx)) != null) {
                return reNew;
            } else {
                this.Pairs.addEdge(Integer.valueOf(indexEx), Integer.valueOf(indexTv));
                return true;
            }
        } else if (this.Flow.size() < MaxTaintValue && this.Flow.add(tv)) {
            this.Pairs.addVertex(Integer.valueOf(this.Flow.indexOf(tv)));
            this.Pairs.addEdge(Integer.valueOf(this.Flow.indexOf(tvEX)), Integer.valueOf(this.Flow.indexOf(tv)));
            return true;
        } else {
            return false;
        }
    }

    public ArrayList<TaintValue> getTVwithpre(TaintValue tv1) {
        ArrayList<TaintValue> vList = new ArrayList<>();
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv1.isPrefixOf(tv)) {
                vList.add(tv);
            }
        }
        return vList;
    }

    public ArrayList<TaintValue> getTVListClassField(TaintValue tv1) {
        ArrayList<TaintValue> vList = new ArrayList<>();
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.gettClass().equals(tv1.gettClass()) && tv.gettMethod().equals(tv1.gettMethod()) && tv.getTW() == TaintWay.ClassField) {
                vList.add(tv);
            }
        }
        return vList;
    }

    TaintValue getTVofThisRef(String SCName) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.getKind() == ValueKind.ThisRef && tv.gettClass().equals(SCName)) {
                return tv;
            }
        }
        return null;
    }

    public boolean hasContext(Context context) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.getContext().equals(context)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasTV(TaintValue tv1) {
        if (tv1.getKind() == null) {
            return false;
        }
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.equals(tv1)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasSameSourceOrSink(TaintValue tv1) {
        if (tv1.getKind() == null) {
            return false;
        }
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.allequals(tv1)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasTVClassField(TaintValue tv1) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.kindIsAcceptable() && tv.gettClass().equals(tv1.gettClass()) && tv.gettMethod().equals(tv1.gettMethod()) && tv.getTW() == TaintWay.ClassFieldThis) {
                return true;
            }
        }
        return false;
    }

    public boolean hasTVShorter(TaintValue tv1) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.kindIsAcceptable() && tv.gettClass().equals(tv1.gettClass()) && tv.gettMethod().equals(tv1.gettMethod()) && tv1.getName().startsWith(tv.getName()) && !tv.getName().equals(tv1.getName())) {
                return true;
            }
        }
        return false;
    }

    public TaintValue getTVShorter(TaintValue tv1) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.kindIsAcceptable() && tv.gettClass().equals(tv1.gettClass()) && tv.gettMethod().equals(tv1.gettMethod()) && tv1.getName().startsWith(tv.getName()) && !tv.getName().equals(tv1.getName())) {
                return tv;
            }
        }
        return null;
    }

    public boolean hasTVArray(TaintValue tv1) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.kindIsAcceptable() && tv.gettClass().equals(tv1.gettClass()) && tv.gettMethod().equals(tv1.gettMethod()) && tv1.getName().startsWith(tv.getName()) && tv.getType().contains("[") && !tv.getName().equals(tv1.getName())) {
                return true;
            }
        }
        return false;
    }

    public boolean hasTVwithPre(TaintValue tv1) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv1.isPrefixOf(tv)) {
                return true;
            }
        }
        return false;
    }

    public int getIndexofTVPre(TaintValue tv1) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv1.isPrefixOf(tv)) {
                return this.Flow.indexOf(tv);
            }
        }
        return -1;
    }

    public boolean hasLocalTV(TaintValue taintValue) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.gettClass().equals(taintValue.gettClass()) && tv.gettMethod().equals(taintValue.gettMethod()) && tv.getName().equals(taintValue.getName()) ) {
                return true;
            }
        }
        return false;
    }

    public boolean hasSameContextTv(TaintValue taintValue) {
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.gettClass().equals(taintValue.gettClass()) && tv.gettMethod().equals(taintValue.gettMethod()) && tv.getContext().toString().equals(taintValue.getContext().toString()) ) {
                return true;
            }
        }
        return false;
    }

    public Collection<? extends TaintValue> getSameContextTVwithpre(TaintValue taintValue) {
        ArrayList<TaintValue> vList = new ArrayList<>();
        Iterator<TaintValue> it = this.Flow.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            if (tv.gettClass().equals(taintValue.gettClass()) && tv.gettMethod().equals(taintValue.gettMethod()) && tv.getContext().toString().equals(taintValue.getContext().toString()) &&tv.getSL().equals(taintValue.getSL())) {
                vList.add(tv);
            }
        }
        return vList;
    }
}

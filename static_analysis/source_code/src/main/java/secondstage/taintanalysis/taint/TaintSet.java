package secondstage.taintanalysis.taint;

import soot.Value;

import java.util.ArrayList;
import java.util.Iterator;


public class TaintSet {
    public ArrayList<TaintFlow> allTFlows = new ArrayList<>();
    private boolean renew = false;

    public boolean isEmpty() {
        return this.allTFlows.isEmpty();
    }

    public int flowSize() {
        return this.allTFlows.size();
    }

    public void print() {
        int i = 0;
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow tf = it.next();
            System.out.println("TaintGraph " + i + ":");
            tf.printAllTV();
            i++;
        }
    }

    boolean addFlow(TaintFlow TF) {
        return this.allTFlows.add(TF);
    }

    boolean isNewFlow(TaintFlow TF) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow tf = it.next();
            if (tf.hasSameSource(TF)) {
                return false;
            }
        }
        return true;
    }

    public void createFlow(Value v, Context context, TaintWay TW) {
        TaintValue source = new TaintValue(v, context, TW);
        if (source.getKind() != null && !source.getName().equals("") && !hasSameSourceOrSink(source)) {
            TaintFlow newFlow = new TaintFlow(source, this.allTFlows.size() + 1);
            this.allTFlows.add(newFlow);
            this.renew = true;
        }
    }

    public boolean hasTV(TaintValue tv) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTV(tv)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasSameSourceOrSink(TaintValue tv) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasSameSourceOrSink(tv)) {
                return true;
            }
        }
        return false;
    }

    public ArrayList<TaintFlow> getFlowListOfTV(TaintValue tv) {
        ArrayList<TaintFlow> flowList = new ArrayList<>();
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTV(tv)) {
                flowList.add(TF);
            }
        }
        if (flowList.isEmpty()) {
            return null;
        }
        return flowList;
    }

    public ArrayList<TaintFlow> getFlowOfTVPre(TaintValue tv) {
        ArrayList<TaintFlow> flowList = new ArrayList<>();
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTVwithPre(tv)) {
                flowList.add(TF);
            }
        }
        if (flowList.isEmpty()) {
            return null;
        }
        return flowList;
    }

    public TaintFlow getFlowByID(int flowID) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.taintFlowID == flowID) {
                return TF;
            }
        }
        return null;
    }

    public ArrayList<Integer> flowIDOfTV(TaintValue tv) {
        ArrayList<Integer> IDList = new ArrayList<>();
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTV(tv)) {
                IDList.add(Integer.valueOf(TF.taintFlowID));
            }
        }
        return IDList;
    }

    public ArrayList<Integer> flowIDOfTVPre(TaintValue tv) {
        ArrayList<Integer> IDList = new ArrayList<>();
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTVwithPre(tv)) {
                IDList.add(Integer.valueOf(TF.taintFlowID));
            }
        }
        return IDList;
    }

    public boolean hasTVShorter(TaintValue tv) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTVShorter(tv)) {
                return true;
            }
        }
        return false;
    }

    public TaintValue getTVShorter(TaintValue tv) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            TaintValue tvReturn = TF.getTVShorter(tv);
            if (tvReturn != null) {
                return tvReturn;
            }
        }
        return null;
    }

    public boolean hasTVArray(TaintValue tv) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTVArray(tv)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasTVwithPre(TaintValue tv) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasTVwithPre(tv)) {
                return true;
            }
        }
        return false;
    }

    public TaintValue getTVArrayLocal(TaintValue tv) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            Iterator<TaintValue> it2 = TF.Flow.iterator();
            while (it2.hasNext()) {
                TaintValue tv1 = it2.next();
                if (tv.gettClass().equals(tv1.gettClass()) && tv.gettMethod().equals(tv1.gettMethod()) && tv.getName().startsWith(tv1.getName()) && tv1.getType().contains("[") && !tv.getName().equals(tv1.getName())) {
                    return tv1;
                }
            }
        }
        return null;
    }

    public ArrayList<TaintValue> getTVListwithpre(TaintValue tv) {
        ArrayList<TaintValue> TVList = new ArrayList<>();
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            TVList.addAll(TF.getTVwithpre(tv));
        }
        return TVList;
    }

    public boolean reNew() {
        if (this.renew) {
            this.renew = false;
            return true;
        }
        return false;
    }

    public int getTaintFlowCount() {
        return this.allTFlows.size();
    }

    public boolean insertTV(TaintValue tv, TaintValue tvEx) {
        if (tv.getKind() == null || !hasTV(tvEx) || tv.equals(tvEx)) {
            return false;
        }
        boolean insertSuccess = false;
        int size = this.allTFlows.size();
        for (int i = 0; i < size; i++) {
            TaintFlow TFi = this.allTFlows.get(i);
            if (TFi.hasTV(tvEx) && this.allTFlows.get(i).addTV(tv, tvEx)) {
                this.renew = true;
                insertSuccess = true;
            }
        }
        return insertSuccess;
    }

    public boolean insertTVConcerningContext(TaintValue tv, TaintValue tvEx) {
        if (tv.getKind() == null || !hasTV(tvEx) || tv.allequals(tvEx)) {
            return false;
        }
        boolean insertSuccess = false;
        int size = this.allTFlows.size();
        for (int i = 0; i < size; i++) {
            TaintFlow TFi = this.allTFlows.get(i);
            if (TFi.hasTV(tvEx) && this.allTFlows.get(i).addTVConcernContext(tv, tvEx)) {
                this.renew = true;
                insertSuccess = true;
            }
        }
        return insertSuccess;
    }

    public boolean cleanTVConcernContext(TaintValue tvClean, Context context) {
        boolean cleaned = false;
        if (tvClean.getKind() == null) {
            return false;
        }
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow flow = it.next();
            if (flow.hasTV(tvClean) && flow.cleanTVConcernContext(tvClean, context)) {
                cleaned = true;
            }
        }
        return cleaned;
    }

    public boolean cleanTV(TaintValue tvClean, TaintValue tvExist, Context context) {
        boolean cleaned = false;
        if (tvClean.getKind() == null || tvExist.getKind() == null) {
            return false;
        }
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow flow = it.next();
            if (flow.cleanTV(tvClean, tvExist, context)) {
                cleaned = true;
            }
        }
        return cleaned;
    }

    public boolean cleanTV(TaintValue tvClean, Context context) {
        boolean cleaned = false;
        if (tvClean.getKind() == null || !hasTV(tvClean)) {
            return false;
        }
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow flow = it.next();
            if (flow.hasTV(tvClean) && flow.cleanTV(tvClean, context)) {
                cleaned = true;
            }
        }
        return cleaned;
    }

    public boolean hasLocalTV(TaintValue taintValue) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasLocalTV(taintValue)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasSameContext(TaintValue tvThis) {
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            if (TF.hasSameContextTv(tvThis)) {
                return true;
            }
        }
        return false;
    }

    public ArrayList<TaintValue> getSameContextTVListwithpre(TaintValue tvThis) {
        ArrayList<TaintValue> TVList = new ArrayList<>();
        Iterator<TaintFlow> it = this.allTFlows.iterator();
        while (it.hasNext()) {
            TaintFlow TF = it.next();
            TVList.addAll(TF.getSameContextTVwithpre(tvThis));
        }
        return TVList;
    }
}

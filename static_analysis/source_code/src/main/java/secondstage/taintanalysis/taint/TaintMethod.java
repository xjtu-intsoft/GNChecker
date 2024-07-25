package secondstage.taintanalysis.taint;

import soot.SootClass;
import soot.SootMethod;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;


public class TaintMethod {
    public SootClass SClass;
    public SootMethod SMethod;
    public String mClass;
    public String mName;
    public int argnum;
    public String returnType;
    public ArrayList<ParameterTainted> allParaTainted = new ArrayList<>();
    public HashSet<TaintValue> returnTainted = new HashSet<>();

    public TaintMethod(SootClass sc, SootMethod sm) {
        this.SClass = sc;
        this.SMethod = sm;
        this.mClass = sc.getName();
        this.mName = sm.getName();
        this.argnum = sm.getParameterCount();
        this.returnType = sm.getReturnType().toString();
    }

    public boolean isReturnTainted() {
        return !this.returnTainted.isEmpty();
    }

    public boolean addReturnTV(ArrayList<TaintValue> tvReturn) {
        if (this.returnTainted.addAll(tvReturn)) {
            return true;
        }
        return false;
    }

    public HashSet<TaintValue> getReturnTV() {
        if (isReturnTainted()) {
            return this.returnTainted;
        }
        return null;
    }

    public ArrayList<Integer> getParaFlowIDSet(int paraIndex) {
        ArrayList<Integer> flowSet = new ArrayList<>();
        if (isParaIndexTaint(paraIndex)) {
            return getParaTaint(paraIndex).getFlowIDSet();
        }
        return flowSet;
    }

    public boolean addParameterTainted(int paraIndex, ArrayList<Integer> flowIndex, ArrayList<String> suffix, Context context) {
        if (!isParaIndexTaint(paraIndex)) {
            ParameterTainted paraTainted = new ParameterTainted(paraIndex);
            paraTainted.addTaintInvoke(flowIndex, suffix, context);
            return this.allParaTainted.add(paraTainted);
        } else if (getParaTaint(paraIndex).addTaintInvoke(flowIndex, suffix, context)) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isParaIndexTaint(int paraindex) {
        if (!this.allParaTainted.isEmpty()) {
            Iterator<ParameterTainted> it = this.allParaTainted.iterator();
            while (it.hasNext()) {
                ParameterTainted parameter = it.next();
                if (parameter.getParaIndex() == paraindex) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    public ParameterTainted getParaTaint(int paraindex) {
        Iterator<ParameterTainted> it = this.allParaTainted.iterator();
        while (it.hasNext()) {
            ParameterTainted parameter = it.next();
            if (parameter.getParaIndex() == paraindex) {
                return parameter;
            }
        }
        return null;
    }

    public int hashCode() {
        int result = (31 * 1) + this.argnum;
        return (31 * ((31 * ((31 * result) + (this.mClass == null ? 0 : this.mClass.hashCode()))) + (this.mName == null ? 0 : this.mName.hashCode()))) + (this.returnType == null ? 0 : this.returnType.hashCode());
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        TaintMethod other = (TaintMethod) obj;
        if (this.argnum != other.argnum) {
            return false;
        }
        if (this.mClass == null) {
            if (other.mClass != null) {
                return false;
            }
        } else if (!this.mClass.equals(other.mClass)) {
            return false;
        }
        if (this.mName == null) {
            if (other.mName != null) {
                return false;
            }
        } else if (!this.mName.equals(other.mName)) {
            return false;
        }
        if (this.returnType == null) {
            if (other.returnType != null) {
                return false;
            }
            return true;
        } else if (!this.returnType.equals(other.returnType)) {
            return false;
        } else {
            return true;
        }
    }
}

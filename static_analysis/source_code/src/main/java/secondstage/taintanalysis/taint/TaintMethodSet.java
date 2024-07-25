package secondstage.taintanalysis.taint;

import soot.SootClass;
import soot.SootMethod;

import java.util.HashSet;
import java.util.Iterator;


public class TaintMethodSet {
    public boolean renew = false;
    public HashSet<TaintMethod> tMethods = new HashSet<>();

    public boolean reNew() {
        if (this.renew) {
            this.renew = false;
            return true;
        }
        return false;
    }

    public boolean addTaintMethod(SootClass sc, SootMethod sm) {
        TaintMethod tMethToAdd = new TaintMethod(sc, sm);
        return this.tMethods.add(tMethToAdd);
    }

    public TaintMethod getTaintMeth(SootClass sc, SootMethod sm) {
        TaintMethod tmethTemp = new TaintMethod(sc, sm);
        Iterator<TaintMethod> it = this.tMethods.iterator();
        while (it.hasNext()) {
            TaintMethod taintMeth = it.next();
            if (taintMeth.equals(tmethTemp)) {
                return taintMeth;
            }
        }
        return null;
    }

    public boolean hasMethod(SootClass sc, SootMethod sm) {
        TaintMethod tmethTemp = new TaintMethod(sc, sm);
        Iterator<TaintMethod> it = this.tMethods.iterator();
        while (it.hasNext()) {
            TaintMethod taintMeth = it.next();
            if (taintMeth.equals(tmethTemp)) {
                return true;
            }
        }
        return false;
    }
}

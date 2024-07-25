package secondstage.taintanalysis.analyzer;

import soot.Local;
import soot.Value;
import soot.jimple.InstanceFieldRef;
import soot.jimple.internal.JInstanceFieldRef;


public class accessPath {
    private String accessName;
    private String fieldName;

    public accessPath(JInstanceFieldRef IF) {
        this.accessName = "";
        this.fieldName = IF.getField().getName();
        Value vi = IF.getBase();
        this.accessName = formAccessName(vi) + this.fieldName;
    }

    private String formAccessName(Value vBase) {
        if (vBase instanceof InstanceFieldRef) {
            InstanceFieldRef lv = (InstanceFieldRef) vBase;
            return formAccessName(lv.getBase()) + lv.getField().getName() + ".";
        } else if (vBase instanceof Local) {
            return ((Local) vBase).getName() + ".";
        } else {
            return "";
        }
    }

    public String getName() {
        if (this.accessName == "") {
            return this.fieldName;
        }
        return this.accessName;
    }
}

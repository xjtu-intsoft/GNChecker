package secondstage.taintanalysis.taint;

import soot.Local;
import soot.SootClass;
import soot.SootMethod;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.StaticFieldRef;
import soot.jimple.ThisRef;
import soot.jimple.internal.JInstanceFieldRef;
import secondstage.taintanalysis.analyzer.accessPath;

import java.util.HashSet;


public class TaintValue {
    private ValueKind kind;
    private String name;
    private String type;
    private String tClass;
    private String tMethodSig;
    private Context context;
    private StmLocation SL;
    private TaintWay TW;
    private HashSet<StmLocation> cleanLocations = new HashSet<>();

    public HashSet<StmLocation> getCleanLocations() {
        return this.cleanLocations;
    }

    public boolean hasCleaned() {
        if (this.cleanLocations == null || this.cleanLocations.isEmpty()) {
            return false;
        }
        return true;
    }

    public boolean addCleanLocation(Context context) {
        if (this.cleanLocations == null) {
            this.cleanLocations = new HashSet<>();
        }
        if (this.cleanLocations.add(context.getLocation())) {
            return true;
        }
        return false;
    }

    public ValueKind getKind() {
        return this.kind;
    }

    public String getName() {
        return this.name;
    }

    public String getType() {
        return this.type;
    }

    public String gettClass() {
        return this.tClass;
    }

    public String gettMethod() {
        return this.tMethodSig;
    }

    public StmLocation getSL() {
        return this.SL;
    }

    public void setSL(StmLocation SL) {
        this.SL = SL;
    }

    public TaintWay getTW() {
        return this.TW;
    }

    public Context getContext() {
        return this.context;
    }

    public void setTW(TaintWay tW) {
        this.TW = tW;
    }

    public TaintValue(ValueKind kind1, String name1, String type1, SootClass sClass, SootMethod sMethod, Context context, TaintWay TW) {
        this.kind = kind1;
        this.name = name1;
        this.type = type1;
        this.tClass = sClass.getName();
        this.tMethodSig = sMethod.getSubSignature();
        this.SL = context.getLocation();
        this.TW = TW;
        this.context = context;
    }

    public TaintValue(ValueKind kind1, String name1, String type1, Context context, TaintWay TW) {
        this.kind = kind1;
        this.name = name1;
        this.type = type1;
        this.tClass = context.getsClass().getName();
        this.tMethodSig = context.getsMethod().getSubSignature();
        this.SL = context.getLocation();
        this.TW = TW;
        this.context = context;
    }

    public TaintValue(Value v, String suffix, String type, Context context, TaintWay TW) {
        if (v instanceof ThisRef) {
            this.kind = ValueKind.ThisRef;
            this.name = "this" + suffix;
            this.type = type;
            this.tClass = context.getsClass().getName();
            this.tMethodSig = context.getsMethod().getSubSignature();
            this.SL = context.getLocation();
            this.TW = TW;
            this.context = context;
        } else if (v instanceof JInstanceFieldRef) {
            JInstanceFieldRef Jl = (JInstanceFieldRef) v;
            accessPath ap = new accessPath(Jl);
            this.kind = ValueKind.InstanceField;
            this.name = ap.getName() + suffix;
            this.type = type;
            this.tClass = context.getsClass().getName();
            this.tMethodSig = context.getsMethod().getSubSignature();
            this.SL = context.getLocation();
            this.TW = TW;
            this.context = context;
        } else if (v instanceof StaticFieldRef) {
            StaticFieldRef sv = (StaticFieldRef) v;
            this.kind = ValueKind.StaticField;
            this.tClass = sv.getField().getDeclaringClass().getName();
            this.name = this.tClass + "." + sv.getField().getName() + suffix;
            this.type = type;
            this.tMethodSig = context.getsMethod().getSubSignature();
            this.SL = context.getLocation();
            this.TW = TW;
            this.context = context;
        } else if (v instanceof Local) {
            Local lv = (Local) v;
            if (suffix.equals("")) {
                this.kind = ValueKind.Local;
            } else {
                this.kind = ValueKind.InstanceField;
            }
            this.name = lv.getName() + suffix;
            this.type = type;
            this.tClass = context.getsClass().getName();
            this.tMethodSig = context.getsMethod().getSubSignature();
            this.SL = context.getLocation();
            this.TW = TW;
            this.context = context;
        } else {
            this.kind = null;
            this.name = null;
            this.type = null;
            this.tClass = null;
            this.tMethodSig = null;
            this.SL = null;
            this.TW = null;
            this.context = null;
        }
    }

    public TaintValue(Value v, Context context, TaintWay TW) {
        if (v instanceof JInstanceFieldRef) {
            JInstanceFieldRef JI = (JInstanceFieldRef) v;
            accessPath ap = new accessPath(JI);
            this.kind = ValueKind.InstanceField;
            this.name = ap.getName();
            this.type = v.getType().toString();
            this.tClass = context.getsClass().getName();
            this.tMethodSig = context.getsMethod().getSubSignature();
            this.SL = context.getLocation();
            this.TW = TW;
            this.context = context;
        } else if (v instanceof StaticFieldRef) {
            StaticFieldRef sv = (StaticFieldRef) v;
            this.kind = ValueKind.StaticField;
            this.tClass = sv.getField().getDeclaringClass().getName();
            this.name = this.tClass + "." + sv.getField().getName();
            this.type = sv.getType().toString();
            this.tMethodSig = "";
            this.SL = context.getLocation();
            this.TW = TW;
            this.context = context;
        } else if (v instanceof Local) {
            Local lv = (Local) v;
            this.kind = ValueKind.Local;
            this.name = lv.getName();
            this.type = lv.getType().toString();
            this.tClass = context.getsClass().getName();
            this.tMethodSig = context.getsMethod().getSubSignature();
            this.SL = context.getLocation();
            this.TW = TW;
            this.context = context;
        } else if (v instanceof ArrayRef) {
            ArrayRef av = (ArrayRef) v;
            Value BaseV = av.getBase();
            if (BaseV instanceof Local) {
                this.kind = ValueKind.Local;
                this.name = ((Local) BaseV).getName() + "[" + av.getIndex() + "]";
                this.type = av.getType().toString();
                this.tClass = context.getsClass().getName();
                this.tMethodSig = context.getsMethod().getSubSignature();
                this.SL = context.getLocation();
                this.TW = TW;
                this.context = context;
            }
        } else {
            this.kind = null;
            this.name = null;
            this.type = null;
            this.tClass = null;
            this.tMethodSig = null;
            this.SL = null;
            this.TW = null;
            this.context = null;
        }
    }

    public boolean kindIsAcceptable() {
        if (this.kind == null) {
            return false;
        }
        if (this.kind == ValueKind.InstanceField || this.kind == ValueKind.StaticField || this.kind == ValueKind.ClassThis || this.kind == ValueKind.Local || this.kind == ValueKind.Param || this.kind == ValueKind.Return || this.kind == ValueKind.ThisRef) {
            return true;
        }
        return false;
    }

    public String suffixOf(TaintValue tv) {
        int len = tv.name.length();
        String suffix = this.name.substring(len);
        return suffix;
    }

    public boolean isPrefixOf(TaintValue tv) {
        if (this.kind == null) {
            return false;
        }
        if (tv.getTW() == TaintWay.ClassField) {
            if (this.tClass.equals(tv.tClass) && tv.name.startsWith(this.name) && !tv.getName().equals(getName())) {
                return true;
            }
            return false;
        } else if (tv.getKind() == ValueKind.StaticField) {
            if (this.tClass.equals(tv.tClass) && tv.name.startsWith(this.name) && !tv.getName().equals(getName())) {
                return true;
            }
            return false;
        } else if (tv.kindIsAcceptable() && this.tClass.equals(tv.tClass) && this.tMethodSig.equals(tv.tMethodSig) && tv.name.startsWith(this.name) && !tv.getName().equals(getName())) {
            return true;
        } else {
            return false;
        }
    }

    public boolean locationEquals(TaintValue TV) {
        if (this.SL.equals(TV.SL)) {
            return true;
        }
        return false;
    }

    public boolean allequals(TaintValue TV) {
        if (this.context.equals(TV.getContext()) && equals(TV)) {
            return true;
        }
        return false;
    }

    public boolean posequals(Object obj) {
        if (obj != null && (obj instanceof TaintValue)) {
            TaintValue TV = (TaintValue) obj;
            if (TV.SL.equals(this.SL)) {
                return true;
            }
            return false;
        }
        return false;
    }

    public int hashCode() {
        int result = (31 * 1) + (this.kind == null ? 0 : this.kind.hashCode());
        return (31 * ((31 * ((31 * ((31 * result) + (this.name == null ? 0 : this.name.hashCode()))) + (this.tClass == null ? 0 : this.tClass.hashCode()))) + (this.tMethodSig == null ? 0 : this.tMethodSig.hashCode()))) + (this.type == null ? 0 : this.type.hashCode());
    }

    public boolean equals(Object obj) {
        if (obj != null && (obj instanceof TaintValue)) {
            TaintValue TV = (TaintValue) obj;
            if (TV.kind.equals(this.kind) && TV.name.equals(this.name) && TV.tClass.equals(this.tClass) && TV.tMethodSig.equals(this.tMethodSig)) {
                return true;
            }
            if (TV.getKind() == ValueKind.StaticField && TV.kind.equals(this.kind) && TV.name.equals(this.name) && TV.tClass.equals(this.tClass) && TV.type.equals(this.type)) {
                return true;
            }
            return false;
        }
        return false;
    }

    public String toString() {
        return "TV [" + this.kind + "," + this.name + "," + this.type + "," + this.tClass + "," + this.tMethodSig + ", SL=" + this.SL + ", TW=" + this.TW + "]";
    }

    public String toFileString() {
        return "TV [" + this.kind + "," + this.name + "," + this.type + "," + this.tClass + "," + this.tMethodSig + ", SL=" + this.SL + ", TW=" + this.TW + "]";
    }

}

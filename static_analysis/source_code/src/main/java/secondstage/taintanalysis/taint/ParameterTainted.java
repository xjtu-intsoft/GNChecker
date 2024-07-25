package secondstage.taintanalysis.taint;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;


public class ParameterTainted {
    private int paraIndex;
    private HashSet<InvokePointInfo> allInvokePointInfo = new HashSet<>();

    /* loaded from: fastdroid.jar:xd/fastdroid/taint/ParameterTainted$InvokePointInfo.class */
    protected class InvokePointInfo {
        private HashSet<Integer> flowID;
        private HashSet<String> suffix;
        private Context context;

        public InvokePointInfo(HashSet<Integer> flowIndexs, HashSet<String> suffix, Context context) {
            this.context = context;
            this.flowID = flowIndexs;
            this.suffix = suffix;
        }

        public HashSet<Integer> getFlowID() {
            return this.flowID;
        }

        public HashSet<String> getSuffix() {
            return this.suffix;
        }

        public Context getContext() {
            return this.context;
        }

        public void setContext(Context context) {
            this.context = context;
        }

        public int hashCode() {
            int result = (31 * 1) + getOuterType().hashCode();
            return (31 * result) + (this.context == null ? 0 : this.context.hashCode());
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            InvokePointInfo other = (InvokePointInfo) obj;
            if (!getOuterType().equals(other.getOuterType())) {
                return false;
            }
            if (this.context == null) {
                if (other.context != null) {
                    return false;
                }
                return true;
            } else if (!this.context.equals(other.context)) {
                return false;
            } else {
                return true;
            }
        }

        private ParameterTainted getOuterType() {
            return ParameterTainted.this;
        }
    }

    public int getParaIndex() {
        return this.paraIndex;
    }

    public HashSet<InvokePointInfo> getInvokePointInfo() {
        return this.allInvokePointInfo;
    }

    public ParameterTainted(int paraIndex) {
        this.paraIndex = paraIndex;
    }

    public ArrayList<Integer> getFlowIDSet() {
        ArrayList<Integer> flowSet = new ArrayList<>();
        Iterator<InvokePointInfo> it = this.allInvokePointInfo.iterator();
        while (it.hasNext()) {
            InvokePointInfo point = it.next();
            flowSet.addAll(point.getFlowID());
        }
        return flowSet;
    }

    public boolean addTaintInvoke(ArrayList<Integer> flowIndex, ArrayList<String> suffix, Context context) {
        HashSet<Integer> flowId = new HashSet<>();
        HashSet<String> suff = new HashSet<>();
        flowId.addAll(flowIndex);
        suff.addAll(suffix);
        InvokePointInfo point = new InvokePointInfo(flowId, suff, context);
        if (this.allInvokePointInfo.contains(point)) {
            Iterator<InvokePointInfo> it = this.allInvokePointInfo.iterator();
            while (it.hasNext()) {
                InvokePointInfo InvP = it.next();
                if (InvP.equals(point)) {
                    if (InvP.flowID.addAll(flowIndex) && InvP.suffix.addAll(suffix)) {
                        return true;
                    }
                    return false;
                }
            }
            return false;
        } else if (this.allInvokePointInfo.add(point)) {
            return true;
        } else {
            return false;
        }
    }
}

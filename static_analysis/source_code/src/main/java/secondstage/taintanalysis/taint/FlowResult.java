package secondstage.taintanalysis.taint;

import java.util.ArrayList;


public class FlowResult {
    public TaintFlow tTree;
    public int indexofTree;
    public ArrayList<Integer> indexesOfTv;
    public ArrayList<TaintValue> Flow;

    public FlowResult(TaintFlow tTree, int indexofTree, ArrayList<TaintValue> flow, ArrayList<Integer> indexofTV) {
        this.tTree = tTree;
        this.indexofTree = indexofTree;
        this.Flow = flow;
        this.indexesOfTv = indexofTV;
    }

    public TaintFlow gettTree() {
        return this.tTree;
    }

    public int getIndexofTree() {
        return this.indexofTree;
    }

    public ArrayList<TaintValue> getFlow() {
        return this.Flow;
    }

    public ArrayList<Integer> getIndexofTV() {
        return this.indexesOfTv;
    }
}

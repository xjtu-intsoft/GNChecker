package secondstage.taintanalysis.analyzer;

import secondstage.taintanalysis.taint.*;
import secondstage.taintanalysis.taint.Context;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.tagkit.JimpleLineNumberTag;
import soot.util.Chain;
import secondstage.taintanalysis.taint.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


public class ClassAnalyzer {
    public ArrayList<SootClass> classList = new ArrayList<>();
    public ArrayList<SootMethod> methodList=new ArrayList<>();
    public TaintSet taintSet;
    public TaintMethodSet taintMethodset;
    public static boolean taintMethodRecord = false;
    public static int RoundAnalyse = 0;
    public static boolean fastMode = false;
    public static boolean pathSen = false;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClassAnalyzer(TaintSet TaintSet) {
        this.taintSet = TaintSet;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void add(SootClass classInfo) {
        this.classList.add(classInfo);
    }
    public void addMethod(SootMethod sootMethod) {
        this.methodList.add(sootMethod);
    }

    void print() {
        Iterator<SootClass> it = this.classList.iterator();
        while (it.hasNext()) {
            SootClass SC1 = it.next();
            System.out.println("----" + SC1.getName());
            for (SootMethod SM : SC1.getMethods()) {
                System.out.println("----" + SM.getSubSignature());
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean have(SootClass classInfo) {
        Iterator<SootClass> it = this.classList.iterator();
        while (it.hasNext()) {
            SootClass SC = it.next();
            if (SC.getName().equals(classInfo.getName())) {
                return true;
            }
        }
        return false;
    }

    protected void analyzeSink(InvokeExpr rv, secondstage.taintanalysis.taint.Context context) {
        SootMethod sMethodr = rv.getMethod();
        if (TaintAnalyzer.sinkSourceBuilder.matchSink(sMethodr)) {
            List<ValueBox> listVB = rv.getUseBoxes();
            for (ValueBox vb : listVB) {
                Value v = vb.getValue();
                boolean newtv = true;
                TaintValue tvTO = new TaintValue(v, context, TaintWay.Sink);
                if (tvTO.getKind() != null) {
                    Iterator<TaintValue> it = TaintAnalyzer.SinkS.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        TaintValue tv = it.next();
                        if (tv.locationEquals(tvTO) && tvTO.equals(tv)) {
                            newtv = false;
                            break;
                        }
                    }
                    if (newtv && !tvTO.getName().equals("")) {
                        TaintAnalyzer.SinkS.add(tvTO);
                    }
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void searchSourceAndSink() {
        TaintAnalyzer.ClassNum = 0;
        TaintAnalyzer.MethodNum = 0;
        TaintAnalyzer.StateMNum = 0;
        Iterator<SootClass> it = this.classList.iterator();
        while (it.hasNext()) {
            SootClass SC1 = it.next();
            TaintAnalyzer.ClassNum++;
            List<SootMethod> methodList = SC1.getMethods();
            for (int i = 0; i < methodList.size(); i++) {
                SootMethod SM = methodList.get(i);
                TaintAnalyzer.MethodNum++;
                try {
                    Body b = SM.retrieveActiveBody();
                    PatchingChain<Unit> units = b.getUnits();
                    int stateNumOfSm = 0;
                    Iterator<Unit> iter = units.snapshotIterator();
                    while (iter.hasNext()) {
                        Unit u = iter.next();
                        TaintAnalyzer.StateMNum++;
                        stateNumOfSm++;
                        JimpleLineNumberTag NTag = new JimpleLineNumberTag(stateNumOfSm);
                        u.addTag(NTag);
                        StmLocation SL = new StmLocation(SC1.getName(), SM.getSubSignature(), stateNumOfSm, u);
                        secondstage.taintanalysis.taint.Context context = new secondstage.taintanalysis.taint.Context(SC1, SM, SL);
                        if (u instanceof AssignStmt) {
                            AssignStmt stmt = (AssignStmt) u;
                            Value l = stmt.getLeftOp();
                            Value r = stmt.getRightOp();
                            if (r instanceof InvokeExpr ) {
                                InvokeExpr rv = (InvokeExpr) r;
                                SootMethod sootMethodr = rv.getMethod();
                                if (TaintAnalyzer.sinkSourceBuilder.matchSource(sootMethodr)) {
                                    this.taintSet.createFlow(l, context, TaintWay.Source);
                                    if (this.taintSet.getTaintFlowCount() >= TaintAnalyzer.MaxTaintTreeCount) {
                                        return;
                                    }
                                }
                                analyzeSink(rv, context);
                            } else {
                                continue;
                            }
                        } else if (u instanceof InvokeStmt) {
                            InvokeExpr invokeExpr = ((InvokeStmt) u).getInvokeExpr();
                            analyzeSink(invokeExpr, context);
                        }
                    }
                    continue;
                }catch (Exception e){
                    continue;
                }
            }
        }
    }

    public void taintAnalysis(int limitRound) {
        RoundAnalyse = 0;
        while (limitRound > 0) {
            RoundAnalyse++;
            taintAnalysisOneTime();
            limitRound--;
            if (!this.taintSet.reNew()) {
                return;
            }
        }
    }
    public void taintAnalysisBaseMethod(int limitRound) {
        RoundAnalyse = 0;
        while (limitRound > 0) {
            RoundAnalyse++;
            taintAnalysisOneTimeBaseMethod();
            limitRound--;
            if (!this.taintSet.reNew()) {
                return;
            }
        }
    }
    public void taintAnalysisOneTimeBaseMethod() {
        Iterator<SootMethod> it = this.methodList.iterator();
        while (it.hasNext()) {
            SootMethod SM = it.next();
            SootClass SC1 = SM.getDeclaringClass();
            if (SM.hasActiveBody()) {
                Body b = SM.getActiveBody();
                PatchingChain<Unit> units = b.getUnits();
                Iterator<Unit> iter = units.snapshotIterator();
                while (iter.hasNext()) {
                    Unit u = iter.next();
                    JimpleLineNumberTag NTag = (JimpleLineNumberTag) u.getTag("JimpleLineNumberTag");
                    int lineTag = NTag == null ? -1 : NTag.getLineNumber();
                    if (lineTag != -1) {
                        StmLocation sLoc = new StmLocation(SC1.getName(), SM.getSubSignature(), lineTag, u);
                        secondstage.taintanalysis.taint.Context context = new secondstage.taintanalysis.taint.Context(SC1, SM, sLoc);
                        analyzeStat(u, context);
                    }
                }
            }
        }
    }
    public void taintAnalysisOneTime() {
        Iterator<SootClass> it = this.classList.iterator();
        while (it.hasNext()) {
            SootClass SC1 = it.next();
            List<SootMethod> methodList = SC1.getMethods();
            for (int i = 0; i < methodList.size(); i++) {
                SootMethod SM = methodList.get(i);
                if (SM.hasActiveBody()) {
                    Body b = SM.getActiveBody();
                    PatchingChain<Unit> units = b.getUnits();
                    Iterator<Unit> iter = units.snapshotIterator();
                    while (iter.hasNext()) {
                        Unit u = iter.next();
                        JimpleLineNumberTag NTag = (JimpleLineNumberTag) u.getTag("JimpleLineNumberTag");
                        int lineTag = NTag == null ? -1 : NTag.getLineNumber();
                        if (lineTag != -1) {
                            StmLocation sLoc = new StmLocation(SC1.getName(), SM.getSubSignature(), lineTag, u);
                            secondstage.taintanalysis.taint.Context context = new secondstage.taintanalysis.taint.Context(SC1, SM, sLoc);
                            analyzeStat(u, context);
                        }
                    }
                }
            }
        }
    }

    protected void analyzeStat(Unit u, secondstage.taintanalysis.taint.Context context) {
        TaintMethod taintMeth;
        SootMethod subClass;
        if (u instanceof IfStmt) {
            JIfStmt stmt = (JIfStmt) u;
            for (ValueBox vb : stmt.getCondition().getUseBoxes()) {
                Value v = vb.getValue();
                if ((v instanceof Local) || (v instanceof JInstanceFieldRef) || (v instanceof StaticFieldRef)) {
                    analyseMayTaint(v, context);
                }
            }
        } else if (u instanceof SwitchStmt) {
            SwitchStmt stmt2 = (SwitchStmt) u;
            Value v2 = stmt2.getKey();
            if ((v2 instanceof Local) || (v2 instanceof JInstanceFieldRef) || (v2 instanceof StaticFieldRef)) {
                analyseMayTaint(v2, context);
            }
        } else if (u instanceof IdentityStmt) {
            IdentityStmt stmt3 = (IdentityStmt) u;
            Value l = stmt3.getLeftOp();
            Value r = stmt3.getRightOp();
            if (r instanceof ThisRef) {
                if (l instanceof Local) {
                    Local lv = (Local) l;
                    TaintValue tvOflv = new TaintValue(lv, context, TaintWay.Normal);
                    if (tvOflv.getKind() != null && this.taintSet.hasTVwithPre(tvOflv)) {
                        taintAnalyseWithSuffix(r, tvOflv, context, TaintWay.ThisIdentity);
                    }
                    TaintValue tvClassFieldThis = new TaintValue(ValueKind.ClassThis, "ClassThis", "", context, TaintWay.ClassFieldThis);
                    if (this.taintSet.hasTVwithPre(tvClassFieldThis)) {
                        ArrayList<TaintValue> TVClassField = this.taintSet.getTVListwithpre(tvClassFieldThis);
                        Iterator<TaintValue> it = TVClassField.iterator();
                        while (it.hasNext()) {
                            TaintValue TVC = it.next();
                            String suffix = TVC.suffixOf(tvClassFieldThis);
                            if (!suffix.isEmpty()) {
                                TaintValue tvField = new TaintValue(lv, suffix, TVC.getType(), context, TaintWay.Identity);
                                if (fastMode) {
                                    this.taintSet.insertTV(tvField, TVC);
                                } else {
                                    this.taintSet.insertTVConcerningContext(tvField, TVC);
                                }
                            }
                        }
                    }
                }
            } else if (r instanceof ParameterRef) {
                analyzeParaIdent(l, (ParameterRef) r, context);
            }
        } else if (u instanceof AssignStmt) {
            AssignStmt stmt4 = (AssignStmt) u;
            Value l2 = stmt4.getLeftOp();
            Value r2 = stmt4.getRightOp();
            if (r2 instanceof Constant) {
                cleanAnalyse(l2, context);
            }
            else if ((r2 instanceof NewExpr) || (r2 instanceof JNewArrayExpr)) {
                cleanAnalyse(l2, context);
            }
            else if (r2 instanceof ThisRef) {
                if (l2 instanceof Local) {
                    Local lv2 = (Local) l2;
                    TaintValue tvOflv2 = new TaintValue(lv2, context, TaintWay.Normal);
                    if (tvOflv2.getKind() != null && this.taintSet.hasTVwithPre(tvOflv2)) {
                        taintAnalyseWithSuffix(r2, tvOflv2, context, TaintWay.AliasBefore);
                    }
                    TaintValue tvClassFieldThis2 = new TaintValue(ValueKind.ClassThis, "ClassThis", "", context, TaintWay.ClassFieldThis);
                    if (this.taintSet.hasTVwithPre(tvClassFieldThis2)) {
                        ArrayList<TaintValue> TVClassField2 = this.taintSet.getTVListwithpre(tvClassFieldThis2);
                        Iterator<TaintValue> it2 = TVClassField2.iterator();
                        while (it2.hasNext()) {
                            TaintValue TVC2 = it2.next();
                            String suffix2 = TVC2.suffixOf(tvClassFieldThis2);
                            if (!suffix2.isEmpty()) {
                                TaintValue tvField2 = new TaintValue(lv2, suffix2, TVC2.getType(), context, TaintWay.Identity);
                                if (fastMode) {
                                    this.taintSet.insertTV(tvField2, TVC2);
                                } else {
                                    this.taintSet.insertTVConcerningContext(tvField2, TVC2);
                                }
                            }
                        }
                    }
                }
            }
            else if (r2 instanceof CastExpr) {
                Value CastV = ((CastExpr) r2).getOp();
                if (isHeap(l2)) {
                    taintAnalyse(l2, CastV, context, TaintWay.AliasBefore);
                    taintAnalyse(CastV, l2, context, TaintWay.Alias);
                    return;
                }
                cleanAnalyse(l2, context);
                taintAnalyse(CastV, l2, context, TaintWay.Normal);
            }
            else if (r2 instanceof InvokeExpr) {
                InvokeExpr rv = (InvokeExpr) r2;
                SootMethod SMethod = rv.getMethodRef().resolve();
                SootClass SClass = SMethod.getDeclaringClass();
                if (r2 instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr rvIns = (InstanceInvokeExpr) r2;
                    Value baseV = rvIns.getBase();
                    if (!SMethod.hasActiveBody() && (baseV.getType() instanceof RefType) && (subClass = getSubMethod(SMethod)) != null) {
                        SMethod = subClass;
                    }
                    if (TaintAnalyzer.taintWraperBuilder.hasMethod(SClass, SMethod)) {
                        TaintWay tw = TaintWay.TaintWrapper;
                        if (SMethod.getName().equals(SootMethod.constructorName)) {
                            tw = TaintWay.Identity;
                        }
                        taintAnalyse(baseV, l2, context, tw);
                    } else {
                        analyzeInvokeClassField(context, rv, baseV);
                    }
                    List<Value> Args = rv.getArgs();
                    if(Args.size()==0){
                        analyzeNewLocalTaint(l2,baseV,context);
                    }
                }
                List<Value> Args = rv.getArgs();
                int indexPara = -1;
                boolean isTRapper = false;
                if (TaintAnalyzer.taintWraperBuilder.hasMethod(SClass, SMethod)) {
                    isTRapper = true;
                }
                for (Value arg : Args) {
                    indexPara++;
                    if (isTRapper) {
                        TaintWay tw2 = TaintWay.TaintWrapper;
                        if (SMethod.getName().equals(SootMethod.constructorName)) {
                            tw2 = TaintWay.Identity;
                        }
                        taintAnalyse(arg, l2, context, tw2);
                    }
                    analyzeNewLocalTaint(l2,arg,context);
                    analzeTaintMethodPara(arg, SMethod, indexPara, context, rv);
                }
                analyseReturnTaint(l2, context, SMethod);
                TaintValue tvClean = new TaintValue(l2, context, TaintWay.Normal);
                if ((this.taintSet.hasTV(tvClean) || this.taintSet.hasTVwithPre(tvClean)) && !SMethod.getName().equals("append")) {
                    cleanAnalyse(l2, context);
                }
            }
            else if (isHeap(r2)) {
                taintAnalyse(l2, r2, context, TaintWay.AliasBefore);
                taintAnalyse(r2, l2, context, TaintWay.Alias);
            } else {
                cleanAnalyse(l2, context);
                taintAnalyse(r2, l2, context, TaintWay.Normal);
            }
        } else if (u instanceof InvokeStmt) {
            InvokeStmt stmt5 = (InvokeStmt) u;
            InvokeExpr invokeExpr = stmt5.getInvokeExpr();
            SootClass SClass2 = invokeExpr.getMethod().getDeclaringClass();
            SootMethod SMethod2 = invokeExpr.getMethod();
            List<Value> Args2 = invokeExpr.getArgs();
            if (invokeExpr instanceof InstanceInvokeExpr) {
                Value baseV2 = ((InstanceInvokeExpr) invokeExpr).getBase();
                if (baseV2 instanceof Local) {
                    if (AndroidSpecialMethodAnalyze(baseV2, Args2, invokeExpr, SClass2, SMethod2, context)) {
                        return;
                    }
                    if (TaintAnalyzer.taintWraperBuilder.hasMethod(SClass2, SMethod2)) {
                        for (Value arg2 : Args2) {
                            TaintWay tw3 = TaintWay.TaintWrapper;
                            if (SMethod2.getName().equals(SootMethod.constructorName)) {
                                tw3 = TaintWay.Identity;
                            }
                            taintAnalyse(arg2, baseV2, context, tw3);
                            taintAnalyse(baseV2, arg2, context, tw3);
                        }
                        return;
                    }
                    analyzeInvokeClassField(context, invokeExpr, baseV2);
                }
            }
            if (SMethod2.getName().equals("arraycopy") && Args2.size() == 5) {
                taintAnalyse(Args2.get(0), Args2.get(2), context, TaintWay.TaintWrapper);
                return;
            }
            int indexPara2 = -1;
            for (Value arg3 : Args2) {
                indexPara2++;
                analzeTaintMethodPara(arg3, SMethod2, indexPara2, context, invokeExpr);
            }
            try {
                JVirtualInvokeExpr u1 = (JVirtualInvokeExpr) ((InvokeStmt) u).getInvokeExpr();
                Value base = u1.getBase();
                for (Value arg3 : Args2) {
                    analyzeNewLocalTaint(base,arg3,context);
                }
            }catch (Exception e){

            }
        } else if (u instanceof ReturnStmt) {
            ReturnStmt stmt6 = (ReturnStmt) u;
            Value Vreturn = stmt6.getOp();
            TaintValue tvEx = new TaintValue(Vreturn, context, TaintWay.Normal);
            if (this.taintSet.hasTV(tvEx)) {
                TaintValue tvTo = new TaintValue(ValueKind.Return, "Return:" + context.getsMethod().getSubSignature(), context.getsMethod().getReturnType().toString(), context, TaintWay.Return);
                if (fastMode) {
                    this.taintSet.insertTV(tvTo, tvEx);
                } else {
                    this.taintSet.insertTVConcerningContext(tvTo, tvEx);
                }
                if (taintMethodRecord) {
                    if (this.taintMethodset.hasMethod(context.getsClass(), context.getsMethod())) {
                        taintMeth = this.taintMethodset.getTaintMeth(context.getsClass(), context.getsMethod());
                    } else {
                        taintMeth = new TaintMethod(context.getsClass(), context.getsMethod());
                        this.taintMethodset.tMethods.add(taintMeth);
                    }
                    ArrayList<TaintValue> tvList = new ArrayList<>();
                    tvList.add(tvEx);
                    taintMeth.addReturnTV(tvList);
                }
            } else if (this.taintSet.hasTVwithPre(tvEx)) {
                ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvEx);
                ArrayList<String> suff = new ArrayList<>();
                Iterator<TaintValue> it3 = TVListSuffix.iterator();
                while (it3.hasNext()) {
                    TaintValue TVsuff = it3.next();
                    String suffix3 = TVsuff.suffixOf(tvEx);
                    suff.add(suffix3);
                    if (!suffix3.isEmpty()) {
                        TaintValue tvReturn = new TaintValue(ValueKind.Return, "Return:" + context.getsMethod().getSubSignature() + suffix3, TVsuff.getType().toString(), context, TaintWay.Return);
                        if (fastMode) {
                            this.taintSet.insertTV(tvReturn, TVsuff);
                        } else {
                            this.taintSet.insertTVConcerningContext(tvReturn, TVsuff);
                        }
                    }
                }
            }
        }
    }

    private void analyzeNewLocalTaint(Value l2, Value arg, secondstage.taintanalysis.taint.Context context) {
        if(l2 instanceof  Local){
            Local l21 = (Local) l2;
            if(arg instanceof Local){
                Local arg1 = (Local) arg;
                TaintValue taintValue = new TaintValue(ValueKind.Local, arg1.getName(), arg1.getType().toString(), context, TaintWay.ReturnBack);
                if(this.taintSet.hasLocalTV(taintValue)){
                    TaintValue taintValue1 = new TaintValue(ValueKind.Local, l21.getName(), l21.getType().toString(), context, TaintWay.Alias);
                    this.taintSet.insertTV(taintValue1,taintValue);
                }
            }
        }
    }

    private void analyzeInvokeClassField(secondstage.taintanalysis.taint.Context context, InvokeExpr invokeExpr, Value baseV) {
        SootMethod SMImple;
        SootMethod SMInvoke = invokeExpr.getMethodRef().resolve();
        SootClass SCInvoke = invokeExpr.getMethodRef().declaringClass();
        TaintValue tvThis = new TaintValue(ValueKind.ThisRef, "this", "", SCInvoke, SMInvoke, context, TaintWay.ThisIdentity);
        if (!SMInvoke.hasActiveBody() && (invokeExpr instanceof InterfaceInvokeExpr) && (SMImple = getImplementMethod(SMInvoke)) != null) {
            tvThis = new TaintValue(ValueKind.ThisRef, "this", "", SMImple.getDeclaringClass(), SMImple, context, TaintWay.ThisIdentity);
        }
        if (this.taintSet.hasTVwithPre(tvThis)) {
            ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvThis);
            Iterator<TaintValue> it = TVListSuffix.iterator();
            while (it.hasNext()) {
                TaintValue TVsuff = it.next();
                String suffix = TVsuff.suffixOf(tvThis);
                if (!suffix.isEmpty()) {
                    TaintValue tvClassField = new TaintValue(ValueKind.InstanceField, baseV.toString() + suffix, TVsuff.getType().toString(), context, TaintWay.ClassField);
                    if (fastMode) {
                        this.taintSet.insertTV(tvClassField, TVsuff);
                    } else {
                        this.taintSet.insertTVConcerningContext(tvClassField, TVsuff);
                    }
                }
            }
        }
        if(this.taintSet.hasSameContext(tvThis)){
            ArrayList<TaintValue> TVListSuffix = this.taintSet.getSameContextTVListwithpre(tvThis);
            Iterator<TaintValue> it = TVListSuffix.iterator();
            while (it.hasNext()) {
                TaintValue TVsuff = it.next();
                String suffix = TVsuff.suffixOf(tvThis);
                if (!suffix.isEmpty()) {
                    TaintValue tvClassField = new TaintValue(ValueKind.InstanceField, baseV.toString() + suffix, TVsuff.getType().toString(), context, TaintWay.ClassField);
                    this.taintSet.insertTV(tvClassField, TVsuff);
                }
            }
        }
        TaintValue tvTaintClassField = new TaintValue(ValueKind.InstanceField, baseV.toString(), "", context, TaintWay.ClassField);
        if (this.taintSet.hasTVwithPre(tvTaintClassField)) {
            ArrayList<TaintValue> TVListSuffix2 = this.taintSet.getTVListwithpre(tvTaintClassField);
            Iterator<TaintValue> it2 = TVListSuffix2.iterator();
            while (it2.hasNext()) {
                TaintValue TVsuff2 = it2.next();
                String suffix2 = TVsuff2.suffixOf(tvTaintClassField);
                if (!suffix2.isEmpty()) {
                    TaintValue tvClassFieldthis = new TaintValue(ValueKind.ClassThis, "ClassThis" + suffix2, TVsuff2.getType(), SCInvoke, SMInvoke, context, TaintWay.ClassFieldThis);
                    if (SCInvoke.getName().contains("Thread") && SMInvoke.getName().equals("start") && SCInvoke.getMethodByName("run") != null) {
                        tvClassFieldthis = new TaintValue(ValueKind.ClassThis, "ClassThis" + suffix2, TVsuff2.getType(), SCInvoke, SCInvoke.getMethodByName("run"), context, TaintWay.ClassFieldThis);
                    }
                    if (fastMode) {
                        this.taintSet.insertTV(tvClassFieldthis, TVsuff2);
                    } else {
                        this.taintSet.insertTVConcerningContext(tvClassFieldthis, TVsuff2);
                    }
                }
            }
        }
    }

    private SootMethod getSubMethod(SootMethod SM) {
        SootClass SCSuper = SM.getDeclaringClass();
        if (this.classList.contains(SCSuper)) {
            Iterator<SootClass> it = this.classList.iterator();
            while (it.hasNext()) {
                SootClass SC = it.next();
                if (!SC.hasSuperclass()) {
                    return null;
                }
                SootClass SCS = SC.getSuperclass();
                if (SCSuper.getName().equals(SCS.getName())) {
                    for (SootMethod SM1 : SC.getMethods()) {
                        if (SM1.hasActiveBody() && !SM1.isAbstract() && SM1.getName().equals(SM.getName())) {
                            return SM1;
                        }
                    }
                    continue;
                }
            }
            return null;
        }
        return null;
    }

    private SootMethod getImplementMethod(SootMethod SM) {
        SootClass SCInterface = SM.getDeclaringClass();
        Iterator<SootClass> it = this.classList.iterator();
        while (it.hasNext()) {
            SootClass SC = it.next();
            Chain<SootClass> chainSC = SC.getInterfaces();
            for (SootClass SC1 : chainSC) {
                if (SC1.getName().equals(SCInterface.getName())) {
                    try {
                        SootMethod SM1 = SC.getMethodByName(SM.getName());
                        if (SM1 != null && SM1.hasActiveBody() && !SM1.isAbstract()) {
                            return SM1;
                        }
                    } catch (Exception e) {
                        return null;
                    }
                }
            }
        }
        return null;
    }

    private void analzeTaintMethodPara(Value arg, SootMethod SMethod, int indexPara, secondstage.taintanalysis.taint.Context context, InvokeExpr invokeExpr) {
        if (!SMethod.hasActiveBody() && (invokeExpr instanceof InterfaceInvokeExpr)) {
            SootMethod SMImple = getImplementMethod(SMethod);
            if (SMImple != null) {
                analzeTaintMethodPara(arg, SMImple, indexPara, context, invokeExpr);
            }
        } else if (SMethod.hasActiveBody()) {
            TaintValue tvOfarg = new TaintValue(arg, context, TaintWay.Normal);
            SootClass scInvoke = SMethod.getDeclaringClass();
            if (tvOfarg.getKind() == null) {
                return;
            }
            TaintValue tvParam = new TaintValue(ValueKind.Param, "@parameter" + indexPara, arg.getType().toString(), scInvoke, SMethod, context, TaintWay.ParamReturn);
            if (this.taintSet.hasTVwithPre(tvParam)) {
                ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvParam);
                Iterator<TaintValue> it = TVListSuffix.iterator();
                while (it.hasNext()) {
                    TaintValue TVsuff = it.next();
                    String suffix = TVsuff.suffixOf(tvParam);
                    if (!suffix.isEmpty() && TVsuff.getTW() == TaintWay.ParamReturn) {
                        TaintValue tvArg = new TaintValue(arg, suffix, TVsuff.getType(), context, TaintWay.Aug);
                        if (fastMode) {
                            this.taintSet.insertTV(tvArg, TVsuff);
                        } else {
                            this.taintSet.insertTVConcerningContext(tvArg, TVsuff);
                        }
                    }
                }
            }
            if (this.taintSet.hasTV(tvOfarg)) {
                TaintValue tvPara = new TaintValue(ValueKind.Param, "@parameter" + indexPara, tvOfarg.getType().toString(), scInvoke, SMethod, context, TaintWay.Param);
                if (fastMode) {
                    this.taintSet.insertTV(tvPara, tvOfarg);
                } else {
                    this.taintSet.insertTVConcerningContext(tvPara, tvOfarg);
                }
            } else if (this.taintSet.hasTVwithPre(tvOfarg)) {
                ArrayList<TaintValue> TVListSuffix2 = this.taintSet.getTVListwithpre(tvOfarg);
                ArrayList<String> suff = new ArrayList<>();
                Iterator<TaintValue> it2 = TVListSuffix2.iterator();
                while (it2.hasNext()) {
                    TaintValue TVsuff2 = it2.next();
                    String suffix2 = TVsuff2.suffixOf(tvOfarg);
                    suff.add(suffix2);
                    if (!suffix2.isEmpty()) {
                        TaintValue tvPara2 = new TaintValue(ValueKind.Param, "@parameter" + indexPara + suffix2, TVsuff2.getType().toString(), scInvoke, SMethod, context, TaintWay.Param);
                        if (fastMode) {
                            this.taintSet.insertTV(tvPara2, TVsuff2);
                        } else {
                            this.taintSet.insertTVConcerningContext(tvPara2, TVsuff2);
                        }
                    }
                }
            }
        }
    }

    protected boolean analyseReturnTaint(Value valueToTaint, secondstage.taintanalysis.taint.Context context, SootMethod SMethod) {
        SootClass sClass = SMethod.getDeclaringClass();
        secondstage.taintanalysis.taint.Context contextReturn = new secondstage.taintanalysis.taint.Context(sClass, SMethod, null);
        TaintValue tvReturn = new TaintValue(ValueKind.Return, "Return:" + SMethod.getSubSignature(), SMethod.getReturnType().toString(), contextReturn, TaintWay.Return);
        TaintValue tvTO = new TaintValue(valueToTaint, context, TaintWay.ReturnBack);
        if (tvTO.getKind() != null && this.taintSet.hasTV(tvReturn)) {
            if (fastMode) {
                this.taintSet.insertTV(tvTO, tvReturn);
                return true;
            }
            this.taintSet.insertTVConcerningContext(tvTO, tvReturn);
            return true;
        } else if (this.taintSet.hasTVwithPre(tvReturn)) {
            ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvReturn);
            ArrayList<String> suff = new ArrayList<>();
            Iterator<TaintValue> it = TVListSuffix.iterator();
            while (it.hasNext()) {
                TaintValue TVsuff = it.next();
                String suffix = TVsuff.suffixOf(tvReturn);
                suff.add(suffix);
                if (!suffix.isEmpty()) {
                    TaintValue tvNew = new TaintValue(valueToTaint, suffix, TVsuff.getType(), context, TaintWay.ReturnBack);
                    if (fastMode) {
                        this.taintSet.insertTV(tvNew, TVsuff);
                    } else {
                        this.taintSet.insertTVConcerningContext(tvNew, TVsuff);
                    }
                }
            }
            return true;
        } else {
            return false;
        }
    }

    protected void cleanAnalyse(Value v, secondstage.taintanalysis.taint.Context context) {
        TaintValue tvClean = new TaintValue(v, context, TaintWay.Normal);
        if (tvClean.getKind() != null) {
            if (this.taintSet.hasTV(tvClean)) {
                this.taintSet.cleanTVConcernContext(tvClean, context);
            } else if (this.taintSet.hasTVwithPre(tvClean)) {
                ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvClean);
                Iterator<TaintValue> it = TVListSuffix.iterator();
                while (it.hasNext()) {
                    TaintValue TVsuff = it.next();
                    String suffix = TVsuff.suffixOf(tvClean);
                    if (!suffix.isEmpty()) {
                        TaintValue tvNewClean = new TaintValue(v, suffix, TVsuff.getType(), context, TaintWay.Normal);
                        this.taintSet.cleanTVConcernContext(tvNewClean, context);
                    }
                }
            }
        }
    }

    protected void taintAnalyse(Value Source, TaintValue Target, secondstage.taintanalysis.taint.Context context) {
        TaintValue tvEX = new TaintValue(Source, context, TaintWay.Normal);
        Source.getType().toString();
        if (tvEX.getKind() != null) {
            if (this.taintSet.hasTV(tvEX)) {
                if (fastMode) {
                    this.taintSet.insertTV(Target, tvEX);
                } else {
                    this.taintSet.insertTVConcerningContext(Target, tvEX);
                }
            } else if (this.taintSet.hasTVwithPre(tvEX)) {
                ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvEX);
                Iterator<TaintValue> it = TVListSuffix.iterator();
                while (it.hasNext()) {
                    TaintValue TVsuff = it.next();
                    String suffix = TVsuff.suffixOf(tvEX);
                    if (!suffix.isEmpty()) {
                        if (fastMode) {
                            this.taintSet.insertTV(Target, TVsuff);
                        } else {
                            this.taintSet.insertTVConcerningContext(Target, TVsuff);
                        }
                    }
                }
            }
        }
    }

    protected void taintAnalyse(Value Source, Value Target, secondstage.taintanalysis.taint.Context context, TaintWay taintway) {
        TaintValue tvEX = new TaintValue(Source, context, TaintWay.Normal);
        if (tvEX.getKind() != null) {
            if (this.taintSet.hasTVShorter(tvEX)) {
                TaintValue tvShorter = this.taintSet.getTVShorter(tvEX);
                TaintValue tvTO = new TaintValue(Target, context, taintway);
                if (tvTO.getKind() != null) {
                    if (fastMode) {
                        this.taintSet.insertTV(tvTO, tvShorter);
                    } else {
                        this.taintSet.insertTVConcerningContext(tvTO, tvShorter);
                    }
                }
            }
            if (this.taintSet.hasTV(tvEX)) {
                TaintValue tvTO2 = new TaintValue(Target, context, taintway);
                if (tvTO2.getKind() != null) {
                    if (fastMode) {
                        this.taintSet.insertTV(tvTO2, tvEX);
                    } else {
                        this.taintSet.insertTVConcerningContext(tvTO2, tvEX);
                    }
                }
            } else if (this.taintSet.hasTVwithPre(tvEX)) {
                taintAnalyseWithSuffix(Target, tvEX, context, taintway);
            } else if ((Source instanceof ArrayRef) && this.taintSet.hasTVArray(tvEX)) {
                TaintValue tvTO3 = new TaintValue(Target, context, taintway);
                TaintValue tvArray = this.taintSet.getTVArrayLocal(tvEX);
                if (fastMode) {
                    this.taintSet.insertTV(tvTO3, tvArray);
                } else {
                    this.taintSet.insertTVConcerningContext(tvTO3, tvArray);
                }
            }
        }
    }

    protected void analyzeParaIdent(Value l, ParameterRef v, secondstage.taintanalysis.taint.Context context) {
        if (l instanceof Local) {
            TaintValue tvPara = new TaintValue(ValueKind.Param, "@parameter" + v.getIndex(), v.getType().toString(), context, TaintWay.Param);
            if (this.taintSet.hasTV(tvPara)) {
                TaintValue tvleft = new TaintValue(l, context, TaintWay.ParamIdentity);
                if (fastMode) {
                    this.taintSet.insertTV(tvleft, tvPara);
                } else {
                    this.taintSet.insertTVConcerningContext(tvleft, tvPara);
                }
            } else if (this.taintSet.hasTVwithPre(tvPara)) {
                ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvPara);
                Iterator<TaintValue> it = TVListSuffix.iterator();
                while (it.hasNext()) {
                    TaintValue TVsuff = it.next();
                    String suffix = TVsuff.suffixOf(tvPara);
                    if (!suffix.isEmpty()) {
                        TaintValue tvleft2 = new TaintValue(l, suffix, TVsuff.getType(), context, TaintWay.ParamIdentity);
                        if (fastMode) {
                            this.taintSet.insertTV(tvleft2, TVsuff);
                        } else {
                            this.taintSet.insertTVConcerningContext(tvleft2, TVsuff);
                        }
                    }
                }
            }
            if (isHeap(l)) {
                TaintValue tvleft3 = new TaintValue(l, context, TaintWay.Normal);
                Iterator<TaintFlow> it2 = this.taintSet.allTFlows.iterator();
                while (it2.hasNext()) {
                    TaintFlow flow = it2.next();
                    if (flow.hasTVwithPre(tvleft3) && !flow.hasTV(tvPara) && !flow.hasTVwithPre(tvPara)) {
                        ArrayList<TaintValue> TVListSuffix2 = flow.getTVwithpre(tvleft3);
                        Iterator<TaintValue> it3 = TVListSuffix2.iterator();
                        while (it3.hasNext()) {
                            TaintValue TVsuff2 = it3.next();
                            String suffix2 = TVsuff2.suffixOf(tvleft3);
                            if (!suffix2.isEmpty()) {
                                TaintValue tvParaReturn = new TaintValue(ValueKind.Param, "@parameter" + v.getIndex() + suffix2, TVsuff2.getType().toString(), context, TaintWay.ParamReturn);
                                if (fastMode) {
                                    this.taintSet.insertTV(tvParaReturn, TVsuff2);
                                } else {
                                    this.taintSet.insertTVConcerningContext(tvParaReturn, TVsuff2);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    protected void analyseMayTaint(Value v, secondstage.taintanalysis.taint.Context context) {
        TaintValue tv = new TaintValue(v, context, TaintWay.May);
        if (tv.getKind() != null && this.taintSet.hasTV(tv) && !TaintAnalyzer.May.contains(tv)) {
            TaintAnalyzer.May.add(tv);
        }
    }

    protected void taintAnalyseWithSuffix(Value v, TaintValue tvPrefix, secondstage.taintanalysis.taint.Context context, TaintWay taintWay) {
        ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvPrefix);
        Iterator<TaintValue> it = TVListSuffix.iterator();
        while (it.hasNext()) {
            TaintValue TVsuff = it.next();
            String suffix = TVsuff.suffixOf(tvPrefix);
            if (!suffix.isEmpty()) {
                if (suffix.contains("[") && taintWay == TaintWay.TaintWrapper) {
                    suffix = "";
                }
                TaintValue tvTo = new TaintValue(v, suffix, TVsuff.getType(), context, taintWay);
                if (fastMode) {
                    this.taintSet.insertTV(tvTo, TVsuff);
                } else {
                    this.taintSet.insertTVConcerningContext(tvTo, TVsuff);
                }
            }
        }
    }

    private boolean isHeap(Value v) {
        if (!(v.getType() instanceof PrimType) && !v.getType().toString().equals("java.lang.String")) {
            return true;
        }
        return false;
    }

    private boolean AndroidSpecialMethodAnalyze(Value baseV, List<Value> Args, InvokeExpr invokeExpr, SootClass SClass, SootMethod SMethod, Context context) {
        if ((invokeExpr instanceof InstanceInvokeExpr) && SMethod.getName().contains("execute")) {
            if (invokeExpr instanceof InstanceInvokeExpr) {
                if (SMethod.getDeclaringClass().getName().contains("ExecutorService")) {
                    for (Value arg : Args) {
                        TaintValue tvArg = new TaintValue(arg, context, TaintWay.Normal);
                        if (this.taintSet.hasTVwithPre(tvArg)) {
                            ArrayList<TaintValue> TVListSuffix = this.taintSet.getTVListwithpre(tvArg);
                            Iterator<TaintValue> it = TVListSuffix.iterator();
                            while (it.hasNext()) {
                                TaintValue TVsuff = it.next();
                                String suffix = TVsuff.suffixOf(tvArg);
                                Type argType = arg.getType();
                                if (!suffix.isEmpty() && (argType instanceof RefType)) {
                                    RefType refTypeArg = (RefType) argType;
                                    SootClass sClassRun = refTypeArg.getSootClass();
                                    SootMethod sMethod2 = sClassRun.getMethodByName("run");
                                    TaintValue tvthis = new TaintValue(ValueKind.ClassThis, "ClassThis" + suffix, TVsuff.getType(), sClassRun, sMethod2, context, TaintWay.ClassFieldThis);
                                    if (fastMode) {
                                        this.taintSet.insertTV(tvthis, TVsuff);
                                    } else {
                                        this.taintSet.insertTVConcerningContext(tvthis, TVsuff);
                                    }
                                }
                            }
                        }
                    }
                    return false;
                } else if (SMethod.getDeclaringClass().getName().equals("android.os.AsyncTask")) {
                    InstanceInvokeExpr expr = (InstanceInvokeExpr) invokeExpr;
                    Type basetype = expr.getBase().getType();
                    if (basetype instanceof RefType) {
                        RefType baseRef = (RefType) basetype;
                        SootClass base = baseRef.getSootClass();
                        for (SootMethod sm : base.getMethods()) {
                            if (sm.getName().equals("doInBackground") || sm.getName().equals("handleMessage")) {
                                int indexPara = 0;
                                for (Value arg2 : Args) {
                                    TaintValue tvParam = new TaintValue(ValueKind.Param, "@parameter" + indexPara, arg2.getType().toString(), base, sm, context, TaintWay.Param);
                                    indexPara++;
                                    taintAnalyse(arg2, tvParam, context);
                                }
                            }
                        }
                        return false;
                    }
                    return false;
                } else {
                    return false;
                }
            }
            return false;
        } else if (SClass.getName().equals("android.widget.Button") && SMethod.getName().equals("setHint")) {
            for (Value arg3 : Args) {
                if (arg3 instanceof Local) {
                    taintAnalyse(arg3, baseV, context, TaintWay.Identity);
                }
            }
            return false;
        } else if (SMethod.getName().contains("getChars")) {
            for (Value arg4 : Args) {
                if (arg4 instanceof Local) {
                    taintAnalyse(baseV, arg4, context, TaintWay.TaintWrapper);
                }
            }
            return true;
        } else {
            return false;
        }
    }

    public void clear() {
        this.classList=new ArrayList<>();
        this.taintSet=new TaintSet();
    }
}

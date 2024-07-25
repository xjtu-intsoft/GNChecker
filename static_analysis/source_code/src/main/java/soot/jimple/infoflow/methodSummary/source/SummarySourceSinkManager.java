package soot.jimple.infoflow.methodSummary.source;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import heros.solver.IDESolver;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.UnitPatchingChain;
import soot.Value;
import soot.jimple.DefinitionStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.ParameterRef;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.Stmt;
import soot.jimple.ThisRef;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.methodSummary.data.factory.SourceSinkFactory;
import soot.jimple.infoflow.methodSummary.data.sourceSink.FlowSource;
import soot.jimple.infoflow.sourcesSinks.manager.IReversibleSourceSinkManager;
import soot.jimple.infoflow.sourcesSinks.manager.SinkInfo;
import soot.jimple.infoflow.sourcesSinks.manager.SourceInfo;

/**
 * SourceSinkManager for computing library summaries
 * 
 * @author Malte Viering
 * @author Steven Arzt
 */
public class SummarySourceSinkManager implements IReversibleSourceSinkManager {

	protected final LoadingCache<SootClass, Collection<SootField>> classToFields = IDESolver.DEFAULT_CACHE_BUILDER
			.build(new CacheLoader<SootClass, Collection<SootField>>() {
				@Override
				public Collection<SootField> load(SootClass sc) throws Exception {
					List<SootField> res = new LinkedList<SootField>();
					List<SootClass> impler = Scene.v().getActiveHierarchy()
							.getSuperclassesOfIncluding(method.getDeclaringClass());
					for (SootClass c : impler)
						res.addAll(c.getFields());
					return res;
				}
			});

	private boolean debug = false;

	private final Logger logger = LoggerFactory.getLogger(SummarySourceSinkManager.class);
	private final String methodSig;
	private final String parentClass;
	private final SourceSinkFactory sourceSinkFactory;

	private SootMethod method = null;

	/**
	 * Creates a new instance of the {@link SummarySourceSinkManager} class
	 * 
	 * @param mSig              The signature of the method for which summaries
	 *                          shall be created
	 * @param parentClass       The parent class containing the method for which
	 *                          summaries shall be created. If mSig is the signature
	 *                          of a method inherited from a base class, this
	 *                          parameter receives the class on which the method
	 *                          denoted by mSig is called.
	 * @param sourceSinkFactory The {@link SourceSinkFactory} to create source and
	 *                          sink data objects
	 */
	public SummarySourceSinkManager(String mSig, String parentClass, SourceSinkFactory sourceSinkFactory) {
		this.methodSig = mSig;
		this.parentClass = parentClass;
		this.sourceSinkFactory = sourceSinkFactory;
	}

	/**
	 * Creates a new instance of the {@link SummarySourceSinkManager} class
	 * 
	 * @param method            The method for which summaries shall be created
	 * @param sourceSinkFactory The {@link SourceSinkFactory} to create source and
	 *                          sink data objects
	 */
	public SummarySourceSinkManager(SootMethod method, SourceSinkFactory sourceSinkFactory) {
		this.method = method;
		this.methodSig = null;
		this.parentClass = null;
		this.sourceSinkFactory = sourceSinkFactory;
	}

	@Override
	public SourceInfo getSourceInfo(Stmt sCallSite, InfoflowManager manager) {
		// If this is not the method we are looking for, we skip it
		SootMethod currentMethod = manager.getICFG().getMethodOf(sCallSite);
		if (!isMethodToSummarize(currentMethod))
			return null;

		if (sCallSite instanceof DefinitionStmt) {
			DefinitionStmt jstmt = (DefinitionStmt) sCallSite;
			Value leftOp = jstmt.getLeftOp();
			Value rightOp = jstmt.getRightOp();

			// check if we have a source with apl = 0 (this or parameter source)
			if (rightOp instanceof ParameterRef) {
				ParameterRef pref = (ParameterRef) rightOp;
				logger.debug("source: " + sCallSite + " " + currentMethod.getSignature());
				if (debug)
					System.out.println("source: " + sCallSite + " " + currentMethod.getSignature());
				return new SourceInfo(null, manager.getAccessPathFactory().createAccessPath(leftOp, true),
						Collections.singletonList(
								sourceSinkFactory.createParameterSource(pref.getIndex(), pref.getType().toString())));
			} else if (rightOp instanceof ThisRef) {
				ThisRef tref = (ThisRef) rightOp;
				if (debug)
					System.out.println("source: (this)" + sCallSite + " " + currentMethod.getSignature());
				return new SourceInfo(null, manager.getAccessPathFactory().createAccessPath(leftOp, true),
						Collections.singletonList(sourceSinkFactory.createThisSource(tref.getType().toString())));
			}
		}
		return null;
	}

	public SinkInfo getInverseSourceInfo(Stmt sCallSite, InfoflowManager manager, AccessPath ap) {
		// If this is not the method we are looking for, we skip it
		SootMethod currentMethod = manager.getICFG().getMethodOf(sCallSite);
		if (!isMethodToSummarize(currentMethod))
			return null;
		if (ap != null)
			return null;

		if (sCallSite instanceof IdentityStmt) {
			IdentityStmt jstmt = (IdentityStmt) sCallSite;
			Value rightOp = jstmt.getRightOp();

			// check if we have a source with apl = 0 (this or parameter source)
			if (rightOp instanceof ParameterRef) {
				logger.debug("source: " + sCallSite + " " + currentMethod.getSignature());
				if (debug)
					System.out.println("source: " + sCallSite + " " + currentMethod.getSignature());

				return new SinkInfo(null);
			} else if (rightOp instanceof ThisRef) {
				if (debug)
					System.out.println("source: (this)" + sCallSite + " " + currentMethod.getSignature());
				return new SinkInfo(null);
			}
		}
		return null;
	}

	private boolean isMethodToSummarize(SootMethod currentMethod) {
		// Initialize the method we are interested in
		if (method == null)
			method = Scene.v().getMethod(methodSig);

		// This must either be the method defined by signature or the
		// corresponding one in the parent class
		if (currentMethod == method)
			return true;

		return parentClass != null && currentMethod.getDeclaringClass().getName().equals(parentClass)
				&& currentMethod.getSubSignature().equals(method.getSubSignature());
	}

	@Override
	public SinkInfo getSinkInfo(Stmt sCallSite, InfoflowManager manager, AccessPath sourceAP) {
		// We only fake the sources during the initial collection pass. During
		// the actual taint propagation, the TaintPropagationHandler will take
		// care of recording the outbound abstractions
		if (sourceAP != null)
			return null;

		// If this is not the method we are looking for, we skip it
		SootMethod currentMethod = manager.getICFG().getMethodOf(sCallSite);
		if (!isMethodToSummarize(currentMethod))
			return null;

		return sCallSite instanceof ReturnStmt || sCallSite instanceof ReturnVoidStmt ? new SinkInfo(null) : null;
	}

	@Override
	public SourceInfo getInverseSinkInfo(Stmt sCallSite, InfoflowManager manager) {
		SootMethod currentMethod = manager.getICFG().getMethodOf(sCallSite);
		if (!isMethodToSummarize(currentMethod))
			return null;

		if (!currentMethod.hasActiveBody())
			return null;

		if (!(sCallSite instanceof ReturnStmt || sCallSite instanceof ReturnVoidStmt))
			return null;

		Set<AccessPath> aps = new HashSet<>();
		List<FlowSource> sources = new ArrayList<>();
		UnitPatchingChain units = currentMethod.getActiveBody().getUnits();
		for (Unit unit : units) {
			if (unit instanceof IdentityStmt) {
				IdentityStmt iStmt = ((IdentityStmt) unit);
				Value leftOp = iStmt.getLeftOp();
				Value rightOp = iStmt.getRightOp();

				if (rightOp instanceof ParameterRef) {
					ParameterRef pref = (ParameterRef) rightOp;
//					logger.debug("source: " + sCallSite + " " + currentMethod.getSignature());
//					if (debug)
//						System.out.println("sink: " + sCallSite + " " + currentMethod.getSignature());
					aps.add(manager.getAccessPathFactory().createAccessPath(leftOp, true));
					sources.add(sourceSinkFactory.createParameterSource(pref.getIndex(), pref.getType().toString()));
				} else if (rightOp instanceof ThisRef) {
					ThisRef tref = (ThisRef) rightOp;
//					if (debug)
//						System.out.println("sink: (this)" + sCallSite + " " + currentMethod.getSignature());
					aps.add(manager.getAccessPathFactory().createAccessPath(leftOp, true));
					sources.add(sourceSinkFactory.createThisSource(tref.getType().toString()));
				}
			}
		}

		return aps.isEmpty() ? null : new SourceInfo(null, aps, sources);
	}

	@Override
	public void initialize() {
		// nothing to do here
	}

	/**
	 * Gets the factory that creates the sources and sinks
	 * 
	 * @return The factory that creates the sources and sinks
	 */
	public SourceSinkFactory getSourceSinkFactory() {
		return sourceSinkFactory;
	}

}

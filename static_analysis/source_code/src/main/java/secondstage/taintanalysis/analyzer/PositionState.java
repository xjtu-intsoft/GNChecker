package secondstage.taintanalysis.analyzer;


public enum PositionState {
    Flexible,
    After,
    Before,
    CheckInvokePoint,
    Ignore,
    HoldToEnd,
    Default
}

package secondstage.taintanalysis.taint;


public enum ValueKind {
    InstanceField,
    ThisRef,
    StaticField,
    Local,
    Return,
    Param,
    Array,
    ClassThis
}

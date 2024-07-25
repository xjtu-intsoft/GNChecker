package secondstage.taintanalysis.taint;

public enum TaintWay {
    Normal,
    Source,
    Sink,
    Alias,
    ReturnBack,
    ThisIdentity,
    AliasBefore,
    May,
    Identity,
    Param,
    Return,
    ParamReturn,
    ParamIdentity,
    Aug,
    TaintWrapper,
    ClassField,
    ClassFieldThis
}

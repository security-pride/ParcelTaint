package com.cxxsheng.sootcore;

import soot.SootMethod;
import soot.Unit;

public interface UnitCallback {
    void handle(SootMethod who,Unit rawUnit ,Unit unit);
}

package com.cxxsheng.sootcore;

import com.cxxsheng.util.StringUtil;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeStmt;

import java.util.ArrayList;
import java.util.List;

public class MethodHandler {

    private final SootMethod method;

    private List<SootMethod> passedMethods = new ArrayList<>();

    private UnitCallback invokeCallback = null;

    private UnitCallback unitCallback = null;

    private List<String> paramHitStrings = new ArrayList<>();

    private boolean runRecurive = false;


    public void setUnitCallback(UnitCallback unitCallback) {
        this.unitCallback = unitCallback;
    }

    public void setInvokeCallback(UnitCallback invokeCallback) {
        this.invokeCallback = invokeCallback;
    }

    public MethodHandler(SootMethod method, boolean runRecurive) {
        this.method = method;
        this.runRecurive = runRecurive;
    }

    public void addHitString(String hitString) {
        paramHitStrings.add(hitString);
    }


    private boolean isHit(SootMethod targetMethod){
        if (paramHitStrings.isEmpty())
            return true;

        if (StringUtil.listContains(paramHitStrings, targetMethod.getParameterTypes())){
            return true;
        }
        return false;
    }


    private void handleInvoke(SootMethod who, Unit rawUnit,  InvokeStmt invokeStmt) {
        if (invokeCallback != null) {
            invokeCallback.handle(who, rawUnit, invokeStmt);
        }

        if (!runRecurive)
            return;

        SootMethod targetMethod = invokeStmt.getInvokeExpr().getMethod();
        if (isHit(targetMethod))
            runMethod(targetMethod);
    }

    private void runMethod(SootMethod method){

        if (passedMethods.contains(method))
            return;
        passedMethods.add(method);

        if (!method.isConcrete())
            return;

        for(Unit unit : method.retrieveActiveBody().getUnits()){

            if (unitCallback != null) {
                unitCallback.handle(method, unit, unit);
            }
            if (unit instanceof InvokeStmt){
                handleInvoke(method, unit, (InvokeStmt) unit);
            }else if (unit instanceof AssignStmt){
                Value v =  ((AssignStmt) unit).getRightOp();
                if (v instanceof InvokeStmt){
                    handleInvoke(method, unit, (InvokeStmt) v);
                }
            }
        }
    }

    public void run(){
        runMethod(this.method);
    }
}

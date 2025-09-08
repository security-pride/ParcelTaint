package com.cxxsheng.util;

import soot.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class AppsharkRuleGenerator {
    private final String outPut;
    private final Set<String> allBundleParcelable;
    private final List<Pair<SootMethod, SootMethod>> entryAndImps =  new ArrayList<>();
    private String path;


    private static final String ENTRY_IDENTIFIER = "\"methods\": []";
    private static final String SOURCE_IDENTIFIER = "\"Param\": {}";
    private static final String SINK_IDENTIFIER = "\"sink\": {}";


    private final StringBuilder entry = new StringBuilder("\"methods\": [");
    private final StringBuilder source = new StringBuilder("\"Param\": {");
    private final StringBuilder sink = new StringBuilder("\"sink\": {");


    public AppsharkRuleGenerator(String path, String outPut, Set<String> allBundleParcelable) {
        this.path = path;
        this.outPut = outPut;
        this.allBundleParcelable = allBundleParcelable;
    }

    public void addEntryAndImp(Pair<SootMethod, SootMethod> entryAndImp) {
        entryAndImps.add(entryAndImp);
    }





    private void process(){
        for (Pair<SootMethod, SootMethod> entryAndImp : entryAndImps) {
            SootMethod managerMethod = entryAndImp.left;
            SootMethod serviceMethod = entryAndImp.right;
            entry.append(String.format("      \"%s\",\n", serviceMethod.toString()));

            StringBuilder paramList = new StringBuilder();
            List<Type> params = serviceMethod.getParameterTypes();
            for (int i = 0; i < params.size(); i++) {
                if (allBundleParcelable.contains(params.get(i).toString())){
                    paramList.append("\"p").append(i).append("\",");
                }
            }

            if (!paramList.isEmpty()) {
                paramList.setLength(paramList.length() - 1);
            }

            source.append(String.format(
                    "        \"%s\": [\n" +
                    "          %s" +
                    "        ],\n"
                  , serviceMethod, paramList));


            List<Type> parameterTypes = managerMethod.getParameterTypes();
            for (Type paramType : parameterTypes) {
                if (paramType instanceof RefType) {
                    if (((RefType) paramType).getSootClass().isInterface())
                        if (Scene.v().getActiveHierarchy().isInterfaceDirectSubinterfaceOf(((RefType) paramType).getSootClass(), Scene.v().getSootClass("android.os.IInterface"))) {
                            sink.append(String.format("      \"%s\": {\n" +
                                    "        \"TaintCheck\": [\n" +
                                    "          \"p*\"\n" +
                                    "        ]\n" +
                                    "      },\n", managerMethod));
                            break;
                        }
                }
            }


//            sink.append(String.format("      \"%s\": {\n" +
//                    "        \"TaintCheck\": [\n" +
//                    "          \"p*\"\n" +
//                    "        ]\n" +
//                    "      },\n", managerMethod));


        }

        entry.append("]");
        source.append("}");
        sink.append("}");



    }


    public void generate() {
        process();
        try {
            String content = Files.readString(Paths.get(path));
            content = content.replace(ENTRY_IDENTIFIER, entry);
            content = content.replace(SOURCE_IDENTIFIER, source);
            content = content.replace(SINK_IDENTIFIER, sink);
            Files.writeString(Paths.get(outPut), content);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}

package com.cxxsheng;

import com.cxxsheng.permission.PermissionParser;
import com.cxxsheng.sootcore.MethodHandler;
import com.cxxsheng.util.*;
import soot.*;
import soot.jimple.InvokeStmt;
import soot.options.Options;

import java.io.IOException;
import java.util.*;


public class Main {


    private static PermissionParser parser;

    private static class MethodPair {
        public String interfaceMethod;
        public String implementationMethod;

        public MethodPair(String interfaceMethod, String implementationMethod) {
            this.interfaceMethod = interfaceMethod;
            this.implementationMethod = implementationMethod;
        }
    }

    private static class ServiceInfo {
        public String interfaceName;
        public String implementationName;
        public List<MethodPair> methods;

        public ServiceInfo(String interfaceName, String implementationName) {
            this.interfaceName = interfaceName;
            this.implementationName = implementationName;
            this.methods = new ArrayList<>();
        }
    }



//    private static final String TARGET_CLASS = "com.android.server.notification.NotificationManagerService";
    private static final String FRAMEWORK = "../aosp14/framework.apk";

    private static final  String androidJarPath = "../appshark/config/tools/platforms/android-34/android.jar";

    private static final String IINTERFACE = "android.os.IInterface";

    private static final List<String> SKIP_MATCH_METHODS = new ArrayList<>();

    private static Hierarchy hierarchy;


    private final static List<String> targetParcelables = new ArrayList<>();

    //fixme not safe!
    private static boolean isSystemAPI(SootMethod serviceTarget){
        MethodHandler handler = new MethodHandler(serviceTarget, true);
        Set<String> allPermissions = new HashSet<>();
        handler.setUnitCallback( (a_, raw, b_) -> {
            if (raw.toString().contains("android.permission.")){
                allPermissions.addAll(StringUtil.extractPermissions(raw.toString()));
            }

        });
        handler.run();
        System.out.println(serviceTarget.toString() + "\n\trequirePermission=" + allPermissions);
        boolean requireSystem = false;
        for (String permission : allPermissions) {
            if (parser.isSystemPermission(permission)){
                requireSystem = true;
                break;
            }
        }

        System.out.println("\trequireSystem=" + requireSystem);

        return  requireSystem;
    }
    // make sure class has this interface, for instance: class a implement interfaceClass; class b extends a;
    // class b should be filtered out
    private static List<SootClass> enforceHasInterface(List<SootClass> classes, SootClass interfaceClass, boolean filterAbstract){
        List<SootClass> filterClasses = new ArrayList<>();
        for (SootClass sootClass : classes) {
            if (sootClass.getInterfaces().contains(interfaceClass)) {
                if (!filterAbstract || !sootClass.isAbstract()) {
                    filterClasses.add(sootClass);
                }
            }
        }
        return filterClasses;
    }



    private static SootMethod tryToFindWriteToParcel(SootClass sootClass){
        SootMethod writeToParcel = sootClass.getMethodUnsafe("void writeToParcel(android.os.Parcel,int)");
        if ( writeToParcel == null)
            while (true){
                sootClass = sootClass.getSuperclass();
                if (sootClass == null)
                    break;
                writeToParcel = sootClass.getMethodUnsafe("void writeToParcel(android.os.Parcel,int)");
                if (writeToParcel != null)
                    break;
            }
        return writeToParcel;
    }

    private static Set<String> getAllBundleParcelable(){
        Map<String, String> allTypes = new HashMap<>();
        SootClass parcelableInterface = Scene.v().getSootClass("android.os.Parcelable");
        List<SootClass> classes = hierarchy.getImplementersOf(parcelableInterface);
        classes = enforceHasInterface(classes, parcelableInterface, true);
        for (SootClass clazz : classes){
            SootMethod writeToParcel = tryToFindWriteToParcel(clazz);
            if (writeToParcel == null){
                throw new RuntimeException(clazz.toString());
            }


            MethodHandler handler = new MethodHandler(writeToParcel, true);
            handler.setInvokeCallback((who, a_, unit) -> {
                InvokeStmt invoke = (InvokeStmt) unit;
                if (invoke.getInvokeExpr().getMethod().getName().contains("writeBundle"))
                    allTypes.put(clazz.getName(), who.toString());
            });

            handler.addHitString("android.os.Parcel");
            handler.run();

        }

        allTypes.putIfAbsent("android.os.Bundle", null);

        StringBuilder sb = new StringBuilder("********************************\n");
        sb.append("All Bundle Parcelable Types:\n");
        for (Map.Entry<String, String> entry : allTypes.entrySet()) {
            sb.append("Class: ").append(entry.getKey());
            if (entry.getValue() != null) {
                sb.append(" -> ").append(entry.getValue());
            }
            sb.append("\n");
        }
        sb.append("********************************");

        Logger.info(sb.toString());
        return allTypes.keySet();
    }

    private static void startAnalysis() {

        FileWriter writer = new FileWriter("target.list");

        Set<String> allBundleParcelable = getAllBundleParcelable();

        AppsharkRuleGenerator generator = new AppsharkRuleGenerator("input.json", "output.json", allBundleParcelable);


        List<ServiceInfo> services = new ArrayList<>();

        SootClass iInterface = Scene.v().getSootClass(IINTERFACE);

        //managerInterface is the first layer of aidl wrapped class
        List<SootClass> managerInterfaces = hierarchy.getSubinterfacesOf(iInterface);
        for (SootClass managerInterface : managerInterfaces) {
            List<SootClass> allImps =  hierarchy.getDirectImplementersOf(managerInterface);
            List<SootClass> filterImps = enforceHasInterface(allImps, managerInterface, false);

            SootClass defaultClass = null;
            SootClass proxyClass = null;
            SootClass stubClass = null;

            for (SootClass filterImp : filterImps) {
                if (filterImp.getName().endsWith("$Default"))
                    defaultClass = filterImp;
                else if (filterImp.getName().endsWith("$Stub$Proxy"))
                    proxyClass = filterImp;
                else if (filterImp.getName().endsWith("$Stub"))
                    stubClass = filterImp;
            }

            Logger.info("Found default/proxy/stub: " + managerInterface + ":\n\t" + (defaultClass != null ? defaultClass.getName() : "null") + " | " + (proxyClass != null ? proxyClass.getName() : "null") + " | " + (stubClass != null ? stubClass.getName() : "null"));

//             default ？
            if (defaultClass != null && !hierarchy.getDirectSubclassesOf(defaultClass).isEmpty())
                Logger.info("There are some default subclasses: " + hierarchy.getDirectSubclassesOf(defaultClass));

            if (proxyClass != null && stubClass != null) {

                List<SootClass> mayRealServices = hierarchy.getDirectSubclassesOf(stubClass);
                if (mayRealServices.size() == 1){
                    SootClass realService = mayRealServices.get(0);
                    if (realService.isAbstract())
                    {
                        Logger.info("realService is abstract: " + realService);
                    }else {
                        ServiceInfo serviceInfo = new ServiceInfo(
                                managerInterface.getName(),
                                realService.getName()
                        );

                        List<SootMethod> managerMethods = managerInterface.getMethods();
                        for (SootMethod managerMethod : managerMethods) {
                            String methodSubSignature = managerMethod.getSubSignature();

                            if(SKIP_MATCH_METHODS.contains(methodSubSignature))
                                continue;

                            SootMethod targetMethod = realService.getMethod(methodSubSignature);


                            if (StringUtil.listContains(allBundleParcelable, targetMethod.getParameterTypes())){
                                Logger.info("TargetMethod has a Bundle Param: " + managerMethod + "/" + targetMethod);
                                writer.writeLine(managerMethod + " / " + targetMethod);
                                generator.addEntryAndImp(new Pair<>(managerMethod, targetMethod));
                            }

                            serviceInfo.methods.add(new MethodPair(
                                    managerMethod.toString(),
                                    targetMethod.toString()
                            ));

                        }
                        services.add(serviceInfo);
                    }

                }else if (mayRealServices.isEmpty()){
                    //do nothing
                    Logger.info("Can't find any implementations for " + managerInterface);
                }else {
                    Logger.info("More than one proxy implementation found for " + managerInterface.getName() + ", list: " + mayRealServices);
                }

            }

        }

        JsonUtil.writeToJsonFile(services, "services_analysis.json");
        generator.generate();
        writer.close();
    }

    private static void initializeSoot(String jarTargetPath) {


        //        String sb = Scene.v().getAndroidJarPath(androidJarPath, jarPath);
        Options.v().set_src_prec(Options.src_prec_apk);
        List<String> processPathList = new ArrayList<>();
        processPathList.add(FRAMEWORK);
        processPathList.add(jarTargetPath);

        Options.v().set_process_dir(processPathList);
        Options.v().set_force_android_jar(androidJarPath);
        Options.v().set_process_multiple_dex(true);


        //        Options.v().set_output_dir("out/");
        Options.v().set_output_format(Options.output_format_jimple);


        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_keep_line_number(false);
        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore);
        Options.v().set_debug(false);
        Options.v().set_verbose(false);
        Options.v().set_validate(false);
        Scene.v().loadNecessaryClasses();

        Scene.v().loadNecessaryClasses();// may take dozens of seconds

        hierarchy = Scene.v().getActiveHierarchy();;

    }



    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Main <jar-path> <class-name>");
            return;
        }
        String jarPath = args[0];
//        String className = args[1];
        initParams();
        initializeSoot(jarPath);
        startAnalysis();
//        forTest();
    }

    private static void initParams() {
        SKIP_MATCH_METHODS.add("void <clinit>()");
        parser = new PermissionParser("android_manifest.xml");
        try {
            parser.parse();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    private static void printSootClass(SootClass sc){
        System.out.println("**************");
        System.out.println(sc.toString());
        for (SootMethod method : sc.getMethods()) {
            if (method.isConcrete()) {
                System.out.println(method.retrieveActiveBody());
            }
        }
    }
    private static void forTest(){
        SootClass INotificationManager = Scene.v().getSootClass("com.android.settings.homepage.SettingsHomepageActivity");
        Hierarchy hierarchy = Scene.v().getActiveHierarchy();
//        List<SootClass> sootClasses = hierarchy.getDirectSubclassesOf(INotificationManager);
        SootClass a = Scene.v().getSootClass("com.android.settings.SettingsActivity");
        printSootClass(a);
//        a = Scene.v().getSootClass("com.android.server.notification.NotificationManagerService$PostNotificationRunnable");
//        printSootClass(a);
//        a = Scene.v().getSootClass("com.android.server.notification.NotificationManagerService$EnqueueNotificationRunnable");
//        printSootClass(a);

        System.out.println();
    }
}

# Artifact for CCS2025b#96: Parcel Mismatch Demystified: Addressing a Decade-Old Security Challenge in Android

### Introduction
- **ServiceExtracter**: A Service Preprocessing module that preprocesses system services and generates rules for Pointer Analysis
- **ParcelTaint**: A pointer analysis tool based on Appshark, extended with Intent modeling, ICC Taint, and DataFlow Filter capabilities
- **aosp14**: Input files including Settings.apk, framework.jar, and services.jar

### Build Instructions
Build the components using the following commands:
```bash
# Build appshark
cd ~/ParcelTaint/appshark && ./gradlew build -x test

# Build ServiceExtracter
cd ~/ParcelTaint/ServiceExtracter && mvn clean package
```

### Running the Analysis

#### 1. Preprocessing
Execute the preprocessing step:
```bash
cd ~/ParcelTaint/ServiceExtracter && ./run.sh
```
This generates appshark rules for SystemServer in `output.json`, which will be used by the taint analysis engine.

#### 2. Running the Taint Analysis Engine
Navigate to the appshark directory:
```bash
cd ~/ParcelTaint/appshark
```

The directory contains three analysis scripts:

##### a. Analysis with DataFlow Filtering (runDataFilterInServer.sh)
Analyzes services.jar with DataFlow Filtering enabled. Results:
```bash
# Total attack chains found
$ find ~/ParcelTaint/appshark/out/ParcelMismatchInSystemServerFilterred/vulnerability -type f -name "*.html" | wc -l 
5

# AC#1 hits (ContentService->sync/requestSync)
$ grep -r -l --include="*.html" "ContentService" ~/ParcelTaint/appshark/out/ParcelMismatchInSystemServerFilterred/vulnerability | wc -l
4

# AC#2 hits (NotificationManagerService->enqueueNotificationWithTag)
$ grep -r -l --include="*.html" "enqueueNotificationWithTag" ~/ParcelTaint/appshark/out/ParcelMismatchInSystemServerFilterred/vulnerability | wc -l
1
```

##### b. Direct Analysis (runInServer.sh)
Analyzes services.jar without filtering:
```bash
# Total attack chains found
$ find ~/ParcelTaint/appshark/out/ParcelMismatchInSystemServer/vulnerability -type f -name "*.html" | wc -l
17
```

##### c. Settings Analysis (runSettings.sh)
Analyzes Settings.apk:
```bash
# AC#3 hits (DeepLinkHomepageActivityInternal)
$ grep -r -l --include="*.html" "DeepLinkHomepageActivityInternal" ~/ParcelTaint/appshark/out/IntentRedirectionPlusVersion/vulnerability | wc -l
1326

# AC#4 hits (AppRestrictionsFragment)
$ grep -r -l --include="*.html" "AppRestrictionsFragment" ~/ParcelTaint/appshark/out/IntentRedirectionPlusVersion/vulnerability | wc -l
1
```
# ParcelTaint

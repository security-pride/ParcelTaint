#!/bin/bash
export JAVA_HOME=/usr/local/Cellar/openjdk@11/11.0.12
export PATH=/usr/local/Cellar/openjdk@11/11.0.12/bin:$PATH
java   -Xmx128g -Xms16g -jar build/libs/AppShark-0.1.2-all.jar config/ParcelMismatchInSystemServerMustPassedConfig.json5

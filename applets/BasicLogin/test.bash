#!/usr/sbin/bash
ant clean
ant build
java -jar /usr/share/java/junit.jar -cp build/jar/BasicLogin.jar:build/classes/:../../references/jcardsim/jcardsim-3.0.4-SNAPSHOT.jar --scan-classpath=build/jar/BasicLoginTest.jar

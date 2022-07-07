ant clean
ant build
java -jar /usr/share/java/junit-platform-console-standalone.jar -cp build/jar/openpgpcard.jar:build/classes/:../../references/jcardsim/jcardsim-3.0.4-SNAPSHOT.jar --scan-classpath=build/jar/PgpTest.jar

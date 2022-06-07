all: build.xml src/HelloWorldApplet.java
	ant

sim:
	java -cp "jcardsim-2.2.2-all.jar:HelloWorld.jar" com.licel.jcardsim.utils.APDUScriptTool jcardsim.cfg apdu.script

clean:
	rm -rf HelloWorldApplet* HelloWorld.jar


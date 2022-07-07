all: build.xml src/*
	ant

sim:
	java -cp "../../references/jcardsim/jcardsim-3.0.4-SNAPSHOT.jar:bin/AlgTest.jar" com.licel.jcardsim.utils.APDUScriptTool jcardsim.cfg

clean:
	rm -rf AlgTest.jar AlgTest*.cap


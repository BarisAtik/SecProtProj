# Path to the Java Card Development Kit
JC_HOME=util/java_card_kit-2_2_1

# Version of JCardSim to use;
JCARDSIM=jcardsim-3.0.4-SNAPSHOT

# Beware that only JCardSim-3.0.4-SNAPSHOT.jar includes the classes
# AIDUtil and CardTerminalSimulator, so some of the code samples on
# https://jcardsim.org/docs do not work with older versions
#    JCARDSIM=jcardsim-2.2.1-all
#    JCARDSIM=jcardsim-2.2.2-all

# Classpath for JavaCard code, ie the smartcard applet; this includes
# way more than is probably needed
JC_CLASSPATH=${JC_HOME}/lib/apdutool.jar:${JC_HOME}/lib/apduio.jar:${JC_HOME}/lib/converter.jar:${JC_HOME}/lib/jcwde.jar:${JC_HOME}/lib/scriptgen.jar:${JC_HOME}/lib/offcardverifier.jar:${JC_HOME}/lib/api.jar:${JC_HOME}/lib/installer.jar:${JC_HOME}/lib/capdump.jar:${JC_HOME}/samples/classes:${CLASSPATH}

all: applet terminal

applet: EPurse/bin/EPurse.class 

EPurse/bin/EPurse.class: EPurse/src/applet/EPurse.java
	javac -d EPurse/bin -cp ${JC_CLASSPATH}:POSTerminal/src EPurse/src/applet/CardAuth.java EPurse/src/applet/EPurse.java 

POSTerminal/bin/terminal/QuickTest.class: POSTerminal/src/terminal/QuickTest.java
	javac -d POSTerminal/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:EPurse/bin POSTerminal/src/terminal/QuickTest.java

terminal: POSTerminal/bin/terminal/POSTerminal.class

POSTerminal/bin/terminal/POSTerminal.class: POSTerminal/src/terminal/POSTerminal.java
	javac -d POSTerminal/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:EPurse/bin:POSTerminal/bin POSTerminal/src/terminal/POSTerminal.java  

runterminal: 
	# Runs the GUI terminal
	java -cp util/jcardsim/${JCARDSIM}.jar:POSTerminal/bin:EPurse/bin terminal.POSTerminal

clean:
	rm -rf EPurse/bin/*  
	rm -rf POSTerminal/bin/*

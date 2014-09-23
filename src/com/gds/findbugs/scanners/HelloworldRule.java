package com.gds.findbugs.scanners;

import java.io.IOException;

import org.apache.bcel.classfile.Code;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.classfile.Utility;
import org.apache.bcel.util.ByteSequence;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.BytecodeScanningDetector;

public class HelloworldRule extends BytecodeScanningDetector {
	
	private final String VULNERABLE_METHOD = "com.mongodb.casbah.MongoDB.eval";
	private final String FUNCTION_DECLARATION = "invokevirtual";
	
	BugReporter bugReporter;
	
	public HelloworldRule(BugReporter bugReporter) {
		this.bugReporter = bugReporter;
	}
	
	public void visit(Code someObj) {
		
		try {
	        ByteSequence stream = new ByteSequence(someObj.getCode());
	    	while (stream.available() > 0) {   
				
				String line = Utility.codeToString(stream, someObj.getConstantPool(), true);
				
				String command = getCommand(line);
				String function = getFunction(line);
				
				if(command.equals(FUNCTION_DECLARATION) && function.startsWith(VULNERABLE_METHOD)) {
					logBug("MONGO_INJECTION", NORMAL_PRIORITY);
				}
	    	}
	    	
		} catch(IOException e) {
			e.printStackTrace();
		}
		
	    super.visit(someObj);
	}
	
	protected String getCommand(String line) {
		String[] parts = line.split("\\t");
		return (parts.length > 0) ? parts[0] : "";
	}
	
	protected String getFunction(String line) {
		String[] parts = line.split("\\t");
		return (parts.length > 1) ? parts[1] : "";
	}
	
	protected void logBug(String type, int priority) {
		BugInstance instance = new BugInstance(type, priority).addClassAndMethod(this).addSourceLine(this);
		bugReporter.reportBug(instance);
	}

}

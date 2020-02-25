/*
	ExitException.java
	
	0.4 (7/27/2016)
	
	SecurityException subclass utilized by the superserial.security.PreventExitSecurityManager class. Specifically, this exception is thrown when the PreventExitSecurityManager
	SecurityManager is installed and a class attempts to call the System.exit() method, thereby preventing the JVM from exiting.
*/

package superserial.security;

public class ExitException extends SecurityException {
	private final int status;
	
	public ExitException(int s) {
		super();
		status = s;
	}
	
	public int getStatus() {
		return status;
	}
}

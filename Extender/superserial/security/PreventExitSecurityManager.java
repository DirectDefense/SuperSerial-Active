/*
	PreventExitSecurityManager.java
	
	0.4 (7/27/2016)
	
	SecurityManager subclass allowing all JVM permissions except the use of the System.exit() function. A superserial.security.ExitException exception is thrown when a class 
	attempts to call the System.exit() method, thereby preventing the JVM from exiting.
*/

package superserial.security;

import java.security.Permission;

public class PreventExitSecurityManager extends SecurityManager {
	
	@Override
	public void checkPermission(Permission perm) {
		//allow anything. TODO: set minimum permissions for ysoserial
	}
	
	@Override
	public void checkPermission(Permission perm,Object context) {
		//allow anything. TODO: set minimum permissions for ysoserial
	}
	
	@Override
	public void checkExit(int status) {
		super.checkExit(status);
		throw new ExitException(status);
	}
}

/*
	SuperSerialNodeHelper.java
	
	v0.4 (7/27/2016)
	
	Class containing static methods to assist in various aspects of processing throughout the SuperSerial node.
*/

//Possible TODO: make all methods package-restricted (no visibility modifier)

package superserial.node;

import java.util.Date;
import java.util.Hashtable;
import java.text.SimpleDateFormat;

public class SuperSerialNodeHelper {
	
	//parses URL parameters (token and write), DOES NOT support multiple parameters of same name (only first occurrence from left will be used)
	public static Hashtable<String,String> parseURLParams(String query) {
		Hashtable<String,String> params = null;
		if(query!=null) {
			params = new Hashtable<String,String>(2);
			String[] paramsList = query.split("&");
			for(int i=0;i<paramsList.length;i++) {
				if(paramsList[i].indexOf('=')>=0) {
					String[] paramSplit = paramsList[i].split("=",2);
					String paramName = paramSplit[0];
					
					if(paramName.equalsIgnoreCase("token")) {
						if(!params.containsKey("token")) { //check if param was already found
								params.put(paramName,paramSplit[1]);
						}
					} else if(paramName.equalsIgnoreCase("write")) {
						if(!params.containsKey("write")) { //check if param was already found
							params.put(paramName,paramSplit[1]);
						}
					} else if(paramName.equalsIgnoreCase("technique")) {
						if(!params.containsKey("technique")) { //check if param was already found
							params.put(paramName,paramSplit[1]);
						}
					}
				}
			}
		}
		return params;
	}
	
	public static void printLogEntry(String message) {
		Date now = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
		System.err.println(sdf.format(now)+": "+message);
	}
	
	//convert byte array to hexadecimal string
	public static String bytesToHex(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length*2];
		for(int j=0;j<bytes.length;j++){
			int v =bytes[j] & 0xFF;
			hexChars[j*2]=hexArray[v>>>4];
			hexChars[j*2+1]=hexArray[v&0x0F];
		}
		return new String(hexChars);
    }
}

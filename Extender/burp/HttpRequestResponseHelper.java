/*
	HttpRequestResponseHelper.java
	
	v0.5 (11/22/2016)
	
	Helper class implementing IHttpRequestResponse interface. Intended to be used for creating IHttpRequestResponse objects without needing to send an HTTP request/receive 
	an HTTP response first (such as for creating an IHttpRequestResponse for Burp Collaborator requests/responses).
*/

package burp;

import java.net.URL;

public class HttpRequestResponseHelper implements IHttpRequestResponse {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private IHttpService httpService;
	private byte[] request;
	private byte[] response;
	
	public HttpRequestResponseHelper(IBurpExtenderCallbacks cb,byte[] req,byte[] resp,String host,int port,boolean https) {
		callbacks = cb;
		helpers = callbacks.getHelpers();
		request = req;
		response = resp;
		
		httpService = helpers.buildHttpService(host,port,https);
	}
	
	//IHttpRequestResponse methods
	@Override
	public String getComment() {
		return null;
	}
	
	@Override
	public String getHighlight() {
		return null;
	}
	
	@Override
	public IHttpService getHttpService() {
		return httpService;
	}
	
	@Override
	public byte[] getRequest() {
		return request;
	}
	
	@Override
	public byte[] getResponse() {
		return response;
	}
	
	@Override
	public void setComment(String comm) {
		
	}
	
	@Override
	public void setHighlight(String color) {
		
	}
	
	@Override
	public void setHttpService(IHttpService service) {
		
	}
	
	@Override
	public void setRequest(byte[] req) {
		request = req;
	}
	
	@Override
	public void setResponse(byte[] resp) {
		response = resp;
	}
}

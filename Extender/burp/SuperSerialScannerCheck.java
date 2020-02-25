/*
	SuperSerialScannerCheck.java
	
	v0.5 (11/22/2016)
	
	Parent abstract class for Active Scan checks to detect Java Deserialization Remote Code Execution using the SuperSerial Node or Burp Collaborator. Initializes all base 
	values for ScannerCheck sub classes, and defines methods for pre-defined token replacement ([NODEHOST], [NODEPORT], etc.) as well as the proper sorting of lists 
	containing issue request/response highlight indices.
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import superserial.payload.SuperSerialPayloadGenerator;
import superserial.settings.SuperSerialSettings;

abstract class SuperSerialScannerCheck implements IScannerCheck {
	protected IBurpExtenderCallbacks callbacks;
	protected IExtensionHelpers helpers;
	protected SuperSerialPayloadGenerator generator;
	protected SuperSerialSettings settings;
	protected PayloadCommandFactory pcf;
	protected PayloadTypeFactory ptf;
	
	protected static final String JBOSS_INSERTION_POINT = "SuperSerial-JBoss";
	protected static final String WEBSPHERE_INSERTION_POINT = "SuperSerial-WebSphere";
	
	public SuperSerialScannerCheck(IBurpExtenderCallbacks cb) {
		callbacks = cb;
		helpers = callbacks.getHelpers();
		generator = SuperSerialPayloadGenerator.getInstance();
		settings = SuperSerialSettings.getInstance();
		pcf = PayloadCommandFactory.getInstance();
		ptf = PayloadTypeFactory.getInstance();
	}
	
	@Override //likely will not implement this method (passive check is handled by SuperSerial-Passive plugin)
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		return null;
	}
	
	@Override
	public abstract int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue);
	
	@Override
	public abstract List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint);
	
	//replace command tokens (for host, port, protocol, etc) with correct values
	protected String makeCommand(String cmd,String protocol,String host,int port,String path,String token,String tech) {
		cmd = cmd.replace("[NODEPROTOCOL]",protocol.toLowerCase());
		cmd = cmd.replace("[NODEHOST]",host);
		cmd = cmd.replace("[NODEPORT]",Integer.toString(port));
		cmd = cmd.replace("[NODEPATH]",path); 
		cmd = cmd.replace("[NODETOKEN]",token);
		cmd = cmd.replace("[TECHNIQUE]",tech);
		return cmd;
	}
	
	//sort list of highlight indices in ascending order (does NOT search for overlapping indices
	protected List<int[]> sortHighlightIndexList(List<int[]> unsortedList) {
		if(unsortedList == null) return null;
		int[] indArr = new int[unsortedList.size()];
		for(int i=0;i<indArr.length;i++) {
			int[] ind = unsortedList.get(i);
			indArr[i] = ind[0];
		}
		Arrays.sort(indArr);
		List<int[]> sortedList = new ArrayList<int[]>(indArr.length);
		for(int i=0;i<indArr.length;i++) {
			for(int j=0;j<unsortedList.size();j++) {
				int[] ind = unsortedList.get(j);
				if(ind[0] == indArr[i]) {
					sortedList.add(ind);
				}
			}
		}
		return sortedList;
	}
}

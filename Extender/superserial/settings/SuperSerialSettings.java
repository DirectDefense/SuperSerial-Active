/*
	SuperSerialSettings.java
	
	v0.5 (11/22/2016)
	
	Maintains the global settings utilized by the SuperSerial-Active extender in various areas. Includes Node connection settings and Active Scan related settings.
*/

package superserial.settings;

import burp.IBurpExtenderCallbacks;

public class SuperSerialSettings {
	private static SuperSerialSettings settings = null;
	private IBurpExtenderCallbacks callbacks;
	
	//node setting fields
	private boolean nodeCollaborator;
	private boolean nodeIntegrated;
	private String nodeHost;
	private int nodePort;
	private boolean nodeHttps;
	private String nodeToken;
	
	//scan setting fields
	private int downloadTries;
	private int waitTime;
	private boolean scanAll;
	
	//constants
	private static final String TAB_CAPTION = "SuperSerial-Active";
	private static final String EXTENDER_VERSION = "0.5"; //TODO: put this somewhere else
	private static final int DEFAULT_DOWNLOAD_TRIES = 5;
	private static final int DEFAULT_DOWNLOAD_WAIT_TIME = 1500;
	
	//default constructor
	private SuperSerialSettings(IBurpExtenderCallbacks cb) {
		callbacks = cb;
		
		//TODO: load saved settings from within IBurpExtenderCallbacks reference
		nodeCollaborator = false;
		nodeIntegrated = false;
		nodeHost = null;
		nodePort = -1;
		nodeHttps = false;
		nodeToken = null;
		
		downloadTries = DEFAULT_DOWNLOAD_TRIES;
		waitTime = DEFAULT_DOWNLOAD_WAIT_TIME;
		scanAll = false;
	}
	
	
	
	//get SuperSerialSettings instance for use elsewhere
	public static SuperSerialSettings getInstance() {
		if(settings==null) {
			settings = new SuperSerialSettings(null);
		}
		return settings;
	}
	
	//get SuperSerialSettings instance for use elsewhere
	//only intended to be called from BurpExtender.registerExtenderCallbacks in order to set IBurpExtenderCallbacks reference accordingly
	public static SuperSerialSettings getInstance(IBurpExtenderCallbacks cb) {
		if(settings==null) {
			settings = new SuperSerialSettings(cb);
		}
		return settings;
	}
	
	//reset all settings back to default
	public static SuperSerialSettings resetSettings() {
		settings = new SuperSerialSettings(null);
		return settings;
	}
	
	//set node collaborator setting
	public void setNodeCollaborator(boolean collab) {
		nodeCollaborator = collab;
	}
	
	//set integrated node setting
	public void setNodeIntegrated(boolean integrated) {
		nodeIntegrated = integrated;
	}
	
	//set settings pertaining to Node connection
	public void setNodeSettings(String host,int port,boolean https,String token) {
		nodeHost = host;
		if(port>0 && port<65536) { //only set port if valid number is entered
			nodePort = port;
		}
		nodeHttps = https;
		nodeToken = token;
		
		//TODO: Save settings within IBurpExtenderCallbacks reference
	}
	
	//set settings pertaining to Active Scanner
	public void setScanSettings(int dt,int wt,boolean sa) {
		downloadTries = dt;
		waitTime = wt;
		scanAll = sa;
	}
	
	
	//config tab accessors
	//get tab title
	public String getTabCaption() {
		return TAB_CAPTION;
	}
	
	//get current SuperSerial extender version
	public String getVersion() {
		return EXTENDER_VERSION;
	}
	
	
	//node connection settings accessors
	//get "Use Burp Collaborator" setting
	public boolean getNodeCollaborator() {
		return nodeCollaborator;
	}
	
	//get "Use Integrated Node" setting
	public boolean getNodeIntegrated() {
		return nodeIntegrated;
	}
	
	//get node host
	public String getNodeHost() {
		return nodeHost;
	}
	
	//get node listening port
	public int getNodePort() {
		return nodePort;
	}
	
	//get node protocol (false: HTTP, true: HTTPS)
	public boolean getNodeHttps() {
		return nodeHttps;
	}
	
	//get node protocol as String
	public String getNodeHttpsStr() {
		String retVal = "http";
		if(nodeHttps) retVal += "s";
		return retVal;
	}
	
	//get node authentication token
	public String getNodeToken() {
		return nodeToken;
	}
	
	
	//scan settings accessors
	//get number of Node download/access attempts used during Active Scan
	public int getDownloadTries() {
		return downloadTries;
	}
	
	//get wait time between Node download/access attempts used during Active Scan
	public int getWaitTime() {
		return waitTime;
	}
	
	//get Scan All setting (whether to skip insertion point creation analysis and instead automatically create insertion points for JBoss and all natively-listed request parameters)
	public boolean getScanAll() {
		return scanAll;
	}
}

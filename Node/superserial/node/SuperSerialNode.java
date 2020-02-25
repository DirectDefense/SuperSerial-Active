/*
	SuperSerialNode.java
	
	v0.4 (7/27/2016)
	
	Node for SuperSerial Active Scan check to use. The active scan check will first make a GET request to the /queue context which will create a new custom
	context (SuperSerialNodeHttpHandler.java) with a randomly-generated path, which will be returned in a JSON object in the response. The Active Scan check 
	will then attempt to force the target system to access the path and either write an access entry or upload a local file. The Active Scan check will then 
	attempt to download the access entry or uploaded file to confirm the presence of a vulnerability. All access is controlled by requiring all client 
	requests to contain a randomly-generated authentication token GUID as a URL parameter. This GUID is either generated at runtime or is specified by the user 
	as a command-line argument, and is outputted to the console immediately when the node is started. This token must be entered into the SuperSerial-Active 
	Scan Settings menu for the check to properly function. Command line arguments are availble to: print a help dialog, choose a port (other than the default 
	15050) for the Node to bind to, choose an authentication token for use (rather than using a runtime-generated one), and whether to try resuming from 
	previous execution(s).
*/

package superserial.node;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.Headers;
import java.net.URI;
import java.net.InetSocketAddress;
import java.io.File;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.ArrayList;
import java.util.Iterator;
import java.security.SecureRandom;
import org.json.JSONObject;

public class SuperSerialNode {
	private HttpServer hs;
	private int port;
	private boolean https;
	private String token;
	private SecureRandom sr;
	private String dir;
	
	private static final String VERSION = "0.5";
	private static final int DEFAULT_PORT = 15050;
	
	public SuperSerialNode(int p,String tk,boolean rs) {
		https=false;
		hs = null;
		if((p>=1) && (p<=65535)) {
			port = p;
		} else {
			System.err.println("Invalid port "+Integer.toString(p)+" specified: falling back to default port "+Integer.toString(DEFAULT_PORT));
			port = DEFAULT_PORT;
		}
		try {
			hs = HttpServer.create(new InetSocketAddress(port),0);
		} catch(IOException e) {
			e.printStackTrace();
			return;
		}
		sr = new SecureRandom();
		token = tk;
		if(token == null) token = generateGUID();
		
		//create directory to store uploaded files/access entries (if not already created)
		dir = System.getProperty("java.io.tmpdir")+System.getProperty("file.separator")+"SuperSerial"+System.getProperty("file.separator");
		File targetDir = new File(dir);
		if(!targetDir.exists()) {
			targetDir.mkdir();
		}
		
		hs.createContext("/queue",new QueueHandler());
		hs.createContext("/heartbeat",new HeartbeatHandler());
		
		//if --resume option is specified, re-create previously-generated contexts
		if(rs) {
			System.err.print("Attempting to resume from previous execution: ");
			File[] prevFiles = targetDir.listFiles();
			if(prevFiles.length>0) {
				ArrayList<String> foundContextList = new ArrayList<String>();
				for(int i=0;i<prevFiles.length;i++) {
					String filename = prevFiles[i].getName();
					String[] fNameSplit = filename.split("\\.",2);
					if(fNameSplit.length==2) {
						if(fNameSplit[1].equals("tmp")) {
							fNameSplit = fNameSplit[0].split("-");
							if(fNameSplit.length==3 && fNameSplit[0].equals("SuperSerial")) {
								boolean uploaded = false;
								String path = fNameSplit[2];
								switch(fNameSplit[1]) {
									case "UF":
										uploaded = true;
										break;
									case "AE":
										break;
									default:
										continue;
								}
								
								if(path.length()==10) { //TODO: validate complete format of path name
									path = "/"+path;
									hs.createContext(path,new SuperSerialNodeHttpHandler(token,path,dir,uploaded));
									foundContextList.add(path);
								}
							}
						}
					}
				}
				
				if(foundContextList.size()==0) {
					System.err.println("No previous executions detected\n");
				} else {
					System.err.print("\n");
					Iterator<String> contextItr = foundContextList.iterator();
					while(contextItr.hasNext()) {
						System.err.println("Context "+contextItr.next()+" created from previous execution");
					}
					System.err.print("\n");
				}
			} else {
				System.err.println("No previous executions detected\n");
			}
		}
		
		
		hs.start();
	}
	
	private void printSessionInfo() {
		System.err.println("SuperSerial Node v"+VERSION);
		System.err.println("Uploaded File/Access Entry Directory: "+dir);
		System.err.println("Node started on HTTP"+(https ? "S" : "")+" port "+port);
		System.err.println("Node Authentication Token for this session: "+token);
	}
	
	//dynamically create new context when requested
	private void createContext(String path) {
		if(path.charAt(0)!='/') path = "/"+path;
		hs.createContext(path,new SuperSerialNodeHttpHandler(token,path,dir));
	}
	
	private String generateGUID() {
		String retVal = generateRandom(16);
		return retVal.substring(0,8)+"-"+retVal.substring(8,12)+"-"+retVal.substring(12,16)+"-"+retVal.substring(16,20)+"-"+retVal.substring(20);
	}
	
	private String generateShortRandom() {
		return generateRandom(5);
	}
	
	private String generateRandom(int l) {
		byte[] buffer = new byte[l];
		sr.nextBytes(buffer);
		return SuperSerialNodeHelper.bytesToHex(buffer);
	}
	
	//handler for /queue context: create new context when requested, return path to created context JSON body (requires authentication token GUID)
	private class QueueHandler implements HttpHandler {
		public void handle(HttpExchange exchange) {
			try {
				OutputStream os = null;
				if(exchange.getRequestMethod().equalsIgnoreCase("GET")) {
					URI uri = exchange.getRequestURI();
					String clientToken = null;
					
					Hashtable<String,String> urlParams = SuperSerialNodeHelper.parseURLParams(uri.getQuery());
					if((urlParams!=null) && urlParams.containsKey("token")) {
						clientToken = urlParams.get("token");
					}
					
					if(token.equalsIgnoreCase(clientToken)) { //valid request: create handler and return URL
						exchange.getRequestBody().close();
						String context = "/"+generateShortRandom();
						createContext(context);
						JSONObject jsonObj = new JSONObject();
						jsonObj.put("path",context);
						String jsonReturn = jsonObj.toString(); //return newly created path as JSON parameter
						Headers respHeaders = exchange.getResponseHeaders();
						respHeaders.add("Content-Type","application/json");
						exchange.sendResponseHeaders(200,jsonReturn.length());
						os = exchange.getResponseBody();
						os.write(jsonReturn.getBytes());
						os.flush();
						os.close();
						SuperSerialNodeHelper.printLogEntry("Queue request from "+exchange.getRemoteAddress().getHostString()+" succeeded, "+context+" context added!");
					} else {
						SuperSerialNodeHelper.printLogEntry("Queue request from "+exchange.getRemoteAddress().getHostString()+" denied (wrong authentication token)");
						exchange.sendResponseHeaders(401,-1);
						os = exchange.getResponseBody();
						os.close();
					}
				} else {
					SuperSerialNodeHelper.printLogEntry("Queue request from "+exchange.getRemoteAddress().getHostString()+" denied (wrong HTTP method)");
					exchange.sendResponseHeaders(405,-1);
					os = exchange.getResponseBody();
					os.close();
				}
			} catch(IOException ioe) {
				ioe.printStackTrace();
			}
		}
	}
	
	//handler for /heartbeat context: check connection to node (requires authentication token GUID)
	private class HeartbeatHandler implements HttpHandler {
		public void handle(HttpExchange exchange) {
			try {
				//Headers reqHeaders = exchange.getRequestHeaders();
				URI uri = exchange.getRequestURI();
				String clientToken = null;
				
				Hashtable<String,String> urlParams = SuperSerialNodeHelper.parseURLParams(uri.getQuery());
				if((urlParams!=null) && urlParams.containsKey("token")) {
					clientToken = urlParams.get("token");
				}
				
				if(token.equalsIgnoreCase(clientToken)) { //valid request: return HTTP 200 to confirm that connection was successful
					JSONObject jsonObj = new JSONObject();
					jsonObj.put("message","They got attacked by Manbearpig and Manbearpig leaves no one alive, I\'m SuperSerial!");
					jsonObj.put("version",VERSION);
					String jsonReturn = jsonObj.toString(); //return newly created path as JSON parameter
					Headers respHeaders = exchange.getResponseHeaders();
					respHeaders.add("Content-Type","application/json");
					exchange.sendResponseHeaders(200,jsonReturn.length());
					OutputStream os = exchange.getResponseBody();
					os.write(jsonReturn.getBytes());
					os.flush();
					os.close();
					SuperSerialNodeHelper.printLogEntry("Heartbeat request from "+exchange.getRemoteAddress().getHostString()+" succeeded");
				} else {
					exchange.sendResponseHeaders(401,-1);
					exchange.getResponseBody().close();
					SuperSerialNodeHelper.printLogEntry("Heartbeat request from "+exchange.getRemoteAddress().getHostString()+" denied (wrong authentication token)");
				}
			} catch(IOException ioe) {
				ioe.printStackTrace();
			}
		}
	}
	
	public static void main(String[] args) {
		//parse command-line arguments
		int p = DEFAULT_PORT;
		String tk = null;
		boolean resume = false;
		if(args.length>0) {
			for(int i=0;i<args.length;i++) {
				args[i] = args[i].trim();
				String[] paramSplit = args[i].split("=",2);
				switch(paramSplit[0]) {
					case "--help":
						System.err.println("Usage: java -jar SuperSerialNode.jar [--help] [--port=[PORT]] [--token=[TOKEN]] [--resume]");
						System.err.println("--help: you\'re looking at it");
						System.err.println("--port=[PORT]: run the SuperSerial Node on port [PORT] (default: 15050)");
						System.err.println("--token=[TOKEN]: run the SuperSerial Node with authentication token [TOKEN] (format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)");
						System.err.println("--resume: during initialization, recreate any contexts from previous executions by polling current list of temporary files");
						return;
					case "--port":
						if(paramSplit.length==2) {
							try {
								p = Integer.parseInt(paramSplit[1]);
							} catch(Exception e) {
								System.err.println("Invalid port \'"+paramSplit[1]+"\' specified: falling back to default port "+Integer.toString(DEFAULT_PORT));
							}
						} else {
							System.err.println("Incomplete Option: "+args[i]+", falling back to default port "+Integer.toString(DEFAULT_PORT));
						}
						break;
					case "--token":
						if(paramSplit.length==2) {
							if(!paramSplit[1].matches("^[a-fA-F0-9\\-]*$")) { //check for correct chars. TODO: update regex to validate 8-4-4-4-12 GUIDs
								System.err.println("Supplied token "+paramSplit[1]+" in wrong format, using runtime-generated token");
							} else {
								tk = paramSplit[1];
							}
						} else {
							System.err.println("Incomplete Option: "+args[i]+", using runtime-generated token");
						}
						break;
					case "--resume":
						resume = true;
						break;
					default:
						System.err.println("Unrecognized Option: "+args[i]);
						break;
				}
			}
		}
		
		SuperSerialNode node = null;
		node = new SuperSerialNode(p,tk,resume);
		node.printSessionInfo();	
	}
}

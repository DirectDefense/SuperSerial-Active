/*
	ConnectionSettingsTab.java
	
	v0.5 (11/22/2016)
	
	UI Component for the "Node Connection Settings" configuration tab under the SuperSerial tab. Allows the user to set the necessary Node connection settings (node host, node 
	port, node protocol (HTTP/HTTPS), and node authentication token). Also allows the user to test the connection from the SuperSerial-Active extender to the Node (user must 
	test connection at least once in order to successfully set node connection settings).
*/

package superserial.ui;

import javax.swing.ButtonGroup;
import javax.swing.JRadioButton;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JButton;
import javax.swing.SwingConstants;
import java.awt.GridLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Enumeration;
import java.net.NetworkInterface;
import java.net.InetAddress;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import org.json.JSONObject;
import org.json.JSONException;
import superserial.settings.SuperSerialSettings;

class ConnectionSettingsTab extends JPanel {
	//UI fields
	private JRadioButton collabNodeField;
	private JRadioButton integratedNodeField;
	private JRadioButton externalNodeField;
	private JButton hostRefreshButton;
	private JTextField hostField;
	private JTextField portField;
	private JCheckBox protocolField;
	private JTextField tokenField;
	private JButton testConnButton;
	private JLabel statusLabel;
	
	//data fields
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private SuperSerialSettings settings;
	
	//constants
	//Node Type text
	private static final String COLLAB_RADIO_BUTTON = "Burp Collaborator";
	private static final String EXT_NODE_RADIO_BUTTON = "External SuperSerial Node";
	private static final String INT_NODE_RADIO_BUTTON = "Integrated SuperSerial Node";
	//status label codes
	static final int INVALID_HOST_CODE = 0;
	static final int INVALID_PORT_CODE = 1;
	static final int INVALID_TOKEN_CODE = 2;
	static final int CONN_ERROR_CODE = 3;
	static final int AUTH_ERROR_CODE = 4;
	static final int NOT_NODE_ERROR_CODE = 5;
	//node expected values
	private static final String nodeMessage = "They got attacked by Manbearpig and Manbearpig leaves no one alive, I\'m SuperSerial!";
	
	
	ConnectionSettingsTab(IBurpExtenderCallbacks cb) {
		super(new GridLayout(6,2));
		
		callbacks = cb;
		helpers = cb.getHelpers();
		settings = SuperSerialSettings.getInstance();
		
		add(new JLabel("Node Type:",SwingConstants.RIGHT));
		
		collabNodeField = new JRadioButton(COLLAB_RADIO_BUTTON,false);
		collabNodeField.setActionCommand(COLLAB_RADIO_BUTTON);
		externalNodeField = new JRadioButton(EXT_NODE_RADIO_BUTTON,true);
		externalNodeField.setActionCommand(EXT_NODE_RADIO_BUTTON);
		integratedNodeField = new JRadioButton(INT_NODE_RADIO_BUTTON+" (not yet supported)",false);
		integratedNodeField.setActionCommand(INT_NODE_RADIO_BUTTON);
		integratedNodeField.setEnabled(false);
		ActionListener nodeTypeAL = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				String command = ae.getActionCommand();
				switch(command) {
					case COLLAB_RADIO_BUTTON:
						settings.setNodeCollaborator(true);
						setCollaboratorUI();
						break;
					case EXT_NODE_RADIO_BUTTON:
						settings.setNodeCollaborator(false);
						settings.setNodeIntegrated(false);
						setExternalNodeUI();
						break;
					case INT_NODE_RADIO_BUTTON:
						settings.setNodeCollaborator(false);
						settings.setNodeIntegrated(true);
						setIntegratedNodeUI();
						break;
				}
				//callbacks.printError("Using "+command+" for Java Deserialization Vulnerability detection");
			}
		};
		collabNodeField.addActionListener(nodeTypeAL);
		externalNodeField.addActionListener(nodeTypeAL);
		integratedNodeField.addActionListener(nodeTypeAL);
		ButtonGroup connBG = new ButtonGroup();
		connBG.add(collabNodeField);
		connBG.add(externalNodeField);
		connBG.add(integratedNodeField);
		JPanel nodeTypePanel = new JPanel(new GridLayout(3,2));
		nodeTypePanel.add(collabNodeField);
		nodeTypePanel.add(externalNodeField);
		nodeTypePanel.add(integratedNodeField);
		add(nodeTypePanel);
		add(new JLabel("Node Host:",SwingConstants.RIGHT));
		/*JPanel hostLabelPanel = new JPanel(new GridLayout(2,1));
		hostLabelPanel.add(new JLabel("Node Host:",SwingConstants.RIGHT));
		hostRefreshButton = new JButton("Refresh Host List");
		hostRefreshButton.setEnabled(false);
		hostLabelPanel.add(hostRefreshButton);
		add(hostLabelPanel);*/
		hostField = new JTextField(settings.getNodeHost());
		add(hostField);
		add(new JLabel("Node Port:",SwingConstants.RIGHT));
		portField = new JTextField(Integer.toString(settings.getNodePort()));
		add(portField);
		add(new JLabel("Use HTTPS (not yet supported):",SwingConstants.RIGHT));
		protocolField = new JCheckBox((String) null,settings.getNodeHttps());
		protocolField.setEnabled(false);
		add(protocolField);
		add(new JLabel("Node Token (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX):",SwingConstants.RIGHT));
		tokenField = new JTextField(settings.getNodeToken());
		add(tokenField);
		testConnButton = new JButton("Test Node Connection");
		ActionListener connAL = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				
				//Thread connTestThread = new Thread(connTestRunn);
				Thread connTestThread = new Thread(new Runnable() { //TODO: create separate Runnable sub-class for this.
					public void run() {
						String host = hostField.getText();
						if(host==null) {
							setStatusError(INVALID_HOST_CODE);
							return;
						} else {
							host = host.trim();
							if(host.isEmpty()) {
								setStatusError(INVALID_HOST_CODE);
								return;
							}
						}
						
						int port = -1;
						try {
							port = Integer.parseInt(portField.getText().trim());
							if((port<1) || (port>65535)) { //specified port is out of range
								setStatusError(INVALID_PORT_CODE);
								return;
							}
						} catch(Exception e) { //specified port is non-numeric
							setStatusError(INVALID_PORT_CODE);
							return;
						}
						
						//When implemented, parse HTTPS options here
						boolean https = protocolField.isSelected();
					
						String tk = tokenField.getText().trim();
						if(!tk.matches("^[a-fA-F0-9\\-]*$")) { //TODO: update regex to validate 8-4-4-4-12 GUIDs
							setStatusError(INVALID_TOKEN_CODE);
							return;
						}
						
						statusLabel.setBackground(Color.YELLOW);
						statusLabel.setForeground(Color.BLACK);
						statusLabel.setText("Testing connection...");
						
						IHttpService httpService = helpers.buildHttpService(host,port,https);
						byte[] req = ("GET /heartbeat?token="+tk+" HTTP/1.1\r\nHost: "+host+":"+Integer.toString(port)+"\r\n\r\n").getBytes(); //consider replacing with function call
						IHttpRequestResponse heartbeatRR = callbacks.makeHttpRequest(httpService,req);
						byte[] resp = heartbeatRR.getResponse();
						IResponseInfo respInfo = null;
						if(resp!=null) //checking for a request failure/timeout
							respInfo = helpers.analyzeResponse(resp);
						if((resp!=null) && (respInfo!=null)) {
							if(respInfo.getStatusCode()==200) {
								//copy response data to string for checking
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
								String message = null;
								String version = null;
								try {
									message = (String) jsonObj.get("message");
								} catch(JSONException jse) {
									//don't care right now
								}
								try {
									version = (String) jsonObj.get("version");
								} catch(JSONException jse) {
									//don't care right now
								}
								
								if(message != null) { //if there was a "message" JSON value
									if(version != null) {
										if(message.equals(nodeMessage) && (version.equals(settings.getVersion()))) { //TODO: actually compare extender version to node version
											statusLabel.setBackground(Color.GREEN);
											statusLabel.setForeground(Color.BLACK);
											statusLabel.setText("Connection to http"+(https ? "s" : "")+"://"+host+":"+Integer.toString(port)+" successful! ("+version+" version node detected)");
										} else {
											statusLabel.setBackground(Color.ORANGE);
											statusLabel.setForeground(Color.BLACK);
											statusLabel.setText("Connection to http"+(https ? "s" : "")+"://"+host+":"+Integer.toString(port)+" successful! (Outdated "+version+" version node detected)");
										}
									} else {
										statusLabel.setBackground(Color.ORANGE);
										statusLabel.setForeground(Color.BLACK);
										statusLabel.setText("Connection to http"+(https ? "s" : "")+"://"+host+":"+Integer.toString(port)+" successful! (Unknown version node detected)");
									}
									settings.setNodeSettings(host,port,https,tk);
								} else {
									setStatusError(NOT_NODE_ERROR_CODE,host,port,https,false);
								}
							} else {
								setStatusError(AUTH_ERROR_CODE,host,port,https,false);
							}
						} else {
							setStatusError(CONN_ERROR_CODE,host,port,https,false);
						}
					}
				});
				connTestThread.start();
			}
		};
		tokenField.addActionListener(connAL);
		testConnButton.addActionListener(connAL);
		
		add(testConnButton);
		statusLabel = new JLabel("Node settings unintialized");
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
		statusLabel.setOpaque(true);
		statusLabel.setForeground(Color.WHITE);
		statusLabel.setBackground(Color.RED);
		statusLabel.setFont(new Font(statusLabel.getFont().getFontName(),Font.BOLD,statusLabel.getFont().getSize()));
		add(statusLabel);
	}
	
	void setStatusError(int errCode) {
		setStatusError(errCode,null,-1,false,false);
	}
	
	void setStatusError(int errCode,String host,int port,boolean https,boolean scan) {
		switch(errCode) {
			case INVALID_HOST_CODE:
				statusLabel.setText("Invalid Node Host specified!");
				break;
			case INVALID_PORT_CODE:
				statusLabel.setText("Invalid Node Port specified!");
				break;
			case INVALID_TOKEN_CODE:
				statusLabel.setText("Invalid Node Token specified!");
				break;
			case CONN_ERROR_CODE:
				statusLabel.setText("Connection to http"+(https ? "s" : "")+"://"+host+":"+Integer.toString(port)+" failed"+(scan ? " during scanning" : "")+"!!! (connection error/timeout)");
				break;
			case AUTH_ERROR_CODE:
				statusLabel.setText("Connection to http"+(https ? "s" : "")+"://"+host+":"+Integer.toString(port)+" failed"+(scan ? " during scanning" : "")+"!!! (wrong token)");
				break;
			case NOT_NODE_ERROR_CODE:
				statusLabel.setText("Connection to http"+(https ? "s" : "")+"://"+host+":"+Integer.toString(port)+" failed"+(scan ? " during scanning" : "")+"!!! (not a SuperSerial Node)");
				break;
			default:
				return;
		}
		statusLabel.setBackground(Color.RED);
		statusLabel.setForeground(Color.WHITE);
	}
	
	private void setCollaboratorUI() {
		//hostRefreshButton.setEnabled(false);
		hostField.setEnabled(false);
		portField.setEnabled(false);
		protocolField.setEnabled(false); //will be set to true once Burp Collaborator HTTPS is supported
		tokenField.setEnabled(false);
		testConnButton.setEnabled(false);
		statusLabel.setBackground(Color.ORANGE);
		statusLabel.setForeground(Color.BLACK);
		statusLabel.setText("Using Burp Collaborator for vulnerability detection. Manage Collaborator connection in \"Project options\"->Misc->\"Burp Collaborator Server\".");
	}
	
	private void setExternalNodeUI() {
		//hostRefreshButton.setEnabled(false);
		hostField.setEnabled(true);
		portField.setEnabled(true);
		protocolField.setEnabled(false); //will be set to true once SuperSerial Node HTTPS is supported
		tokenField.setEnabled(true);
		testConnButton.setEnabled(true);
		statusLabel.setForeground(Color.WHITE);
		statusLabel.setBackground(Color.RED);
		statusLabel.setText("Node settings unintialized");
	}
	
	private void setIntegratedNodeUI() {
		//hostRefreshButton.setEnabled(true);
		hostField.setEnabled(true);
		portField.setEnabled(true);
		protocolField.setEnabled(false); //will be set to true once SuperSerial Node HTTPS is supported
		tokenField.setEnabled(true);
		testConnButton.setEnabled(true);
	}
	
	private String[] getNetworkAddress() {
		ArrayList<String> addrList = new ArrayList<String>();
		try {
			Enumeration e = NetworkInterface.getNetworkInterfaces();
			while(e.hasMoreElements())
			{
				NetworkInterface n = (NetworkInterface) e.nextElement();
				Enumeration ee = n.getInetAddresses();
				while (ee.hasMoreElements())
				{
					InetAddress i = (InetAddress) ee.nextElement();
					addrList.add(i.getHostAddress());
				}
			}
		} catch(Exception e) {
			return null;
		}
		String[] retArr = new String[addrList.size()];
		return addrList.toArray(retArr);
	}
}

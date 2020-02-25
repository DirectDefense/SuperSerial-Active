/*
	SuperSerialConfigTab.java
	
	v0.3 (3/10/2016)
	
	Main UI component for the SuperSerial-Active extender configuration tab, which is registered with Burp using the IBurpExtenderCallbacks.addSuiteTab() method. Contains the 
	"Node Connection Settings" and "Scan Settings" tabs. May eventually contain additional configuration/other tabs pertaining to SuperSerial-Active.
*/

package superserial.ui;

import javax.swing.JTabbedPane;
import java.awt.Component;
import burp.IBurpExtenderCallbacks;

public class SuperSerialConfigTab extends JTabbedPane {
	private IBurpExtenderCallbacks callbacks;
	
	//ITab fields
	private String caption;
	
	//UI fields
	private ConnectionSettingsTab connSettingsTab;
	private ScanSettingsTab scanSettingsTab;
	//Help/Tutorial tab will eventually be here
	
	//constants
	//node connection
	public static final int INVALID_HOST_CODE = ConnectionSettingsTab.INVALID_HOST_CODE;
	public static final int INVALID_PORT_CODE = ConnectionSettingsTab.INVALID_PORT_CODE;
	public static final int INVALID_TOKEN_CODE = ConnectionSettingsTab.INVALID_TOKEN_CODE;
	public static final int CONN_ERROR_CODE = ConnectionSettingsTab.CONN_ERROR_CODE;
	public static final int AUTH_ERROR_CODE = ConnectionSettingsTab.AUTH_ERROR_CODE;
	
	public SuperSerialConfigTab(IBurpExtenderCallbacks cb) {
		super();
		callbacks = cb;
		caption = "SuperSerial";
		connSettingsTab = new ConnectionSettingsTab(callbacks);
		scanSettingsTab = new ScanSettingsTab(callbacks);
		addTab("Node Connection Settings",connSettingsTab);
		addTab("Scan Settings",scanSettingsTab);
	}
	
	public void setStatusError(int errCode,String host,int port,boolean https,boolean scan) {
		connSettingsTab.setStatusError(errCode,host,port,https,scan);
	}
}

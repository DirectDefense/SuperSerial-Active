/*
	ScanSettingsTab.java
	
	v0.4 (7/27/2016)
	
	UI Component for the "Scan Settings" configuration tab under the SuperSerial tab. Allows the user to set settings related to the Active Scan checks performed by the 
	SuperSerial-Active extender (scan all parameters option, number of Node download attempts, time to wait between attempts). Also allows users to enable/disable the 
	different ysoserial payload types used during and Active Scan, as well as add/edit/delete operating commands used during scanning.
*/

package superserial.ui;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.TableModelListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import java.awt.GridLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.ItemListener;
import java.awt.event.ItemEvent;
import java.util.Hashtable;

import burp.IBurpExtenderCallbacks;
import burp.PayloadCommandFactory;
import burp.PayloadTypeFactory;
import superserial.settings.SuperSerialSettings;

class ScanSettingsTab extends JPanel {
	//UI fields
	private JCheckBox scanAllField;
	private JTextField numAttemptsField;
	private JTextField waitTimeField;
	private JButton typesAllButton;
	private JButton typesNoneButton;
	private JCheckBox[] typesFields;
	private JButton cmdUpButton;
	private JButton cmdDownButton;
	private JButton cmdAddButton;
	private JButton cmdRemoveButton;
	private JTable cmdTable;
	private CommandTableModel dtm;
	
	//data fields
	private SuperSerialSettings settings;
	private PayloadCommandFactory pcf;
	private PayloadTypeFactory ptf;
	private IBurpExtenderCallbacks callbacks;

	ScanSettingsTab(IBurpExtenderCallbacks cb) {
		super(new GridLayout(5,2));
		
		settings = SuperSerialSettings.getInstance();
		pcf = PayloadCommandFactory.getInstance();
		ptf = PayloadTypeFactory.getInstance();
		callbacks = cb;
		
		add(new JLabel("Automatically test all parameters: (WARNING: This will significantly increase scan duration!):",SwingConstants.RIGHT));
		scanAllField = new JCheckBox((String) null,settings.getScanAll());
		scanAllField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				JCheckBox jcb = (JCheckBox) ae.getSource();
				if(jcb.isSelected()) {
					if(JOptionPane.showConfirmDialog(null,"Are you sure you want to automatically test all parameters?\nThis will SIGNIFICANTLY increase active scan duration."+
								"\nOnly enable this setting if needed.","Confirm",JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE)==JOptionPane.YES_OPTION) {
						settings.setScanSettings(settings.getDownloadTries(),settings.getWaitTime(),true);
					} else {
						jcb.setSelected(false);
						settings.setScanSettings(settings.getDownloadTries(),settings.getWaitTime(),false);
					}
				} else {
					settings.setScanSettings(settings.getDownloadTries(),settings.getWaitTime(),false);
				}
			}
		});
		add(scanAllField);
		add(new JLabel("Number of download attempts:",SwingConstants.RIGHT));
		numAttemptsField = new JTextField(Integer.toString(settings.getDownloadTries()));
		numAttemptsField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent de) {
				changeAttempts();
			}
			public void insertUpdate(DocumentEvent de) {
				changeAttempts();
			}
			public void removeUpdate(DocumentEvent de) {
				changeAttempts();
			}
			public void changeAttempts() {
				try{
					settings.setScanSettings(Integer.parseInt(numAttemptsField.getText()),settings.getWaitTime(),settings.getScanAll());
				} catch(Exception e) {
					callbacks.issueAlert("Scan Settings: Invalid download attemps value!");
				}
			}
		});
		add(numAttemptsField);
		add(new JLabel("Milliseconds to wait between tries (1000 = 1 sec):",SwingConstants.RIGHT));
		waitTimeField = new JTextField(Integer.toString(settings.getWaitTime()));
		waitTimeField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent de) {
				changeTime();
			}
			public void insertUpdate(DocumentEvent de) {
				changeTime();
			}
			public void removeUpdate(DocumentEvent de) {
				changeTime();
			}
			public void changeTime() {
				try{
					settings.setScanSettings(settings.getDownloadTries(),Integer.parseInt(waitTimeField.getText()),settings.getScanAll());
				} catch(Exception e) {
					callbacks.issueAlert("Scan Settings: Invalid wait time value!");
				}
			}
		});
		add(waitTimeField);
		
		//create payload types label and buttons
		JPanel typesButtonPanel = new JPanel(new GridLayout(3,1,3,0));
		typesButtonPanel.add(new JLabel("Enabled ysoserial Payload Types:",SwingConstants.RIGHT));
		typesAllButton = new JButton("Enable All");
		typesAllButton.setActionCommand("Enable All");
		typesNoneButton = new JButton("Enable None");
		typesNoneButton.setActionCommand("Enable None");
		ActionListener typeButtonAL = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				switch(ae.getActionCommand()) {
					case "Enable All":
						for(int i=0;i<typesFields.length;i++) {
							typesFields[i].setSelected(true);
						}
						break;
					case "Enable None":
						for(int i=0;i<typesFields.length;i++) {
							typesFields[i].setSelected(false);
						}
						break;
				}
			}
		};
		typesAllButton.addActionListener(typeButtonAL);
		typesNoneButton.addActionListener(typeButtonAL);
		typesButtonPanel.add(typesAllButton);
		typesButtonPanel.add(typesNoneButton);
		
		//create payload types checkbox grid
		int typeCount = ptf.getTypesCount();
		String[] types = ptf.getAllTypes();
		int rowCount = (typeCount/4);
		int lastRowCount = typeCount%4;
		if(lastRowCount>0) rowCount++;
		GridLayout tcpGrid = new GridLayout(rowCount,4);
		JPanel typesCheckPanel = new JPanel(tcpGrid);
		typesFields = new JCheckBox[types.length];
		ItemListener typeCheckBoxIL = new ItemListener() {
			public void itemStateChanged(ItemEvent ie) {
				JCheckBox jcb = (JCheckBox) ie.getItem();
				switch(ie.getStateChange()) {
					case ItemEvent.SELECTED:
						ptf.toggleType(jcb.getText(),true);
						break;
					case ItemEvent.DESELECTED:
						ptf.toggleType(jcb.getText(),false);
						break;
				}
			}
		};
		int l=0;
		//create checkboxes
		for(int j=0;j<typesFields.length;j++) {
			typesFields[j] = new JCheckBox(types[l++],false);
			typesFields[j].addItemListener(typeCheckBoxIL);
		}
		//check boxes for enabled types
		types = ptf.getEnabledTypes();
		for(int j=0;j<types.length;j++) {
			for(int k=0;k<typesFields.length;k++) {
				if(typesFields[k].getText().equals(types[j])) {
					typesFields[k].setSelected(true);
					break;
				}
			}
		}
		//populate grid; TODO: sort alphetically by columns instead of rows
		for(int j=0;j<typesFields.length;j++) {
			typesCheckPanel.add(typesFields[j]);
		}
		
		//add components to panel
		add(typesButtonPanel);
		add(typesCheckPanel);
		
		//create panel for buttons
		JPanel cmdButtonPanel = new JPanel(new GridLayout(4,1,0,2));
		cmdUpButton = new JButton("Move Selected Command Up");
		cmdDownButton = new JButton("Move Selected Command Down");
		cmdAddButton = new JButton("Add New Command");
		cmdRemoveButton = new JButton("Remove Selected Command(s)");
		ActionListener cmdButtonAL = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				JButton jb = (JButton) ae.getSource();
				String buttonText = jb.getText();
				int selectedCount = cmdTable.getSelectedRowCount();
				int[] selectedRows = cmdTable.getSelectedRows();
				int rowCount = cmdTable.getRowCount();
				
				if(buttonText.contains("Add")) { //add new command (if blank row is not already created)
					//check if table contains rows and if last row command is blank
					if(dtm.getRowCount()>0) {
						String cmd = (String) dtm.getValueAt(rowCount-1,0);
						if(cmd!=null) cmd = cmd.trim();
						int select = rowCount;
						if((cmd!=null) && (!cmd.isEmpty())) { //if command is inputted
							dtm.addRow(new Object[] {"","Unknown",false});
						} else { //if command is blank
							select--;
						}
						cmdTable.setRowSelectionInterval(select,select);
						cmdTable.setColumnSelectionInterval(0,0);
					} else { //if table is blank, add new row
						dtm.addRow(new Object[] {"","Unknown",false});
						cmdTable.setRowSelectionInterval(0,0);
						cmdTable.setColumnSelectionInterval(0,0);
					}
				} else if(selectedRows.length!=0) { //if at least one row is selected
					if(buttonText.contains("Remove")) { //remove the selected rows; if 1 row is selected, selected the next row
						for(int i=(selectedRows.length-1);i>-1;i--) {
							pcf.remove(selectedRows[i]);
							dtm.removeRow(selectedRows[i]);
						}
						rowCount = cmdTable.getRowCount();
						if(selectedRows.length==1) { //only one row was selected/deleted
							if(rowCount>0) {
								int selected = selectedRows[0]-1;
								if(selectedRows[0]==rowCount) { //if last row was removed
									selected = rowCount-1;
								} else if(selectedRows[0]==0) { //if first row was removed
									selected = 0;
								}
								cmdTable.setRowSelectionInterval(selected,selected);
							}
						}
					} else if(selectedRows.length==1) { //if only 1 row is selected
						if(buttonText.contains("Up")) { //if a row besides the top row or bottom row that contains a blank command is selected, move the selected row up one
							if(selectedRows[0]!=0) {
								boolean swap = true;
								if(selectedRows[0]==(rowCount-1)) {
									String cmd = (String) dtm.getValueAt(selectedRows[0],0);
									String os = (String) dtm.getValueAt(selectedRows[0],1);
									if(cmd!=null && os!=null) {
										if(cmd.isEmpty() || os.isEmpty()) {
											swap = false;
										}
									} else {
										swap = false;
									}
								}
								if(swap) {
									pcf.swap((String) dtm.getValueAt(selectedRows[0],0),(String) dtm.getValueAt(selectedRows[0]-1,0));
									dtm.moveRow(selectedRows[0],selectedRows[0],selectedRows[0]-1);
									cmdTable.setRowSelectionInterval(selectedRows[0]-1,selectedRows[0]-1);
								}
							}
						} else if(buttonText.contains("Down")) { //if a row besides the bottom row is selected, move the selected row down one
							if(selectedRows[0]!=rowCount-1) {
								pcf.swap((String) dtm.getValueAt(selectedRows[0],0),(String) dtm.getValueAt(selectedRows[0]+1,0));
								dtm.moveRow(selectedRows[0],selectedRows[0],selectedRows[0]+1);
								cmdTable.setRowSelectionInterval(selectedRows[0]+1,selectedRows[0]+1);
							}
						}
					}
				}
			}
		};
		cmdUpButton.addActionListener(cmdButtonAL);
		cmdDownButton.addActionListener(cmdButtonAL);
		cmdAddButton.addActionListener(cmdButtonAL);
		cmdRemoveButton.addActionListener(cmdButtonAL);
		cmdButtonPanel.add(cmdUpButton);
		cmdButtonPanel.add(cmdDownButton);
		cmdButtonPanel.add(cmdAddButton);
		cmdButtonPanel.add(cmdRemoveButton);
		
		//create commands table
		Hashtable[] cmdHT = pcf.getCommandsArray();
		cmdTable = new JTable(new CommandTableModel());
		dtm = (CommandTableModel) cmdTable.getModel();
		dtm.addTableModelListener(new TableModelListener() {
			public void tableChanged(TableModelEvent tme) {
				switch(tme.getType()) {
					case TableModelEvent.UPDATE:
						int firstRow = tme.getFirstRow();
						int lastRow = tme.getLastRow();
						if(firstRow==lastRow) { //only one row updated (command editted)
							if(lastRow == dtm.getRowCount()-1) {
								String cmd = (String) dtm.getValueAt(lastRow,0);
								String os = (String) dtm.getValueAt(lastRow,1);
								boolean upload = (Boolean) dtm.getValueAt(lastRow,2);
								if(lastRow>=pcf.getCommandsCount()) { //add new command
									pcf.add(cmd,os,"web",upload);
								} else { //edit existing command
									pcf.edit(lastRow,cmd,os,"web",upload);
								}
							} else {
								String cmd = (String) dtm.getValueAt(lastRow,0);
								String os = (String) dtm.getValueAt(lastRow,1);
								boolean upload = (Boolean) dtm.getValueAt(lastRow,2);
								pcf.edit(lastRow,cmd,os,"web",upload);
							}
						}
						break;
				}
			}
		});
		
		//populate table with default built-in commands
		for(int i=0;i<cmdHT.length;i++) {
			Hashtable cmd = cmdHT[i];
			dtm.addRow(new Object[] {cmd.get("cmd"),cmd.get("os"),new Boolean(Boolean.parseBoolean((String) cmd.get("upload")))});
		}
		
		//add buttons and table to panel
		add(cmdButtonPanel);
		add(new JScrollPane(cmdTable));
	}
	
	private class CommandTableModel extends DefaultTableModel {
		
		public CommandTableModel() {
			super(new String[] {"Command","OS","File Upload"},0);
		}
		
		@Override
		public Class<?> getColumnClass(int columnIndex) {
			Class c = String.class;
			switch(columnIndex) {
				case 2: c = Boolean.class;
			}
			return c;
		}
		
		@Override
		public boolean isCellEditable(int row, int column) {
			return true;
		}
	}
}

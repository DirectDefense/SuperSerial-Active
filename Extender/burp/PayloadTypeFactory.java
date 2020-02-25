/*
	PayloadTypeFactory.java
	
	0.4 (7/27/2016)
	
	Maintains list of Hashtables containing enabled ysoserial payload types that will be used by the active scanner. Used by the SuperSerial->"Scan Settings" tab during 
	initialization to create the necessary checkboxes, thereby supporting ysoserial versions >=0.0.3. Flags payload types as "stable" 
	(ysoserial.payloads.annotations.Dependencies.Utils.getDependencies(payloadClass) returns results) or "unstable" (Dependencies.Utils.getDependencies(payloadClass) 
	does not return any results), and automatically enables any types marked as "stable".
	
	Hashtable keys:
		type (name of payload type)
		enabled (whether type is enabled)
		stability (whether type is "stable" or "unstable")
*/

package burp;

//standard includes
import java.util.List;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

//third-party includes
import ysoserial.GeneratePayload;
import ysoserial.GeneratePayload.ToStringComparator;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.annotation.Dependencies;

public class PayloadTypeFactory {
	//data fields
	private static PayloadTypeFactory typeFactory = null;
	private ArrayList<Hashtable<String,String>> types;
	private IBurpExtenderCallbacks callbacks = null;
	
	//constants
	//keys
	private static final String[] HT_KEYS = {"type","enabled","stability"};
	//values
	private static final String STABLE = "stable";
	private static final String UNSTABLE = "unstable";
	
	//default constructor (and include IBurpExtenderCallbacks reference for printing output)
	private PayloadTypeFactory(IBurpExtenderCallbacks cb) {
		initFields();
		callbacks = cb;
	}
	
	//instantiate PayloadTypeFactory with default settings: all payload types
	private void initFields() {
		types = new ArrayList<Hashtable<String,String>>();
		
		//get payload list
		final List<Class<? extends ObjectPayload>> payloadClasses = new ArrayList<Class<? extends ObjectPayload>>(ObjectPayload.Utils.getPayloadClasses());
		Collections.sort(payloadClasses, new ToStringComparator()); // alphabetize
		for (Class<? extends ObjectPayload> payloadClass : payloadClasses) {
			List<String> deps = Arrays.asList(Dependencies.Utils.getDependencies(payloadClass));
			Hashtable<String,String> type = new Hashtable<String,String>();
			type.put(HT_KEYS[0],payloadClass.getSimpleName());
			if(deps.isEmpty()) {
				type.put(HT_KEYS[1],Boolean.toString(false));
				type.put(HT_KEYS[2],UNSTABLE);
			} else {
				type.put(HT_KEYS[1],Boolean.toString(true));
				type.put(HT_KEYS[2],STABLE);
			}
			types.add(type);
		}
	}
	
	//get PayloadTypeFactory instance for use elsewhere
	public static PayloadTypeFactory getInstance() {
		if(typeFactory == null) {
			typeFactory = new PayloadTypeFactory(null);
		}
		return typeFactory;
	}
	
	//get PayloadTypeFactory instance for use elsewhere
	//NOTE: this is only intended to be called in BurpExtender.registerExtenderCallbacks(), so that the IBurpExtenderCallbacks reference can be successfully added
	public static PayloadTypeFactory getInstance(IBurpExtenderCallbacks cb) {
		if(typeFactory == null) {
			typeFactory = new PayloadTypeFactory(cb);
		}
		return typeFactory;
	}
	
	//get number of payload types
	public int getTypesCount() {
		return types.size();
	}
	
	//get full list of payload types
	public String[] getAllTypes() {
		Iterator<Hashtable<String,String>> itr = types.iterator();
		String[] retArr = new String[types.size()];
		int i=0;
		while(itr.hasNext()) {
			Hashtable<String,String> ht = itr.next();
			retArr[i] = ht.get(HT_KEYS[0]);
			i++;
		}
		return retArr;
	}
	
	//get list of enabled payload types
	public String[] getEnabledTypes() {
		Iterator<Hashtable<String,String>> itr = types.iterator();
		int size = 0;
		while(itr.hasNext()) {
			Hashtable<String,String> ht = itr.next();
			if(ht.get(HT_KEYS[1]).equals(Boolean.toString(true))) {
				size++;
			}
		}
		
		String[] retArr = new String[size];
		if(retArr.length>0){
			itr = types.iterator();
			int i=0;
			while(itr.hasNext()) {
				Hashtable<String,String> ht = itr.next();
				if(ht.get(HT_KEYS[1]).equals(Boolean.toString(true))) {
					retArr[i] = ht.get(HT_KEYS[0]);
					i++;
				}
			}
		}
		
		return retArr;
	}
	
	//set inputted type to enabled/disabled
	public void toggleType(String type,boolean en) {
		Iterator<Hashtable<String,String>> itr = types.iterator();
		while(itr.hasNext()) {
			Hashtable<String,String> ht = itr.next();
			if(ht.get(HT_KEYS[0]).equals(type)) {
				ht.put(HT_KEYS[1],Boolean.toString(en));
				break;
			}
		}
	}
}

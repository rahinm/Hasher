package net.dollmar.tools;

import java.util.HashMap;
import java.util.Map;

public enum DataLabel {

	TEXT("Text String"),
	HEX("Hex String"),
	BASE64("Base64 String"),
	FILE("File");
	
	private static final Map<String, DataLabel> BY_LABEL = new HashMap<>();
	
	private final String label;

	static {
		for (DataLabel te: values()) {
			BY_LABEL.put(te.label, te);
		}
	}
	
	private DataLabel(String enc) {
		label = enc;
	}
	
	
	public String getLabel() {
		return label;
	}
	
	
	public static DataLabel valueOfLabel(String label) {
		return BY_LABEL.get(label);
	}
}

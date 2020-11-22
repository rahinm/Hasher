package net.dollmar.tools;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.security.Security;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * This is a simple GUI tool to calculate hash (message digest) of an
 * input data or the contents of an input file. The tool also supports 
 * calculation of HMAC of the same input.
 * 
 * A number of hashing algorithms are supported.
 * 
 * This tool is a clone of the HashCalc tool developed by SlavaSoft
 * (https://www.slavasoft.com/hashcalc/index.htm).
 * 
 * This is a free software. Permission is granted for all forms of use 
 * except for any form intended for causing malicious damage.
 * 
 * @author Mohammad A. Rahin
 *
 */
public class Hasher extends JFrame {
	private static final long serialVersionUID = -4765249574155179019L;

	private static final String VERSION_NUMBER = "1.0";
	private static final String COPYRIGHT = "(c) 2020 Dollmar Enterprised Ltd.";

	public static class DigestAlgorithm {
		private String algName;

		private String hmacAlgName;

		public DigestAlgorithm(String an, String han) {
			this.algName = an;
			this.hmacAlgName = han;
		}

		public String getAlgName() {
			return algName;
		}

		public String getHmacAlgName() {
			return hmacAlgName;
		}
		
		public boolean isHmacEligible() {
			return this.hmacAlgName != null;
		}
	}

	public static class DigestWidget {
		private JCheckBox sb;
		private JTextField value;

		public DigestWidget(String name, JPanel parent) {
			sb = new JCheckBox(name);
			value = new JTextField(30);
			value.setEditable(false);

			parent.add(sb);
			parent.add(value);
		}

		public boolean isSelected() {
			return sb.isSelected();
		}

		public void setSelected(boolean flag) {
			sb.setSelected(flag);
		}

		public boolean isEnabled() {
			return sb.isEnabled();
		}
		
		public void setEnabled(boolean falg) {
			sb.setEnabled(falg);
		}


		public String getValue() {
			return value.getText().trim();
		}

		public void setValue(String v) {
			value.setText(v);
			value.requestFocus();
			value.setCaretPosition(0);
		}
	}


	private static DigestAlgorithm[] ALGOS = 
		{
				new DigestAlgorithm("MD5", "HmacMD5"),
				new DigestAlgorithm("RIPEMD128", "HmacRIPEMD128"),
				new DigestAlgorithm("RIPEMD160", "HmacRIPEMD160"),
				new DigestAlgorithm("RIPEMD256", null),
				new DigestAlgorithm("SHA1", "HmacSHA1"),
				new DigestAlgorithm("SHA256", "HmacSHA256"),
				new DigestAlgorithm("SHA384", "HmacSHA384"),
				new DigestAlgorithm("SHA512", "HmacSHA512"),
				new DigestAlgorithm("Tiger", null),
				new DigestAlgorithm("Whirlpool", null)
		};

	private JComboBox<String> dataSource;
	private JTextField dataToHash;
	private JButton fsButton;

	private JCheckBox hmac;
	private JComboBox<String> keyFormat;
	private JTextField hmacKey;

	private JButton calculateBtn;
	private JButton clearBtn;
	private JButton quitBtn;
	private JButton helpBtn;

	private DigestWidget[] digestWidgets = new DigestWidget[ALGOS.length];

	private void buildDisgestWidgets(JPanel parent) {
		for (int i = 0; i < ALGOS.length; i++) {
			digestWidgets[i] = new DigestWidget(ALGOS[i].algName, parent);
			digestWidgets[i].setEnabled(ALGOS[i].isHmacEligible() || !isHmacSelected());
			digestWidgets[i].setSelected(ALGOS[i].isHmacEligible() || !isHmacSelected());
		}
	}

	private void setDisgestWidgets() {
		for (int i = 0; i < ALGOS.length; i++) {
			if (digestWidgets[i] != null) {
				digestWidgets[i].setEnabled(ALGOS[i].isHmacEligible() || !isHmacSelected());
				digestWidgets[i].setSelected(ALGOS[i].isHmacEligible() || !isHmacSelected());
			}
		}
	}

	private boolean isFileSourceSelected() {
		String item = (dataSource != null) ? dataSource.getItemAt(dataSource.getSelectedIndex()) : "";
		return "File".equals(item);
	}

	private String getDataSourceType() {
		return (dataSource != null) ? dataSource.getItemAt(dataSource.getSelectedIndex()) : "";
	}
	
	private boolean isHmacSelected() {
		return (hmac != null) ? hmac.isSelected() : false;
	}

	private String getKeyFormat() {
		return (keyFormat != null) ? keyFormat.getItemAt(keyFormat.getSelectedIndex()) : "";
	}
	
	
	private void setFsButtonState() {
		if (fsButton != null) {
			fsButton.setEnabled(isFileSourceSelected());
		}
	}

	
	private void calculateHashValues() {
		String dsType = getDataSourceType();
		String keyData = hmacKey.getText().trim();
		boolean hexEncodedKey = "Hex String".equals(getKeyFormat());

		if (isHmacSelected() && (keyData == null || keyData.length() == 0)) {
			this.showErrorMessageDialog("Error: Missing HMAC Key");
			return;
		}
		
		if ("File".equals(dsType)) {
			String fileName = dataToHash.getText().trim();
			for (int i = 0; i < digestWidgets.length; i++) {
				DigestWidget dw = digestWidgets[i];
				if (dw != null & dw.isEnabled() && dw.isSelected()) {
					String result = null;
					if (isHmacSelected()) {
						result = HmacCalculator.calculateFileHmac(ALGOS[i].hmacAlgName, fileName, keyData, hexEncodedKey);
					}
					else {
						result = HashCalculator.calculateFileHash(ALGOS[i].algName, fileName);
					}
					dw.setValue(result);
				}
			}
		}
		else {
			String messageData = dataToHash.getText().trim();
			boolean hexEncodedData = "Hex String".equals(dsType);
			
			for (int i = 0; i < digestWidgets.length; i++) {
				DigestWidget dw = digestWidgets[i];
				if (dw != null & dw.isEnabled() && dw.isSelected()) {
					String result = null;
					if (isHmacSelected()) {
						result = HmacCalculator.calculateHmac(ALGOS[i].hmacAlgName, messageData, hexEncodedData, keyData, hexEncodedKey);
					}
					else {
						result = HashCalculator.calculateHash(ALGOS[i].algName, messageData, hexEncodedData);
					}
					dw.setValue(result);
				}
			}
		}
	}

	
	private void clearHashValues() {
		for (int i = 0; i < digestWidgets.length; i++) {
			DigestWidget dw = digestWidgets[i];
			if (dw != null) {
				dw.setValue("");
			}
		}
		
	}
	
	public Hasher() {
		super("Hasher");

		Container contentPane = getContentPane();

		setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
		JPanel hdrPanel = new JPanel();
		hdrPanel.setLayout(new GridLayout(2, 1, 0, 0));
		hdrPanel.setBorder(BorderFactory.createTitledBorder(""));
		contentPane.add(hdrPanel);

		JLabel header = new JLabel("<html><h4><FONT COLOR=RED>Hasher: Message hash/digest calculator</FONT></h4></html>", JLabel.CENTER);
		JLabel vInfo = new JLabel("Version: " + VERSION_NUMBER + ", " + COPYRIGHT, JLabel.CENTER);
		hdrPanel.add(header);
		hdrPanel.add(vInfo);

		JPanel dataPanel = new JPanel();
		dataPanel.setBorder(BorderFactory.createTitledBorder("Data"));
		dataPanel.setLayout(new GridLayout2(2, 3, 5, 0));
		contentPane.add(dataPanel);

		dataPanel.add(new JLabel("Source")); 
		dataPanel.add(new JLabel("Data"));
		dataPanel.add(new JLabel(""));

		String sources[] = {"File", "Text String", "Hex String" };
		dataSource = new JComboBox<String>(sources);
		//dataSource.setPreferredSize(new Dimension(5, 10));
		ItemListener dsListener = new ItemListener() {

			public void itemStateChanged(ItemEvent e) {
				setFsButtonState();
			}
		};
		dataSource.addItemListener(dsListener);
		dataPanel.add(dataSource);

		dataToHash = new JTextField(20);
		dataPanel.add(dataToHash);

		fsButton = new JButton("...");
		fsButton.setPreferredSize(new Dimension(20, 10));
		setFsButtonState();
		ActionListener doChooseFile = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
				int rc = jfc.showOpenDialog(null);
				if (rc == JFileChooser.APPROVE_OPTION) {
					File selectedFile = jfc.getSelectedFile();
					if (dataToHash != null) {
						dataToHash.setText(selectedFile.getAbsolutePath());
					}
				}
			}
		};
		fsButton.addActionListener(doChooseFile);
		dataPanel.add(fsButton);

		JPanel hmacPanel = new JPanel();
		hmacPanel.setBorder(BorderFactory.createTitledBorder("HMAC"));
		hmacPanel.setLayout(new GridLayout2(2, 3, 5, 0));
		contentPane.add(hmacPanel);

		hmacPanel.add(new JLabel()); 
		hmacPanel.add(new JLabel("Key Format"));
		hmacPanel.add(new JLabel("Key"));

		hmac = new JCheckBox("Apply HMAC Key");
		ItemListener hmacEnabler = new ItemListener() {

			public void itemStateChanged(ItemEvent e) {
				boolean state = isHmacSelected();
				if (keyFormat != null) keyFormat.setEnabled(state);
				if (hmacKey != null) hmacKey.setEnabled(state);
				setDisgestWidgets();
			}
		}; 
		hmac.addItemListener(hmacEnabler);
		hmacPanel.add(hmac);

		String keyFormats[] = {"Text String", "Hex String" };
		keyFormat = new JComboBox<String>(keyFormats);
		keyFormat.setEnabled(hmac.isSelected());
		hmacPanel.add(keyFormat);

		hmacKey = new JTextField(20);
		hmacKey.setEnabled(hmac.isSelected());
		hmacPanel.add(hmacKey);


		JPanel resultsPanel = new JPanel();
		resultsPanel.setBorder(BorderFactory.createTitledBorder("Calculated hash values"));
		resultsPanel.setLayout(new GridLayout2(ALGOS.length, 2, 5, 5));
		contentPane.add(resultsPanel);

		this.buildDisgestWidgets(resultsPanel);

		JPanel btnPanel = new JPanel();
		btnPanel.setBorder(BorderFactory.createTitledBorder(""));
		btnPanel.setLayout(new GridLayout(1, 4));
		contentPane.add(btnPanel);

		calculateBtn = new JButton("Calculate");
		calculateBtn.setToolTipText("Calculates hash values");
		ActionListener doCalculateHash = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				calculateHashValues();
			}
		};
		ActionListener calcHash = CursorController.createListener(this, doCalculateHash);
		calculateBtn.addActionListener(calcHash);
		btnPanel.add(calculateBtn);


		clearBtn = new JButton("Clear");
		clearBtn.setToolTipText("Clears all hash values");
		ActionListener doClearHash = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				clearHashValues();
			}
		};
		clearBtn.addActionListener(doClearHash);
		btnPanel.add(clearBtn);
		
		quitBtn = new JButton("QUIT");
		ActionListener doQuit = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				System.exit(ABORT);
			}
		}; 
		quitBtn.addActionListener(doQuit);
		btnPanel.add(quitBtn);

		helpBtn = new JButton("Help");
		helpBtn.setToolTipText("Online help");
		ActionListener doHelp = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				showInfoMessageDialog("Coming soon ....");
			}
		};
		helpBtn.addActionListener(doHelp);
		btnPanel.add(helpBtn);

		setDefaultCloseOperation(EXIT_ON_CLOSE);
		setSize(300, 600);
		// Place the dialog at the centre of the screen
		final Toolkit toolkit = Toolkit.getDefaultToolkit();
		final Dimension screenSize = toolkit.getScreenSize();
		final int x = (screenSize.width - getWidth()) / 2;
		final int y = (screenSize.height - getHeight()) / 2;
		setLocation(x, y);	    	    

		setResizable(false);
		setVisible(true);
		pack();
	}

	public static void setLook() {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} 
		catch (Exception ex) {
		}
	}


	private void showErrorMessageDialog(final String msg) {
		JOptionPane.showMessageDialog(this, msg, "ERROR", JOptionPane.ERROR_MESSAGE);
	}

	private void showInfoMessageDialog(final String msg) {
		JOptionPane.showMessageDialog(this, msg, "Information", JOptionPane.INFORMATION_MESSAGE);
	}

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		setLook();
		new Hasher();
	}
}


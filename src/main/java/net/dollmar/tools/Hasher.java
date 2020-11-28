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
 * This tool is inspired by the HashCalc tool developed by SlavaSoft
 * (https://www.slavasoft.com/hashcalc/index.htm).
 * 
 * This is a free software. Permission is granted for all forms of use 
 * except for any form intended for causing malicious damage.
 * 
 * @author Mohammad A. Rahin / Dollmar Enterprises Ltd
 *
 */
public class Hasher extends JFrame {
	private static final long serialVersionUID = -4765249574155179019L;

	private static final String VERSION_NUMBER = "1.1";
	private static final String COPYRIGHT = "(c) 2020 Dollmar Enterprises Ltd.";

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
	
	private boolean hexEncodedOutput = true;
	private boolean upcasedOutput = false;

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


	private String getComboBoxLabel(JComboBox<String> cb) {
		return (cb != null) ? cb.getItemAt(cb.getSelectedIndex()) : "";
	}

	
	private boolean isHmacSelected() {
		return (hmac != null) ? hmac.isSelected() : false;
	}

	private void setFsButtonState() {
		if (fsButton != null) {
			fsButton.setEnabled(isFileSourceSelected());
		}
	}

	
	/*
	 * Performs calculation of Hash or HMAC values
	 */
	private void calculateHashValues() {
		// data source
		DataLabel ds = DataLabel.valueOfLabel(getComboBoxLabel(dataSource));
		// key
		DataLabel kf = DataLabel.valueOfLabel(getComboBoxLabel(keyFormat));

		String keyData = hmacKey.getText().trim();

		if (isHmacSelected() && (keyData == null || keyData.length() == 0)) {
			this.showErrorMessageDialog("Error: Missing HMAC Key");
			return;
		}
		
		if (DataLabel.FILE.equals(ds)) {
			String fileName = dataToHash.getText().trim();
			for (int i = 0; i < digestWidgets.length; i++) {
				DigestWidget dw = digestWidgets[i];
				if (dw != null & dw.isEnabled() && dw.isSelected()) {
					String result = null;
					if (isHmacSelected()) {
						result = HmacCalculator.calculateFileHmac(ALGOS[i].hmacAlgName, fileName, keyData, kf, hexEncodedOutput, upcasedOutput);
					}
					else {
						result = HashCalculator.calculateFileHash(ALGOS[i].algName, fileName, hexEncodedOutput, upcasedOutput);
					}
					dw.setValue(result);
				}
			}
		}
		else {
			String messageData = dataToHash.getText().trim();
			
			for (int i = 0; i < digestWidgets.length; i++) {
				DigestWidget dw = digestWidgets[i];
				if (dw != null & dw.isEnabled() && dw.isSelected()) {
					String result = null;
					if (isHmacSelected()) {
						result = HmacCalculator.calculateHmac(ALGOS[i].hmacAlgName, messageData, ds, keyData, kf, hexEncodedOutput, upcasedOutput);
					}
					else {
						result = HashCalculator.calculateHash(ALGOS[i].algName, messageData, ds, hexEncodedOutput, upcasedOutput);
					}
					dw.setValue(result);
				}
			}
		}
	}

	
	/*
	 * Zaps all calculated values in preparation of next calculation action
	 */
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

		String sources[] = {DataLabel.TEXT.getLabel(), DataLabel.HEX.getLabel(), DataLabel.BASE64.getLabel(), DataLabel.FILE.getLabel()};
		dataSource = new JComboBox<String>(sources);
		dataSource.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				setFsButtonState();
				clearHashValues();
			}
		});
		dataPanel.add(dataSource);

		dataToHash = new JTextField(20);
		dataToHash.getDocument().addDocumentListener((SimpleDocumentListener) e -> {
			clearHashValues();
			dataToHash.requestFocus();
		});
		dataPanel.add(dataToHash);

		
		fsButton = new JButton("...");
		fsButton.setPreferredSize(new Dimension(20, 10));
		setFsButtonState();
		fsButton.addActionListener(new ActionListener() {
			@Override
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
		});
		dataPanel.add(fsButton);

		JPanel hmacPanel = new JPanel();
		hmacPanel.setBorder(BorderFactory.createTitledBorder("HMAC"));
		hmacPanel.setLayout(new GridLayout2(2, 3, 5, 0));
		contentPane.add(hmacPanel);

		hmacPanel.add(new JLabel()); 
		hmacPanel.add(new JLabel("Key Format"));
		hmacPanel.add(new JLabel("Key"));

		hmac = new JCheckBox("Apply HMAC Key");
		hmac.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				boolean state = isHmacSelected();
				if (keyFormat != null) keyFormat.setEnabled(state);
				if (hmacKey != null) hmacKey.setEnabled(state);
				setDisgestWidgets();
				clearHashValues();
			}
		}); 
		hmacPanel.add(hmac);

		String keyFormats[] = {DataLabel.TEXT.getLabel(), DataLabel.HEX.getLabel(), DataLabel.BASE64.getLabel()};
		keyFormat = new JComboBox<String>(keyFormats);
		keyFormat.setEnabled(hmac.isSelected());
		keyFormat.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				clearHashValues();
			}
		});
		hmacPanel.add(keyFormat);

		hmacKey = new JTextField(20);
		hmacKey.setEnabled(hmac.isSelected());
		hmacKey.getDocument().addDocumentListener((SimpleDocumentListener) e -> {
			clearHashValues();
			hmacKey.requestFocus();
			
		});
		hmacPanel.add(hmacKey);

		// Result Encoding Panel
		JPanel rePanel = new JPanel();
		rePanel.setBorder(BorderFactory.createTitledBorder("Output Encoding"));
		rePanel.setLayout(new GridLayout2(1, 2, 5, 5));
		contentPane.add(rePanel);
		
		JCheckBox ucSelector = new JCheckBox("Upper Case");
		ucSelector.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				upcasedOutput = ucSelector.isSelected();
			}
		});
		ucSelector.setEnabled(hexEncodedOutput);
		ucSelector.setSelected(upcasedOutput);

		JRadioButton hexEncodingBtn = new JRadioButton("Hex");
		hexEncodingBtn.setSelected(hexEncodedOutput);
		hexEncodingBtn.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				hexEncodedOutput = hexEncodingBtn.isSelected();
				ucSelector.setEnabled(hexEncodedOutput);
				clearHashValues();
			}
		});
		
		JRadioButton b64EncodingBtn = new JRadioButton("Base64");
		b64EncodingBtn.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				hexEncodedOutput = !b64EncodingBtn.isSelected();
				ucSelector.setEnabled(hexEncodedOutput);
				clearHashValues();
			}
		});
		ButtonGroup bg = new ButtonGroup();
		bg.add(hexEncodingBtn);
		bg.add(b64EncodingBtn);

		rePanel.add(hexEncodingBtn);
		rePanel.add(b64EncodingBtn);
		rePanel.add(ucSelector);

		
		JPanel resultsPanel = new JPanel();
		resultsPanel.setBorder(BorderFactory.createTitledBorder("Calculated Hash Values"));
		resultsPanel.setLayout(new GridLayout2(ALGOS.length, 2, 5, 5));
		contentPane.add(resultsPanel);

		
		this.buildDisgestWidgets(resultsPanel);

		JPanel btnPanel = new JPanel();
		btnPanel.setBorder(BorderFactory.createTitledBorder(""));
		btnPanel.setLayout(new GridLayout(1, 3));
		contentPane.add(btnPanel);

		calculateBtn = new JButton("Calculate");
		calculateBtn.setToolTipText("Calculates hash values");
		calculateBtn.addActionListener(CursorController.createListener(this, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				calculateHashValues();
			}
		}));
		btnPanel.add(calculateBtn);


		clearBtn = new JButton("Clear");
		clearBtn.setToolTipText("Clears all hash values");
		clearBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				clearHashValues();
			}
		});
		btnPanel.add(clearBtn);
		
		quitBtn = new JButton("QUIT");
		quitBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				System.exit(ABORT);
			}
		}); 
		btnPanel.add(quitBtn);


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


	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		setLook();
		new Hasher();
	}
}


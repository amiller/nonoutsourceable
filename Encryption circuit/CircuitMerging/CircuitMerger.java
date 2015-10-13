import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Scanner;

public class CircuitMerger {

	private class WiresPair {
		int wire1;
		int wire2;

		public WiresPair(int w1, int w2) {
			wire1 = w1;
			wire2 = w2;
		}
	}

	private Properties transformProp;
	private HashMap<Integer, Integer> wireMapper1;
	private HashMap<Integer, Integer> wireMapper2;

	private StringBuffer outCircuitBuffer;
	private int currentWireIndex;

	public CircuitMerger(String propertiesPath) {
		super();
		transformProp = new Properties();
		try {
			transformProp.load(new FileInputStream(propertiesPath));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void run() throws FileNotFoundException, IOException {
		init();
		transformFiles();
		writeOutput();
	}


	private void init() {
		outCircuitBuffer = new StringBuffer();
		wireMapper1 = new HashMap<Integer, Integer>();
		wireMapper2 = new HashMap<Integer, Integer>();

	}

	private void transformFiles() throws FileNotFoundException {

		ArrayList<Integer> inputsToKeep1 = parseSequenceLists((String) transformProp
				.get("KeepInput1"));
		ArrayList<Integer> inputsToKeep2 = parseSequenceLists((String) transformProp
				.get("KeepInput2"));
		int wireOneId1 = Integer.parseInt((String) transformProp
				.get("OneInput1"));
		int wireOneId2 = Integer.parseInt((String) transformProp
				.get("OneInput2"));
		ArrayList<Integer> nizkInputsToKeep1 = parseSequenceLists((String) transformProp
				.get("NizkKeepInput1"));
		ArrayList<Integer> nizkInputsToKeep2 = parseSequenceLists((String) transformProp
				.get("NizkKeepInput2"));
		ArrayList<Integer> outputsToKeep1 = parseSequenceLists((String) transformProp
				.get("KeepOutput1"));
		
		
		ArrayList<WiresPair> connections = parseMappingLists((String) transformProp
				.get("WiresToConnect"));
		ArrayList<Integer> outputsToKeep2 = parseSequenceLists((String) transformProp
				.get("KeepOutput2"));

		
		
		for (int wId : inputsToKeep1) {
			int newWireId = currentWireIndex++;
			wireMapper1.put(wId, newWireId);
			outCircuitBuffer.append("input " + newWireId
					+ "\t\t\t\t# input from circuit 1 \n");
		}

		for (int wId : inputsToKeep2) {
			int newWireId = currentWireIndex++;
			wireMapper2.put(wId, newWireId);
			outCircuitBuffer.append("input " + newWireId
					+ "\t\t\t\t# input from circuit 2 \n");
		}

		int newOneWireId = currentWireIndex++;
		outCircuitBuffer
				.append("input "
						+ newOneWireId
						+ "\t\t\t\t# one wire for both circuits (make sure this is one in your input file to avoid NIZK bugs)  \n");
		wireMapper1.put(wireOneId1, newOneWireId);
		wireMapper2.put(wireOneId2, newOneWireId);

		for (int wId : nizkInputsToKeep1) {
			int newWireId = currentWireIndex++;
			wireMapper1.put(wId, newWireId);
			outCircuitBuffer.append("nizkinput " + newWireId
					+ "\t\t\t\t# nizk input from circuit 1 \n");
		}

		for (int wId : nizkInputsToKeep2) {
			int newWireId = currentWireIndex++;
			wireMapper2.put(wId, newWireId);
			outCircuitBuffer.append("nizkinput " + newWireId
					+ "\t\t\t\t# nizk input from circuit 2 \n");
		}

		int newWireId = currentWireIndex++;
		outCircuitBuffer.append("nizkinput " + newWireId
				+ "\t\t\t\t# A dummy NIZK input to avoid bugs\n");
		
		// ////////////// START READING FILES ////////////////////////

		
		// scan through the first circuit file ..  replace what is necessary
		scanFile((String)transformProp.get("Circuit1"), wireMapper1, outputsToKeep1);
		
		// ready now to resolve mappings issues 
		for(WiresPair pair: connections){
			wireMapper2.put(pair.wire2, wireMapper1.get(pair.wire1));
		}

		// scan through the second circuit file ..  replace what is necessary
		scanFile((String)transformProp.get("Circuit2"), wireMapper2, outputsToKeep2);
		
		
	}
	
	private void scanFile(String path, HashMap<Integer, Integer> mapper,
			ArrayList<Integer> outputsToKeep) throws FileNotFoundException {
		Scanner scanner = new Scanner(new File(path));
		while (scanner.hasNext()) {
			String line = scanner.nextLine();
			if (line.startsWith("total") || line.startsWith("input")
					|| line.startsWith("nizk")) {
				continue;
			} else if (line.startsWith("output")) {
				String[] tokens = line.split("\\s+");
				int wireIndex = Integer.parseInt(tokens[1]);
				if (outputsToKeep.contains(wireIndex)) {
					outCircuitBuffer.append("output "
							+ mapper.get(wireIndex)
							+ "\t\t\t\t# output from circuit 1 \n");
				} else {
					// nothing to do for an unkept circuit output for now
				}
			} else {

				// extract input and output portions, replace and add to the
				// mapping data structures if necessary
				int idx1 = line.indexOf("<");
				int idx2 = line.indexOf(">");
				if (idx1 == -1 || idx2 == -1)
					throw new RuntimeException(
							"Problem occurred, unexpected string .. need to be handled!: "
									+ line);

				String inputWires = line.substring(idx1 + 1, idx2);
				String[] wireIds = inputWires.split(" ");
				String inReplacement = "<";
				for (String idStr : wireIds) {
					if (idStr.isEmpty()) {
						continue;
					}
					int id = Integer.parseInt(idStr);
					if (mapper.containsKey(id)) {
						inReplacement += " " + mapper.get(id) + " ";
					} else {
						throw new RuntimeException(
								"Problem occurred, unexpected wire being used "
										+ line);
					}
				}
				inReplacement += ">";
				
				int idx3 = line.indexOf("<", idx2+1);
				int idx4 = line.indexOf(">", idx2+1);
				
				String outWires = line.substring(idx3 +1, idx4);
				wireIds = outWires.split(" ");
				String outReplacement = "<";
				for (String idStr : wireIds) {
					if (idStr.isEmpty()) {
						continue;
					}
					int id = Integer.parseInt(idStr);
					if (mapper.containsKey(id)) { 
						// very unlikely, but keep it for now. ToDO: Check.
					} else {
						int newWireId = currentWireIndex++;
						mapper.put(id,  newWireId);	
					}
					outReplacement += " " + mapper.get(id) + " ";
				}
				outReplacement += ">";

				line = line.replace("<"+inputWires+">", inReplacement).replace("<"+outWires+">", outReplacement);
				outCircuitBuffer.append(line + "\n");
			}
		}

		scanner.close();
	}

	private ArrayList<Integer> parseSequenceLists(String s) {

		ArrayList<Integer> list = new ArrayList<Integer>();
		String[] chunks = s.split(",");
		for (String chunk : chunks) {
			if (chunk.equals(""))
				continue;
			int lower = Integer.parseInt(chunk.split(":")[0]);
			int upper = Integer.parseInt(chunk.split(":")[1]);
			for (int i = lower; i <= upper; i++) {
				list.add(i);
			}
		}
		return list;
	}

	private ArrayList<WiresPair> parseMappingLists(String s) {

		ArrayList<WiresPair> list = new ArrayList<WiresPair>();
		String[] chunks = s.split(",");
		for (String chunk : chunks) {
			if (chunk.equals(""))
				continue;
			String[] subChunks = chunk.split("->");
			ArrayList<Integer> l1 = parseSequenceLists(subChunks[0]);
			ArrayList<Integer> l2 = parseSequenceLists(subChunks[1]);
			for (int i = 0; i < l1.size(); i++) {
				list.add(new WiresPair(l1.get(i), l2.get(i)));
			}
		}
		return list;
	}
	
	private void writeOutput() throws FileNotFoundException {
		PrintWriter printWriter = new PrintWriter(new File(transformProp.getProperty("OutCircuit")));
		printWriter.println("total " + currentWireIndex);
		printWriter.print(outCircuitBuffer.toString());
		printWriter.close();
	}
	
	public static void main(String[] args) {

		try {
			new CircuitMerger("input2.properties").run();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Scanner;


/**** VERY CUSTOMIZED CODE ******/

public class DHCircuitAdapter {

	private static void adaptCircuit(String path) throws FileNotFoundException{
			
			int currentWireIndex = 0;
		
			Scanner scanner = new Scanner(new File(path));
			int numWires= Integer.parseInt(scanner.nextLine().split(" ")[1]);
			currentWireIndex = numWires;
			int oneWireIndex = 1; 
			
			StringBuffer buffer = new StringBuffer();
			int outputCounter = 0;
			int[] outputToReplace = new int [4]; 
			while(scanner.hasNext()){
				String line = scanner.nextLine();
				if(line.startsWith("output")){
					if(outputCounter < 4)
						buffer.append(line+"\n");
					else{
						outputToReplace[outputCounter - 4] = Integer.parseInt(line.split(" ")[1]);
					}
					outputCounter++;
				}
				else{
					buffer.append(line+"\n");
				}
			}

			int[] outputs = new int[32];
			
			for(int k = 0; k < outputToReplace.length; k++){
				int wireToSplit = outputToReplace[k];
				int[] bits = new int[254];
				buffer.append("split in 1 <" + wireToSplit + "> out 254 <");
				for (int j = 0; j < 254; j++) {
					bits [j] = currentWireIndex++;
					buffer.append(bits[j] + " ");
				}
				buffer.append(">\n");
				
				
				for(int i = 0; i < 8; i++){
					int[] accum = new int[i == 7 ? 30: 32];
					String accumStr = "";
					for (int j = 0; j < accum.length; j++) {
						accum[j] = currentWireIndex++;
						accumStr += accum[j] + " ";
						buffer.append("const-mul-" + Integer.toHexString(1 << j)
								+ " in 1 <" + bits[i * 32 + j] + "> out 1 <"
								+ accum[j] + ">\n");
					}
					outputs[k*8+i] = currentWireIndex++;
					buffer.append("add in " + accum.length + " <" + accumStr + "> out 1 <"
							+ outputs[k*8+i] + ">\n");
				}
			}

			for (int i = 0; i < outputs.length; i++) {
				int outputWire = currentWireIndex++;
				buffer.append("mul in 2 <" + outputs[i] + " " + oneWireIndex
						+ "> out 1 <" + outputWire + ">\n");
				buffer.append("output " + outputWire + "\n");
			}
			
			PrintWriter printWriter = new PrintWriter(new File("adapted_DH.arith"));
			printWriter.println("total " + currentWireIndex);
			printWriter.print(buffer.toString());
			printWriter.close();
			
			String circuitContents = buffer.toString();
			System.out.println(circuitContents);
			scanner.close();
	}
	

	
	public static void main(String[] args) {
		try {
			adaptCircuit("DH.arith");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}


}

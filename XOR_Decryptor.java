//Script to decrypt a user-selected buffer with a
//key also given by analyst. The decryption routine
//used is simple xor decryption.
//@author Fare9
//@category _NEW_
//@keybinding k
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.List;
import java.util.ArrayList;

public class XOR_Decryptor extends GhidraScript {
	List<Byte> originalBuffer = new ArrayList<Byte>();
	List<Byte> newBuffer = new ArrayList<Byte>();
	
	private void replace_buffer(Address startAddress)
	{
		Address i;
		int j = 0;
		
		i = startAddress;
		
		for (j = 0; j < newBuffer.size(); j++)
		{
			println("[+] Replacing byte " + originalBuffer.get(j).toString() + " in address "+i.toString()+" with decrypted byte " + newBuffer.get(j).toString());
			byte new_byte = newBuffer.get(j);
			
			try {
				setByte(i, new_byte);
			} catch(MemoryAccessException mae)
			{
				println("[-] Error accessing address " + i.toString());
				break;
			}
			
			i = i.next();
		}
	}
	
	private String decrypt_xor(byte xorKey, Address startAddress, Address endAddress)
	{
		String result = "";
		Address i;
		int j = 0;
		long size = endAddress.getOffset() - startAddress.getOffset() + 1;
		
		println("[!] Going to decrypt from " + startAddress.toString() +
				"to " + endAddress.toString() + " size " + String.valueOf(size) +
				" with key " + String.valueOf(xorKey));
		
		i = startAddress;
		
		for(j = 0; j < size; j++)
		{
			println("[+] Accessing address " + i.toString() + "["+String.valueOf(j)+"]");
			
			byte read_byte, decrypted_byte;
			
			try {
				read_byte = getByte(i);
			} catch(MemoryAccessException mae)
			{
				println("[-] Error accessing address " + i.toString());
				break;
			}
			
			decrypted_byte = (byte) (read_byte ^ xorKey);
			originalBuffer.add(read_byte);
			newBuffer.add(decrypted_byte);
			
			println("[!] Decrypted byte "+String.valueOf(read_byte)+" to "+decrypted_byte+"("+(char)decrypted_byte+")");
			result += (char)decrypted_byte;
			
			i = i.next();
		}
		
		return result;
	}
	
    @Override
    public void run() throws Exception {
        Address decryptStart;
        Address decryptEnd;
        String decryptedString;

        println("\"XOR_Decryptor\"Script to decrypt a selection of bytes\n" +
                "using xor decryption routine and a given byte.\n"+
        		"Created by Fare9!.");
        
        if(currentSelection != null)
        {
            decryptStart = currentSelection.getMinAddress();
            decryptEnd = currentSelection.getMaxAddress();
            
            println("[!] Obtained address: "+String.valueOf(decryptStart)+" - "+String.valueOf(decryptEnd));
        }
        else
        {
        	println("Please select a starting address and ending address\n" + 
        			"in order to apply the decryption.");
        	return;
        }
        
        int decryptionInt = askInt("Key", "enter key (between 0 and 255");
        
        if (decryptionInt < 0 || decryptionInt > 255)
        {
        	println("[-] ERROR, key can only be a byte number (between 0 and 255)");
        	return;
        }
        
        byte decryptionKey = (byte)decryptionInt;
        
        decryptedString = decrypt_xor(decryptionKey, decryptStart, decryptEnd);
        
        println("[!] Decrypted string = " + decryptedString);
        
        boolean replace = askYesNo("replace or not", "Do you want to replace bytes (yes/no)?");
        
        if (replace)
        {
        	replace_buffer(decryptStart);
        }
        
    }

}

package app;

import java.util.*;
import java.security.*;


/*
* @ Author: Carolina Costa Lopes
* @ Version_Date: 05/12/2019
*/

public class Sign{

    private static String algorithm;

    private static String sigFile; // holds produced signature

    private static byte[] masterSk; // holds the master secret key
    private static byte[] msg; // holds the message
    private static int windowSize;
    private static int numCheckSumBlocks;
    private static int numSks;
    private static ArrayList<byte[]> sig; // holds the signature

    public static void main(String[] args) throws Exception {
      setUp(args);
      run();
    }

    public static void setUp(String[] args){
      //Step 1 : Get window size and algorithm from sk file
      String[] setUp = HashLib.setUp(args[1]);

      //Step 2 : Set algorithm
      algorithm = setUp[1];

      //Step 3 : IO File handling for output file
      sigFile = args[0];

      //Step 4 : Set Window size
      windowSize = Integer.parseInt(setUp[0]);

      //Step 5 : File Handling to retrieve master sk from skFile
      masterSk = HashLib.decodeHexString(HashLib.readFile(args[1]));


      //Step 6 : File Handling to retrieve msg from msgFile
      //         Human readable -> byte[32]
      msg = new byte[32];
      msg = HashLib.readMessage(args[2]);

      // Step 7 : calculate numCheckSumBlocks
      numCheckSumBlocks = HashLib.setNumCheckSumBlocks(windowSize);

      numSks = HashLib.setNumSks(windowSize);
    }

    public static void run(){
        sig = new ArrayList<>();
        //Step 1 : Hash the message
        byte[] hashedMsg = new byte[32];
        try {
            hashedMsg = HashLib.getSHA(msg); }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Exception thrown for incorrect algorithm: " + e);}

        //Step 2 : Split message into windowSize-bit blocks
        ArrayList<String> msgBlocks = HashLib.splitBinary(HashLib.toBinary(hashedMsg),windowSize);



        //Step 4 : calculate checksum
        int checksum = HashLib.calculateCheckSum(msgBlocks);
        ArrayList<String> checksumBlocks = HashLib.encodeChecksum(checksum);

        //Step 5 : append checksum blocks to the msg blocks
        msgBlocks.addAll(checksumBlocks);

        //Step 6 : generate secret keys
        ArrayList<byte[]> sk = HashLib.generateSks(masterSk);

        //Step 7 : generate the signature
        for (int i = 0; i < msgBlocks.size(); i++) {
            String block = msgBlocks.get(i);
            int intRep = Integer.parseInt(block,2);

            byte[] skToChain = sk.get(i);
            byte[] hashedSig = null;

            try {
              hashedSig = HashLib.getChainSHA(skToChain,intRep); }
            catch (NoSuchAlgorithmException e) {
              System.out.println("Exception thrown for incorrect algorithm: " + e);}
            sig.add(hashedSig);
        }

        HashLib.writeFile(sigFile,String.format("ALGORITHM = %s\nWINDOW SIZE = %d\n%s",algorithm,windowSize,HashLib.arrayListByteToHex(sig)));
    }

    public void run(String[] files){
      for(int i = 0; i < files.length;i++){
        //Step 1 : split string into the different file names
        msg = HashLib.readMessage(files[i]);
        sigFile =  String.format("sig_%s", files[i]);
        run();
      }
    }


}

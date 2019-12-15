package app;

import java.util.*;
import java.security.*;

/*
* @ Author: Carolina Costa Lopes
* @ Version_Date: 05/12/2019
*/

public class Verify{

    private static String algorithm;
    private static int windowSize;
    private static ArrayList<byte[]> pk; // holds the public key
    private static byte[] msg; // holds the message
    private static ArrayList<byte[]> sig = new ArrayList<>(); // holds the signature
    private static int numCheckSumBlocks;

    public static void main(String[] args) throws Exception {
      setUp(args);
      run();
    }

    public static void setUp(String[] args){
      //Step 1 : Get window size and algorithm from sk file
      String[] setUp = HashLib.setUp(args[1]);

      //Step 1.2 : Set algorithm
      algorithm = setUp[0];

      //Step 1.3 : Get window size from pk
      windowSize = Integer.parseInt(setUp[0]);

      //Step 2 : File Handling for pkFile
      //         read pk
      pk = HashLib.decodeFileString(HashLib.readFile(args[0]));

      //Step 3 : File Handling for msgFile
      //         read message
      msg = HashLib.readMessage(args[2]);

      //Step 4 : File Handling for sigFile
      //         read sig
      sig = HashLib.decodeFileString(HashLib.readFile(args[1]));


    }

    public static boolean run(){
        int falseCounter = 0; // Holds number of mismatches

        //Step 1 : Hash the message
        byte[] hashedMsg = new byte[32];
        try {
            hashedMsg = HashLib.getSHA(msg);}
        catch (NoSuchAlgorithmException e) {
            System.out.println("Exception thrown for incorrect algorithm: " + e);}

        //Step 2 : Split message into windowSize-bit blocks
        ArrayList<String> msgBlocks = HashLib.splitBinary(HashLib.toBinary(hashedMsg),windowSize);

        numCheckSumBlocks = HashLib.setNumCheckSumBlocks(windowSize);

        //Step 4 : Calculate checksum
        int checksum = HashLib.calculateCheckSum(msgBlocks);
        ArrayList<String> checksumBlocks = HashLib.encodeChecksum(checksum);

        //Step 4.1 : append checksum blocks to the msg blocks
        msgBlocks.addAll(checksumBlocks);

        //Step 5 : Calculate chain length
        int chainLength = (int) Math.pow(2,windowSize);

        //Step 6 : Compare generate sig to given sig
        for (int i = 0; i < msgBlocks.size(); i++) {
            String block = msgBlocks.get(i);
            int intRep = Integer.parseInt(block,2);

            int numOfChains = chainLength-intRep;

            byte[] sigToChain = sig.get(i);
            byte[] hashedSig = null;

            try {
              hashedSig = HashLib.getChainSHA(sigToChain,numOfChains);}
            catch (NoSuchAlgorithmException e) {
              System.out.println("Exception thrown for incorrect algorithm: " + e);}
        }

        //Step 7 : Check if any mismatches
        if (falseCounter > 0){
            System.out.println("Number of errors found at verification = " + falseCounter);
            return false;
        }else{
            return true;
        }
    }

    public static boolean run(String[] msgFiles, String[] sigFiles){
      int failedCounter = 0;
      for(int i = 0; i < msgFiles.length;i++){
        //Step 1 : split string into the four different file names
        msg = HashLib.readMessage(msgFiles[i]);
        sig = HashLib.decodeFileString(HashLib.readFile(sigFiles[i]));
        boolean isVerified = run();
        if(isVerified==false){
          failedCounter++;
        }
      }

      //Check if all files were verified
      if(failedCounter > 0){
        System.out.print(failedCounter + " files failed to verify");
        return false;
      }
      else{
        System.out.println("ALL FILES VERIFIED TRUE");
        return true;
      }
    }


}

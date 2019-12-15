package app;

import java.util.*;
import java.security.*;

/*
* @ Author: Carolina Costa Lopes
* @ Version_Date: 15/12/2019
*/

public class KeyGen{
    private static String algorithm;
    private static int windowSize;

    private static String skFile;
    private static String pkFile;

    private static byte[] masterSk = new byte[32];
    private static int numCheckSumBlocks;
    private static int numSks;
    private static ArrayList<byte[]> pk = new ArrayList<>();

    public static void main(String[] args) throws Exception {
      setUp(args);
      run();
    }

    public static void setUp(String [] args){
      //Step 1 : Check if input algorithm belongs to implemented algorithms
      algorithm = HashLib.checkAlgorithm(args[0]);


      //Step 2 : IO File handling for output file
      skFile = args[1];
      pkFile = args[3];

      //Step 3 : check if window size is a multiple of 2
      if(algorithm.equals("Lamport")){
        windowSize = 1;
      }
      else{
        // Step 3.2 : if winternitz then get window size
        windowSize = Integer.parseInt(args[2]);
      }

      HashLib.checkWindowSize(windowSize);

      // Step 2 : calculate numCheckSumBlocks
      numCheckSumBlocks = HashLib.setNumCheckSumBlocks(windowSize);

      //Step 3 : Generate chains of sk
      numSks = HashLib.setNumSks(windowSize);
    }

    public static void run(){
        //Step 1 : Generate master sk using a Secure Random
        try{
            masterSk = SecureRandom.getInstance("SHA1PRNG").generateSeed(32); }
        catch (NoSuchAlgorithmException e){
            System.out.println("No such algorithm as :" + e); }
        //Step 1.1 : Save master secret key in a skFile
        HashLib.writeFile(skFile,String.format("ALGORITHM = %s\nWINDOW SIZE = %d\n%s",algorithm,windowSize,HashLib.byteArrayToHex(masterSk)));


        // Step 2 : Generate secret keys
        ArrayList<byte[]> sk = HashLib.generateSks(masterSk);

        //Step 3: Generate pk by chaining all the sks
        try {
            pk = HashLib.getArrayChainSHA(sk,(int) Math.pow(2,windowSize));}
        catch (NoSuchAlgorithmException e) {
            System.out.println("Exception thrown for incorrect algorithm: " + e); }

        //Step 4 : Save pk in pkFile
        HashLib.writeFile(pkFile,String.format("ALGORITHM = %s\nWINDOW SIZE = %d\n%s",algorithm,windowSize,HashLib.arrayListByteToHex(pk)));
    }

}

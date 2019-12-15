package app;

import java.util.*;
import java.security.*;
import java.io.*;
import java.nio.file.NoSuchFileException;

/*
* @ Author: Carolina Costa Lopes
* @ Version_Date: 23/11/2019
*/

public class HashLib{
    private static int windowSize;
    private static int numCheckSumBlocks;
    private static int numSks;
    private static List<String> implementedAlgorithms = Arrays.asList("Lamport","Winternitz");
    private static String algorithm;

    private static enum Error {
        UndefinedAlgorithm, WindowSizeNotAccepted, WindowSizeNotProvided;
    }
    public static void raise(Error error, String message) {
        System.out.println(error.toString() + " - " + message);
        System.exit(1);
    }

    public HashLib(){
      }

    public static String[] setUp(String fileName){
      String[] output = new String[2];
      String windowLine = readFileWithTag(fileName)[0];
      String algorithmLine = readFileWithTag(fileName)[1];
      if(windowLine != null && algorithmLine != null){
        int size = Integer.parseInt(windowLine);
        checkWindowSize(size);
        output[0] = Integer.toString(size);
        String algo = algorithmLine;
        checkAlgorithm(algo);
        output[1] = algo;
        return output;
      }
      else{
        //TODO add diff windowsize or algo missing
        raise(Error.WindowSizeNotProvided,"Please insert a tag at the beginning of the message file with the window size and algorithm name");
        return output;
      }
    }

    public static void checkWindowSize(int size){
      switch(size){
          case 1:
          case 2:
          case 4:
          case 8:
              windowSize = size;
              break;
          default:
              raise(Error.WindowSizeNotAccepted,"size");
      }
    }

    public static String checkAlgorithm (String algo){
      //Step 1 : Check if input algorithm belongs to implemented algorithms
      if(implementedAlgorithms.contains(algo)){
          algorithm = algo;
          return algorithm;
      }
      else{
          raise(Error.UndefinedAlgorithm,(algo + " not found"));
          return null;
      }
    }

    public static int setNumCheckSumBlocks(int windowSize){
        // calculate numCheckSumBlocks
        switch (windowSize) {
            case 1 : numCheckSumBlocks = 8;
            break;
            case 2 : numCheckSumBlocks = 5;
            break;
            case 4 : numCheckSumBlocks = 3;
            break;
            case 8 : numCheckSumBlocks = 13;
            break;
            default : numCheckSumBlocks = 4;
        }

      return numCheckSumBlocks;
    }

    public static int setNumSks(int windowSize){
      numSks = (256/windowSize) + numCheckSumBlocks;
      return numSks;
    }

    public static byte[] getSHA(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] hashValue = md.digest(input);
        return hashValue;
    }

    public static byte[] getChainSHA(byte[] input, int iterations) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] hashValue = input;
        for (int j = 0; j < iterations ;j++){
            hashValue = md.digest(hashValue);
        }
        return hashValue;
    }

    public static ArrayList<byte[]> getArrayChainSHA(ArrayList<byte[]> input, int iterations) throws NoSuchAlgorithmException {
        ArrayList<byte[]> output = new ArrayList<>();

        for (byte[] hashValue : input) {
          hashValue = getChainSHA(hashValue, iterations);
          output.add(hashValue);
        }
        return output;
    }

    public static int calculateCheckSum(ArrayList<String> input){
        int checksum = 0 ;
        for (String block : input) {
            int intRep = Integer.parseInt(block,2);
            int maxBlockValue = ((int) Math.pow(2,windowSize)) - 1 ;
            checksum += (maxBlockValue - intRep);
        }
        return checksum;
    }

    public static ArrayList<byte[]> generateSks(byte[] masterSk){
        // Step 1: construct PRNG from master secret seed
         SecureRandom prng = new SecureRandom();

         try{
           prng = SecureRandom.getInstance("SHA1PRNG");}
         catch (NoSuchAlgorithmException e){
           System.out.println("No such algorithm as :" + e);}

         prng.setSeed(masterSk);

         // Step 2: take the first 64 bytes of output from prng and print them
         ArrayList<byte[]> stream = new ArrayList<>();
         byte[] bytes = new byte[32];

         for(int i = 0 ; i < numSks; i++){
           byte[] newByte = new byte[32];
           prng.nextBytes(bytes);
           for(int j = 0; j<bytes.length;j++){
             byte b = bytes[j];
             newByte[j] = b;
           }
           stream.add(newByte);
         }

         return stream;
    }

    public static ArrayList<String> encodeChecksum(int checksum){
        ArrayList<String> checksumBlocks = splitBinary(Integer.toBinaryString(checksum),windowSize); //padding if needed
        String zeroBlock = "" ;
        for(int i = 0; i<windowSize;i++){
          zeroBlock += "0";
        }
        while(checksumBlocks.size() < numCheckSumBlocks){
          checksumBlocks.add(zeroBlock);
        }
        return checksumBlocks;
    }

    public static ArrayList<String> splitBinary(String input,int blockSize){
        ArrayList<String> outputBlocks = new ArrayList<String>();

        if(input.length() % blockSize != 0){
          int remainder = blockSize - (input.length() % blockSize);
          for(int i = 0; i <remainder;i++) {
            input = "0" + input;
          }
        }
        for(int i=0; i < input.length(); i=i+blockSize){
          outputBlocks.add(input.substring(i,i+blockSize));
        }

        return outputBlocks;
    }

    public static String toBinary(byte[] bytes) {
        // SOURCE: STACKOVERFLOW
        StringBuilder sb = new StringBuilder(bytes.length * Byte.SIZE);
        for (int i = 0; i < Byte.SIZE * bytes.length; i++) {
            sb.append((bytes[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0' : '1');
        }
        return sb.toString();
    }

    public static byte[] readMessage(String fileName){
        String message = readFile(fileName);

        byte[] messageBytes = message.getBytes();

        //Hash message in order to make sure it's 256 bits
        try {
            messageBytes = getSHA(messageBytes);}
        catch (NoSuchAlgorithmException e) {
            System.out.println("Exception thrown for incorrect algorithm: " + e);}

        return messageBytes;
    }

    public static String readFile(String fileName){
      String content = readFileWithTag(fileName)[2];
      return content;
    }

    public static void writeFile(String fileName,String content){

        // If the file doesn't exists, create and write to it
        // If the file exists, truncate (remove all content) and write to it , if you wanna append then add , true next to filename
        try (FileWriter writer = new FileWriter(fileName);
             BufferedWriter bw = new BufferedWriter(writer)) {

            bw.write(content);

        } catch (IOException e) {
            System.err.format("IOException: %s%n", e);
        }
    }

    public static String byteArrayToHex(byte[] input) {
        String output = "";
        for (byte b : input) {
          output += String.format("%02x", b);
        }
        return output;
    }

    public static String arrayListByteToHex(ArrayList<byte[]> input) {
        String output = "";
        for(int i =0; i< input.size();i++){
          output += byteArrayToHex(input.get(i));
        }
        return output;
    }

    public static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    public static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
              "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }

    public static byte[] decodeHexString(String hexString) {
      if (hexString.length() % 2 == 1) {
          throw new IllegalArgumentException(
            "Invalid hexadecimal String supplied.");
      }
      byte[] bytes = new byte[hexString.length() / 2];
      for (int i = 0; i < hexString.length(); i += 2) {
        bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
      }
      return bytes;
    }

    public static ArrayList<byte[]> decodeFileString(String hexString){
        //every byte becomes 64 characters
        ArrayList<byte[]> output= new ArrayList<>();
        for(int i = 0; i<hexString.length();i = i +64){
          byte[] bytes = decodeHexString(hexString.substring(i, i+64));
          output.add(bytes);
        }
        return output;
    }

    private static String[] readFileWithTag(String fileName){
          String line = null;
          String content= "";
          String tag = "";
          String algo = "";
          String[] output = new String[3];
          try {
              FileReader fileReader = new FileReader(fileName);
              BufferedReader bufferedReader = new BufferedReader(fileReader);
              // check for algorithm
              if((line = bufferedReader.readLine()) != null){
                if(line.startsWith("ALGORITHM = ")){
                  algo = line.substring(12,line.length());
                  output[1] = algo;
                }
                else{
                  //TODO throw error for windowSize not being provided
                  content += line;
                }
              }
              //check for window size tag
              if((line = bufferedReader.readLine()) != null){
                if(line.startsWith("WINDOW SIZE = ")){
                  tag = line.substring(14,line.length());
                  output[0] = tag;
                }
                else{
                  //TODO throw error for windowSize not being provided
                  content += line;
                }
              }
              //read rest of file
              while ((line = bufferedReader.readLine()) != null) {
                // System.out.println(line);
                  content += line;
              }
              output[2] = content;
              bufferedReader.close();
          } catch (FileNotFoundException ex) {
              System.out.println("Unable to open file '" + fileName + "'");
              System.exit(0);
          } catch (IOException ex) {
              System.out.println("Error reading file '" + fileName + "'");
              System.exit(0);
          }
          return output;
        }
}

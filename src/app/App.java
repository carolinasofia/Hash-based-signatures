package app;
import java.util.*;
import java.security.*;
import java.io.*;
import java.nio.file.NoSuchFileException;

/*
* @ Author: Carolina Costa Lopes
* @ Version_Date: 15/12/2019
*/

public class App {
    static Scanner myObj = new Scanner(System.in);  // Create a Scanner object
    static String algorithm;
    static int windowSize;
    static String skFile = "sk.txt"; // holds the master sks
    static String msgFile = "msg.txt"; // holds the msg
    static String sigFile = "sig.txt"; // holds the signature
    static String pkFile = "pk.txt"; // holds the public key
    static int nOfRuns = 1;

    public static void main(String[] args) throws Exception {

          //testMultipleFiles();

          System.out.println("Running tests for time");
          //getInfo();
          testTime();
          //testAll();

    }

    public static void testTime() throws Exception {
        getInfo();
        System.out.println("Running...");

        // set up of functions
        String[] info = new String[]{algorithm,skFile,Integer.toString(windowSize),pkFile}; //Saves window size as tag on pk and sk
        KeyGen.setUp(info);

        long KeyGenStart = System.nanoTime();
        for(int i = 0; i < nOfRuns;i++){
          KeyGen.run();
        }
        //end time
        long KeyGenEnd = System.nanoTime();
        long KeyGenAverage = (KeyGenEnd - KeyGenStart)/nOfRuns;

        String[] signInfo = new String[]{sigFile, skFile, msgFile}; //Window Size is found in msgFile
        Sign.setUp(signInfo);

        //starting time
        long SignStart = System.nanoTime();
        for(int i = 0; i < nOfRuns;i++){
          Sign.run();
        }
        //end time
        long SignEnd = System.nanoTime();
        long SignAverage = (SignEnd - SignStart)/nOfRuns;

        String[] verifyInfo = new String[]{pkFile, sigFile, msgFile}; //Window size is found in pk and sig
        Verify.setUp(verifyInfo);


        //starting time
        long VerifyStart = System.nanoTime();
        for(int i = 0; i < nOfRuns;i++){
          Verify.run();
        }
        //end time
        long VerifyEnd = System.nanoTime();
        long VerifyAverage = (VerifyEnd - VerifyStart)/nOfRuns;

        //Calculate averages
        writeToFile("KeyGenAverage.txt",String.format("NUMBER OF RUNS : %d\n",nOfRuns));
        writeToFile("SignAverage.txt",String.format("NUMBER OF RUNS : %d\n",nOfRuns));
        writeToFile("VerifyAverage.txt",String.format("NUMBER OF RUNS : %d\n",nOfRuns));

        System.out.println("KeyGen running average = " + KeyGenAverage + "ns");
        recordAverage("KeyGenAverage.txt",KeyGenAverage);
        System.out.println("Sign running average = " + SignAverage + "ns");
        recordAverage("SignAverage.txt",SignAverage);
        System.out.println("Verify average = " + VerifyAverage + "ns");
        recordAverage("VerifyAverage.txt",VerifyAverage);
    }

    public static void testAll() throws Exception {
      algorithm = "Lamport";
      testTime();
      algorithm = "Winternitz";
      windowSize = 1;
      testTime();
      algorithm = "Winternitz";
      windowSize = 2;
      testTime();
      algorithm = "Winternitz";
      windowSize = 4;
      testTime();
      algorithm = "Winternitz";
      windowSize = 8;
      testTime();

    }


    // public static void testMultipleFiles(){
    //   getInfo();
    //   KeyGen keygen = null;
    //   try {
    //       keygen = new KeyGen(algorithm, skFile, windowSize,pkFile);
    //   }catch (NoSuchAlgorithmException e){
    //       System.out.println("Exception thrown for incorrect algorithm: " + e);}
    //
    //   keygen.run();
    //
    //   Sign sign = new Sign(algorithm, sigFile, skFile, pkFile, msgFile, windowSize);
    //   String[] msgFiles = new String[5];
    //   msgFiles[0]=("msg.txt");
    //   msgFiles[1]=("msg1.txt");
    //   msgFiles[2]=("msg2.txt");
    //   msgFiles[3]=("msg3.txt");
    //   msgFiles[4]=("msg4.txt");
    //
    //   sign.run(msgFiles);
    //
    //   Verify verify = new Verify(pkFile, msgFile, sigFile, windowSize);
    //
    //   String[] sigFiles = new String[5];
    //   sigFiles[0]=("sig_msg.txt");
    //   sigFiles[1]=("sig_msg1.txt");
    //   sigFiles[2]=("sig_msg2.txt");
    //   sigFiles[3]=("sig_msg3.txt");
    //   sigFiles[4]=("sig_msg4.txt");
    //
    //   boolean isVerified = verify.run(msgFiles,sigFiles);
    // }

    public static void getInfo(){
      System.out.println("Pick an algorithm\n1.Lamport\n2.Winternitz");
      switch(myObj.nextInt()){
          case 1 : algorithm = "Lamport"; break;
          case 2 : algorithm = "Winternitz"; break;
          default : algorithm = null;
      }
      // Step 2 : if lamport = windowSize = 1
      if(algorithm.equals("Lamport")){
        windowSize=1;
      }
      else{
        // Step 2.2 : if winternitz then get window size
        System.out.println("Enter window size (Please use a multiple of 2)");
        int tempWindowSize = myObj.nextInt();
        if(tempWindowSize==1){
          windowSize=tempWindowSize;
        }
        else{
          while(tempWindowSize % 2 != 0){
            System.out.println("Please use a multiple of 2");
            tempWindowSize = myObj.nextInt();
          }
          windowSize = tempWindowSize;
        }
      }
    }

    private static void writeToFile(String fileName,String content){
      // If the file doesn't exists, create and write to it
      // If the file exists, truncate (remove all content) and write to it , if you wanna append then add , true next to filename
      try (FileWriter writer = new FileWriter(fileName,true);
           BufferedWriter bw = new BufferedWriter(writer)) {

          bw.write(content);

      } catch (IOException e) {
          System.err.format("IOException: %s%n", e);
      }
    }


    public static void recordAverage(String fileName,long average){

        // If the file doesn't exists, create and write to it
        // If the file exists, truncate (remove all content) and write to it , if you wanna append then add , true next to filename
        try (FileWriter writer = new FileWriter(fileName,true);
             BufferedWriter bw = new BufferedWriter(writer)) {

            // bw.write(String.format("WindowSize = %d\t Average for %d runs = %dns\n",windowSize,nOfRuns,average));
            bw.write(String.format("%d,%d\n",windowSize,average));

        } catch (IOException e) {
            System.err.format("IOException: %s%n", e);
        }
    }
}

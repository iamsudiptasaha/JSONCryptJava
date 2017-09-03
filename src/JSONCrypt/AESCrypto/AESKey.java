/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.AESCrypto;

import java.io.Serializable;
import java.security.SecureRandom;

/**
 * Object of AES Key. Required for 128 bit AES encryption.
 * <pre>
 * You are required to acquire an instance of this class, in order to create a 128 bit key of AES encryption.  
 * </pre>
 * @author Sudipta Saha
 * @version 1.0
 * @since 27/06/17
 */
public class AESKey implements Serializable{
    private String key;

    private AESKey(String key) {
        this.key=key;
    }
    
    String getKey(){
        return key;
    }
    /**
     * This function creates AES key from binary string input. 
     * @param key Binary string of 128 binary bits.
     * @return object of AESKey, which will be required for AES Encryption.
     * @throws InvalidFormatException If the input string is not 128 bits in length or is not of valid binary format.
     */
    public static AESKey binaryToKey(String key) throws InvalidFormatException{
        if(key.trim().length()==128 && SimpleCipher.Strings.Validate.isBinary(key)){
            return new AESKey(key);        
        }
        else if(key.trim().length()!=128){
            throw new InvalidFormatException("Key length not valid 128 bits. Current key length is "+key.trim().length());
        }
        else{
            throw new InvalidFormatException("Invalid binary format key.");
        }
    }
    
    /**
     * This function creates AES key from hexadecimal string input. 
     * <pre>
     * Hexadecimal encoding :
     * 00 - 00
     * 01 - 01
     * 02 - 02
     * 03 - 03
     * 04 - 04 
     * 05 - 05
     * 06 - 06
     * 07 - 07
     * 08 - 08
     * 09 - 09
     * 10 -  A
     * 11 -  B
     * 12 -  C
     * 13 -  D
     * 14 -  E
     * 15 -  F
     * </pre>
     * @param key Hexadecimal string of 32 set of 4 bits.
     * @return object of AESKey, which will be required for AES Encryption.
     * @throws InvalidFormatException If the input string is not 32 characters in length or is not of valid hexadecimal format.
     */
    public static AESKey hexToKey(String key) throws InvalidFormatException{
        if(key.trim().length()==32 && SimpleCipher.Strings.Validate.isHex(key)){
            return new AESKey(hexToBinary(key));
        }
        else{
            throw new InvalidFormatException("Not a valid 128 bit hex string.");
        }
    }
    
    /**
     * This function creates AES key from default java UTF-8 string input. 
     * @param key string of 16 characters.
     * @return object of AESKey, which will be required for AES Encryption.
     * @throws InvalidFormatException If the input string is not 16 characters in length or is not of valid format.
     */
    public static AESKey stringToKey(String key) throws InvalidFormatException{
       if(key.length()==16){
           return new AESKey(asciitoBinary(key));
       }
       else{
            throw new InvalidFormatException("Key should be 128 bits or 16 characters in length.");
       } 
    }
    
    
    /**
     * This function creates AES key from alpha numeric string input. 
     * @param key string of 16 characters, containing either alphabets or digits or both.
     * @return object of AESKey, which will be required for AES Encryption.
     * @throws InvalidFormatException InvalidFormatException If the input string is not 16 characters in length or is not of valid alphanumeric format.
     */
    public static AESKey alphanumericToKey(String key) throws InvalidFormatException{
       if(key.trim().length()==16 && SimpleCipher.Strings.Validate.isAlphanumeric(key)){
           return new AESKey(asciitoBinary(key));
       }
       else if(key.trim().length()!=16){
           throw new InvalidFormatException("Key length not valid 16 characters. Current key length is "+key.trim().length());
        }
       
       else{
            throw new InvalidFormatException("Not a valid 16 characters alphanumeric string.");
       }
    }
    /**
     * This function generates a random 128 bit AES key.
     * @return object of AESKey, which will be required for AES Encryption.
     */
    
    public static AESKey randomToKey(){    
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[16]; 
        random.nextBytes(bytes);
        return new AESKey(byteArrayToBinary(bytes));  
    }
    
    /**
     * This function converts byte array to it's equivalent binary string of 128 bits.
     * @param bytes 16 characters byte array for 128 bits key.
     * @return 128 bit binary string.
     */
    private static String byteArrayToBinary(byte[] bytes){
        StringBuffer sb=new StringBuffer("");
        for(int i=0;i<bytes.length;i++){
          sb.append(String.format("%8s",Integer.toBinaryString((bytes[i]+256)%256)).replace(' ', '0'));
        } 
        // System.out.print("\n Aes key length : "+sb.length());
        return sb.toString();
      
    }
    /**
     * This function converts input hexadecimal string to it's equivalent binary string of 128 bits.
     * @param hex 32 characters hexadecimal string for 128 bits key.
     * @return 128 bit binary string.
     */
    private static String hexToBinary(String hex){
       StringBuffer sb=new StringBuffer("");
       for(int i=0;i<hex.length();i=i+2){
           sb.append(String.format("%8s",Integer.toBinaryString(Integer.parseInt(hex.substring(i, i+2),16) & 0xff)).replace(' ', '0'));
       }       
       return sb.toString();
    }
    /**
     * This function converts input java default UTF-8 string to it's equivalent binary string of 128 bits.
     * @param ascii 16 characters string for 128 bits key.
     * @return 128 bit binary string.
     */
    private static String asciitoBinary(String ascii){ 
       StringBuffer binary_Data=new StringBuffer("");
       for(int i=0;i<ascii.length();i++){
           binary_Data.append(String.format("%8s", Integer.toBinaryString(ascii.charAt(i))).replace(" ", "0"));       
       }
       return binary_Data.toString();
    }
    
    String toASCIIString(){
       StringBuffer asciiString=new StringBuffer("");
        for(int i=0;i<key.length();i+=8){
            asciiString.append((char)Integer.parseInt(key.substring(i, i+8), 2));

        }
        
        return asciiString.toString();
    }
}

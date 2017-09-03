/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.AESCrypto;

import JSONCrypt.CustomEncryption;
import java.math.BigInteger;
import org.json.JSONException;

/**
 * This class contains functionalities for converting a plain text to it's equivalent AES encrypted cipher text
 * @author Sudipta Saha
 * @since 27/06/17
 * @version 1.0
 */
public class CipherText {
   /**
    * This function creates the required encrypted data from a given plain text. This function also encrypts the AES key using RSA encryption. 
    * @param aESKey The object of AESKey that contains the 128 bit encryption key.
    * @param plainText The string equivalent of data that needs to be encrypted.
    * @param e The RSA encryption key for encrypting the AES key.
    * @param N The RSA N key for encryption the AES key.
    * @return The JSON encoded encryptedJSONCRYPT string which contains both the encrypted data and key.
    * @throws JSONException JSON parse error.
    */ 
   public static String getAESEncryptedText(AESKey aESKey, String plainText, BigInteger e, BigInteger N) throws JSONException{
    AES_encrypt aES_encrypt=new AES_encrypt(aESKey, plainText);
    String cipherText=aES_encrypt.do_AES_encryption();
    
  //  System.out.print("\nAES key at encryption: "+aESKey.getKey());
    String cipherKey=new BigInteger(aESKey.getKey()).modPow(e, N).toString();
    
    //   System.out.print("\nCipher key AES key at encryption : "+cipherKey);
       org.json.JSONObject jbj=new org.json.JSONObject();
       jbj.put("encryptedJSONCRYPT", cipherText+"-"+cipherKey);
    return jbj.toString();
   }
   
   public static String getAESEncryptedText(AESKey aESKey, String plainText,Object customEncryptionClass) throws JSONException{
       AES_encrypt aES_encrypt=new AES_encrypt(aESKey, plainText);
       String cipherText=aES_encrypt.do_AES_encryption();
       CustomEncryption customEncryption=(CustomEncryption) customEncryptionClass;
       String cipherKey=customEncryption.customEncryption(aESKey.toASCIIString());
       org.json.JSONObject jbj=new org.json.JSONObject();
       jbj.put("encryptedJSONCRYPT", cipherText+"-"+cipherKey);
       return jbj.toString();
   }
}

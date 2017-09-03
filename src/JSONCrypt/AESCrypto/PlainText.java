/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.AESCrypto;

import JSONCrypt.CustomDecryption;
import JSONCrypt.RSACrypto.RSAKeys;
import java.math.BigInteger;

import org.json.JSONException;

/**
 * This class contains functionalities for converting a AES encrypted cipher text to it's equivalent plain text.
 * @author Sudipta Saha
 * @since 27/06/17
 * @version 1.0
 */
public class PlainText {
    /**
     * This function generates the required decrypted data from a given cipher text. This function also decrypts the AES key using RSA decryption. 
     * @param transmittedText The string equivalent of data that needs to be decrypted.
     * @param rSAKeys The RSAKey object containing the decryption key. 
     * @return The decrypted data.
     * @throws JSONException JSON parse error.
     * @throws InvalidFormatException Error while regenerating the AES key. Generally throws error, if the AES key has been tampered. 
     */
    public static String getAESDncryptedText(String transmittedText, RSAKeys rSAKeys) throws JSONException, InvalidFormatException{
        org.json.JSONObject jbj=new org.json.JSONObject(transmittedText);
        transmittedText=jbj.getString("encryptedJSONCRYPT");
        String cipherText=transmittedText.substring(0, transmittedText.lastIndexOf("-"));
        String cipherKey=transmittedText.substring(transmittedText.lastIndexOf("-")+1);
      //  System.out.print("\nCipher key at decryption : "+cipherKey);
        BigInteger key=new BigInteger(cipherKey).modPow(rSAKeys.getDecryptKey(), rSAKeys.getN());
        cipherKey=String.format("%128s",key).replace(" ", "0");
        AESKey aESKey=AESKey.binaryToKey(cipherKey);
        AES_decrypt aES_decrypt=new AES_decrypt(aESKey, cipherText);
        String plainText=aES_decrypt.do_AES_decryption();
      
    
        return plainText;
    }
    public static String getAESDncryptedText(String transmittedText,Object customDecryptionClass) throws JSONException, InvalidFormatException{
        org.json.JSONObject jbj=new org.json.JSONObject(transmittedText);
        transmittedText=jbj.getString("encryptedJSONCRYPT");
        String cipherText=transmittedText.substring(0, transmittedText.lastIndexOf("-"));
        String cipherKey=transmittedText.substring(transmittedText.lastIndexOf("-")+1);
        JSONCrypt.CustomDecryption customDecryption=(CustomDecryption) customDecryptionClass;
        cipherKey=customDecryption.customDecryption(cipherKey);
        
        AESKey aESKey=AESKey.stringToKey(cipherKey);
        AES_decrypt aES_decrypt=new AES_decrypt(aESKey, cipherText);
        String plainText=aES_decrypt.do_AES_decryption();
        return plainText;
    }
}

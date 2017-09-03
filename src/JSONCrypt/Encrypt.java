/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt;

import JSONCrypt.AESCrypto.CipherText;
import java.math.BigInteger;
import org.json.JSONException;

/**
 * This class contains functionalities for Encryption. 
 * @author Sudipta Saha
 * @since 29/06/17
 * @version 2.5
 */
public class Encrypt {
    
    /**
     * This function performs AES encryption.
     * @param aESKey Object of AESKey containing 128 bit AES key.
     * @param plainText User data that is required to be encrypted.
     * @param e RSA encryption key.
     * @param N RSA N key.
     * @return JSON encoded encrypted data.
     * @throws JSONException JSON parse error.
     */
    public static String AESEncrypt(JSONCrypt.AESCrypto.AESKey aESKey,String plainText,String e, String N) throws JSONException{
        return CipherText.getAESEncryptedText(aESKey, plainText, new BigInteger(e), new BigInteger(N));
    }
    
    /**
     * This function performs AES encryption.
     * @param aESKey Object of AESKey containing 128 bit AES key.
     * @param plainText User data that is required to be encrypted.
     * @param e RSA encryption key.
     * @param N RSA N key.
     * @return JSON encoded encrypted data.
     * @throws JSONException JSON parse error.  
     */
    public static String AESEncrypt(JSONCrypt.AESCrypto.AESKey aESKey,org.json.JSONObject plainText,String e, String N) throws JSONException{
        return CipherText.getAESEncryptedText(aESKey, plainText.toString(), new BigInteger(e), new BigInteger(N));
    }
    
    /**
     * This function performs AES encryption.
     * @param aESKey Object of AESKey containing 128 bit AES key.
     * @param plainText User data that is required to be encrypted.
     * @param rSAKeys JSON encoded RSA key.
     * @return JSON encoded encrypted data.
     * @throws JSONException JSON parse error.   
     */
    public static String AESEncrypt(JSONCrypt.AESCrypto.AESKey aESKey,String plainText, org.json.JSONObject rSAKeys) throws JSONException{
        if(rSAKeys.has("e") && rSAKeys.has("N")){
        
            return CipherText.getAESEncryptedText(aESKey, plainText.toString(), new BigInteger(rSAKeys.getString("e")), new BigInteger(rSAKeys.getString("N")));
       
        }
        else{
            
            throw new NullPointerException("Invalid RSAKeys.");
        }
    
    }
    
    /**
     * This function performs AES encryption.
     * @param aESKey Object of AESKey containing 128 bit AES key.
     * @param plainText User data that is required to be encrypted.
     * @param customEncryptionClass Object of class that implements CustomEncryption.
     * @return JSON encoded encrypted data.
     * @throws ClassNotFoundException If <b>customEncryptionClass</b> doesn't implement Interface CustomEncryption then an error is thrown.
     * @throws JSONException JSON parse error.
     */
    public static String AESEncrypt(JSONCrypt.AESCrypto.AESKey aESKey, String plainText, Object customEncryptionClass) throws ClassNotFoundException, JSONException{
        if(CustomEncryption.class.isInstance(customEncryptionClass)){
          //  System.out.print("\nGood to go.");
            return CipherText.getAESEncryptedText(aESKey, plainText, customEncryptionClass);
        }
        else{
           throw new ClassNotFoundException(customEncryptionClass.getClass()+" needs to implement JSONCrypt.CustomEncryption.");
        }
        
    }
    
     /**
     * This function performs AES encryption.
     * @param aESKey Object of AESKey containing 128 bit AES key.
     * @param plainText User data that is required to be encrypted.
     * @param customEncryptionClass Object of class that implements CustomEncryption.
     * @return JSON encoded encrypted data.
     * @throws ClassNotFoundException If <b>customEncryptionClass</b> doesn't implement Interface CustomEncryption then an error is thrown.
     * @throws JSONException JSON parse error.
     */
    public static String AESEncrypt(JSONCrypt.AESCrypto.AESKey aESKey, org.json.JSONObject plainText, Object customEncryptionClass) throws ClassNotFoundException, JSONException{
        if(CustomEncryption.class.isInstance(customEncryptionClass)){
          //  System.out.print("\nGood to go.");
            return CipherText.getAESEncryptedText(aESKey, plainText.toString(), customEncryptionClass);
        }
        else{
           throw new ClassNotFoundException(customEncryptionClass.getClass()+" needs to implement JSONCrypt.CustomEncryption.");
        }
        
    }
    
    /**
     * This function performs AES encryption.
     * @param aESKey Object of AESKey containing 128 bit AES key.
     * @param plainText User data that is required to be encrypted.
     * @param rSAKeys JSON encoded RSA key.
     * @return JSON encoded encrypted data.
     * @throws JSONException JSON parse error.   
     */
    public static String AESEncrypt(JSONCrypt.AESCrypto.AESKey aESKey,org.json.JSONObject plainText, org.json.JSONObject rSAKeys) throws JSONException{
        if(rSAKeys.has("e") && rSAKeys.has("N")){
            return CipherText.getAESEncryptedText(aESKey, plainText.toString(), new BigInteger(rSAKeys.getString("e")), new BigInteger(rSAKeys.getString("N")));
        }
        else{
            throw new NullPointerException("Invalid RSAKeys.");
        }
    }
    
    /**
     * This function performs RSA encryption.
     * @param plainText User data that is required to be encrypted.
     * @param e RSA encryption key.
     * @param N RSA N key.
     * @return JSON encoded encrypted data. 
     * @throws JSONException JSON parse error.   
     */
    public static String RSAEncrypt(org.json.JSONObject plainText, BigInteger e, BigInteger N) throws JSONException{
        return JSONCrypt.RSACrypto.CipherText.getRSAEncryptedText(plainText.toString(), e, N);
    }
    
    /**
     * This function performs RSA encryption.
     * @param plainText User data that is required to be encrypted.
     * @param rSAKeys JSON encoded RSA key.
     * @return JSON encoded encrypted data. 
     * @throws JSONException JSONException JSON parse error.   
     */
    public static String RSAEncrypt(org.json.JSONObject plainText, org.json.JSONObject rSAKeys) throws JSONException{
        if(rSAKeys.has("e") && rSAKeys.has("N")){
            return JSONCrypt.RSACrypto.CipherText.getRSAEncryptedText(plainText.toString(), new BigInteger(rSAKeys.getString("e")),new BigInteger(rSAKeys.getString("N")));
        }
        else{
            throw new NullPointerException("Invalid RSAKeys.");
        }
    }
    
    /**
     * This function performs RSA encryption.
     * @param plainText User data that is required to be encrypted.
     * @param e RSA encryption key.
     * @param N RSA N key.
     * @return JSON encoded encrypted data. 
     * @throws JSONException JSON parse error.   
     */
    public static String RSAEncrypt(String plainText, BigInteger e, BigInteger N) throws JSONException{
        return JSONCrypt.RSACrypto.CipherText.getRSAEncryptedText(plainText, e, N);
    }
    
    /**
     * This function performs RSA encryption.
     * @param plainText User data that is required to be encrypted.
     * @param rSAKeys JSON encoded RSA key.
     * @return JSON encoded encrypted data. 
     * @throws JSONException JSONException JSON parse error.   
     */
    public static String RSAEncrypt(String plainText, org.json.JSONObject rSAKeys) throws JSONException{
        if(rSAKeys.has("e") && rSAKeys.has("N")){
            return JSONCrypt.RSACrypto.CipherText.getRSAEncryptedText(plainText, new BigInteger(rSAKeys.getString("e")),new BigInteger(rSAKeys.getString("N")));
        }
        else{
            throw new NullPointerException("Invalid RSAKeys.");
        }
    }
    
    
}

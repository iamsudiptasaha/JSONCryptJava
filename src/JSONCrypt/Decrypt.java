/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt;

import JSONCrypt.AESCrypto.InvalidFormatException;
import JSONCrypt.AESCrypto.PlainText;
import org.json.JSONException;

/**
 * This class contains functionalities for Decryption. 
 * @author Sudipta Saha
 * @since 29/06/17
 * @version 2.5
 */
public class Decrypt {
    /**
     * This function decrypts AES encrypted data.
     * @param cipherText String that contains the encrypted text.
     * @param rSAKeys RSA keys that will decrypt the AES key.
     * @return decrypted user data.
     * @throws JSONException JSON parse error.
     * @throws InvalidFormatException Error while regenerating the AES key. Generally throws error, if the AES key has been tampered. 
     */
    public static String AESDecrypt(String cipherText, JSONCrypt.RSACrypto.RSAKeys rSAKeys) throws JSONException, InvalidFormatException{
        return PlainText.getAESDncryptedText(cipherText, rSAKeys);
    }
    
    /**
     * This function decrypts AES encrypted data.
     * @param cipherText String that contains the encrypted text.
     * @param customDecryptionClass Object of class that implements CustomDecryption.
     * @return decrypted user data.
     * @throws JSONException JSON parse error.
     * @throws InvalidFormatException Error while regenerating the AES key. Generally throws error, if the AES key has been tampered.  
     * @throws ClassNotFoundException If <b>customDecryptionClass</b> doesn't implement Interface CustomDecryption then an error is thrown.
     */
    public static String AESDecrypt(String cipherText, Object customDecryptionClass) throws JSONException, InvalidFormatException, ClassNotFoundException{
        if(CustomEncryption.class.isInstance(customDecryptionClass)){
        return PlainText.getAESDncryptedText(cipherText, customDecryptionClass);
        }
        else{
            throw new ClassNotFoundException(customDecryptionClass.getClass()+" needs to implement JSONCrypt.CustomDecryption.");
        }
    }
    
    /**
     * This function decrypts RSA encrypted data.
     * @param cipherText String that contains the encrypted text.
     * @param rSAKeys RSA keys that will decrypt the AES key.
     * @return decrypted user data.
     * @throws JSONException JSON parse error. 
     */
    public static String RSADecrypt(String cipherText, JSONCrypt.RSACrypto.RSAKeys rSAKeys) throws JSONException{
        return JSONCrypt.RSACrypto.PlainText.getRSADecryptedText(cipherText, rSAKeys);
    }
   
}

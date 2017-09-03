/*
 * Copyright 2017 Sudipta Saha.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package JSONCrypt.RSACrypto;

import java.math.BigInteger;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This class contains functionalities for converting a plain text to it's equivalent RSA encrypted cipher text.
 * @author Sudipta Saha
 * @since 04/07/17
 * @version 1.0
 */
public class CipherText {
    /**
     * This function creates the required encrypted data from a given plain text. This function uses RSA encryption. 
     * @param plainText The string equivalent of data that needs to be encrypted.
     * @param e The RSA encryption key.
     * @param N The RSA N key.
     * @return The JSON encoded encryptedJSONCRYPT string which contains the encrypted data.
     * @throws JSONException JSONException JSON parse error. 
     */
    public static String getRSAEncryptedText(String plainText, BigInteger e, BigInteger N) throws JSONException{
       RSA_encrypt rSA_encrypt=new RSA_encrypt(e, N, plainText);
       org.json.JSONObject jbj=new JSONObject();
       jbj.put("encryptedJSONCRYPT", rSA_encrypt.do_RSA_Encryption());
       return jbj.toString();
    }
}

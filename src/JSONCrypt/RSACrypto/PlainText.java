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

import org.json.JSONException;

/**
 * This class contains functionalities for converting a RSA encrypted cipher text to it's equivalent plain text.
 * @author Sudipta Saha
 * @since 04/07/17
 * @version 1.0
 */
public class PlainText {
    /**
     * This function generates the required decrypted data from a given cipher text. This function also uses RSA decryption. 
     * @param transmittedText The string equivalent of data that needs to be decrypted.
     * @param rSAKeys The RSAKey object containing the decryption key. 
     * @return The decrypted data.
     * @throws JSONException JSONException JSON parse error. 
     */
    public static String getRSADecryptedText(String transmittedText, RSAKeys rSAKeys) throws JSONException {
        org.json.JSONObject jbj=new org.json.JSONObject(transmittedText);
        RSA_decrypt rSA_decrypt=new RSA_decrypt(rSAKeys.getDecryptKey(), rSAKeys.getN(), jbj.getString("encryptedJSONCRYPT"));
        return rSA_decrypt.do_RSA_Decryption();
    }
}

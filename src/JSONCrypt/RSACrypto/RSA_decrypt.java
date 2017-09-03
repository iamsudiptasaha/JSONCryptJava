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
import java.util.StringTokenizer;

/**
 * This class has functionalities for decrypting a RSA encrypted data.
 * @author Sudipta Saha
 * @since 03/07/17
 * @version 1.5
 */
class RSA_decrypt {
    private BigInteger d;
    private BigInteger N;
    private String cipherText;
    private StringBuffer decryptedData;
    
    /**
     * Constructor to initialize the class with required cipherText that needs to be decrypted, RSA decryption key and N.
     * @param d The RSA decryption key.
     * @param N The RSA N key.
     * @param cipherText String text that needs to be decrypted.
     */
    RSA_decrypt(BigInteger d, BigInteger N, String cipherText) {
        this.d = d;
        this.N = N;
        this.cipherText = cipherText;
        
    }
    
    /**
     * This function performs the RSA decryption on a given data of 128 bits.
     * @return The decrypted java default UTF-8 string.  
     */
    String do_RSA_Decryption(){
        decryptedData=new StringBuffer("");
        StringTokenizer st=new StringTokenizer(cipherText,"-");
        while (st.hasMoreTokens()) {             
            String temp=st.nextToken();
            BigInteger b=new BigInteger(temp).modPow(d, N);
            decryptedData.append(String.format("%128s", b).replace(' ', '0'));
        }
        String asciiString= toASCIIString(decryptedData.toString());
        return asciiString.substring(asciiString.indexOf("{")+1, asciiString.lastIndexOf("}"));
    }
    /**
     * This function converts a 128 bit binary data to it's equivalent java default UTF-8 string.
     * @param binaryData 128 bit binary string.
     * @return Equivalent java default UTF-8 string.
     */
    private String toASCIIString(String binaryData){
        StringBuffer asciiString=new StringBuffer("");
        for(int i=0;i<binaryData.length();i+=8)
            asciiString.append((char)Integer.parseInt(binaryData.substring(i, i+8), 2));

        return asciiString.toString();
    
    }
      
}

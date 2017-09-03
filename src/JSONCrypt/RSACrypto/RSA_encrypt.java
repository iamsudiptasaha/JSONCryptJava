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
import java.util.Collections;

/**
 * This class has functionalities for RSA encryption of user data.
 * @author Sudipta Saha
 * @since 03/07/17
 * @version 1.0
 */

class RSA_encrypt {
    private BigInteger e;
    private BigInteger N;
   
    private String plainText;
    private StringBuffer binary_Data;
    private StringBuffer encryptedData;
    
    /**
     * Constructor to initialize the class with required RSA encryption key and N key are required to encrypt plain text.
     * @param e The RSA encryption key.
     * @param N The RSA N key.
     * @param plainText String text that needs to be encrypted.
     */
    RSA_encrypt(BigInteger e, BigInteger N, String plainText) {
        this.e = e;
        this.N = N;
        this.plainText = "{"+plainText+"}";
        toBinaryData();
    }
    
    /**
     * This function converts the string data to it's equivalent binary bits.
     */
    private void toBinaryData() {
        int digitCount=plainText.length();
        if(plainText.length()%16!=0){
           plainText=plainText+String.join("", Collections.nCopies(16-plainText.length()%16, "*"));
       
        }    
        binary_Data=new StringBuffer("");
        for(int i=0;i<plainText.length();i++)
            binary_Data.append(String.format("%8s", Integer.toBinaryString(plainText.charAt(i))).replace(" ", "0")); 
        System.out.print("\n");
        
    }
    
    /**
     * This function performs the RSA encryption on a given data.
     * @return The encrypted java default UTF-8 string.
     */
    String do_RSA_Encryption(){
        encryptedData=new StringBuffer();
        String pull=null;
        System.out.print("\n Binary length : "+binary_Data.length());
        for(int i=0;i<binary_Data.length();i+=128){
            if(binary_Data.length()- i > 128){
           
                encryptedData.append(new BigInteger(binary_Data.substring(i, i+128)).modPow(e, N)+"-");
                
            }
         
            else{
           
                encryptedData.append(new BigInteger(binary_Data.substring(i)).modPow(e, N));
            }
               
        }
     
        return encryptedData.toString();
    }
    
}

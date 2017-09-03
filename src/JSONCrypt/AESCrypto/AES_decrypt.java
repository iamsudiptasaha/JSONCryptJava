/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.AESCrypto;

/**
 * This class has functionalities for decrypting a 128 bit AES encrypted data.
 * @author Sudipta Saha
 * @since 26/06/17
 * @version 1.0
 */
class AES_decrypt {
    private StringBuffer decryptedData;
    private byte[][] roundkey;
    private AESKey aESKey;
    private String cipherText;
    private StringBuffer binary_Data;
    /**
     * Constructor to initialize the class with required AESKey object which can be obtained by creating an instance of AESKey class and cipherText here is the data that needs to be decrypted.
     * @param aESKey AESKey object. 
     * <pre>
     * For example : 
     * AESKey aESKey=AESKey.randomToKey();
     * </pre>
     * @param cipherText String text that needs to be decrypted.
     */
    AES_decrypt(AESKey aESKey, String cipherText){
        this.aESKey=aESKey;
        this.cipherText=cipherText;
        toBinaryData();
    }
    
     /**
     * Constructor to initialize the class with required AESKey object which can be obtained by creating an instance of AESKey class and cipherText here is the data that needs to be decrypted.
     * @param aESKey AESKey object. 
     * <pre>
     * For example : 
     * AESKey aESKey=AESKey.randomToKey();
     * </pre>
     * @param cipherText JSON object that needs to be decrypted.
     */
    AES_decrypt(AESKey aESKey, org.json.JSONObject cipherText){
        this.aESKey=aESKey;
        this.cipherText=cipherText.toString();
        toBinaryData();
    }
    
    /**
     * This function converts the string data to it's equivalent binary bits.
     */    
    private void toBinaryData() {     
        binary_Data=new StringBuffer("");      
        for(int i=0;i<cipherText.length();i++)
            binary_Data.append(String.format("%8s", Integer.toBinaryString(cipherText.charAt(i))).replace(" ", "0"));         
    }
 
    /**
     * This function converts a 4x4 stateMatrix required for encryption to its equivalent binary data.
     * @param stateMatrix The stateMatrix that needs to be converted.
     * @return The binary equivalent string data.
     */
    private String stateMatrix_to_data(byte[][] stateMatrix){
        StringBuffer sb=new StringBuffer("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        int cork;
        for(int i=0;i<128;i+=8){
            cork=(i+8)/8;
  
            if(cork>=1 && cork<=4){
             
                sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(stateMatrix[0][cork%4]& 0xff)).replace(' ', '0'));
             
            }
            else if(cork>=5 && cork<=8){
          
                sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(stateMatrix[1][cork%4]& 0xff)).replace(' ', '0'));
             
            }
            else if(cork>=9 && cork<=12){
          
                sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(stateMatrix[2][cork%4]& 0xff)).replace(' ', '0'));
             
            }
            else if(cork>=13 && cork<=16){
            
                sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(stateMatrix[3][cork%4]& 0xff)).replace(' ', '0'));
            
            }      
        }

        return sb.toString();       
    }
    
    
    /**
     * This function converts a binary string data to it's equivalent stateMatrix required for encryption.
     * @param data Binary string data that needs to be converted.
     * @return 4X4 stateMatrix of binary data.
     */
    private byte[][] data_to_StateMatrix(String data){
        byte[][] stateMatrix=new byte[4][4];
        int cork;
        for(int i=0;i<binary_Data.length();i+=8){
            cork=(i+8)/8;
            
            if(cork>=1 && cork<=4){
                
                stateMatrix[0][cork%4]=(byte) Integer.parseInt(data.substring(i, i+8),2);
           
            }
            else if(cork>=5 && cork<=8){
                
                stateMatrix[1][cork%4]=(byte) Integer.parseInt(data.substring(i, i+8),2);
            
            }
            else if(cork>=9 && cork<=12){
           
                stateMatrix[2][cork%4]=(byte) Integer.parseInt(data.substring(i, i+8),2);
           
            }
            else if(cork>=13 && cork<=16){
           
                stateMatrix[3][cork%4]=(byte) Integer.parseInt(data.substring(i, i+8),2);
            
            }    
        }
        
        return stateMatrix;
         
    }
    /**
     * This function performs the AES decryption on a given data of 128 bits.
     * @return The decrypted java default UTF-8 string. 
     */
    String do_AES_decryption(){
        decryptedData=new StringBuffer("");
        byte[][] stateMatrix;
        String intermediate_data;
        roundkey=new GenerateRoundKey().getRoundKey(Utility.AESKey_to_AESKeyMatrix(aESKey.getKey()));
        Utility utility=new Utility(roundkey);
        for(int i=0;i<binary_Data.length();i+=128){
            intermediate_data=binary_Data.substring(i, i+128);
        
            stateMatrix=data_to_StateMatrix(intermediate_data);
            for(int j=0;j<11;j++){
                if(j==0){
               
                    stateMatrix=Utility.inverse_addRoundKey(stateMatrix, j);
          
                    stateMatrix=Utility.inverse_shiftRows(stateMatrix);
            
                    stateMatrix=Utility.inverse_subBytes(stateMatrix);
                }
                else if(j==10){
         
                    stateMatrix=Utility.inverse_addRoundKey(stateMatrix, j);
           
                }
                else{
          
                    stateMatrix=Utility.inverse_addRoundKey(stateMatrix, j);
        
                    stateMatrix=utility.inverse_mixColumns(stateMatrix);
        
                    stateMatrix=Utility.inverse_shiftRows(stateMatrix);
         
                    stateMatrix=Utility.inverse_subBytes(stateMatrix);
                
                }
           
            }     
            decryptedData.append(stateMatrix_to_data(stateMatrix));  
        }
     //   System.out.print("\n Binary decrypted data : "+decryptedData.toString());
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

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.AESCrypto;

/**
 * This class contains primitive and referential functionalities for encryption and decryption of AES Encryption technique.
 * @author Sudipta Saha
 * @since 25/06/17
 * @version 1.5
 */
class Utility {
    private static byte[][] roundKey;
    
    /**
     * Constructor to initialize the AES round key.
     * @param roundKey AES round key
     */
    Utility(byte[][] roundKey){
       this.roundKey=roundKey;
       
    }
    /**
     * This function converts a binary 128 bit AES key string to it's equivalent AES key Matrix required for encryption.
     * @param AESKey The binary string equivalent of AES key.
     * @return The AES key matrix.
     */
    static byte[][] AESKey_to_AESKeyMatrix(String AESKey){
        byte[][] AESKeyMatrix=new byte[4][4];
        int cork;
        for(int i=0;i<AESKey.length();i+=8){
            cork=(i+8)/8;
            
            if(cork>=1 && cork<=4){
              
                AESKeyMatrix[0][cork%4]=(byte) Integer.parseInt(AESKey.substring(i, i+8),2);
            
            }
            else if(cork>=5 && cork<=8){
                
                AESKeyMatrix[1][cork%4]=(byte) Integer.parseInt(AESKey.substring(i, i+8),2);
            }
            else if(cork>=9 && cork<=12){
                
                 AESKeyMatrix[2][cork%4]=(byte) Integer.parseInt(AESKey.substring(i, i+8),2);
            }
            else if(cork>=13 && cork<=16){
                
                AESKeyMatrix[3][cork%4]=(byte) Integer.parseInt(AESKey.substring(i, i+8),2);
            }
            
        }
        return AESKeyMatrix;
    }
    
    /**
     * This function converts a 4x4 AES key Matrix to its equivalent AES binary key.
     * @param AESKeyMatrix The AES key Matrix that needs to be converted.
     * @return The binary equivalent 128 bit AES key.
     */
    static String AESKeyMatrix_to_AESKey(byte[][] AESKeyMatrix){
       
        StringBuffer sb=new StringBuffer("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        int cork;
        for(int i=0;i<128;i+=8){
            cork=(i+8)/8;
            
            if(cork>=1 && cork<=4){
              
              sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(AESKeyMatrix[0][cork%4]& 0xff)).replace(' ', '0'));
             
            }
            else if(cork>=5 && cork<=8){
         
                sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(AESKeyMatrix[1][cork%4]& 0xff)).replace(' ', '0'));
             
            }
            else if(cork>=9 && cork<=12){
           
                sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(AESKeyMatrix[2][cork%4]& 0xff)).replace(' ', '0'));
             
            }
            else if(cork>=13 && cork<=16){
                
                sb.replace(i,i+8,String.format("%8s",Integer.toBinaryString(AESKeyMatrix[3][cork%4]& 0xff)).replace(' ', '0'));
             
            }
            
        }
    
          return sb.toString();
    }
    
    /**
     * This function substitutes the elements of the matrix from equivalent AES SBOX.
     * @param stateMatrix The stateMatrix whose elements are required to be substituted.
     * @return The altered matrix.
     */
    static byte[][] subBytes(byte[][] stateMatrix){
        int n;  
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                n=(stateMatrix[i][j]+256)%256;  
                stateMatrix[i][j]=(byte)ReferenceBytes.sbox[n >>> 4][n & 0x0F];
               }
           }
        return stateMatrix;
    }
      static byte[][] inverse_subBytes(byte[][] stateMatrix){
         int n;  
         for(int i=0;i<4;i++){
               for(int j=0;j<4;j++){
                   n=(stateMatrix[i][j]+256)%256;  
                   stateMatrix[i][j]=(byte)ReferenceBytes.inverse_sbox[n >>> 4][n & 0x0F];
               }
           }
         return stateMatrix;
    }
     
    /**
     * This function performs AES inverse shift rows.
     * @param stateMatrix The stateMatrix whose rows are required to be inversely shifted.
     * @return The altered matrix.
     */
    static byte[][] inverse_shiftRows(byte[][] stateMatrix){
        int count=0;    
        for(int i=0;i<4;i++){
              switch(i){
                  case 0: break;
                  
                  case 1: stateMatrix[i]=rowShifter(stateMatrix[i],false);
                          break;
                  case 2: while(count++<2)
                            stateMatrix[i]=rowShifter(stateMatrix[i],false);
                          break;
                  case 3: count=0;
                          while(count++<3)
                            stateMatrix[i]=rowShifter(stateMatrix[i],false);                     
                          break;
                      
              }  
            }
        return stateMatrix;
    }  
    
    
    
    /**
     * This function performs AES inverse shift rows.
     * @param stateMatrix The stateMatrix whose rows are required to be shifted.
     * @return The altered matrix.
     */
    static byte[][] shiftRows(byte[][] stateMatrix){
        int count=0;    
        for(int i=0;i<4;i++){
              switch(i){
                  case 0: break;
                  
                  case 1: stateMatrix[i]=rowShifter(stateMatrix[i],true);
                          break;
                  case 2: while(count++<2)
                            stateMatrix[i]=rowShifter(stateMatrix[i],true);
                          break;
                  case 3: count=0;
                          while(count++<3)
                            stateMatrix[i]=rowShifter(stateMatrix[i],true);                     
                          break;
                      
              }  
            }
        return stateMatrix;
    }  
    
    /**
     * This function performs one byte shift of rows.
     * @param row The row whose data is required to be shifted.
     * @param forward The direction in which the data is required to be shifted. 
     * <pre>
     * <b>True</b> : Forward shift.
     * <b>False</b> : Reverse shift.
     * </pre>
     * @return The altered row.
     */
    private static byte[] rowShifter(byte[] row,boolean forward){
      byte temp;
      if(forward){
      temp=row[0];       
      for(int i=0;i<3;i++){
          row[i]=row[i+1];
      }
      row[3]=temp;
      }
      else{
        temp=row[3];     
        for(int i=3;i>0;i--){
          row[i]=row[i-1];
      }
       row[0]=temp; 
      }
      return row;
      
    }
    
    
    
     /**
     * This function returns the specific column of a matrix.
     * @param matrix The matrix whose column needs to be selected.
     * @param column The column index which needs to be selected. 
     * @return The selected column.
     */
    private static byte[] getColumn(byte[][] matrix, int column){
       byte[] tempbytes=new byte[4];
        for(int i=0;i<4;i++){
            tempbytes[i]=matrix[i][column];
            
        }
        return tempbytes;
    }
    
    /**
     * This function replaces a column of a matrix with a new column.
     * @param matrix The matrix whose column will be replaced.
     * @param columnMatrix The new column that the old column will be substituted with.
     * @param column The column index which will be replaced.
     * @return The altered matrix.
     */
    private static byte[][] setColumn(byte[][] matrix, byte[] columnMatrix, int column){
        for(int i=0;i<4;i++){
            matrix[i][column]=columnMatrix[i];
            
        }
        return matrix;
    }
    
    
    
    /**
     * This function performs XOR operation on two bytes.
     * @param a The first byte.
     * @param b The second byte.
     * @return The XOR operation result.
     */
    private static byte xorBytes(byte a, byte b){  
     return (byte)(0xff & ((int)a ^ (int)b));  
    }
    
    
    
    /**
     * This function calculates the byte multiplication with 2.
     * @param a The byte that needs to be multiplied with 2.
     * @return The multiplication with 2 result.
     */
    private static byte byteMultiplyByTwo(byte a){
        
        if(a<0){
         a=(byte)(a << 1);  
         a=(byte)(a^0x1B);  
       }
       else{
         a=(byte)(a << 1);  
         a^=0x00;  
       }
       return a;
    }
    
    
    
    /**
     * This function performs byte multiplication with 1, 2, 3, 9, 11, 13, 14
     * @param a The byte that needs to be multiplied.
     * @param b Either of 1 or 2 or 3 or 9 or 11 or 13 or 14 that the byte shall be multiplied with.
     * @return The multiplication result.
     */
    private byte byteMultiply(byte a,byte b){
        
        //HERE (X * 2) is done by the function byteMultiplyByTwo(a)
        // a+b in Rijndael is xor operation.
        if(b==2){ 
            
            return byteMultiplyByTwo(a);
       
        }
      
        else if(b==3){
            byte c; 
            c=a;   
            a=byteMultiplyByTwo(a);
            a=(byte)(a^c);    
            return a;
       
        }
      
        else if(b==9){
            
            //x * 9= ( ( ( x * 2 ) * 2 ) * 2 ) + x  
            
            a=xorBytes(byteMultiplyByTwo(byteMultiplyByTwo(byteMultiplyByTwo(a))),a);
            
            return a;
        }
        else if(b==11){
            
            //x*11=((((x*2)*2)+x)*2)+x
            
            a=xorBytes(byteMultiplyByTwo(xorBytes(byteMultiplyByTwo(byteMultiplyByTwo(a)),a)),a);
            
            return a;
        
        }
        
        else if(b==13){
          
            //x*13=((((x*2)+x)*2)*2)+x
            
            a=xorBytes(byteMultiplyByTwo(byteMultiplyByTwo(xorBytes(byteMultiplyByTwo(a),a))),a);
            
            return a;
        }
        else if(b==14){
          
            //x*14=((((x*2)+x)*2)+x)*2
            
            a=byteMultiplyByTwo(xorBytes(byteMultiplyByTwo(xorBytes(byteMultiplyByTwo(a),a)),a));
            
            return a;
        }
      
        else 
            
            return a;
      
    }
    
    
    
    /**
     * This function performs AES inverse mix columns operation.
     * @param stateMatrix The stateMatrix which requires inverse mixColumn operation.
     * @return The altered matrix.
     */
    byte[][] inverse_mixColumns(byte[][] stateMatrix){
        byte[] temprow;
        byte[] mixColRow;
        byte[] rijndaelRow=new byte[4];
        byte rijndaelXor=0x00;
        for(int i=0;i<4;i++){
           temprow=getColumn(stateMatrix, i);
           for(int j=0;j<4;j++){
               rijndaelXor=0x00; 
               mixColRow=ReferenceBytes.inverse_mixColumnMatrix[j];
               for(int k=0;k<4;k++){
                    rijndaelRow[k]=byteMultiply(temprow[k], mixColRow[k]);
                    
                    rijndaelXor ^= rijndaelRow[k];
                 
                }
            
            stateMatrix[j][i]=rijndaelXor;
           
           }
        }
        return stateMatrix;
    }
    
    /**
     * This function performs AES mix columns operation.
     * @param stateMatrix The stateMatrix which requires mixColumn operation.
     * @return The altered matrix.
     */
    byte[][] mixColumns(byte[][] stateMatrix){
        byte[] temprow;
        byte[] mixColRow;
        byte[] rijndaelRow=new byte[4];
        byte rijndaelXor=0x00;
        for(int i=0;i<4;i++){
            temprow=getColumn(stateMatrix, i);
            
            
            
            
            for(int j=0;j<4;j++){
                rijndaelXor=0x00; 
                mixColRow=ReferenceBytes.mixColumnMatrix[j];
                for(int k=0;k<4;k++){
                    rijndaelRow[k]=byteMultiply(temprow[k], mixColRow[k]);
                    rijndaelXor ^= rijndaelRow[k];
                }
              
                stateMatrix[j][i]=rijndaelXor;
            }
       
        }
         
        return stateMatrix;
    }
    
    /**
     * This function performs AES addRoundKey operation. This is done in reference to AES round key.
     * @param stateMatrix The state matrix on which roundkey is to be added.
     * @param turn The round key iteration.
     * @return The altered matrix.
     */
    static byte[][] addRoundKey(byte[][] stateMatrix,int turn){
        turn*=4;
        for(int i=0;i<4;i++){
            
            for(int j=0;j<4;j++){
               
                int n=(stateMatrix[j][i]+256)%256;
                stateMatrix[j][i]=xorBytes(stateMatrix[j][i], roundKey[j][turn]);

            }
            turn++;
        }
        return stateMatrix;
    }
    
    /**
     * This function performs AES inverse addRoundKey operation. This is done in reference to AES round key.
     * @param stateMatrix The state matrix on which inverse roundkey is to be added.
     * @param turn The round key iteration.
     * @return The altered matrix.
     */
    static byte[][] inverse_addRoundKey(byte[][] stateMatrix,int turn){
        turn=(10-turn)*4;
        for(int i=0;i<4;i++){
            
            for(int j=0;j<4;j++){
               
          
               stateMatrix[j][i]=xorBytes(stateMatrix[j][i], roundKey[j][turn]);
          
            }
            turn++;
        }
        return stateMatrix;
    }
   
    /**
     * This function prints hexadecimal representation of input byte. 
     * <pre>
     * Format : [XX-XX]
     * For example : [3f-17]
     * </pre>
     * @param mybyte The byte whose hexadecimal representation is required to be printed.
     */
    static void printHexByte(byte mybyte){
        int n=(mybyte+256)%256;
        System.out.print("\n ["+(n >>> 4)+"-"+(n & 0x0F)+"]");
        
    }
    
    /**
     * This function returns hexadecimal representation of input byte. 
     * <pre>
     * Format : [XX-XX]
     * For example : [3f-17]
     * </pre>
     * @param mybyte The byte whose hexadecimal representation is required to be found.
     * @return string representation of equivalent hexadecimal value.
     */
    static String getHexByte(byte mybyte){
        int n=(mybyte+256)%256;
        return "["+(n >>> 4)+"-"+(n & 0x0F)+"]";
    }
     
     
}

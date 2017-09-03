/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.AESCrypto;

/**
 * This class generates the AES Round key from 128 bit AES encryption key.
 * @author Sudipta Saha
 * @version 1.0
 * @since 28/06/17
 */
class GenerateRoundKey {
    
   /**
    * This function rotates a row clockwise.
    * @param row The row that needs to be rotated.
    * @return The row after being rotated.
    */  
   private static byte[] rotateRow(byte[] row){
      byte temp;
      temp=row[0];       
      for(int i=0;i<3;i++){
          row[i]=row[i+1];
      }
      row[3]=temp;
      return row;
    } 
    
    /**
     * This function XORs the elements of two rows.
     * @param row1 The first row.
     * @param row2 The second row.
     * @return Equivalent row after XOR operation.
     */
    private static byte[] xorRow(byte[] row1, byte[] row2){
      int n;
      int p;
      for(int i=0;i<4;i++){
            row1[i] =(byte)(0xff & ((int)row1[i] ^ (int)row2[i]));
      }
      return row1;
      
    }
    /**
     * This function substitutes the elements of the row from equivalent AES SBOX.
     * @param row The row whose values need to be substituted.
     * @return The altered row.
     */
    private static byte[] subBytes(byte[] row){
        int n;
        for(int i=0;i<4;i++){
            n=(row[i]+256)%256;        
            row[i]=(byte)ReferenceBytes.sbox[n >>> 4][n & 0x0F];
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
     * This function generates the 44x4 round key matrix of AES 128 bit encryption.
     * @param AESKeyMatrix The 4x4 equivalent 128 AES key matrix.
     * @return The round key matrix.
     */
    byte[][] getRoundKey(byte[][] AESKeyMatrix){
        byte roundKey[][]=new byte[4][44];
         byte[] tempbytes;
        byte[] temprow;
       // short s=0xBA;
        for(int i=0;i<4;i++){
            roundKey[0][i]=AESKeyMatrix[0][i];
              roundKey[1][i]=AESKeyMatrix[1][i];
                roundKey[2][i]=AESKeyMatrix[2][i];
                  roundKey[3][i]=AESKeyMatrix[3][i];
                  
        }
        
        
        for(int i=4;i<=43;i++){
       
            if(i%4==0){
                //take i-1 as x row; 
                //--------------------------------------------------------------------------------------
                temprow=getColumn(roundKey, i-1);
             
                //rotateRow x            
                //-------------------------------------------------------------------------------------- 
                temprow=rotateRow(temprow);
       
                //subbytes x 
                //-------------------------------------------------------------------------------------- 
                temprow=subBytes(temprow);
                
                //xorRow i-4 with x
                //-------------------------------------------------------------------------------------- 
                 temprow=xorRow(getColumn(roundKey, i-4), temprow);
             
                // xorRow x with rcon(i/4) row
                //-------------------------------------------------------------------------------------- 
                temprow=xorRow(temprow, getColumn(ReferenceBytes.rcon,(i/4)-1));
        
                //save row   
                //-------------------------------------------------------------------------------------- 
                for(int j=0;j<4;j++){
                    roundKey[j][i]=temprow[j];
             
                }
     
            }
            else{
                //take i-1 as x row;   
                //-------------------------------------------------------------------------------------- 
                temprow=getColumn(roundKey, i-1);
                
                //xorRow i-4 with x
                //-------------------------------------------------------------------------------------- 
                temprow=xorRow(getColumn(roundKey, i-4), temprow);
                //save row 
                //-------------------------------------------------------------------------------------- 
                for(int j=0;j<4;j++){
                    roundKey[j][i]=temprow[j];
             
                }
                  
            }
        }
        
        return roundKey;
    } 
    
}

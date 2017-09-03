/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.AESCrypto;

/**
 * Exception class for invalid expression format.
 * @author Sudipta Saha
 * @since 21/06/17
 * @version 1.0
 */
public class InvalidFormatException extends Exception{
    InvalidFormatException(String s){
        super(s);
        System.out.print(s);
    } 
}

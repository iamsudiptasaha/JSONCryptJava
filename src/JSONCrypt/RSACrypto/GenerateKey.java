/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.RSACrypto;

import java.math.BigInteger;
import java.util.Random;

/**
 * This class contains functionalities for generating a RSA key.
 * @author Sudipta Saha
 * @since 26/07/17
 * @version 1.2
 */


class GenerateKey {
    private Random r;
    private static BigInteger p;
    private static BigInteger q;
    protected static BigInteger N;
    private static BigInteger phi;
    protected static BigInteger e;
    protected static BigInteger d;
    private final static int bitlength = 256;
    
    /**
     * Constructor that generates a RSA key.
     */
    GenerateKey(){
       r=new Random();
       p=BigInteger.probablePrime(bitlength, r);
       q=BigInteger.probablePrime(bitlength, r);
       N = p.multiply(q);
       phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
       e = BigInteger.probablePrime(bitlength/2, r);
            while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0 ) {
		e.add(BigInteger.ONE);
 
            }
 
	    d = e.modInverse(phi);
        }
    }

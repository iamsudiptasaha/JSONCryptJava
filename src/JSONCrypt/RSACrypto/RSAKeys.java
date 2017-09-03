/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JSONCrypt.RSACrypto;
import java.math.BigInteger;
import org.json.JSONException;

/**
 * This class is required to acquire an instance of RSA key. RSA key encrypts the 128 bit AES key.
 * @author Sudipta Saha
 * @version 1.0
 * @since 27/06/17
 */
public class RSAKeys {
    private BigInteger e;
    private BigInteger d;
    private BigInteger N;
    private RSAKeys rSAKeys;
    
    /**
     * Constructor to generate a RSA key. 
     */
    public RSAKeys() {
        GenerateKey generateKey=new GenerateKey();
        
        this.e = generateKey.e;
        this.d = generateKey.d;
        this.N = generateKey.N;
    }

    /**
     * @return the encryption key.
     */
    public BigInteger getEncryptKey() {
        return e;
    }

    /**
     * @return the decryption key.
     */
    public BigInteger getDecryptKey() {
        return d;
    }

    /**
     * @return the N
     */
    public BigInteger getN() {
        return N;
    }
    
    /**
     * This function returns the string representation of JSON encoded RSA key for transmission.
     * <pre><b>The JSON string only contains the encryption key and N.</b>
     * Decryption key should be private. DONOT SHARE DECRYPTION KEY. Intruders will be able to decrypt data with decryption key.
     * </pre>
     * @return String representation of JSON encoded RSA key.
     * @throws JSONException JSON parse error.
     */
    public String getJsonEncodedRSAKey() throws JSONException{
        org.json.JSONObject jbj=new org.json.JSONObject();
        jbj.put("e", e);
        jbj.put("N", N);
        return jbj.toString();
    }
}

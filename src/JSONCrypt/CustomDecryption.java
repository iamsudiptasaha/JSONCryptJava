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
package JSONCrypt;

/**
 * This interface contains abstract methods for user defined decryption of AES key.
 * @author Sudipta Saha
 * @since 04/07/17
 * @version 1.0
 */
public interface CustomDecryption {
    
    /**
     * This abstract method let's you define your own method for AES key decryption. 
     * @param cipherKey user encrypted cipher key.
     * @return 128 bit or 16 character java default UTF-8 string key. 
     */
    public String customDecryption(String cipherKey);
}

package security;

import java.math.BigInteger;

public class Operations {
    public static BigInteger encrypt(Key key, Long plainText){
        return key.getEncryption_dict().get(plainText);
    }
    public static Long decrypt(Key key, BigInteger ciphered){
        return key.getDecryption_dict().get(ciphered);
    }
    public static String keyGeneration(){
        StringBuilder keyContent = new StringBuilder(new String(""));
        for(int i=1;i<65536;i++){
            keyContent.append(Integer.toString(i)).append("=").append
                    (BigInteger.valueOf(i).multiply(BigInteger.valueOf(66000)).add(BigInteger.valueOf(8))).append("\n");
        }
        return keyContent.toString();

    }
}

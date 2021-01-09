package security;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class Key {
    private final Map<Long, BigInteger> encryption_dict = new HashMap<>();
    private final Map<BigInteger, Long> decryption_dict = new HashMap<>();
    public Key(String keyFile) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(keyFile));
        String line = reader.readLine();
        while (line != null){
            String[] attrib_value = line.split("=");
            encryption_dict.put(Long.parseLong(attrib_value[0]), new BigInteger(attrib_value[1]));
            decryption_dict.put(new BigInteger(attrib_value[1]), Long.parseLong(attrib_value[0]));
            line = reader.readLine();
        }
        reader.close();
    }

    public Map<Long, BigInteger> getEncryption_dict() {
        return encryption_dict;
    }

    public Map<BigInteger, Long> getDecryption_dict() {
        return decryption_dict;
    }
}

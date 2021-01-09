package encoder;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class EncodingScheme {
    private final Map<String, Integer> encoder = new HashMap<>();
    public EncodingScheme(String encoding_file) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(encoding_file));
        String line = reader.readLine();
        while (line != null){
            String[] attrib_value = line.split("=");
            encoder.put(attrib_value[0], Integer.parseInt(attrib_value[1]));
            line = reader.readLine();
        }
        reader.close();
    }
    public Integer getEncodedValue(String attrib)
    {
        return encoder.get(attrib);
    }
}

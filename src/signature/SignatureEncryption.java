package signature;

import encoder.EncodingScheme;
import hashing.SHA;
import security.Key;
import security.Operations;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class SignatureEncryption {
    private final EncodingScheme encoder;
    private final Key key;
    private final BufferedReader reader;
    private final ArrayList<String> results = new ArrayList<>();

    public SignatureEncryption(Key key, String signature_file, String encoding_file) throws IOException {
        this.key = key;
        this.reader = new BufferedReader(new FileReader(signature_file));
        this.encoder = new EncodingScheme(encoding_file);
        this.encrypt();
        this.reader.close();
    }
    private void encrypt() throws IOException {
        String line = this.reader.readLine();
        StringBuilder result = new StringBuilder();
        while (line != null){
            String[] inbound_outbound = line.split("->");
            String inbound = inbound_outbound[0];
            String outbound = inbound_outbound[1];
            String[] inbound_attrib = inbound.split(" ");
            String protocol = inbound_attrib[0];
            String IN_IP = inbound_attrib[1];
            String inbound_port = inbound_attrib[2];
            String[] outbound_attrib = outbound.split(" ");
            String OUT_IP = outbound_attrib[1];
            String outbound_port = outbound_attrib[2];
            try
            {
                result.append(SHA.toHexString(SHA.getSHA("Protocol")));
                result.append(Operations.encrypt
                        (this.key, Long.valueOf(this.encoder.getEncodedValue(protocol)))).append("\n");
                result.append(SHA.toHexString(SHA.getSHA("IN_IP")));
                result.append(Operations.encrypt
                        (this.key, Long.valueOf(this.encoder.getEncodedValue(IN_IP)))).append("\n");
                String[] lower_upper;
                if (inbound_port.matches("\\d+:\\d+")){
                    lower_upper = inbound_port.split(":");
                    result.append(SHA.toHexString(SHA.getSHA("inbound_port")));
                    result.append(Operations.encrypt(this.key, Long.parseLong(lower_upper[0])));
                    result.append(SHA.toHexString(SHA.getSHA("-")));
                    result.append(Operations.encrypt(this.key, Long.parseLong(lower_upper[1]))).append("\n");
                }
                else if (inbound_port.matches(":\\d+")){
                    result.append(SHA.toHexString(SHA.getSHA("inbound_port<")));
                    result.append(Operations.encrypt(this.key,
                            Long.parseLong(inbound_port.substring(1)))).append("\n");
                }
                else {
                    result.append(SHA.toHexString(SHA.getSHA("inbound_port>")));
                    result.append(Operations.encrypt(this.key,
                            Long.parseLong(inbound_port.replace(":", "")))).append("\n");
                }
                result.append(SHA.toHexString(SHA.getSHA("OUT_IP")));
                result.append(Operations.encrypt
                        (this.key, Long.valueOf(this.encoder.getEncodedValue(OUT_IP)))).append("\n");
                if (outbound_port.matches("\\d+:\\d+")){
                    lower_upper = outbound_port.split(":");
                    result.append(SHA.toHexString(SHA.getSHA("outbound_port")));
                    result.append(Operations.encrypt(this.key, Long.parseLong(lower_upper[0])));
                    result.append(SHA.toHexString(SHA.getSHA("-")));
                    result.append(Operations.encrypt(this.key, Long.parseLong(lower_upper[1]))).append("\n");
                }
                else if (outbound_port.matches(":\\d+")){
                    result.append(SHA.toHexString(SHA.getSHA("outbound_port<")));
                    result.append(Operations.encrypt(this.key,
                            Long.parseLong(outbound_port.substring(1)))).append("\n");
                }
                else {
                    result.append(SHA.toHexString(SHA.getSHA("outbound_port>")));
                    result.append(Operations.encrypt(this.key,
                            Long.parseLong(outbound_port.replace(":", ""))));
                }
            }catch (NoSuchAlgorithmException e) {
                System.out.println("Exception thrown for incorrect algorithm: " + e);
            }
            line = reader.readLine();
        }
        this.results.add(result.toString());
    }
    public void saveToFile(String file) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(file));
        for(int i=0;i<this.results.size();i++){
            if (i != this.results.size()-1){
                writer.write(this.results.get(i) + "\n");
            }
            else {
                writer.write(this.results.get(i));
            }
        }
        writer.close();
    }
}

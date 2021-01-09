import network.NetworkTraffic;
import network.Packet;
import network.RuleMatcher;
import security.Key;
import signature.SignatureEncryption;
import signature.SignatureParser;


import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;

public class run {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Key key = new Key("/Users/aminnemati/Order_Preserving/Files/key.txt");
        SignatureEncryption signature_encryptor = new SignatureEncryption(key,
                "/Users/aminnemati/Order_Preserving/Files/Signature.txt",
                "/Users/aminnemati/Order_Preserving/Files/Encoding_Scheme.txt");
        signature_encryptor.saveToFile("/Users/aminnemati/Order_Preserving/Files/ENC_SIG.txt");
        NetworkTraffic net = new NetworkTraffic("/Users/aminnemati/Order_Preserving/Files/Small.txt");
        Instant start = Instant.now();
        SignatureParser parser = new SignatureParser("/Users/aminnemati/Order_Preserving/Files/ENC_SIG.txt");
        RuleMatcher rule = new RuleMatcher(key, parser, net);
        rule.match();
        Instant finish = Instant.now();
        long timeElapsed = Duration.between(start, finish).toMillis();
        for(Packet var: rule.getMatched_traffic())
        {
            System.out.println(var.getContent());
        }
        System.out.println("Elapsed time since beginning of matching: " + timeElapsed);
        System.out.println("Total number of packets matched out of one million: " + rule.getMatched_traffic().size());
    }
}

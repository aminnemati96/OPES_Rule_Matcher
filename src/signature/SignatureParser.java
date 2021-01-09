package signature;

import hashing.SHA;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

public class SignatureParser {
    private BigInteger inLowerBound, inUpperBound, outLowerBound,
            outUpperBound, Encoded_IP_IN, Encoded_IP_OUT, Encoded_Protocol;

    public SignatureParser(String file) throws IOException, NoSuchAlgorithmException {
        parser(readFile(file));
    }

    private String readFile(String file) throws IOException {
        return Files.readString(Paths.get(file), StandardCharsets.UTF_8);
    }

    private void parser(String content) throws NoSuchAlgorithmException {
        String[] lines;
        String[] temp;
        lines = content.split("\\n");
        for (String var: lines) {
            if(var.contains(SHA.toHexString(SHA.getSHA("Protocol")))){
                this.Encoded_Protocol = new BigInteger(
                        var.replace(SHA.toHexString(SHA.getSHA("Protocol")), ""));
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("IN_IP")))){
                this.Encoded_IP_IN = new BigInteger(
                        var.replace(SHA.toHexString(SHA.getSHA("IN_IP")), ""));
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("inbound_port")))){
                var = var.replace(SHA.toHexString(SHA.getSHA("inbound_port")), "");
                temp = var.split(SHA.toHexString(SHA.getSHA("-")));
                this.inLowerBound = new BigInteger(temp[0]);
                this.inUpperBound = new BigInteger(temp[1]);
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("inbound_port<")))){
                this.inLowerBound = null;
                this.inUpperBound = new BigInteger(
                        var.replace(SHA.toHexString(SHA.getSHA("inbound_port<")), ""));
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("inbound_port>")))){
                this.inUpperBound = null;
                this.inLowerBound = new BigInteger(
                        var.replace(SHA.toHexString(SHA.getSHA("inbound_port>")), ""));
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("OUT_IP")))){
                this.Encoded_IP_OUT = new BigInteger(
                        var.replace(SHA.toHexString(SHA.getSHA("OUT_IP")),""));
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("outbound_port")))){
                var = var.replace(SHA.toHexString(SHA.getSHA("outbound_port")), "");
                temp = var.split(SHA.toHexString(SHA.getSHA("-")));
                this.outLowerBound = new BigInteger(temp[0]);
                this.outUpperBound = new BigInteger(temp[1]);
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("outbound_port<")))){
                this.outLowerBound = null;
                this.outUpperBound = new BigInteger(
                        var.replace(SHA.toHexString(SHA.getSHA("outbound_port<")), ""));
            }
            if(var.contains(SHA.toHexString(SHA.getSHA("outbound_port>")))){
                this.outUpperBound = null;
                this.outLowerBound = new BigInteger(
                        var.replace(SHA.toHexString(SHA.getSHA("outbound_port>")), ""));
            }
        }
    }

    public BigInteger getInUpperBound() {
        return inUpperBound;
    }

    public BigInteger getOutLowerBound() {
        return outLowerBound;
    }

    public BigInteger getOutUpperBound() {
        return outUpperBound;
    }

    public BigInteger getEncoded_IP_IN() {
        return Encoded_IP_IN;
    }

    public BigInteger getEncoded_IP_OUT() {
        return Encoded_IP_OUT;
    }

    public BigInteger getEncoded_Protocol() {
        return Encoded_Protocol;
    }

    public BigInteger getInLowerBound() {
        return inLowerBound;
    }
}

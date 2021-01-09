package network;

import security.Key;
import security.Operations;
import signature.SignatureParser;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class RuleMatcher {
    private Key key;
    private final SignatureParser parser;
    private final NetworkTraffic networkTraffic;
    private final List<Packet> matched_traffic;
    public RuleMatcher(Key SKey, SignatureParser parser,
                       NetworkTraffic networkTraffic) {
        this.key = SKey;
        this.parser = parser;
        this.networkTraffic = networkTraffic;
        this.matched_traffic = new ArrayList<>();
    }
    public void match(){
        int inLowerBoundDifference;
        int outLowerBoundDifference;
        int inUpperBoundDifference;
        int outUpperBoundDifference;
        BigInteger encrypted_inPort;
        BigInteger encrypted_outPort;

        if (parser.getInLowerBound() != null && parser.getInUpperBound() == null){
            if(parser.getOutLowerBound() != null && parser.getOutUpperBound() == null){
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inLowerBoundDifference = parser.getInLowerBound().compareTo(encrypted_inPort);
                    outLowerBoundDifference = parser.getOutLowerBound().compareTo(encrypted_outPort);
                    if(inLowerBoundDifference <= 0 && outLowerBoundDifference <= 0){
                        matched_traffic.add(var);
                    }
                }
            }
            else if (parser.getOutLowerBound() == null && parser.getOutUpperBound() != null){
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inLowerBoundDifference = parser.getInLowerBound().compareTo(encrypted_inPort);
                    outUpperBoundDifference = parser.getOutUpperBound().compareTo(encrypted_outPort);
                    if(inLowerBoundDifference <= 0 && outUpperBoundDifference >= 0){
                        matched_traffic.add(var);
                    }
                }
            }
            else {
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inLowerBoundDifference = parser.getInLowerBound().compareTo(encrypted_inPort);
                    outUpperBoundDifference = parser.getOutUpperBound().compareTo(encrypted_outPort);
                    outLowerBoundDifference = parser.getOutLowerBound().compareTo(encrypted_outPort);
                    if(inLowerBoundDifference <= 0 && outUpperBoundDifference >= 0 && outLowerBoundDifference <= 0){
                        matched_traffic.add(var);
                    }

                }
            }
        }
        else if(parser.getInLowerBound() == null && parser.getInUpperBound() != null){
            if(parser.getOutLowerBound() != null && parser.getOutUpperBound() == null){
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inUpperBoundDifference = parser.getInUpperBound().compareTo(encrypted_inPort);
                    outLowerBoundDifference = parser.getOutLowerBound().compareTo(encrypted_outPort);
                    if(inUpperBoundDifference >= 0 && outLowerBoundDifference <= 0){
                        matched_traffic.add(var);
                    }
                }
            }
            else if (parser.getOutLowerBound() == null && parser.getOutUpperBound() != null){
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inUpperBoundDifference = parser.getInUpperBound().compareTo(encrypted_inPort);
                    outUpperBoundDifference = parser.getOutUpperBound().compareTo(encrypted_outPort);
                    if(inUpperBoundDifference >= 0 && outUpperBoundDifference >= 0){
                        matched_traffic.add(var);
                    }
                }
            }
            else {
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inUpperBoundDifference = parser.getInUpperBound().compareTo(encrypted_inPort);
                    outUpperBoundDifference = parser.getOutUpperBound().compareTo(encrypted_outPort);
                    outLowerBoundDifference = parser.getOutLowerBound().compareTo(encrypted_outPort);
                    if(inUpperBoundDifference >= 0 && outUpperBoundDifference >= 0 && outLowerBoundDifference <= 0){
                        matched_traffic.add(var);
                    }
                }
            }
        }
        else{
            if(parser.getOutLowerBound() != null && parser.getOutUpperBound() == null){
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inLowerBoundDifference = parser.getInLowerBound().compareTo(encrypted_inPort);
                    inUpperBoundDifference = parser.getInUpperBound().compareTo(encrypted_inPort);
                    outLowerBoundDifference = parser.getOutLowerBound().compareTo(encrypted_outPort);
                    if(inLowerBoundDifference <= 0 && inUpperBoundDifference >= 0 && outLowerBoundDifference <= 0){
                        matched_traffic.add(var);
                    }
                }
            }
            else if (parser.getOutLowerBound() == null && parser.getOutUpperBound() != null){
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inLowerBoundDifference = parser.getInLowerBound().compareTo(encrypted_inPort);
                    inUpperBoundDifference = parser.getInUpperBound().compareTo(encrypted_inPort);
                    outUpperBoundDifference = parser.getOutUpperBound().compareTo(encrypted_outPort);
                    if(inLowerBoundDifference <= 0 && inUpperBoundDifference >= 0 && outUpperBoundDifference >= 0){
                        matched_traffic.add(var);
                    }
                }
            }
            else {
                for(Packet var: networkTraffic.getPackets()){
                    if(var.getAttrib().get("Src Port") == null || var.getAttrib().get("Dst Port") == null){
                        continue;
                    }
                    encrypted_inPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Src Port")));
                    encrypted_outPort = Operations.encrypt(
                            this.key, Long.parseLong(var.getAttrib().get("Dst Port")));
                    inLowerBoundDifference = parser.getInLowerBound().compareTo(encrypted_inPort);
                    inUpperBoundDifference = parser.getInUpperBound().compareTo(encrypted_inPort);
                    outLowerBoundDifference = parser.getOutLowerBound().compareTo(encrypted_outPort);
                    outUpperBoundDifference = parser.getOutUpperBound().compareTo(encrypted_outPort);
                    if(inLowerBoundDifference <= 0 && outLowerBoundDifference <= 0 &&
                            inUpperBoundDifference >= 0 && outUpperBoundDifference >= 0){
                        matched_traffic.add(var);
                    }
                }
            }
        }
    }

    public List<Packet> getMatched_traffic() {
        return matched_traffic;
    }
}

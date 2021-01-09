package network;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NetworkTraffic {
    public List<Packet> packets = new ArrayList<>();
    public NetworkTraffic(String file) throws IOException {
        stringToPackets(readFile(file));
    }
    private String readFile(String file) throws IOException {
        String content = Files.readString(Paths.get(file), StandardCharsets.UTF_8);
        return content;
    }
    private void stringToPackets(String content){
        Pattern pattern = Pattern.compile("\\bNo\\.");
        Matcher matcher = pattern.matcher(content);
        List<Integer> matches = new ArrayList<>();
        while (matcher.find()){
            matches.add(matcher.start());
        }
        for(int i=0;i<matches.size();i++){
            if(i < matches.size() -1){
                this.packets.add(new Packet(content.substring(matches.get(i), matches.get(i+1))));
            }
            else {
                this.packets.add(new Packet(content.substring(matches.get(i))));
            }
        }

    }
    public List<Packet> getPackets() {
        return packets;
    }
}

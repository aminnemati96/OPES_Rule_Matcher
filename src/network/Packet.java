package network;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Packet {
    public String content;
    public HashMap<String, String> attrib;

    public Packet(String str) {
        this.attrib = new HashMap<>();
        this.content = str;
        setAttrib();
    }
    private void setAttrib(){
        String[] lines = this.content.split("\\n");
        String line = lines[1].trim().replaceAll("[ ]+", " ");
        String[] attributes = line.split(" ");
        this.attrib.put("Src IP", attributes[2]);
        this.attrib.put("Dst IP", attributes[3]);
        this.attrib.put("Protocol", attributes[4]);
        this.attrib.put("Src Port", null);
        this.attrib.put("Dst Port", null);
        line = lines[4];
        Pattern p = Pattern.compile("(?<=\\().*?(?=\\))");
        Matcher m = p.matcher(line);
        int i = 0;
        while (m.find()){
            if(i == 0){
                this.attrib.put("Src MAC", m.group());
            }
            else {
                this.attrib.put("Dst MAC", m.group());
            }
            i++;
        }
        i = 0;
        p = Pattern.compile("(?<=\\bPort: )\\d+\\b");
        m = p.matcher(this.content);
        for (String var: lines){
            m.reset(var);
            while (m.find()){
                if (i == 0){
                    this.attrib.put("Src Port", m.group());
                }
                else if (i == 1){
                    this.attrib.put("Dst Port", m.group());
                }
                i++;
            }
        }
    }

    public HashMap<String, String> getAttrib() {
        return attrib;
    }

    public String getContent() {
        return content;
    }
}

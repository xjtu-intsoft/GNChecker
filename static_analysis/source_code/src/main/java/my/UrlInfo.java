package my;

import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @description:
 * @author: xxx
 * @date: 2023/2/10 20:42
 **/
public class UrlInfo {
    String url;
    List<JsonObject> ip_info;

    public void setIp_info(List<JsonObject> ip_info) {
        this.ip_info = ip_info;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public List<JsonObject> getIp_info() {
        return ip_info;
    }

    public String getUrl() {
        return url;
    }

    public Map<String,Object> infoToMap(){
        HashMap<String, Object> map = new HashMap<>();
        map.put("url",url);
        ArrayList<Map> ip_infos = new ArrayList<>();
        for(JsonObject info:ip_info){
            ip_infos.add(info.asMap());
        }
        map.put("ip_info",ip_infos);
        return map;
    }
}

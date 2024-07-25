package my;

import com.github.kevinsawicki.http.HttpRequest;
import com.google.gson.Gson;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

/**
 * @description:
 * @author: xxx
 * @date: 2023/2/10 19:51
 **/

public class Client {
    String ip="http://127.0.0.1:5000";

    public UrlInfo requestUrlParse(String url) throws UnsupportedEncodingException {
        String targetUrl=ip+"/urlParse";
        Map<String,String> data = new HashMap();
        data.put("url",url);
        HttpRequest post = HttpRequest.post(targetUrl, data, false);
        String body = post.body("utf-8");
        System.out.println(body);
        Gson gson = new Gson();
        UrlInfo urlInfo = gson.fromJson(body, UrlInfo.class);
        return urlInfo;
    }
    public String requestComponentInfo(String resourcePath,String apk){
        String targetUrl=ip+"/componentInfo";
        Map<String,String> data = new HashMap();
        data.put("path",resourcePath);
        data.put("apk",apk);
        HttpRequest post = HttpRequest.post(targetUrl, data, false);
        String body = post.body();
        return body;
    }
    public String requestScreenInfo(String resourcePath,String apk){
        String targetUrl=ip+"/screenInfo";
        Map<String,String> data = new HashMap();
        data.put("path",resourcePath);
        data.put("apk",apk);
        HttpRequest post = HttpRequest.post(targetUrl, data, false);
        String body = post.body();
        return body;
    }
    public static void main(String[] args) {
        Client client = new Client();
        String code=client.requestComponentInfo("D:\\decompiled_apk\\qutoutiao.apk\\resources\\res","qutoutiao.apk");

    }

}

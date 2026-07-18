// 端到端验证 Java SDK：起本地目标 → 启 FlowMint 代理 → 走代理请求 → 断言回调捕获。
import com.sun.net.httpserver.HttpServer;
import flowmint.FlowMint;

import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;

public class Verify {
    static int reqs = 0, resps = 0;

    public static void main(String[] args) throws Throwable {
        HttpServer target = HttpServer.create(new InetSocketAddress("127.0.0.1", 9603), 0);
        target.createContext("/", ex -> {
            byte[] b = "hello-java-target".getBytes();
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        target.start();

        FlowMint fm = new FlowMint();
        System.out.println("SDK 版本: " + fm.version());
        fm.bindPort((short) 8894);
        fm.onHttp(ev -> {
            if (ev.isRequest()) {
                reqs++;
                System.out.println("请求 " + ev.method + " " + ev.url);
            } else {
                resps++;
                System.out.println("响应 " + ev.status + " " + ev.url + " " + ev.body.length + " 字节");
            }
        });
        fm.start();
        System.out.println("代理已启动 127.0.0.1:8894");

        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8894));
        HttpURLConnection c = (HttpURLConnection) new URL("http://127.0.0.1:9603/api/java").openConnection(proxy);
        System.out.println("目标返回: " + c.getResponseCode());
        c.getInputStream().readAllBytes();

        Thread.sleep(300);
        fm.stop();
        target.stop(0);
        fm.close();

        if (reqs < 1 || resps < 1) {
            System.out.println("FAIL：未捕获到回调");
            System.exit(1);
        }
        System.out.println("OK: Java SDK 捕获 " + reqs + " 请求 / " + resps + " 响应");
    }
}

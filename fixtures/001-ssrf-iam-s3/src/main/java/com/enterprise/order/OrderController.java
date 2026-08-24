package com.enterprise.order;

import org.springframework.web.bind.annotation.*;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;

@RestController
@RequestMapping("/api/v1/orders")
public class OrderController {

    @GetMapping("/health")
    public String health() {
        return "OK";
    }

    /**
     * VULNERABILITY: Server-Side Request Forgery (SSRF)
     * Takes an unvalidated user-supplied URL and makes an HTTP request from inside the pod.
     * Can be exploited by an attacker to query the AWS IMDS (169.254.169.254) or Kubernetes metadata.
     */
    @PostMapping("/webhook-callback")
    public String triggerWebhook(@RequestParam String callbackUrl) {
        try {
            URL url = new URL(callbackUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            
            try (InputStream in = conn.getInputStream()) {
                return "Webhook delivered: " + conn.getResponseCode();
            }
        } catch (Exception e) {
            return "Failed to deliver webhook: " + e.getMessage();
        }
    }
}

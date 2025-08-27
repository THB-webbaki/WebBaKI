package de.thb.webbaki.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Service
public class TurnstileService{
    private final RestClient rest = RestClient.create("https://challenges.cloudflare.com");
    private final String secret;

    @Value("${turnstile.sitekey}")
    private String sitekey;

    @Value("${turnstile.use}")
    private boolean use;

    public TurnstileService(@Value("${turnstile.secret}") String secret) {
        this.secret = secret;
    }

    public boolean validate(String token, String remoteIp) {
        if (token == null || token.isBlank() || secret == null || secret.isBlank()) return false;

        Map<String, Object> body = Map.of(
                "secret", secret,
                "response", token,
                "remoteip", remoteIp == null ? "" : remoteIp
        );

        Map resp = rest.post()
                .uri("/turnstile/v0/siteverify")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(Map.class);

        Object success = resp == null ? null : resp.get("success");
        return Boolean.TRUE.equals(success);
    }

    public String getSitekey() {return sitekey;}
    public boolean getUse() {return use;}
}

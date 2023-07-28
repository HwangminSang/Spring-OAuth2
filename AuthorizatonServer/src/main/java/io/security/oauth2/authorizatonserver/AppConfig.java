package io.security.oauth2.authorizatonserver;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

@Configuration
public class AppConfig {


    // 발급자 . 인가서버
    @Bean
    public ProviderSettings providerSettings(){
        return ProviderSettings.builder().issuer("http://localhost:9000").build();
    }



    // 등록된 클라이언트 정보
    @Bean
    public RegisteredClientRepository registeredClientRepository(){

        RegisteredClient registeredClient1= getRegisteredClient("oauth2-client-app1", "{noop}secret1", "read", "write");
        RegisteredClient registeredClient2= getRegisteredClient("oauth2-client-app2", "{noop}secret2", "read", "delete");
        RegisteredClient registeredClient3= getRegisteredClient("oauth2-client-app3", "{noop}secret3", "read", "update");


        // 메모리 방식 저장.
        return new InMemoryRegisteredClientRepository(Arrays.asList(registeredClient1,registeredClient2,registeredClient3));

    }

    private RegisteredClient getRegisteredClient(String clientId, String clientSecret, String scope1, String scope2) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientName(clientId)
                .clientIdIssuedAt(Instant.now())
                .clientSecretExpiresAt(Instant.MAX)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // PKCE 기능으로 올때. 클라이언트 ID  , 비번 없이

                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // 일반적인 OUAHT2 로그인시
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // 서버 투 서버
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)  // 에세스 토큰 만료시
                .redirectUri("http://127.0.0.1:8081")  // 클라이언트 서버
                .redirectUri("http://127.0.0.1:8081/login/oauth2/code/springoauth2")
                .scope(OidcScopes.OPENID)  // 스코프 영역 권한 설정으로 간다 . < OPENTID -> id_token 발급  >  -> userInfo 요청시 사용
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope(scope1)
                .scope(scope2)
                .scope("photo")
                .scope("friend")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())  // 동의 페이지
//                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(1L)).build())  // 리플레시 토큰 시간 샛팅
                .build();
    }


    // 토근을 만들떄 ,검증할때 사용하는 키 .
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();
        // JWK-SET URI 로 왔을때 공개키를 던져줘 토큰 DECODE 함,
        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    private RSAKey generateRsa() throws NoSuchAlgorithmException {

        KeyPair keyPair = generateKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        return new RSAKey
                .Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }


    // 저장된 클라이언트 정보 가져오는 서비스
    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(){
        return new InMemoryOAuth2AuthorizationService();
    }


    //동의페이지
    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(){
        return new InMemoryOAuth2AuthorizationConsentService();
    }
}

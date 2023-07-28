package io.client.oauth2client;

import io.security.sharedobject.AccessToken;
import io.security.sharedobject.Photo;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.Series.CLIENT_ERROR;
import static org.springframework.http.HttpStatus.Series.SERVER_ERROR;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final RestTemplate restTemplate;

    // 서버쪽으로 요청 < accessToken 만료시 >
    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/token")
    public OAuth2AccessToken token(@RegisteredOAuth2AuthorizedClient("springOAuth2") OAuth2AuthorizedClient oAuth2AuthorizedClient){
        return oAuth2AuthorizedClient.getAccessToken();
    }

    @GetMapping("/tokenExpire")
    public Map<String,Object> tokenExpire(AccessToken accessToken){

        HttpHeaders header = new HttpHeaders();
        header.add("Authorization", "Bearer " + accessToken.getToken());
        HttpEntity<?> entity = new HttpEntity<>(header);
        String url = "http://localhost:8082/tokenExpire"; // 자원서버
        ResponseEntity<Map<String,Object>> response = restTemplate.exchange(url, HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

        return response.getBody();
    }

    @GetMapping("/newAccessToken")  // 새로운 accessToken 발급
    public OAuth2AccessToken newAccessToken(OAuth2AuthenticationToken authentication, HttpServletRequest request, HttpServletResponse response){


        // 인가는 끝난 상황.  -> refreshToken을 꺼낸다. < 해당 인가받은 클라이언트를 찾자.
        OAuth2AuthorizedClient authorizedClient
                = authorizedClientService.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(), authentication.getName());

        // 인가서버가 발급했던 리플레시 토큰을 이용하여 새로운 토큰을 인가서버에 요청하여 받는다.
        if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {


            // grantType 변경 -> refreshToken
            ClientRegistration clientRegistration = ClientRegistration.withClientRegistration
                    (authorizedClient.getClientRegistration()).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

            // grant_type -> refresh로 변경하여 인가서버 요청하기 위해
            OAuth2AuthorizedClient oAuth2AuthorizedClient =
                    new OAuth2AuthorizedClient(clientRegistration, authorizedClient.getPrincipalName(),
                            authorizedClient.getAccessToken(),authorizedClient.getRefreshToken());

            // 인가서버로 요청하기위한 request객체생성
            OAuth2AuthorizeRequest oAuth2AuthorizeRequest =
                    OAuth2AuthorizeRequest.withAuthorizedClient(oAuth2AuthorizedClient)
                            .principal(authentication)
                            .attribute(HttpServletRequest.class.getName(), request)
                            .attribute(HttpServletResponse.class.getName(), response)
                            .build();


            // 인가서버로 요청
            authorizedClient = oAuth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        }

        return authorizedClient.getAccessToken();
    }
}
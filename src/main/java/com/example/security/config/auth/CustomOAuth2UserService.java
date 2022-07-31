package com.example.security.config.auth;

import com.example.security.config.auth.dto.OAuthAttributes;
import com.example.security.config.auth.dto.SessionUser;
import com.example.security.domain.User;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final HttpSession httpSession;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration() // 현재 로그인 진행 중인 서비스 구분 코드
                .getRegistrationId();

        UserInfoEndpoint userInfoEndpoint = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint();

        String userNameAttributeName = userInfoEndpoint.getUserNameAttributeName(); // 로그인 진행 시 키가 되는 필드 값, PK와 같은 의미

        OAuthAttributes attributes = OAuthAttributes.of( // OAuth2User 객체의 Attribute를 담을 클래스
                registrationId,
                userNameAttributeName,
                oAuth2User.getAttributes());

        User user = saveOrUpdate(attributes); // 데이터베이스에 사용자 정보를 저장하거나, 업데이트

        //httpSession.setAttribute("user", new SessionUser(user)); // 세션에 사용자 정보를 저장

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRole().getKey())),
                attributes.getAttributes(),
                attributes.getNameAttributeKey());
    }

    private User saveOrUpdate(OAuthAttributes attributes) {
        User user = userRepository.findByEmail(attributes.getEmail())
                .map(entity -> entity.update(attributes.getName(), attributes.getPicture()))
                .orElse(attributes.toEntity());

        return userRepository.save(user);
    }
}

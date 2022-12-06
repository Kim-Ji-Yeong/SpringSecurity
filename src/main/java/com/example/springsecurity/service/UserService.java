package com.example.springsecurity.service;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.exception.AppException;
import com.example.springsecurity.exception.ErrorCode;
import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.utils.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    @Value("${jwt.token.secret")
    private String key;
    private Long expireTimeMs = 1000 * 60 * 60L;

    public String join(String userName, String password){

        // userName 중복 check
        userRepository.findByUserName(userName)
                .ifPresent(user -> {
                    throw new AppException(ErrorCode.USERNAME_DUPLICATED,userName + "는 이미 있습니다.");
                });

        // 저장
        User user = User.builder()
                .userName(userName)
                .password(encoder.encode(password))
                .build();
        userRepository.save(user);

        return "SUCCESS";
    }

    public String login(String userName, String password){

        //userName없음
        User selectedUser = userRepository.findByUserName(userName)
                .orElseThrow(() -> new AppException(ErrorCode.USERNAME_NOTFOUND, userName + "이 없습니다."));

        //password틀림
        if(!encoder.matches(password,selectedUser.getPassword())){
            throw new AppException(ErrorCode.INVALID_PASSWORD,"패스워드를 잘못 입력헀습니다.");
        }

        String token = JwtTokenUtil.createToken(selectedUser.getUserName(),key,expireTimeMs);
        //앞에서 Exception안났으면 토큰 발행
       return token;
    }
}

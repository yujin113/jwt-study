package study.jwt.jwttutorial.service;

import java.util.Collections;
import java.util.Optional;
import study.jwt.jwttutorial.dto.UserDto;
import study.jwt.jwttutorial.entity.Authority;
import study.jwt.jwttutorial.entity.User;
import study.jwt.jwttutorial.Repository.UserRepository;
import study.jwt.jwttutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    //회원가입 로직 수행
    @Transactional
    public UserDto signup(UserDto userDto) {
        //username이 DB에 존재하지 않으면 Authority와 User 정보 생성해서 UserRepository의 save 메소드를 통해 DB에 정보 저장
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        //권한 정보 생성
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        //권한 정보 넣어서 User 객체 생성
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return UserDto.from(userRepository.save(user));
    }

    // username 기준으로 유저, 권한정보 가져오는 메소드
    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    // 현재 SecurityContext에 저장된 username에 해당하는 유저, 권한 정보만 가져오는 메소드
    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername).orElse(null));
    }
}
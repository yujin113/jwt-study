package study.jwt.jwttutorial.Repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import study.jwt.jwttutorial.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @EntityGraph(attributePaths = "authorities") //쿼리 수행 시 Lazy 조회가 아닌 Eager 조회로 authorities 정보를 같이 가져와줌
    Optional<User> findOneWithAuthoritiesByUsername(String username); //username을 기준으로 User 정보 가져올 때 권한 정보도 함께 가져오는 메소드
}

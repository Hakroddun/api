package com.test.api.Repository;

import com.test.api.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long>
{
    @Query("select new User(u.id, u.phone) from User u")
    List<User> findAll();

    @Query("select new User(u.id, u.phone, u.jwtToken) from User u WHERE u.jwtToken IS NOT NULL")
    List<User> findAllWithToken();

    Optional<User> findById(Long id);

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    @Query("SELECT case when (count(u) > 0)  then true else false end FROM User u WHERE u.username = ?1 AND u.jwtToken IS NOT NULL")
    Boolean tokenExistsByUsername(String username);
}


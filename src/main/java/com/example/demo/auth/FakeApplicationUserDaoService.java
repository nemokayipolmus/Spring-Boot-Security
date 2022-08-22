package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUser()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUser() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "anna",
                        passwordEncoder.encode("pass"),
                        STUDENT.getGrantedAuthories(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "layla",
                        passwordEncoder.encode("pass123"),
                        ADMIN.getGrantedAuthories(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "Tom",
                        passwordEncoder.encode("pass.123*"),
                        ADMINTRAINEE.getGrantedAuthories(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }

    }

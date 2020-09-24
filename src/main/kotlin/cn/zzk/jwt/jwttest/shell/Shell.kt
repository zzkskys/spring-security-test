package cn.zzk.jwt.jwttest.shell

import cn.zzk.jwt.jwttest.domain.User
import cn.zzk.jwt.jwttest.domain.UserRepo
import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component

@Component
class Shell(
        private val userRepo: UserRepo,
        private val passwordEncoder: PasswordEncoder
) {

    @Bean
    fun userInit() = CommandLineRunner {
        val users = listOf(
                User( "a",  "1"),
                User( "b",  "2"),
                User( "c",  "3")
        )
        users.forEach {
            val securityPassword = passwordEncoder.encode(it.password)
            it.password = securityPassword
        }
        userRepo.saveAll(users)
    }
}
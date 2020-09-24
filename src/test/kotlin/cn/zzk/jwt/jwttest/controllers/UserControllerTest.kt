package cn.zzk.jwt.jwttest.controllers

import cn.zzk.jwt.jwttest.config.SecurityConfig
import cn.zzk.jwt.jwttest.config.authentication.RestLogoutHandler
import cn.zzk.jwt.jwttest.domain.User
import cn.zzk.jwt.jwttest.domain.UserRepo
import com.fasterxml.jackson.databind.ObjectMapper
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.whenever
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Import
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [UserController::class, SecurityTestConfig::class])
internal class UserControllerTest(
        @Autowired private val userController: UserController
) {
    @MockBean
    lateinit var userRepo: UserRepo

    @BeforeEach
    fun setUp() {
        val users = listOf(
                User( "张三",  "a"),
                User( "李四",  "b"),
                User( "王五",  "c")
        )
        whenever(userRepo.findAll()) doReturn users
    }

    @Test
    fun users1() {
        val users = userController.users()
        assertEquals(3, users.size)
    }

    @Test
    fun users2() {
        assertThrows<RuntimeException> {
            userController.users2()
        }

        mockAuthenticatedUser("aa")
        userController.users2()
    }


    @Test
    fun user3() {
        assertThrows<RuntimeException> { userController.users3() }

        mockAuthenticatedUser("b")
        assertThrows<RuntimeException> { userController.users3() }

        mockAuthenticatedUser("a")
        userController.users3()
    }
}

/**
 * 模拟认证成功后的 User
 */
fun mockAuthenticatedUser(username: String,
                          password: String = "",
                          authorities: Collection<GrantedAuthority> = emptyList()) {
    val user = org.springframework.security.core.userdetails.User
            .withUsername(username)
            .password(password)
            .authorities(authorities)
            .build()
    val auth = UsernamePasswordAuthenticationToken(user, user.password, authorities)

    val context = SecurityContextHolder.createEmptyContext()
    context.authentication = auth

    SecurityContextHolder.setContext(context)
}

/**
 * 导入 SecurityConfig 作为 bean 对象。
 */
@TestConfiguration
@ComponentScan(basePackageClasses = [RestLogoutHandler::class])
@Import(SecurityConfig::class)
class SecurityTestConfig {
    @MockBean
    lateinit var objectMapper: ObjectMapper

    @MockBean
    lateinit var userDetailsService: UserDetailsService
}
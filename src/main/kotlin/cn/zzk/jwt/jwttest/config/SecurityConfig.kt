package cn.zzk.jwt.jwttest.config

import cn.zzk.jwt.jwttest.config.authentication.*
import cn.zzk.jwt.jwttest.domain.UserRepo
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.SecurityConfigurerAdapter
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Service
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.util.Collections.singletonList


/**
 *
 * Create Time : 2019/11/12
 * @author zzk
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfig(
        private val restAuthenticationEntryPoint: RestAuthenticationEntryPoint,
        private val restAuthenticationSuccessHandler: RestAuthenticationSuccessHandler,
        private val authenticationFailureHandler: RestAuthenticationFailureHandler,
        private val simpleLogoutHandler: RestLogoutHandler,
        private val restAccessDeniedHandler: RestAccessDeniedHandler
) : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var userLoginService: UserLoginService

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    override fun configure(http: HttpSecurity) {
        http
                .cors { it.configurationSource(corsConfigurationSource()) }
                .csrf().disable()
                .headers {
                    it.frameOptions().disable()
                }
                .exceptionHandling { exceptionHandling ->
                    exceptionHandling.authenticationEntryPoint(restAuthenticationEntryPoint)
                    exceptionHandling.accessDeniedHandler(restAccessDeniedHandler)
                }
                .authorizeRequests {
                    it.antMatchers("/public/**", "/login").permitAll()
                    it.antMatchers("/**").permitAll()
                }
                .formLogin { formLogin ->
                    formLogin.loginProcessingUrl("/login")
                    formLogin.successHandler(restAuthenticationSuccessHandler)
                    formLogin.failureHandler(authenticationFailureHandler)
                }
                .logout { logout ->
                    logout.logoutSuccessHandler(simpleLogoutHandler)
                }
    }


    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val encoder: DelegatingPasswordEncoder = PasswordEncoderFactories
                .createDelegatingPasswordEncoder() as DelegatingPasswordEncoder
        encoder.setDefaultPasswordEncoderForMatches(NoOpPasswordEncoder.getInstance())
        return encoder
    }


    override fun configure(auth: AuthenticationManagerBuilder) {
        auth
                .userDetailsService(userLoginService)
                .passwordEncoder(passwordEncoder)
    }


    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = singletonList("*")
        configuration.allowedMethods = singletonList("*")
        configuration.allowedHeaders = singletonList("*")
        configuration.allowCredentials = true
        configuration.addExposedHeader("X-Auth-Token")
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }

    @Service
    class UserLoginService(
            private val userRepo: UserRepo
    ) : UserDetailsService {

        private val log = LoggerFactory.getLogger(UserLoginService::class.java)

        override fun loadUserByUsername(username: String): UserDetails? {
            log.info("通过 UserLoginService 提供认证身份, username : $username")
            return userRepo.findByName(username)
        }
    }
}


@Configuration
@Order(10)
class MobileSecurityConfig : WebSecurityConfigurerAdapter() {

    @Autowired
    lateinit var restAuthenticationSuccessHandler: RestAuthenticationSuccessHandler

    @Autowired
    lateinit var authenticationFailureHandler: RestAuthenticationFailureHandler

    @Autowired
    lateinit var restAuthenticationEntryPoint: AuthenticationEntryPoint

    @Autowired
    lateinit var restAccessDeniedHandler: AccessDeniedHandler

    @Autowired
    lateinit var mobileProvider: MobileAuthenticationProvider

    @Autowired
    lateinit var logoutHandler: RestLogoutHandler


    override fun configure(http: HttpSecurity) {
        // mobile 登录认证
        http
                .csrf().disable()
                .authenticationProvider(mobileProvider)
                .formLogin { formLogin ->
                    formLogin.loginProcessingUrl("/mobile/login")
                    formLogin.usernameParameter("mobile")
                    formLogin.successHandler(restAuthenticationSuccessHandler)
                    formLogin.failureHandler(authenticationFailureHandler)
                }
                .exceptionHandling { exceptionHandling ->
                    exceptionHandling.authenticationEntryPoint(restAuthenticationEntryPoint)
                    exceptionHandling.accessDeniedHandler(restAccessDeniedHandler)
                }
                .logout { logout ->
                    logout.logoutSuccessHandler(logoutHandler)
                }
                .authorizeRequests {
                    it.antMatchers("/public/**", "/mobile/login").permitAll()
                    it.antMatchers("/**").permitAll()
                }
    }

//    override fun configure(auth: AuthenticationManagerBuilder) {
//        auth
//                .authenticationProvider(mobileProvider)
//    }
}




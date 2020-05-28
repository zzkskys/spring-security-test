package cn.zzk.jwt.jwttest.config

import cn.zzk.jwt.jwttest.config.authentication.RestAccessDeniedHandler
import cn.zzk.jwt.jwttest.config.authentication.RestAuthenticationEntryPoint
import cn.zzk.jwt.jwttest.config.authentication.RestAuthenticationFailureHandler
import cn.zzk.jwt.jwttest.config.authentication.RestLogoutHandler
import cn.zzk.jwt.jwttest.config.jwt.JwtAuthenticationSuccessHandler
import cn.zzk.jwt.jwttest.config.jwt.JwtFilter
import cn.zzk.jwt.jwttest.domain.UserRepo
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.event.EventListener
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.WebAuthenticationDetails
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
        private val jwtAuthenticationSuccessHandler: JwtAuthenticationSuccessHandler,
        private val authenticationFailureHandler: RestAuthenticationFailureHandler,
        private val simpleLogoutHandler: RestLogoutHandler,
        private val restAccessDeniedHandler: RestAccessDeniedHandler,
        private val userLoginService: UserLoginService
) : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var jwtFilter: JwtFilter

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val encoder: DelegatingPasswordEncoder = PasswordEncoderFactories
                .createDelegatingPasswordEncoder() as DelegatingPasswordEncoder
        encoder.setDefaultPasswordEncoderForMatches(NoOpPasswordEncoder.getInstance())
        return encoder
    }

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
                    it.antMatchers("/**").permitAll()
                }
                .formLogin { formLogin ->
                    formLogin.loginProcessingUrl("/login")
                    formLogin.successHandler(jwtAuthenticationSuccessHandler)
                    formLogin.failureHandler(authenticationFailureHandler)
                }
                .logout { logout ->
                    logout.logoutSuccessHandler(simpleLogoutHandler)
                    logout.invalidateHttpSession(true)
                }
                //因为使用 jwt 认证，则无需使用 session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter::class.java)
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

    @EventListener
    fun whenever(success: AuthenticationSuccessEvent) {
        val authentication = success.source as Authentication
        if (authentication.details is WebAuthenticationDetails) {
            val details = authentication.details as WebAuthenticationDetails
            log.info("有用户登录成功 , 账号 : ${authentication.name}, ip : ${details.remoteAddress}")
        }
    }

}

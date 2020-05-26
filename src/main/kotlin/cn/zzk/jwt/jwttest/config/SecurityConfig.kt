package cn.zzk.jwt.jwttest.config

import cn.zzk.jwt.jwttest.config.authentication.*
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
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.WebAuthenticationDetails
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter
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
    private lateinit var mobileProvider: MobileAuthenticationProvider

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var validateCodeFilter: ValidateCodeFilter

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


        // mobile 登录认证
        val filter = MobileLoginAuthenticationFilter("/mobile/login", "mobile")
        filter.setAuthenticationSuccessHandler(restAuthenticationSuccessHandler)
        filter.setAuthenticationFailureHandler(authenticationFailureHandler)
        filter.setAuthenticationManager(this.authenticationManager())
        http
                .addFilterBefore(validateCodeFilter, AbstractPreAuthenticatedProcessingFilter::class.java)
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter::class.java)
    }


    override fun configure(auth: AuthenticationManagerBuilder) {
        auth
                .authenticationProvider(mobileProvider)
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

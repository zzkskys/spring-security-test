package cn.zzk.jwt.jwttest.config

import cn.zzk.jwt.jwttest.config.authentication.*
import cn.zzk.jwt.jwttest.domain.UserRepo
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
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
        private val restAccessDeniedHandler: RestAccessDeniedHandler,
        private val userDetailsService: UserDetailsService
) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
//                .cors { it.configurationSource(corsConfigurationSource()) }
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
                    formLogin.successHandler(restAuthenticationSuccessHandler)
                    formLogin.failureHandler(authenticationFailureHandler)
                }
                .logout { logout ->
                    logout.logoutSuccessHandler(simpleLogoutHandler)
                }
    }


    override fun authenticationManager(): AuthenticationManager {
        val manager = super.authenticationManager() as ProviderManager
        println(manager.providers)
        return manager
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories
                .createDelegatingPasswordEncoder()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder())
    }

//    @Bean
//    fun corsConfigurationSource(): CorsConfigurationSource {
//        val configuration = CorsConfiguration()
//        configuration.allowedOrigins = singletonList("*")
//        configuration.allowedMethods = singletonList("*")
//        configuration.allowedHeaders = singletonList("*")
//        configuration.allowCredentials = true
//        configuration.addExposedHeader("X-Auth-Token")
//        val source = UrlBasedCorsConfigurationSource()
//        source.registerCorsConfiguration("/**", configuration)
//        return source
//    }

}


@Service
@Primary
class UserLoginService(
        private val userRepo: UserRepo
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        return userRepo.findByName(username)
                ?: throw UsernameNotFoundException("用户名或密码错误")
    }
}


package cn.zzk.jwt.jwttest.config

import cn.zzk.jwt.jwttest.domain.User
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


@Component
class MobileAuthenticationProvider : AuthenticationProvider {

    private val log = LoggerFactory.getLogger(MobileAuthenticationProvider::class.java)

    override fun authenticate(authentication: Authentication): Authentication {
        authentication as MobileLoginAuthenticationToken
        val username = authentication.principal as String
        val password = "1"

        val user = User(username = username, password = password)
        log.info("MobileAuthenticationProvider 提供认证逻辑处理.......")
        return MobileLoginAuthenticationToken(user, emptyList())
    }

    override fun supports(authentication: Class<*>): Boolean {
        return MobileLoginAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}

class MobileLoginAuthenticationToken : AbstractAuthenticationToken {

    private val principal: Any

    /**
     * 构造待认证的凭证
     */
    constructor(phone: String) : super(null) {
        this.principal = phone
        this.isAuthenticated = false
    }

    /**
     * 构造受认证的凭证
     */
    constructor(principal: Any, authorities: Collection<GrantedAuthority>) : super(authorities) {
        this.principal = principal
        super.setAuthenticated(true)
    }

    override fun getCredentials(): Any? {
        return null
    }

    override fun getPrincipal(): Any {
        return principal
    }
}

class MobileLoginAuthenticationFilter : AbstractAuthenticationProcessingFilter {

    private val log = LoggerFactory.getLogger(MobileLoginAuthenticationFilter::class.java)

    private val mobileParamName: String

    constructor(mobileLoginUrl: String, mobileParamName: String)
            : super(AntPathRequestMatcher(mobileLoginUrl, "POST")) {
        this.mobileParamName = mobileParamName
    }

    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {

        val phone = request.getParameter(mobileParamName)
        val details = authenticationDetailsSource.buildDetails(request)

        log.info("MobileLoginAuthenticationFilter 进行拦截认证, phone : $phone")

        val authRequest = MobileLoginAuthenticationToken(phone)
        authRequest.details = details
        authRequest.isAuthenticated = true
        return this.authenticationManager.authenticate(authRequest)
    }
}
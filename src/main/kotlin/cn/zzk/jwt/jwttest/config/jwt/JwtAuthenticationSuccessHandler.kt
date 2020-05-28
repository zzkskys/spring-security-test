package cn.zzk.jwt.jwttest.config.jwt

import cn.zzk.jwt.jwttest.config.jwt.JwtAuthenticationProvider
import cn.zzk.jwt.jwttest.domain.User
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


/**
 *
 * Create Time : 2019/11/12
 * @author zzk
 */
@Component
class JwtAuthenticationSuccessHandler(
        private val objectMapper: ObjectMapper,
        private val jwtAuthenticationProvider: JwtAuthenticationProvider
) : AuthenticationSuccessHandler {


    @Throws(IOException::class)
    override fun onAuthenticationSuccess(request: HttpServletRequest,
                                         response: HttpServletResponse,
                                         authentication: Authentication) {
        val user = authentication.principal as User
        val jwt = jwtAuthenticationProvider.writeToken(user)


        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.setHeader(jwtAuthenticationProvider.headerParamName, jwt)
        val outputStream = response.outputStream
        objectMapper.writeValue(response.outputStream, user)
        outputStream.flush()
    }
}
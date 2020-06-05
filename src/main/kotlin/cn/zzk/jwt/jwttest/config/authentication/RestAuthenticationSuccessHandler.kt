package cn.zzk.jwt.jwttest.config.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


/**
 *
 * Create Time : 2019/11/12
 * @author zzk
 */
@Component
class RestAuthenticationSuccessHandler(
        private val objectMapper: ObjectMapper
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
            request: HttpServletRequest,
            response: HttpServletResponse,
            authentication: Authentication) {

        response.contentType = MediaType.APPLICATION_JSON_VALUE
        val outputStream = response.outputStream

        val principal = SecurityContextHolder
                .getContext()
                .authentication
                .principal as UserDetails

        objectMapper.writeValue(response.outputStream, principal)
        outputStream.flush()
    }

}
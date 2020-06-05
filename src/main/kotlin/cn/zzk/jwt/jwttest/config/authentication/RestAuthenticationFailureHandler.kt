package cn.zzk.jwt.jwttest.config.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.stereotype.Component
import java.io.IOException
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * Create Time : 2019/11/12
 * @author zzk
 */
@Component
class RestAuthenticationFailureHandler(
        private val objectMapper: ObjectMapper
) : AuthenticationFailureHandler {

    @Throws(IOException::class, ServletException::class)
    override fun onAuthenticationFailure(request: HttpServletRequest, response: HttpServletResponse, exception: AuthenticationException) {
        response.status = AuthResponse.ERROR_AUTH.code
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(response.outputStream, AuthResponse.ERROR_AUTH)
    }
}
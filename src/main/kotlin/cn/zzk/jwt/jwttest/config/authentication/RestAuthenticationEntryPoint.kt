package cn.zzk.jwt.jwttest.config.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * 认证入口。
 * 需要认证时从这里进入。对于rest应用来说，为需要登录的用户不需要重定向为登录界面 -- 返回401 状态码，并提示用户需要登录(认证)
 * Create Time : 2019/11/12
 * @author zzk
 */
@Component
class RestAuthenticationEntryPoint(
        private val objectMapper: ObjectMapper
) : AuthenticationEntryPoint {

    override fun commence(request: HttpServletRequest,
                          response: HttpServletResponse,
                          authException: AuthenticationException) {
        response.status = AuthResponse.WITHOUT_AUTH.code
        response.contentType = MediaType.APPLICATION_JSON_VALUE

        objectMapper.writeValue(response.outputStream, AuthResponse.WITHOUT_AUTH)
    }
}
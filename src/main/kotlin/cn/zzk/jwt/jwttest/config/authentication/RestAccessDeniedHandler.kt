package cn.zzk.jwt.jwttest.config.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * 权限不足时的逻辑处理
 *
 * Create Time : 2019/11/12
 * @author zzk
 */
@Component
class RestAccessDeniedHandler(
        private val objectMapper: ObjectMapper
) : AccessDeniedHandler {

    override fun handle(request: HttpServletRequest, response: HttpServletResponse, accessDeniedException: AccessDeniedException) {
        response.status = AuthResponse.NO_AUTHORITY.code
        response.contentType = MediaType.APPLICATION_JSON_VALUE

        objectMapper.writeValue(response.outputStream, AuthResponse.NO_AUTHORITY)
    }
}
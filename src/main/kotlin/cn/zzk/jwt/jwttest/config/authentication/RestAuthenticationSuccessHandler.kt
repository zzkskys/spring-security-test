package cn.zzk.jwt.jwttest.config.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.stereotype.Component
import org.springframework.util.StringUtils
import java.io.IOException
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
) : SimpleUrlAuthenticationSuccessHandler() {

    private var requestCache: RequestCache = HttpSessionRequestCache()

    @Throws(IOException::class)
    override fun onAuthenticationSuccess(
            request: HttpServletRequest,
            response: HttpServletResponse,
            authentication: Authentication) {

        setResponse(request, response)

        val savedRequest = requestCache.getRequest(request, response)

        if (savedRequest == null) {
            clearAuthenticationAttributes(request)
            return
        }
        val targetUrlParam = targetUrlParameter
        if (isAlwaysUseDefaultTargetUrl || targetUrlParam != null && StringUtils.hasText(request.getParameter(targetUrlParam))) {
            requestCache.removeRequest(request, response)
            clearAuthenticationAttributes(request)
            return
        }
        clearAuthenticationAttributes(request)
    }

    private fun setResponse(request: HttpServletRequest, response: HttpServletResponse) {
        clearAuthenticationAttributes(request)
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
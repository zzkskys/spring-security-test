package cn.zzk.jwt.jwttest.config.jwt

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtFilter(
        private val jwtAuthenticationProvider: JwtAuthenticationProvider
) : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val token = request.getHeader(jwtAuthenticationProvider.headerParamName)

        try {
            if (token != null && jwtAuthenticationProvider.validateToken(token)) {
                val auth = jwtAuthenticationProvider
                        .authenticate(UsernamePasswordAuthenticationToken(null, token))
                if (auth != null) {
                    SecurityContextHolder
                            .getContext()
                            .authentication = auth
                }
            }
            filterChain.doFilter(request, response)
        } catch (e: Exception) {
            filterChain.doFilter(request, response)
        }
    }
}
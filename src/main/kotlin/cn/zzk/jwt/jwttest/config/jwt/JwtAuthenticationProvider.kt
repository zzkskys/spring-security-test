package cn.zzk.jwt.jwttest.config.jwt

import cn.zzk.jwt.jwttest.domain.User
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.impl.DefaultClaims
import org.springframework.security.authentication.AccountExpiredException
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.util.*

@Component
class JwtAuthenticationProvider(
        private val jwtProperties: JwtProperties,
        private val objectMapper: ObjectMapper
) : AuthenticationProvider {

    /**
     * 若是 http 请求，则从 http请求 header中获取的参数名
     */
    val headerParamName: String = "x-auth-token"

    override fun authenticate(authentication: Authentication): Authentication? {
        if (authentication.credentials !is String) return null

        val token = authentication.credentials as String
        try {
            val user = getUserFromJwt(token)
            return if (user != null) {
                return UsernamePasswordAuthenticationToken(user, user.password, user.authorities)
            } else null
        } catch (e: Exception) {
            return null
        }
    }


    override fun supports(authentication: Class<*>): Boolean {
        return UsernamePasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    fun writeToken(user: UserDetails): String {
        val now = Date()
        return Jwts
                .builder()
                .addClaims(mapOf("user" to user))
                .setIssuedAt(now)
                .setExpiration(Date(now.time + jwtProperties.expirationTime))
                .signWith(SignatureAlgorithm.HS256, jwtProperties.secret)
                .compact()
    }

    fun getUserFromJwt(token: String): UserDetails? {
        val jws = Jwts
                .parser()
                .setSigningKey(jwtProperties.secret)
                .parseClaimsJws(token)
        val claims = jws.body as DefaultClaims

        return if (claims.contains("user"))
            objectMapper.convertValue(claims["user"], User::class.java)
        else null
    }

    @Throws(AccountExpiredException::class)
    fun validateToken(token: String?): Boolean {
        val claims: Jws<Claims> = Jwts
                .parser()
                .setSigningKey(jwtProperties.secret)
                .parseClaimsJws(token)
        return !claims.body.expiration.before(Date())
    }
}
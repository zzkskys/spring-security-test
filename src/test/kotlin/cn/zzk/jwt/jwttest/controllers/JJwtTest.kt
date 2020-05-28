package cn.zzk.jwt.jwttest.controllers

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.convertValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.impl.DefaultJws
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertEquals

class JJwtTest {

    /**
     * 过期时间 ： 单位毫秒
     */
    private val expirationTime = 1000 * 60 * 60

    private val secretKey = "qunchuang"

    private val objectMapper = ObjectMapper().registerKotlinModule()

    @Test
    fun create() {
        val now = Date()
        val expiration = Date(now.time + expirationTime)


        val token = Jwts
                .builder()
                .setAudience("1")
                .addClaims(mapOf("user" to Person("张三", "1")))
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact()

        println(token)

        val getClaims = Jwts
                .parser()
                .setSigningKey(secretKey)
                .parse(token)

        getClaims as DefaultJws
        val getBody = getClaims.body as DefaultClaims
        val any = getBody.get("user")!!

        val person = objectMapper.convertValue<Person>(any)
        assertEquals("张三", person.username)
        assertEquals("1", person.password)


    }

    @Test
    fun convertMapToPerson() {
        val map = mapOf<String, Any>("username" to "a", "password" to "A")
        val p = objectMapper.convertValue<Person>(map)
        assertEquals("a", p.username)
        assertEquals("A", p.password)
    }


}


private data class Person(
        val username: String,
        val password: String
)
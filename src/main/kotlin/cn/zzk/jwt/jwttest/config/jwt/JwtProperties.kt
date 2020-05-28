package cn.zzk.jwt.jwttest.config.jwt

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@ConfigurationProperties(prefix = "jwt")
@Component
class JwtProperties {

    /**
     * 过期时间，单位是毫秒，默认 4 小时
     */
    var expirationTime: Long = 1000 * 60 * 60 * 4

    /**
     * 加密密钥
     */
    var secret: String = "qunchuang"


}
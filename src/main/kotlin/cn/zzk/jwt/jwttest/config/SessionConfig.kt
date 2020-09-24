package cn.zzk.jwt.jwttest.config

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.springframework.beans.factory.BeanClassLoaderAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession
import org.springframework.session.web.http.HeaderHttpSessionIdResolver
import org.springframework.session.web.http.HttpSessionIdResolver

@EnableRedisHttpSession
@Configuration
class SessionConfig : BeanClassLoaderAware {

    lateinit var loader: ClassLoader

    @Bean
    fun httpSessionIdResolver(): HttpSessionIdResolver {
        return HeaderHttpSessionIdResolver.xAuthToken()
    }

    @Bean
    fun springSessionDefaultRedisSerializer(): RedisSerializer<Any?> {
        val objectMapper = ObjectMapper()
                .registerKotlinModule()
                .registerModules(SecurityJackson2Modules.getModules(loader))
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        objectMapper
                .activateDefaultTyping(objectMapper.polymorphicTypeValidator, ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY)

        return GenericJackson2JsonRedisSerializer(objectMapper)
    }


    override fun setBeanClassLoader(classLoader: ClassLoader) {
        this.loader = classLoader
    }

}
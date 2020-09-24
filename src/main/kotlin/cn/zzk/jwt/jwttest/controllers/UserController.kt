package cn.zzk.jwt.jwttest.controllers

import cn.zzk.jwt.jwttest.domain.User
import cn.zzk.jwt.jwttest.domain.UserRepo
import org.springframework.security.access.PermissionEvaluator
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.io.Serializable

@RestController
@RequestMapping("/users")
class UserController(
        private val userRepo: UserRepo
) {
    @GetMapping
    fun users() = userRepo.findAll()

    @GetMapping("/current")
    fun users(@AuthenticationPrincipal user: User) = user

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/2")
    fun users2() = userRepo.findAll()

    @PreAuthorize("authentication.name == 'a'")
    @GetMapping("/3")
    fun users3() = userRepo.findAll()

    @PreAuthorize("hasPermission(null,'read')")
    @GetMapping("/4")
    fun users4() = userRepo.findAll()

    @PreAuthorize("@permission.hasPermission(authentication,#age)")
    @GetMapping("/5")
    fun users5(@RequestParam(defaultValue = "5") age: Int) = userRepo.findAll()
}

@Component
class Permission {

    fun hasPermission(authentication: Authentication, age: Int): Boolean {
        println("name : ${authentication.name} , age : $age")
        return true
    }
}

@Component
class PermissionTest : PermissionEvaluator {


    override fun hasPermission(authentication: Authentication,
                               targetDomainObject: Any?,
                               permission: Any?): Boolean {
        if (permission != null && authentication.isAuthenticated) {
            return true
        }
        return false
    }

    override fun hasPermission(authentication: Authentication,
                               targetId: Serializable?,
                               targetType: String?,
                               permission: Any?): Boolean {
        return false
    }
}
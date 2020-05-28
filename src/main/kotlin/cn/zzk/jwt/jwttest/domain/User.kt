package cn.zzk.jwt.jwttest.domain

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.*
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.Id

@Entity
class User(
        @Id
        @Column(length = 36)
        var id: String = UUID.randomUUID().toString(),

        private val username: String,

        private var password: String
) : UserDetails {

    override fun getAuthorities(): MutableList<GrantedAuthority> = mutableListOf()

    override fun isEnabled(): Boolean = true

    override fun getUsername(): String = username

    override fun isCredentialsNonExpired(): Boolean = true

    override fun getPassword(): String = password

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true


    fun setPassword(password: String) {
        this.password = password
    }
}

interface UserRepo : JpaRepository<User, String> {

    @Query("select u from User u where u.username = ?1")
    fun findByName(name: String): User?
}